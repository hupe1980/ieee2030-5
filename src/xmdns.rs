//! Site-scoped IEEE 2030.5-2018 discovery for configured interfaces.
//! The browser resolves complete DNS-SD answers from a PTR exchange. DNS data
//! supplies a route hint. Authenticate the selected server with the TLS runtime.

use crate::discovery::{Endpoint, Service, from_record};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA, PTR, SRV, TXT},
    },
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroU32,
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 251);
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0xfb);
pub const PORT: u16 = 5353;
const DOMAIN: &str = "_smartenergy._tcp.site.";
const MAX_PACKET: usize = 9000; // RFC 6762 §17
const MAX_RECORDS: usize = 128;
const MAX_INSTANCES: usize = 64;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn dns_error(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
fn query_name(service: Service) -> Name {
    // All components come from the IEEE subtype table or a validated SFDI.
    Name::from_ascii(service.local_name().replace(".local.", ".site.")).expect("known service type")
}

/// Select the interface explicitly. The IPv6 address must have global or
/// unique-local scope so clients on other links can route the unicast reply.
#[derive(Debug, Copy, Clone)]
pub enum Interface {
    V4(Ipv4Addr),
    V6 {
        address: Ipv6Addr,
        index: NonZeroU32,
    },
}
impl Interface {
    fn addr(self) -> SocketAddr {
        match self {
            Self::V4(v) => SocketAddr::new(v.into(), PORT),
            Self::V6 { address, index } => SocketAddrV6::new(address, PORT, 0, index.get()).into(),
        }
    }
    fn group(self) -> SocketAddr {
        match self {
            Self::V4(_) => SocketAddr::new(GROUP_V4.into(), PORT),
            Self::V6 { index, .. } => SocketAddrV6::new(GROUP_V6, PORT, 0, index.get()).into(),
        }
    }
    fn socket(self, address: SocketAddr, multicast: bool) -> io::Result<UdpSocket> {
        let ip = self.addr().ip();
        if ip.is_unspecified()
            || ip.is_multicast()
            || matches!(self,Self::V6{address,..} if !(address.segments()[0]&0xe000==0x2000 || address.is_unique_local()))
        {
            return Err(invalid(
                "expected a unicast interface address with suitable scope",
            ));
        }
        let sock = Socket::new(
            if ip.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        sock.set_reuse_address(true)?;
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        sock.set_reuse_port(true)?;
        match self {
            Self::V4(v) => {
                #[cfg(target_os = "linux")]
                sock.set_multicast_all_v4(false)?;
                sock.set_multicast_if_v4(&v)?;
                sock.set_multicast_ttl_v4(255)?;
            }
            Self::V6 { index, .. } => {
                #[cfg(target_os = "linux")]
                sock.set_multicast_all_v6(false)?;
                sock.set_only_v6(true)?;
                sock.set_multicast_if_v6(index.get())?;
                sock.set_multicast_hops_v6(255)?;
            }
        }
        sock.bind(&address.into())?;
        if multicast {
            match self {
                Self::V4(v) => sock.join_multicast_v4(&GROUP_V4, &v)?,
                Self::V6 { index, .. } => sock.join_multicast_v6(&GROUP_V6, index.get())?,
            }
        }
        sock.set_nonblocking(true)?;
        UdpSocket::from_std(sock.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    Multicast,
    Unicast,
}

/// One validated, self-contained advertisement. Use one unique instance label
/// for the server and another for each published function set (2018 §7.2/7.5).
pub struct Advertisement {
    owner: Name,
    ptr: Record,
    additional: [Record; 3],
}
impl Advertisement {
    pub fn new(
        instance: &str,
        host: &str,
        ip: IpAddr,
        endpoint: Endpoint<'_>,
        function: Option<(Service, &str)>,
    ) -> io::Result<Self> {
        if instance.is_empty()
            || instance.len() > 63
            || host.len() > 255
            || !host.ends_with('.')
            || ip.is_unspecified()
            || ip.is_multicast()
        {
            return Err(invalid("invalid service instance, host or address"));
        }
        let (service, path) = function.map_or((Service::Capabilities, None), |(s, p)| (s, Some(p)));
        if service == Service::Capabilities && path.is_some() {
            return Err(invalid("main service has no function path"));
        }
        let https = endpoint.https_port.to_string();
        from_record(
            Some("1"),
            Some("-S1"),
            Some(&https),
            Some(endpoint.capability_path),
            path,
            service,
        )
        .map_err(|e| dns_error(format!("{e:?}")))?;
        let owner = query_name(service);
        let instance = Name::from_labels([instance.as_bytes()])
            .and_then(|label| label.append_domain(&Name::from_ascii(DOMAIN)?))
            .map_err(dns_error)?;
        let host = Name::from_ascii(host).map_err(dns_error)?;
        if host.is_root() {
            return Err(invalid("missing service host"));
        }
        let mut txt = vec![
            "txtvers=1".into(),
            format!("dcap={}", endpoint.capability_path),
            format!("https={https}"),
            "level=-S1".into(),
        ];
        if let Some(path) = path {
            txt.push(format!("path={path}"))
        }
        let ptr = Record::from_rdata(owner.clone(), 120, RData::PTR(PTR(instance.clone())));
        let mut additional = [
            Record::from_rdata(
                instance.clone(),
                120,
                RData::SRV(SRV::new(0, 0, 80, host.clone())),
            ),
            Record::from_rdata(instance, 120, RData::TXT(TXT::new(txt))),
            Record::from_rdata(
                host,
                120,
                match ip {
                    IpAddr::V4(v) => RData::A(A(v)),
                    IpAddr::V6(v) => RData::AAAA(AAAA(v)),
                },
            ),
        ];
        for r in &mut additional {
            r.mdns_cache_flush = true
        }
        Ok(Self {
            owner,
            ptr,
            additional,
        })
    }
}

/// Enforce a per-packet record budget before allocating for peer-supplied counts.
/// Hickory handles wire labels, compression, RDATA and message flags.
fn decode(packet: &[u8]) -> Option<Message> {
    if !(12..=MAX_PACKET).contains(&packet.len()) {
        return None;
    }
    let count: usize = packet[4..12]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| usize::from(u16::from_be_bytes(*v)))
        .sum();
    if count > MAX_RECORDS {
        return None;
    }
    let msg = Message::from_vec(packet).ok()?;
    (msg.metadata.op_code == OpCode::Query
        && msg.metadata.response_code == ResponseCode::NoError
        && !msg.metadata.truncation)
        .then_some(msg)
}

/// A responder for explicitly provisioned, unique service instance names.
pub struct Responder {
    socket: UdpSocket,
    sender: UdpSocket,
    group: SocketAddr,
    announcements: Vec<Advertisement>,
}
impl Responder {
    pub fn bind(interface: Interface, announcements: Vec<Advertisement>) -> io::Result<Self> {
        if announcements.is_empty() || announcements.len() > MAX_INSTANCES {
            return Err(invalid("invalid service instance count"));
        }
        for (i, a) in announcements.iter().enumerate() {
            if announcements[..i]
                .iter()
                .any(|b| a.owner == b.owner || a.additional[0].name == b.additional[0].name)
            {
                return Err(invalid("duplicate service or instance"));
            }
        }
        Ok(Self {
            socket: interface.socket(interface.group(), true)?,
            // Keep the transmitting socket off the group address. A unicast
            // client bound to its interface address can receive QU replies
            // even when the responder is running on the same host.
            sender: interface.socket(
                SocketAddr::new(
                    if interface.addr().is_ipv4() {
                        Ipv4Addr::UNSPECIFIED.into()
                    } else {
                        Ipv6Addr::UNSPECIFIED.into()
                    },
                    PORT,
                ),
                false,
            )?,
            group: interface.group(),
            announcements,
        })
    }

    /// Serve site-scoped PTR questions with the required associated records.
    /// Drop the future to stop. QU and device-specific queries use unicast.
    pub async fn run(&self) -> io::Result<()> {
        let mut buf = [0u8; MAX_PACKET + 1];
        loop {
            let (len, peer) = self.socket.recv_from(&mut buf).await?;
            if peer.port() != PORT {
                continue;
            }
            let Some(msg) = decode(&buf[..len]) else {
                continue;
            };
            if msg.metadata.message_type != MessageType::Query {
                continue;
            }
            // Keep QU and QM answers separate when both occur in one packet.
            for unicast in [false, true] {
                let mut answer = Message::response(0, OpCode::Query);
                answer.metadata.authoritative = true;
                for a in &self.announcements {
                    if !msg.queries.iter().any(|q| {
                        q.mdns_unicast_response == unicast
                            && q.query_class == DNSClass::IN
                            && q.query_type == RecordType::PTR
                            && q.name == a.owner
                    }) {
                        continue;
                    }
                    if !unicast
                        && (a.owner.to_ascii().starts_with("edev-")
                            || msg.answers.iter().any(|r| {
                                r.name == a.owner && r.data == a.ptr.data && r.ttl >= a.ptr.ttl / 2
                            }))
                    {
                        continue;
                    }
                    answer.answers.push(a.ptr.clone());
                    for r in &a.additional {
                        if !answer.additionals.contains(r) {
                            answer.additionals.push(r.clone())
                        }
                    }
                }
                if answer.answers.is_empty() {
                    continue;
                }
                let bytes = answer.to_vec().map_err(dns_error)?;
                if bytes.len() <= MAX_PACKET {
                    self.sender
                        .send_to(&bytes, if unicast { peer } else { self.group })
                        .await?;
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub host: String,
    pub address: SocketAddr,
    pub capability_path: String,
    pub resource_path: String,
}

/// Link live records by their expanded DNS names. A matching TXT record from
/// another instance, or address from another host, cannot complete this chain.
fn resolve(msg: &Message, owner: &Name, service: Service) -> Option<Resolved> {
    if msg.metadata.message_type != MessageType::Response || !msg.metadata.authoritative {
        return None;
    }
    let records = || {
        msg.answers
            .iter()
            .chain(&msg.additionals)
            .filter(|r| r.ttl != 0 && r.dns_class == DNSClass::IN)
    };
    let domain = Name::from_ascii(DOMAIN).ok()?;
    for ptr in records().filter(|r| r.name == *owner) {
        let RData::PTR(instance) = &ptr.data else {
            continue;
        };
        if instance.0.base_name() != domain {
            continue;
        }
        let Some(srv) = records().find_map(|r| {
            if r.name == instance.0
                && let RData::SRV(s) = &r.data
            {
                Some(s)
            } else {
                None
            }
        }) else {
            continue;
        };
        let Some(txt) = records().find_map(|r| {
            if r.name == instance.0
                && let RData::TXT(t) = &r.data
            {
                Some(t)
            } else {
                None
            }
        }) else {
            continue;
        };
        if !txt
            .txt_data
            .first()
            .is_some_and(|kv| kv.eq_ignore_ascii_case(b"txtvers=1"))
        {
            continue;
        }
        let field = |key: &str| {
            txt.txt_data.iter().find_map(|raw| {
                let end = raw.iter().position(|b| *b == b'=').unwrap_or(raw.len());
                raw[..end]
                    .eq_ignore_ascii_case(key.as_bytes())
                    .then(|| std::str::from_utf8(raw.get(end + 1..).unwrap_or_default()).ok())
                    .flatten()
            })
        };
        let path = field("path");
        let Ok(endpoint) = from_record(
            field("txtvers"),
            field("level"),
            field("https"),
            field("dcap"),
            path,
            service,
        ) else {
            continue;
        };
        let Some(ip) = records()
            .filter(|r| r.name == srv.target)
            .find_map(|r| match r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                _ => None,
            })
            .filter(|ip| !ip.is_multicast() && !ip.is_unspecified())
        else {
            continue;
        };
        return Some(Resolved {
            host: srv.target.to_ascii().trim_end_matches('.').into(),
            address: SocketAddr::new(ip, endpoint.https_port.get()),
            capability_path: endpoint.capability_path.into(),
            resource_path: if service == Service::Capabilities {
                endpoint.capability_path
            } else {
                path?
            }
            .into(),
        });
    }
    None
}

/// Decode a captured DNS message and resolve the chain for the requested
/// service. Returns None for a malformed, incomplete, expired or unrelated answer.
pub fn resolve_packet(packet: &[u8], service: Service) -> Option<Resolved> {
    resolve(&decode(packet)?, &query_name(service), service)
}

/// Send a site-scoped PTR query and wait for the first complete, secure
/// endpoint within a caller-supplied deadline. Repeat on loss as appropriate.
pub async fn browse(
    interface: Interface,
    service: Service,
    reply: Reply,
    wait: Duration,
) -> io::Result<Resolved> {
    if matches!(service, Service::Device(_)) && reply != Reply::Unicast {
        return Err(invalid(
            "device-specific discovery requires unicast replies",
        ));
    }
    let owner = query_name(service);
    let mut q = Query::query(owner.clone(), RecordType::PTR);
    q.set_mdns_unicast_response(reply == Reply::Unicast);
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.queries.push(q);
    let sender = interface.socket(interface.addr(), false)?;
    let multicast = if reply == Reply::Multicast {
        Some(interface.socket(interface.group(), true)?)
    } else {
        None
    };
    let receiver = multicast.as_ref().unwrap_or(&sender);
    let bytes = msg.to_vec().map_err(dns_error)?;
    timeout(wait, async {
        sender.send_to(&bytes, interface.group()).await?;
        let mut buf = [0u8; MAX_PACKET + 1];
        loop {
            let (n, source) = receiver.recv_from(&mut buf).await?;
            if source.port() == PORT
                && let Some(m) = decode(&buf[..n])
                && let Some(result) = resolve(&m, &owner, service)
            {
                return Ok(result);
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "xmDNS response deadline expired"))?
}
