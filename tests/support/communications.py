"""Independent client for SunSpec CSIP-TP v1.3 COMM-002 and COMM-003."""

import http.client
import io
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from xml.etree import ElementTree


SEP = "{urn:ieee:std:2030.5:ns}"


class RecordedResponse:
    """Adapt the captured HTTP wire bytes for the standard response parser."""

    def __init__(self, data):
        self.data = data

    def makefile(self, mode):
        return io.BytesIO(self.data)


def check_handshake(trace):
    # RFC 5246 §7.4.1.3. The session ID is variable-length and precedes the suite.
    match = re.search(r"^<<< TLS 1\.2, Handshake .*?, ServerHello\s*\n((?: +[0-9a-fA-F ]+\n)+)", trace, re.MULTILINE)
    assert match, "No TLS 1.2 ServerHello in the handshake record"
    record = bytes.fromhex(match[1])
    assert record[0] == 2 and int.from_bytes(record[1:4], "big") == len(record) - 4
    assert record[4:6] == bytes.fromhex("0303")
    suite_offset = 39 + record[38]
    suite = record[suite_offset:suite_offset + 2].hex()
    assert suite == "c0ae", f"Unexpected cipher suite {suite}"
    assert re.search(r"^<<< .*?, CertificateRequest$", trace, re.MULTILINE)
    assert re.search(r"^>>> .*?, CertificateVerify$", trace, re.MULTILINE)
    assert re.search(r"^<<< .*?, Finished$", trace, re.MULTILINE)
    assert re.search(r"^>>> .*?, Finished$", trace, re.MULTILINE)
    print(f"ServerHello TLS 1.2 cipher 0x{suite}; both Finished messages recorded")


def fetch(directory, address, port, path, inspect):
    request = (
        f"GET {path} HTTP/1.1\r\nHost: server.local:{port}\r\n"
        "Accept: application/sep+xml\r\nConnection: close\r\n\r\n"
    )
    trace = directory / "handshake.txt"
    # OpenSSL 4 rates the mandated 64-bit tag below its default security
    # level. Keep the peer restricted to the single suite and test trust root.
    args = [
        "openssl", "s_client", "-quiet", "-ign_eof", "-ignore_unexpected_eof",
        "-verify_return_error", "-no-CApath", "-no-CAstore", "-verify_hostname", "server.local",
        "-connect", f"{address}:{port}", "-servername", "server.local", "-tls1_2",
        "-cipher", "ECDHE-ECDSA-AES128-CCM8:@SECLEVEL=0",
        "-CAfile", str(directory / "ca.pem"), "-cert", str(directory / "client.pem"),
        "-key", str(directory / "client.pem"),
    ]
    if inspect:
        args.extend(["-msg", "-msgfile", str(trace)])
    result = subprocess.run(args, input=request.encode("ascii"), capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()
    if inspect:
        check_handshake(trace.read_text())
    response = http.client.HTTPResponse(RecordedResponse(result.stdout))
    response.begin()
    print(f"GET {path} -> {response.status}")
    assert response.status == 200
    assert response.getheader("Content-Type") == "application/sep+xml"
    return ElementTree.fromstring(response.read())


def main():
    procedure, address, port, capability_path = sys.argv[1:]
    ca, identity = sys.stdin.buffer.read().split(b"\0")
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        (directory / "ca.pem").write_bytes(ca)
        (directory / "client.pem").write_bytes(identity)
        capability = fetch(directory, address, port, capability_path, procedure == "COMM-003")
        assert capability.tag == SEP + "DeviceCapability"
        assert capability.get("href") == capability_path
        if procedure == "COMM-002":
            link = capability.find(SEP + "EndDeviceListLink")
            assert link is not None
            target = link.attrib["href"]
            devices = fetch(directory, address, port, target, False)
            assert devices.tag == SEP + "EndDeviceList"
            assert devices.get("href") == target
            assert devices.attrib["all"] == devices.attrib["results"] == link.attrib["all"]
            assert len(devices.findall(SEP + "EndDevice")) == int(devices.attrib["results"])
        else:
            assert procedure == "COMM-003"


if __name__ == "__main__":
    main()
