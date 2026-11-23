//! Change-only subscriptions for DER control lists.
//!
//! Each side binds a subscription to the authenticated peer's LFDI. On the publishing
//! side construct the expected callback from the subscriber's provisioned endpoint.
use super::{Client, ControlFeed, link, post_location};
use crate::codec::{self, Document, Limits};
use crate::encode::Element;
use crate::model;
use crate::runtime::RuntimeError;
use crate::security::Lfdi;
use bytes::Bytes;
use hyper::{Method, StatusCode};

#[derive(Clone, Debug)]
pub struct ControlSubscription {
    resource: String,
    location: String,
    callback: String,
    peer: Lfdi,
    href_bytes: usize,
}

fn absolute(value: &str, max_bytes: usize) -> Result<String, RuntimeError> {
    link(value, "", max_bytes)
}

fn xml_text(value: &str) -> String {
    let mut escaped = String::new();
    codec::escape(value, false, &mut escaped);
    escaped
}

impl ControlSubscription {
    /// Configure the authorized resource, subscription URI, callback URI and inbound peer.
    /// This is a local authorization decision, made before inspecting a subscriber's POST.
    pub fn new(
        resource: &str,
        location: &str,
        callback: &str,
        peer: Lfdi,
        href_bytes: usize,
    ) -> Result<Self, RuntimeError> {
        let resource = absolute(resource, href_bytes)?;
        if resource.contains('?') {
            return Err("expected a list URI without a query".into());
        }
        let location = link(&resource, location, href_bytes)?;
        let callback = absolute(callback, href_bytes)?;
        Ok(Self {
            resource,
            location,
            callback,
            peer,
            href_bytes,
        })
    }
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Verify the authenticated subscriber and its requested change-only subscription.
    /// Register with the resource tree only after this succeeds.
    pub fn validate_request(
        &self,
        peer: Lfdi,
        xml: &str,
        limits: Limits,
    ) -> Result<(), RuntimeError> {
        if peer != self.peer {
            return Err("unauthorized subscriber".into());
        }
        let doc = Document::parse(xml, limits)?;
        let sub = doc.as_type::<model::Subscription>()?;
        let target = codec::element_text(
            sub.as_base()
                .subscribed_resource()
                .ok_or("missing target")?,
        );
        let callback = codec::element_text(sub.notification_uri().ok_or("missing callback")?);
        let resource = link(&self.location, &target, self.href_bytes)?;
        let resource = resource.split('?').next().ok_or("missing target path")?;
        if resource != self.resource || absolute(&callback, self.href_bytes)? != self.callback {
            return Err("unauthorized subscription target or callback".into());
        }
        if sub.condition().is_some()
            || sub.encoding().ok_or("missing encoding")?.value() != 0
            || sub.limit().ok_or("missing limit")?.value() != 0
            || sub.level().ok_or("missing schema level")?.value() != "-S1"
        {
            return Err("expected a change-only, base-schema XML subscription".into());
        }
        Ok(())
    }

    /// Send a zero-result list notification through a preconfigured callback client.
    /// An error leaves the subscription available for a later retry.
    pub async fn notify(&self, target: &Client, total: u32) -> Result<(), RuntimeError> {
        let resource = xml_text(&self.resource);
        let location = xml_text(&self.location);
        let xml = format!(
            r#"<Notification xmlns="{}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><subscribedResource>{resource}</subscribedResource><Resource xsi:type="DERControlList" all="{total}" results="0"/><status>0</status><subscriptionURI>{location}</subscriptionURI></Notification>"#,
            codec::SEP
        );
        Document::parse(&xml, target.limits.xml)?;
        let response = target
            .request(Method::POST, &self.callback, Bytes::from(xml))
            .await?;
        post_location(&response, &self.callback, self.href_bytes)?;
        Ok(())
    }

    /// Authenticate and correlate a change-only notification before refetching the feed.
    pub fn validate_notification(
        &self,
        peer: Lfdi,
        xml: &str,
        limits: Limits,
    ) -> Result<(), RuntimeError> {
        if peer != self.peer {
            return Err("unauthorized notification publisher".into());
        }
        let doc = Document::parse(xml, limits)?;
        let note = doc.as_type::<model::Notification>()?;
        let target = codec::element_text(
            note.as_base()
                .subscribed_resource()
                .ok_or("missing resource")?,
        );
        let location = codec::element_text(note.subscription_uri().ok_or("missing subscription")?);
        if absolute(&location, self.href_bytes)? != self.location
            || link(&self.location, &target, self.href_bytes)? != self.resource
            || note.new_resource_uri().is_some()
            || note.status().ok_or("missing notification status")?.value() != 0
        {
            return Err("unexpected subscription, target or notification status".into());
        }
        use model::View;
        let item = note.resource().ok_or("missing list summary")?.node();
        let ty = item
            .attribute(("http://www.w3.org/2001/XMLSchema-instance", "type"))
            .ok_or("missing list type")?
            .trim();
        let (prefix, name) = ty.split_once(':').map_or((None, ty), |(p, n)| (Some(p), n));
        if item.lookup_namespace_uri(prefix) != Some(codec::SEP)
            || name != "DERControlList"
            || super::number(item.attribute("results"))? != 0
            || item.children().any(|n| n.is_element())
        {
            return Err("expected an empty DERControlList summary".into());
        }
        Ok(())
    }
}
impl Client {
    /// Subscribe at the registered device's advertised collection. The callback URI
    /// must identify the application's own HTTPS notification endpoint.
    pub async fn subscribe_controls(
        &self,
        feed: &ControlFeed,
        callback: &str,
        publisher: Lfdi,
    ) -> Result<ControlSubscription, RuntimeError> {
        let collection = feed
            .subscription_list
            .as_deref()
            .ok_or("device has no SubscriptionListLink")?;
        let collection = link(&self.origin, collection, self.limits.href_bytes)?;
        let callback = absolute(callback, self.limits.href_bytes)?;
        let target = link(&self.origin, &feed.url, self.limits.href_bytes)?;
        let target = target.split('?').next().ok_or("missing list path")?;
        let e = Element::sep;
        let body = e("Subscription")
            .child(e("subscribedResource").text(target))
            .child(e("encoding").text(0))
            .child(e("level").text("-S1"))
            .child(e("limit").text(0))
            .child(e("notificationURI").text(&callback))
            .encode(self.limits.xml)?;
        let response = self
            .request(Method::POST, &collection, Bytes::from(body))
            .await?;
        let location = post_location(&response, &collection, self.limits.href_bytes)?;
        ControlSubscription::new(
            target,
            &location,
            &callback,
            publisher,
            self.limits.href_bytes,
        )
    }

    /// Remove the remote subscription. Callers can then drop their local callback binding.
    pub async fn unsubscribe_controls(
        &self,
        sub: &ControlSubscription,
    ) -> Result<(), RuntimeError> {
        let response = self
            .request(Method::DELETE, sub.location(), Bytes::new())
            .await?;
        if matches!(response.status(), StatusCode::OK | StatusCode::NO_CONTENT) {
            Ok(())
        } else {
            Err(format!("subscription DELETE returned {}", response.status()).into())
        }
    }
}
