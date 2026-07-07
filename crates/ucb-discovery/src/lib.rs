//! ucb-discovery — see ARCHITECTURE.md for the contract this crate implements.
//!
//! LAN peer discovery over mDNS (DISC-1) plus a peer up/down event surface
//! (the part of DISC-4 that lives here). We advertise our own service on
//! `_ucb._tcp.local.` and continuously browse the same service type, bridging
//! mdns-sd's synchronous (flume) event stream onto a `tokio::sync::mpsc`
//! channel of [`PeerEvent`]s.

use std::collections::HashMap;
use std::net::IpAddr;
use std::thread::JoinHandle;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::mpsc;
use ucb_core::{DeviceId, MDNS_SERVICE_TYPE};

/// Channel capacity for the bridged peer-event stream.
const EVENT_CHANNEL_CAP: usize = 64;

/// Errors surfaced while starting or running discovery.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mdns error: {0}")]
    Mdns(String),
}

impl From<mdns_sd::Error> for Error {
    fn from(e: mdns_sd::Error) -> Self {
        Error::Mdns(e.to_string())
    }
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// What this device publishes about itself on the LAN.
#[derive(Clone, Debug)]
pub struct Advertisement {
    pub device_id: DeviceId,
    pub name: String,
    pub port: u16,
    pub version: u16,
}

/// A discovered remote device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub device_id: DeviceId,
    pub name: String,
    pub addrs: Vec<IpAddr>,
    pub port: u16,
    pub version: u16,
}

/// Peer up/down events (DISC-4 surface).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerEvent {
    Found(Peer),
    Lost(DeviceId),
}

/// A running discovery instance: an mDNS registration plus a continuous
/// browse whose events are bridged onto the returned channel.
pub struct Discovery {
    daemon: ServiceDaemon,
    fullname: String,
    bridge: Option<JoinHandle<()>>,
}

impl Discovery {
    /// Register our advertisement and begin browsing. Returns the handle and
    /// the receiving end of the peer-event channel. Dropping the handle (or
    /// calling [`Discovery::shutdown`]) tears down the daemon and stops the
    /// bridge thread.
    pub fn start(ad: Advertisement) -> Result<(Discovery, mpsc::Receiver<PeerEvent>)> {
        let daemon = ServiceDaemon::new()?;

        let instance = ad.device_id.short();
        // A unique-ish hostname; addresses are auto-detected below.
        let host = format!("{instance}.local.");

        let mut props: HashMap<String, String> = HashMap::new();
        props.insert("id".to_string(), ad.device_id.to_string());
        props.insert("name".to_string(), ad.name.clone());
        props.insert("v".to_string(), ad.version.to_string());

        let info = ServiceInfo::new(MDNS_SERVICE_TYPE, &instance, &host, "", ad.port, props)?
            .enable_addr_auto();
        let fullname = info.get_fullname().to_string();
        daemon.register(info)?;

        let events = daemon.browse(MDNS_SERVICE_TYPE)?;
        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAP);

        let me = ad.device_id;
        let bridge = std::thread::Builder::new()
            .name("ucb-discovery-bridge".to_string())
            .spawn(move || browse_loop(events, me, tx))
            .expect("spawn discovery bridge thread");

        Ok((
            Discovery {
                daemon,
                fullname,
                bridge: Some(bridge),
            },
            rx,
        ))
    }

    /// Gracefully unregister and tear down. Consumes the handle.
    pub fn shutdown(self) {
        // Explicit goodbye so peers see us leave promptly; Drop then shuts
        // the daemon down and joins the bridge thread.
        let _ = self.daemon.unregister(&self.fullname);
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        // Shutting the daemon down drops the browse sender, which disconnects
        // the flume receiver so the bridge thread's `recv()` loop exits.
        let _ = self.daemon.shutdown();
        if let Some(bridge) = self.bridge.take() {
            let _ = bridge.join();
        }
    }
}

/// Bridge loop: translate mdns-sd events into [`PeerEvent`]s on `tx`.
///
/// Runs on a dedicated blocking thread. Exits when the browse channel
/// disconnects (daemon shutdown) or when the receiver is dropped.
fn browse_loop(events: mdns_sd::Receiver<ServiceEvent>, me: DeviceId, tx: mpsc::Sender<PeerEvent>) {
    // device_id -> last emitted (sorted addrs, port), for de-duplication.
    let mut known: HashMap<DeviceId, (Vec<IpAddr>, u16)> = HashMap::new();
    // mDNS fullname -> device_id, so ServiceRemoved (which only carries the
    // fullname) can be mapped back to a DeviceId for `Lost`.
    let mut by_fullname: HashMap<String, DeviceId> = HashMap::new();

    while let Ok(event) = events.recv() {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                let parsed = {
                    let pairs: Vec<(&str, &str)> = info
                        .get_properties()
                        .iter()
                        .map(|p| (p.key(), p.val_str()))
                        .collect();
                    parse_advertisement(&pairs)
                };
                let parsed = match parsed {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(
                            fullname = %info.get_fullname(),
                            error = ?e,
                            "skipping peer with malformed TXT records"
                        );
                        continue;
                    }
                };

                // Never emit ourselves as a peer.
                if is_self(parsed.device_id, me) {
                    continue;
                }

                let mut addrs: Vec<IpAddr> = info.get_addresses().iter().copied().collect();
                addrs.sort();

                let peer = Peer {
                    device_id: parsed.device_id,
                    name: parsed.name,
                    addrs,
                    port: info.get_port(),
                    version: parsed.version,
                };

                by_fullname.insert(info.get_fullname().to_string(), peer.device_id);

                if peer_is_new_or_changed(&known, &peer) {
                    known.insert(peer.device_id, (peer.addrs.clone(), peer.port));
                    if tx.blocking_send(PeerEvent::Found(peer)).is_err() {
                        break; // receiver dropped
                    }
                }
            }
            ServiceEvent::ServiceRemoved(_ty, fullname) => {
                if let Some(id) = by_fullname.remove(&fullname) {
                    known.remove(&id);
                    if tx.blocking_send(PeerEvent::Lost(id)).is_err() {
                        break; // receiver dropped
                    }
                }
            }
            // SearchStarted / ServiceFound / SearchStopped: not actionable here.
            _ => {}
        }
    }
}

/// The subset of a peer's identity carried in its TXT records.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAdvertisement {
    device_id: DeviceId,
    name: String,
    version: u16,
}

/// Why a set of TXT records could not be turned into a peer identity.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TxtParseError {
    MissingId,
    BadId,
    MissingVersion,
    BadVersion,
}

/// Pure, testable TXT-record parser. Case-insensitive on keys. `name` is
/// optional (defaults to empty); `id` and `v` are required and must be
/// well-formed, otherwise the peer is rejected rather than panicking.
fn parse_advertisement(
    pairs: &[(&str, &str)],
) -> std::result::Result<ParsedAdvertisement, TxtParseError> {
    let get = |key: &str| -> Option<&str> {
        pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| *v)
    };

    let id_hex = get("id").ok_or(TxtParseError::MissingId)?;
    let bytes = hex::decode(id_hex).map_err(|_| TxtParseError::BadId)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| TxtParseError::BadId)?;
    let device_id = DeviceId(arr);

    let name = get("name").unwrap_or("").to_string();

    let v = get("v").ok_or(TxtParseError::MissingVersion)?;
    let version = v.parse::<u16>().map_err(|_| TxtParseError::BadVersion)?;

    Ok(ParsedAdvertisement {
        device_id,
        name,
        version,
    })
}

/// True when a resolved advertisement is our own.
fn is_self(parsed_id: DeviceId, me: DeviceId) -> bool {
    parsed_id == me
}

/// De-dup predicate: emit `Found` only for a peer we have not seen, or whose
/// address set or port changed since we last emitted it. `peer.addrs` is
/// assumed sorted so the comparison is order-insensitive.
fn peer_is_new_or_changed(known: &HashMap<DeviceId, (Vec<IpAddr>, u16)>, peer: &Peer) -> bool {
    match known.get(&peer.device_id) {
        None => true,
        Some((addrs, port)) => addrs != &peer.addrs || *port != peer.port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> DeviceId {
        DeviceId([byte; 32])
    }

    #[test]
    fn txt_roundtrip_parses_full_advertisement() {
        let device_id = id(0xAB);
        let id_hex = device_id.to_string();
        let pairs = [("id", id_hex.as_str()), ("name", "Laptop"), ("v", "1")];

        let parsed = parse_advertisement(&pairs).expect("should parse");
        assert_eq!(parsed.device_id, device_id);
        assert_eq!(parsed.name, "Laptop");
        assert_eq!(parsed.version, 1);
    }

    #[test]
    fn txt_parse_is_case_insensitive_on_keys() {
        let id_hex = id(1).to_string();
        let pairs = [("ID", id_hex.as_str()), ("Name", "x"), ("V", "7")];
        let parsed = parse_advertisement(&pairs).expect("should parse");
        assert_eq!(parsed.device_id, id(1));
        assert_eq!(parsed.version, 7);
    }

    #[test]
    fn txt_parse_name_is_optional() {
        let id_hex = id(2).to_string();
        let pairs = [("id", id_hex.as_str()), ("v", "1")];
        let parsed = parse_advertisement(&pairs).expect("should parse");
        assert_eq!(parsed.name, "");
    }

    #[test]
    fn txt_parse_missing_id_is_rejected() {
        let pairs = [("name", "x"), ("v", "1")];
        assert_eq!(parse_advertisement(&pairs), Err(TxtParseError::MissingId));
    }

    #[test]
    fn txt_parse_non_hex_id_is_rejected() {
        let pairs = [("id", "not-hex!!"), ("v", "1")];
        assert_eq!(parse_advertisement(&pairs), Err(TxtParseError::BadId));
    }

    #[test]
    fn txt_parse_wrong_length_id_is_rejected() {
        // Valid hex but only 2 bytes instead of 32.
        let pairs = [("id", "abcd"), ("v", "1")];
        assert_eq!(parse_advertisement(&pairs), Err(TxtParseError::BadId));
    }

    #[test]
    fn txt_parse_missing_version_is_rejected() {
        let id_hex = id(3).to_string();
        let pairs = [("id", id_hex.as_str()), ("name", "x")];
        assert_eq!(
            parse_advertisement(&pairs),
            Err(TxtParseError::MissingVersion)
        );
    }

    #[test]
    fn txt_parse_non_numeric_version_is_rejected() {
        let id_hex = id(4).to_string();
        let pairs = [("id", id_hex.as_str()), ("v", "abc")];
        assert_eq!(parse_advertisement(&pairs), Err(TxtParseError::BadVersion));
    }

    #[test]
    fn self_advertisement_is_filtered() {
        let me = id(0x11);
        assert!(is_self(me, me));
        assert!(!is_self(id(0x22), me));
    }

    #[test]
    fn dedup_unknown_peer_is_new() {
        let known = HashMap::new();
        let peer = Peer {
            device_id: id(1),
            name: "a".into(),
            addrs: vec!["10.0.0.1".parse().unwrap()],
            port: 9000,
            version: 1,
        };
        assert!(peer_is_new_or_changed(&known, &peer));
    }

    #[test]
    fn dedup_identical_peer_is_not_reemitted() {
        let mut known = HashMap::new();
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        known.insert(id(1), (vec![addr], 9000u16));
        let peer = Peer {
            device_id: id(1),
            name: "renamed-but-same-endpoint".into(),
            addrs: vec![addr],
            port: 9000,
            version: 1,
        };
        assert!(!peer_is_new_or_changed(&known, &peer));
    }

    #[test]
    fn dedup_changed_addr_or_port_re_emits() {
        let mut known = HashMap::new();
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        known.insert(id(1), (vec![addr], 9000u16));

        let changed_port = Peer {
            device_id: id(1),
            name: "a".into(),
            addrs: vec![addr],
            port: 9001,
            version: 1,
        };
        assert!(peer_is_new_or_changed(&known, &changed_port));

        let changed_addr = Peer {
            device_id: id(1),
            name: "a".into(),
            addrs: vec!["10.0.0.2".parse().unwrap()],
            port: 9000,
            version: 1,
        };
        assert!(peer_is_new_or_changed(&known, &changed_addr));
    }

    /// Real multicast end-to-end check. Ignored by default: multicast is
    /// flaky in CI and on macOS may trigger the local-network permission
    /// prompt. Run explicitly with `cargo test -p ucb-discovery -- --ignored`.
    #[ignore]
    #[tokio::test]
    async fn e2e_two_instances_discover_each_other() {
        use std::time::Duration;

        let a = Advertisement {
            device_id: id(0xA1),
            name: "alpha".into(),
            port: 7001,
            version: 1,
        };
        let b = Advertisement {
            device_id: id(0xB2),
            name: "bravo".into(),
            port: 7002,
            version: 1,
        };

        let (disc_a, mut rx_a) = Discovery::start(a).expect("start a");
        let (disc_b, mut rx_b) = Discovery::start(b).expect("start b");

        let found_a = wait_for_found(&mut rx_a, id(0xB2)).await;
        let found_b = wait_for_found(&mut rx_b, id(0xA1)).await;

        assert!(found_a, "alpha should discover bravo");
        assert!(found_b, "bravo should discover alpha");

        disc_a.shutdown();
        disc_b.shutdown();

        async fn wait_for_found(rx: &mut mpsc::Receiver<PeerEvent>, want: DeviceId) -> bool {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return false;
                }
                match tokio::time::timeout(remaining, rx.recv()).await {
                    Ok(Some(PeerEvent::Found(peer))) if peer.device_id == want => return true,
                    Ok(Some(_)) => continue,
                    Ok(None) | Err(_) => return false,
                }
            }
        }
    }
}
