//! Daemon-side pairing helpers: the `ucb://` URI scheme (DISC-3 QR-fallback for
//! multicast-blocked networks), terminal QR rendering (PAIR-2), and best-effort
//! local-IP enumeration — all pure functions so they can be unit-tested without
//! touching the network or a terminal.
//!
//! The URI only carries the *connection endpoint* (`ip:port`). It is not a
//! secret and grants no trust on its own: pairing still completes only after
//! both sides confirm the 6-digit verification code (PAIR-2). The QR simply
//! saves the user from typing an address on a network where mDNS discovery is
//! blocked.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use anyhow::{anyhow, Result};
use qrcode::render::unicode::Dense1x2;
use qrcode::QrCode;

/// Scheme prefix for pairing URIs.
const SCHEME: &str = "ucb://";

/// Format a pairing URI for a host/port endpoint, e.g. `ucb://192.168.1.5:48521`.
pub fn format_pairing_uri(host: &str, port: u16) -> String {
    format!("{SCHEME}{host}:{port}")
}

/// Normalize a pairing target given on `ucb pair --connect`.
///
/// Accepts either a bare `ip:port` (as before) or a `ucb://ip:port` URI, and
/// returns the bare `ip:port` authority suitable for `TcpStream::connect`.
/// Malformed input — an unknown URI scheme, a missing host, or a bad/zero
/// port — is rejected with a clear error. Hostnames are permitted for the host
/// part (as the previous bare-address path allowed); only the port is strictly
/// validated as a `u16`.
pub fn parse_pairing_target(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("empty pairing address; expected `ip:port` or `ucb://ip:port`"));
    }
    let authority = match trimmed.strip_prefix(SCHEME) {
        Some(rest) => rest,
        None => {
            if trimmed.contains("://") {
                return Err(anyhow!(
                    "unsupported URI scheme in {trimmed:?}; expected `ucb://ip:port` or `ip:port`"
                ));
            }
            trimmed
        }
    };
    let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
        anyhow!("malformed pairing address {input:?}: expected `ip:port` (host and port)")
    })?;
    if host.is_empty() {
        return Err(anyhow!("malformed pairing address {input:?}: missing host"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow!("malformed pairing address {input:?}: invalid port {port:?}"))?;
    if port == 0 {
        return Err(anyhow!("malformed pairing address {input:?}: port must be nonzero"));
    }
    Ok(format!("{host}:{port}"))
}

/// Render `uri` as a scannable QR code using Unicode half-block glyphs
/// (`Dense1x2`), suitable for printing under the URI in a terminal. Returns a
/// non-empty multi-line string. Encoding only fails for inputs far larger than
/// any pairing URI, so callers may treat an error as unexpected.
pub fn render_qr(uri: &str) -> Result<String> {
    let code =
        QrCode::new(uri.as_bytes()).map_err(|e| anyhow!("could not encode pairing QR: {e}"))?;
    Ok(code.render::<Dense1x2>().quiet_zone(true).build())
}

/// Best-effort primary local IPv4 address.
///
/// Uses the classic "connect a UDP socket toward a public address" trick: no
/// packets are sent, but the kernel picks the source address it *would* use to
/// reach that destination — i.e. the address on the default-route interface.
/// Returns `None` when offline or when no usable IPv4 route exists. This
/// function is total and never panics.
///
/// Tradeoff: without an interface-enumeration dependency (`if_addrs`,
/// `local-ip-address`, …) this reports only the *single* default-route
/// address, not every NIC. On a multi-homed host the peer may need to reach a
/// different interface; use `ucb pair --listen --host <ip>` to advertise that
/// address explicitly.
pub fn primary_local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    // A UDP `connect` only records the default peer; it sends nothing on the
    // wire, so this does not leak the pairing attempt to 8.8.8.8.
    socket.connect(("8.8.8.8", 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_then_parse_round_trips() {
        let uri = format_pairing_uri("192.168.1.5", 48521);
        assert_eq!(uri, "ucb://192.168.1.5:48521");
        assert_eq!(parse_pairing_target(&uri).unwrap(), "192.168.1.5:48521");
    }

    #[test]
    fn parse_accepts_bare_and_uri_forms() {
        assert_eq!(parse_pairing_target("10.0.0.7:9000").unwrap(), "10.0.0.7:9000");
        assert_eq!(
            parse_pairing_target("ucb://10.0.0.7:9000").unwrap(),
            "10.0.0.7:9000"
        );
        // Surrounding whitespace is tolerated (copy/paste from a QR scanner).
        assert_eq!(
            parse_pairing_target("  ucb://127.0.0.1:48521 \n").unwrap(),
            "127.0.0.1:48521"
        );
    }

    #[test]
    fn parse_rejects_malformed() {
        for bad in [
            "",
            "   ",
            "nocolon",
            "1.2.3.4:",
            "1.2.3.4:notaport",
            "1.2.3.4:0",
            "1.2.3.4:99999",
            ":48521",
            "http://1.2.3.4:5",
            "ucb://",
        ] {
            assert!(
                parse_pairing_target(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn render_qr_is_nonempty_and_uses_block_glyphs() {
        let uri = format_pairing_uri("192.168.1.5", 48521);
        let rendered = render_qr(&uri).unwrap();
        assert!(!rendered.is_empty());
        assert!(rendered.lines().count() > 1, "QR should be multi-line");
        // Dense1x2 draws with Unicode half-block / full-block glyphs.
        assert!(
            rendered.chars().any(|c| matches!(c, '\u{2580}' | '\u{2584}' | '\u{2588}' | ' ')),
            "expected Unicode block glyphs in the rendered QR"
        );
        assert!(
            rendered.contains('\u{2588}') || rendered.contains('\u{2580}') || rendered.contains('\u{2584}'),
            "expected at least one dark module glyph"
        );
    }

    #[test]
    fn primary_local_ipv4_is_total() {
        // Must not panic whether or not a network is present. Any value (or
        // `None` offline) is acceptable; a returned address must be a
        // non-loopback IPv4.
        if let Some(ip) = primary_local_ipv4() {
            assert!(!ip.is_loopback());
            assert!(!ip.is_unspecified());
        }
    }
}
