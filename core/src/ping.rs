//! Which probe a location gets — the CLI mirror of the desktop client's
//! `src/lib/location-ping.ts`. The two must agree: a location that reads
//! healthy in one client and dead in the other is a bug report either way.

use crate::subscription::VlessServer;

/// Budget for a TCP-capable location probed through the proxy.
pub const PROXY_PING_TIMEOUT_MS: u32 = 5_000;

/// Budget for a UDP-only location probed through the proxy.
///
/// Hysteria2 and QUIC pay a handshake on top of the request, and ordinary
/// datagram loss stretches it: a healthy Hysteria2 node has been measured
/// answering in 5.8 s. Judging it on the TCP budget reports live locations as
/// dead, which is how "our subscription does not ping" gets filed.
pub const UDP_PROXY_PING_TIMEOUT_MS: u32 = 15_000;

const UDP_ONLY_PROTOCOLS: [&str; 4] = ["hysteria", "hysteria2", "hy2", "wireguard"];
const UDP_ONLY_TRANSPORTS: [&str; 5] = ["hysteria", "hysteria2", "hy2", "kcp", "quic"];

/// Whether a bare TCP handshake to the endpoint says anything true.
///
/// A Hysteria2 or WireGuard endpoint does not listen for TCP at all, so its
/// handshake "timing out" measures the absence of a protocol, not the health of
/// the location.
pub fn supports_tcp_endpoint_ping(server: &VlessServer) -> bool {
    !(UDP_ONLY_PROTOCOLS.contains(&server.protocol.trim().to_lowercase().as_str())
        || UDP_ONLY_TRANSPORTS.contains(&server.transport.trim().to_lowercase().as_str()))
}

/// The proxy-probe budget a location needs.
pub fn proxy_ping_timeout_ms(server: &VlessServer) -> u32 {
    if supports_tcp_endpoint_ping(server) {
        PROXY_PING_TIMEOUT_MS
    } else {
        UDP_PROXY_PING_TIMEOUT_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription::parse_proxy_uri;

    fn location(protocol: &str, transport: &str) -> VlessServer {
        let mut server = parse_proxy_uri(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Loc",
        )
        .expect("uri parses");
        server.protocol = protocol.to_string();
        server.transport = transport.to_string();
        server
    }

    #[test]
    fn udp_only_endpoints_are_not_tcp_probed() {
        for (protocol, transport) in [
            ("hysteria", "hysteria"),
            ("hysteria2", "hysteria2"),
            ("hy2", "hy2"),
            ("wireguard", "wireguard"),
            ("vless", "kcp"),
            ("vless", "quic"),
        ] {
            let server = location(protocol, transport);
            assert!(!supports_tcp_endpoint_ping(&server), "{protocol}/{transport}");
            assert_eq!(proxy_ping_timeout_ms(&server), UDP_PROXY_PING_TIMEOUT_MS);
        }
    }

    #[test]
    fn tcp_endpoints_keep_the_short_budget() {
        let server = location("vless", "tcp");
        assert!(supports_tcp_endpoint_ping(&server));
        assert_eq!(proxy_ping_timeout_ms(&server), PROXY_PING_TIMEOUT_MS);
    }
}
