//! Human-readable summary of what a location actually is.
//!
//! Mirrors `src/lib/server-label.ts` in the desktop client; the two must agree,
//! so the tests below cover the cases that file's behaviour depends on.

use crate::subscription::VlessServer;

fn protocol_label(protocol: &str) -> String {
    match protocol {
        "vless" => "VLESS".to_string(),
        "trojan" => "Trojan".to_string(),
        "shadowsocks" => "Shadowsocks".to_string(),
        "vmess" => "VMess".to_string(),
        "wireguard" => "WireGuard".to_string(),
        other => other.to_uppercase(),
    }
}

/// e.g. `VLESS / TCP`, `VLESS / TCP / JSON`, `Trojan / WS / TLS`, `Hysteria2`,
/// `Hysteria2 / JSON`.
///
/// `reality` is deliberately omitted: it is the default for the locations that
/// use it and carries no information for the reader.
pub fn transport_summary(server: &VlessServer) -> String {
    if server.protocol.to_lowercase() == "hysteria" {
        let version = server
            .raw_outbound
            .as_ref()
            .and_then(|outbound| outbound.get("settings"))
            .and_then(|settings| settings.get("version"))
            .and_then(|version| version.as_u64());
        // Hysteria names its own transport, but a JSON-backed location still
        // needs the JSON marker: it is edited as a provider profile, not a URI.
        let mut parts = vec![if version == Some(2) {
            "Hysteria2".to_string()
        } else {
            "Hysteria".to_string()
        }];
        if server.source_json.is_some() {
            parts.push("JSON".to_string());
        }
        return parts.join(" / ");
    }

    let mut parts = vec![
        protocol_label(&server.protocol),
        server.transport.to_uppercase(),
    ];
    if !server.security.is_empty() && server.security != "none" && server.security != "reality" {
        parts.push(server.security.to_uppercase());
    }
    if server.source_json.is_some() {
        parts.push("JSON".to_string());
    }
    parts.join(" / ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription::parse_proxy_uri;

    fn server(uri: &str) -> VlessServer {
        parse_proxy_uri(uri).expect("uri parses")
    }

    #[test]
    fn reality_is_not_shown_but_tls_is() {
        let reality = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443\
             ?security=reality&pbk=k&sid=00&type=tcp#Loc",
        );
        assert_eq!(transport_summary(&reality), "VLESS / TCP");

        let tls = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443\
             ?security=tls&type=ws#Loc",
        );
        assert_eq!(transport_summary(&tls), "VLESS / WS / TLS");
    }

    #[test]
    fn json_locations_are_marked() {
        let mut location = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Loc",
        );
        assert_eq!(transport_summary(&location), "VLESS / TCP");
        location.source_json = Some("{}".to_string());
        assert_eq!(transport_summary(&location), "VLESS / TCP / JSON");
    }

    #[test]
    fn hysteria_version_two_is_named_separately() {
        let mut location = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Loc",
        );
        location.protocol = "hysteria".to_string();
        assert_eq!(transport_summary(&location), "Hysteria");
        location.raw_outbound = Some(serde_json::json!({"settings": {"version": 2}}));
        assert_eq!(transport_summary(&location), "Hysteria2");
    }

    #[test]
    fn json_marker_covers_hysteria_too() {
        let mut location = server(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp#Loc",
        );
        location.protocol = "hysteria".to_string();
        location.raw_outbound = Some(serde_json::json!({"settings": {"version": 2}}));
        location.source_json = Some("{}".to_string());
        assert_eq!(transport_summary(&location), "Hysteria2 / JSON");
    }
}
