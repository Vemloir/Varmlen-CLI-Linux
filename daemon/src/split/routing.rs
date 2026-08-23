use std::net::IpAddr;
use std::process::Stdio;

use tokio::process::Command;

use super::SplitError;
use crate::nft::apply_ruleset_with_code;
use crate::protocol::DaemonErrorCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalRoute {
    pub interface: String,
    pub gateway: Option<String>,
}

pub fn parse_default_route(line: &str) -> Option<PhysicalRoute> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.first().copied()? != "default" {
        return None;
    }
    let interface = fields
        .windows(2)
        .find_map(|window| (window[0] == "dev").then_some(window[1]))?;
    if interface.is_empty()
        || interface.len() > libc::IFNAMSIZ
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return None;
    }
    let gateway = fields
        .windows(2)
        .find_map(|window| (window[0] == "via").then_some(window[1]));
    if gateway.is_some_and(|value| value.parse::<IpAddr>().is_err()) {
        return None;
    }
    Some(PhysicalRoute {
        interface: interface.to_string(),
        gateway: gateway.map(ToString::to_string),
    })
}

pub fn render_split_rules(
    cgroup_relative: &str,
    route: &PhysicalRoute,
) -> Result<String, SplitError> {
    let components: Vec<&str> = cgroup_relative.split('/').collect();
    if components.is_empty()
        || components.iter().any(|component| {
            component.is_empty()
                || *component == "."
                || *component == ".."
                || !component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@')
                })
        })
    {
        return Err(SplitError::RoutingUnavailable);
    }
    if parse_default_route(&format!("default dev {}", route.interface)).is_none() {
        return Err(SplitError::RoutingUnavailable);
    }
    Ok(format!(
        r#"table inet varmlen_split {{
  chain mark_output {{
    type route hook output priority mangle; policy accept;
    socket cgroupv2 level {level} "{cgroup}" meta mark set 0x2025
    meta mark 0x2025 ct mark set meta mark
  }}
  chain nat_postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    meta mark 0x2025 oifname "{interface}" masquerade
  }}
}}
"#,
        level = components.len(),
        cgroup = cgroup_relative,
        interface = route.interface,
    ))
}

pub async fn detect_default_route() -> Result<PhysicalRoute, SplitError> {
    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .await
        .map_err(|_| SplitError::RoutingUnavailable)?;
    if !output.status.success() {
        return Err(SplitError::RoutingUnavailable);
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(parse_default_route)
        .ok_or(SplitError::RoutingUnavailable)
}

pub async fn install_routing(
    cgroup_relative: &str,
    route: &PhysicalRoute,
) -> Result<(), SplitError> {
    let mut default = vec!["route", "replace", "default"];
    if let Some(gateway) = route.gateway.as_deref() {
        default.extend(["via", gateway]);
    }
    default.extend(["dev", &route.interface, "table", "100"]);
    run_ip(&default).await?;
    let _ = run_ip(&["rule", "del", "fwmark", "0x2025", "lookup", "100"]).await;
    run_ip(&[
        "rule", "add", "priority", "100", "fwmark", "0x2025", "lookup", "100",
    ])
    .await?;
    let rules = render_split_rules(cgroup_relative, route)?;
    apply_ruleset_with_code(&rules, DaemonErrorCode::Internal)
        .await
        .map_err(|_| SplitError::RoutingUnavailable)
}

pub async fn remove_routing() -> Result<(), SplitError> {
    let _ = run_ip(&["rule", "del", "fwmark", "0x2025", "lookup", "100"]).await;
    let _ = run_ip(&["route", "flush", "table", "100"]).await;
    let output = Command::new("nft")
        .args(["delete", "table", "inet", "varmlen_split"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|_| SplitError::RollbackFailed)?;
    if output.success() {
        Ok(())
    } else {
        // Missing table is an idempotent cleanup condition.
        Ok(())
    }
}

async fn run_ip(arguments: &[&str]) -> Result<(), SplitError> {
    let output = Command::new("ip")
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .await
        .map_err(|_| SplitError::RoutingUnavailable)?;
    if output.success() {
        Ok(())
    } else {
        Err(SplitError::RoutingUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_default_route, render_split_rules, PhysicalRoute};

    #[test]
    fn generic_marking_covers_tcp_and_udp_without_protocol_filter() {
        let rules = render_split_rules(
            "varmlen/user-1000/bypass",
            &PhysicalRoute {
                interface: "enp11s0".into(),
                gateway: Some("192.168.1.1".into()),
            },
        )
        .unwrap();
        assert!(rules
            .contains("socket cgroupv2 level 3 \"varmlen/user-1000/bypass\" meta mark set 0x2025"));
        assert!(rules.contains("meta mark 0x2025 oifname \"enp11s0\" masquerade"));
        assert!(!rules.contains("tcp "));
        assert!(!rules.contains("udp "));
    }

    #[test]
    fn parses_only_safe_default_route_tokens() {
        assert_eq!(
            parse_default_route("default via 192.168.1.1 dev enp11s0 proto dhcp metric 100"),
            Some(PhysicalRoute {
                interface: "enp11s0".into(),
                gateway: Some("192.168.1.1".into()),
            })
        );
        assert!(parse_default_route("default via 1.1.1.1 dev bad\\\";flush ruleset").is_none());
    }
}
