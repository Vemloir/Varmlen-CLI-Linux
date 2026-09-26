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

/// The routing table and policy-rule priority owned by the per-app split.
///
/// Table 100 belongs to the network helper: it carries the physical default
/// route that Xray's own dials (mark 0x2024) leave by. Sharing it meant that
/// tearing the split down — clearing the last excluded application, switching
/// the applications to selective mode, or reconnecting with a changed list —
/// flushed that route while the tunnel stayed up, and every direct outbound of
/// Xray looped back into its own tun.
pub const SPLIT_TABLE: &str = "102";
pub const SPLIT_RULE_PRIORITY: &str = "100";

/// Destinations that must leave by the main table even from a bypassed
/// socket: a physical default would send LAN traffic to the gateway.
const LOCAL_THROWS: [&str; 7] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "255.255.255.255/32",
];

/// `ip` invocations that lay the split's own table and rule, in order.
pub fn routing_setup_commands(route: &PhysicalRoute) -> Vec<Vec<String>> {
    let owned = |items: &[&str]| items.iter().map(|item| item.to_string()).collect::<Vec<_>>();
    let mut default = vec!["route", "replace", "default"];
    if let Some(gateway) = route.gateway.as_deref() {
        default.extend(["via", gateway]);
    }
    default.extend(["dev", &route.interface, "table", SPLIT_TABLE]);
    let mut commands = vec![owned(&default)];
    for network in LOCAL_THROWS {
        commands.push(owned(&["route", "replace", "throw", network, "table", SPLIT_TABLE]));
    }
    commands.push(owned(&[
        "rule",
        "add",
        "priority",
        SPLIT_RULE_PRIORITY,
        "fwmark",
        "0x2025",
        "lookup",
        SPLIT_TABLE,
    ]));
    commands
}

/// `ip` invocations that remove only what the split laid. Nothing here names
/// table 100 or a rule the helper owns.
pub fn routing_teardown_commands() -> Vec<Vec<String>> {
    let owned = |items: &[&str]| items.iter().map(|item| item.to_string()).collect::<Vec<_>>();
    vec![
        owned(&[
            "rule",
            "del",
            "priority",
            SPLIT_RULE_PRIORITY,
            "fwmark",
            "0x2025",
            "lookup",
            SPLIT_TABLE,
        ]),
        owned(&["route", "flush", "table", SPLIT_TABLE]),
    ]
}

pub async fn install_routing(
    cgroup_relative: &str,
    route: &PhysicalRoute,
) -> Result<(), SplitError> {
    let rules = render_split_rules(cgroup_relative, route)?;
    // Idempotent: a refresh after a reconnect lays the same state again.
    for command in routing_teardown_commands() {
        let _ = run_ip(&command).await;
    }
    for command in routing_setup_commands(route) {
        run_ip(&command).await?;
    }
    apply_ruleset_with_code(&rules, DaemonErrorCode::Internal)
        .await
        .map_err(|_| SplitError::RoutingUnavailable)
}

pub async fn remove_routing() -> Result<(), SplitError> {
    for command in routing_teardown_commands() {
        let _ = run_ip(&command).await;
    }
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

async fn run_ip<S: AsRef<std::ffi::OsStr>>(arguments: &[S]) -> Result<(), SplitError> {
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
    use super::{
        parse_default_route, render_split_rules, routing_setup_commands,
        routing_teardown_commands, PhysicalRoute,
    };

    fn joined(commands: Vec<Vec<String>>) -> Vec<String> {
        commands.into_iter().map(|command| command.join(" ")).collect()
    }

    #[test]
    fn the_split_never_touches_the_helpers_table() {
        let route = PhysicalRoute {
            interface: "enp11s0".into(),
            gateway: Some("192.168.1.1".into()),
        };
        let all = [
            joined(routing_setup_commands(&route)),
            joined(routing_teardown_commands()),
        ]
        .concat();
        // Table 100 carries Xray's own direct dials; flushing it while the
        // tunnel is up loops them back into the tun.
        assert!(all.iter().all(|command| !command.contains("table 100")
            && !command.contains("lookup 100")));
        assert!(all.contains(&"route flush table 102".to_string()));
        assert!(all.contains(&"rule del priority 100 fwmark 0x2025 lookup 102".to_string()));
    }

    #[test]
    fn local_networks_are_thrown_back_to_the_main_table() {
        let route = PhysicalRoute {
            interface: "wwan0".into(),
            gateway: None,
        };
        let setup = joined(routing_setup_commands(&route));
        assert_eq!(setup[0], "route replace default dev wwan0 table 102");
        assert!(setup.contains(&"route replace throw 192.168.0.0/16 table 102".to_string()));
        assert_eq!(setup.last().unwrap(), "rule add priority 100 fwmark 0x2025 lookup 102");
    }

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
