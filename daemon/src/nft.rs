use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::protocol::{DaemonError, DaemonErrorCode};

pub fn render_dns_rules() -> String {
    r#"table inet varmlen_dns {
  chain mark_output {
    type route hook output priority mangle + 10; policy accept;
    ip daddr 127.0.0.0/8 return
    ip6 daddr ::1 return
    meta mark & 0x0000ffff != 0x2024 meta mark & 0x0000ffff != 0x2025 udp dport 53 meta mark set 0x2023 ct mark set meta mark
    meta mark & 0x0000ffff != 0x2024 meta mark & 0x0000ffff != 0x2025 tcp dport 53 meta mark set 0x2023 ct mark set meta mark
  }
  chain guard_output {
    type filter hook output priority filter - 10; policy accept;
    oifname "lo" accept
    meta mark & 0x0000ffff == 0x2025 udp dport 53 accept
    meta mark & 0x0000ffff == 0x2025 tcp dport 53 accept
    meta mark & 0x0000ffff == 0x2025 tcp dport 853 accept
    meta mark & 0x0000ffff == 0x2023 oifname "varmlen0" udp dport 53 accept
    meta mark & 0x0000ffff == 0x2023 oifname "varmlen0" tcp dport 53 accept
    oifname "varmlen0" tcp dport 853 accept
    udp dport 53 reject
    tcp dport 53 reject
    tcp dport 853 reject
  }
}
"#
    .to_string()
}

pub async fn apply_ruleset(ruleset: &str) -> Result<(), DaemonError> {
    apply_ruleset_with_code(ruleset, DaemonErrorCode::DnsInstallFailed).await
}

pub async fn apply_ruleset_with_code(
    ruleset: &str,
    error_code: DaemonErrorCode,
) -> Result<(), DaemonError> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| DaemonError::new(error_code, format!("could not start nft: {error}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(ruleset.as_bytes()).await.map_err(|error| {
            DaemonError::new(
                error_code,
                format!("could not write nft transaction: {error}"),
            )
        })?;
    }
    let output = child.wait_with_output().await.map_err(|error| {
        DaemonError::new(error_code, format!("could not wait for nft: {error}"))
    })?;
    if !output.status.success() {
        return Err(DaemonError::new(
            error_code,
            format!(
                "nft rejected DNS transaction: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(())
}

pub async fn remove_dns_table() -> Result<(), DaemonError> {
    let output = Command::new("nft")
        .args(["delete", "table", "inet", "varmlen_dns"])
        .output()
        .await
        .map_err(|error| {
            DaemonError::new(
                DaemonErrorCode::DnsInstallFailed,
                format!("could not remove DNS table: {error}"),
            )
        })?;
    if output.status.success()
        || String::from_utf8_lossy(&output.stderr).contains("No such file or directory")
    {
        return Ok(());
    }
    Err(DaemonError::new(
        DaemonErrorCode::DnsInstallFailed,
        format!(
            "could not remove DNS table: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::render_dns_rules;

    #[test]
    fn system_dns_is_marked_for_the_tun_without_a_local_redirect() {
        let rules = render_dns_rules();
        assert!(!rules.contains("redirect"));
        assert!(!rules.contains("5353"));
        assert!(rules.contains("priority mangle + 10"));
        let loopback = rules.find("ip daddr 127.0.0.0/8 return").unwrap();
        let mark = rules
            .find("meta mark & 0x0000ffff != 0x2024 meta mark & 0x0000ffff != 0x2025 udp dport 53")
            .unwrap();
        assert!(loopback < mark);
        assert!(rules.contains("ip6 daddr ::1 return"));
        assert!(rules.contains("meta mark & 0x0000ffff != 0x2024"));
        assert!(rules.contains("meta mark & 0x0000ffff != 0x2025"));
        assert!(rules.contains("meta mark set 0x2023 ct mark set meta mark"));
        assert!(rules
            .contains("meta mark & 0x0000ffff == 0x2023 oifname \"varmlen0\" udp dport 53 accept"));
        assert!(rules
            .contains("meta mark & 0x0000ffff == 0x2023 oifname \"varmlen0\" tcp dport 53 accept"));
        assert!(rules.contains("tcp dport 853 reject"));
    }

    #[test]
    fn xray_dials_are_not_reclassified_as_system_dns() {
        let rules = render_dns_rules();
        let mark_rule = rules
            .lines()
            .find(|line| line.contains("udp dport 53") && line.contains("meta mark set 0x2023"))
            .expect("UDP DNS marking rule");
        assert!(mark_rule.contains("meta mark & 0x0000ffff != 0x2024"));
        assert!(mark_rule.contains("meta mark & 0x0000ffff != 0x2025"));
        let allow = rules
            .find("meta mark & 0x0000ffff == 0x2023 oifname \"varmlen0\" udp dport 53 accept")
            .unwrap();
        let reject = rules.find("udp dport 53 reject").unwrap();
        assert!(allow < reject);
    }

    #[test]
    fn excluded_application_dns_is_not_forced_back_into_the_tunnel() {
        let rules = render_dns_rules();
        let bypass = rules
            .find("meta mark & 0x0000ffff == 0x2025 udp dport 53 accept")
            .unwrap();
        let reject = rules.find("udp dport 53 reject").unwrap();
        assert!(bypass < reject);
        assert!(rules.contains("meta mark & 0x0000ffff == 0x2025 tcp dport 853 accept"));
    }
}
