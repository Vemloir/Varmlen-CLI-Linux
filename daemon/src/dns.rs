use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use crate::nft::{apply_ruleset, remove_dns_table, render_dns_rules};
use crate::protocol::{DaemonError, DaemonErrorCode};

#[async_trait]
pub trait DnsBackend {
    async fn apply(&mut self) -> Result<(), DaemonError>;
    async fn probe_through_tunnel(&mut self) -> Result<bool, DaemonError>;
    async fn remove(&mut self) -> Result<(), DaemonError>;
}

pub struct DnsGuard<B> {
    backend: B,
}

#[derive(Default)]
pub struct SystemDnsBackend;

impl SystemDnsBackend {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DnsBackend for SystemDnsBackend {
    async fn apply(&mut self) -> Result<(), DaemonError> {
        let rules = render_dns_rules();
        apply_ruleset(&rules).await
    }

    async fn probe_through_tunnel(&mut self) -> Result<bool, DaemonError> {
        let socket = UdpSocket::bind(("0.0.0.0", 0)).await.map_err(|error| {
            DaemonError::new(
                DaemonErrorCode::DnsVerificationFailed,
                format!("could not bind DNS probe socket: {error}"),
            )
        })?;
        let transaction_id = (std::process::id() as u16) ^ 0x564d;
        let query = build_dns_query(transaction_id, "mullvad.net")?;
        socket
            .send_to(&query, ("1.1.1.1", 53))
            .await
            .map_err(|error| {
                DaemonError::new(
                    DaemonErrorCode::DnsVerificationFailed,
                    format!("could not send DNS probe: {error}"),
                )
            })?;
        let mut response = [0_u8; 2048];
        let received = timeout(Duration::from_secs(5), socket.recv(&mut response))
            .await
            .map_err(|_| {
                DaemonError::new(
                    DaemonErrorCode::DnsVerificationFailed,
                    "DNS probe timed out",
                )
            })?
            .map_err(|error| {
                DaemonError::new(
                    DaemonErrorCode::DnsVerificationFailed,
                    format!("DNS probe failed: {error}"),
                )
            })?;
        Ok(validate_dns_response(transaction_id, &response[..received]))
    }

    async fn remove(&mut self) -> Result<(), DaemonError> {
        remove_dns_table().await
    }
}

pub fn build_dns_query(transaction_id: u16, domain: &str) -> Result<Vec<u8>, DaemonError> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&transaction_id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]);
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(DaemonError::new(
                DaemonErrorCode::DnsVerificationFailed,
                "invalid DNS probe domain",
            ));
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    if query.len() > 512 {
        return Err(DaemonError::new(
            DaemonErrorCode::DnsVerificationFailed,
            "DNS probe query is too large",
        ));
    }
    Ok(query)
}

pub fn validate_dns_response(transaction_id: u16, response: &[u8]) -> bool {
    response.len() >= 12
        && response[0..2] == transaction_id.to_be_bytes()
        && response[2] & 0x80 != 0
}

impl<B: DnsBackend> DnsGuard<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub async fn install(&mut self) -> Result<(), DaemonError> {
        self.backend.apply().await?;
        let probe = self.backend.probe_through_tunnel().await;
        if !matches!(&probe, Ok(true)) {
            let cleanup = self.backend.remove().await;
            probe?;
            cleanup?;
            return Err(DaemonError::new(
                DaemonErrorCode::DnsVerificationFailed,
                "DNS interception could not be verified",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::{build_dns_query, validate_dns_response};
    use super::{DnsBackend, DnsGuard};
    use crate::protocol::{DaemonError, DaemonErrorCode};

    #[derive(Default)]
    struct FakeDnsBackend {
        probe_ok: bool,
        probe_error: bool,
        installed: bool,
        removed: bool,
    }

    #[async_trait]
    impl DnsBackend for FakeDnsBackend {
        async fn apply(&mut self) -> Result<(), DaemonError> {
            self.installed = true;
            Ok(())
        }

        async fn probe_through_tunnel(&mut self) -> Result<bool, DaemonError> {
            if self.probe_error {
                return Err(DaemonError::new(
                    DaemonErrorCode::DnsVerificationFailed,
                    "injected DNS probe failure",
                ));
            }
            Ok(self.probe_ok)
        }

        async fn remove(&mut self) -> Result<(), DaemonError> {
            self.removed = true;
            self.installed = false;
            Ok(())
        }
    }

    #[tokio::test]
    async fn verified_tunnel_dns_activates_policy() {
        let backend = FakeDnsBackend {
            probe_ok: true,
            ..Default::default()
        };
        let mut guard = DnsGuard::new(backend);
        guard.install().await.unwrap();
        assert!(guard.backend().installed);
        assert!(!guard.backend().removed);
    }

    #[tokio::test]
    async fn upstream_probe_failure_rolls_back_and_fails_closed() {
        let backend = FakeDnsBackend {
            probe_ok: false,
            ..Default::default()
        };
        let mut guard = DnsGuard::new(backend);
        let error = guard.install().await.unwrap_err();
        assert_eq!(error.code, DaemonErrorCode::DnsVerificationFailed);
        assert!(guard.backend().removed);
    }

    #[tokio::test]
    async fn probe_error_rolls_back_dns_policy() {
        let backend = FakeDnsBackend {
            probe_error: true,
            ..Default::default()
        };
        let mut guard = DnsGuard::new(backend);
        let error = guard.install().await.unwrap_err();
        assert_eq!(error.code, DaemonErrorCode::DnsVerificationFailed);
        assert!(guard.backend().removed);
        assert!(!guard.backend().installed);
    }

    #[test]
    fn probe_query_is_a_bounded_a_record_request() {
        let query = build_dns_query(0x1234, "example.com").unwrap();
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        assert_eq!(&query[2..4], &[0x01, 0x00]);
        assert_eq!(&query[4..6], &[0x00, 0x01]);
        assert!(query.len() < 512);
    }

    #[test]
    fn response_validation_requires_matching_id_and_response_bit() {
        let mut response = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        assert!(validate_dns_response(0x1234, &response));
        assert!(!validate_dns_response(0x9999, &response));
        response[2] &= 0x7f;
        assert!(!validate_dns_response(0x1234, &response));
    }
}
