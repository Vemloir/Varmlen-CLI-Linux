use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const PROTOCOL_VERSION: u16 = 3;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 384 * 1024;
pub const MAX_SERVER_IPS: usize = 64;
const MAX_EXCLUDED_APPS: usize = 256;
const MAX_APP_SELECTOR_BYTES: usize = 4096;
const MAX_PING_HOST_BYTES: usize = 253;
const MAX_DNS_PROBE_URLS: usize = 8;
const MAX_DNS_PROBE_URL_BYTES: usize = 2048;
const MIN_PING_TIMEOUT_MS: u32 = 100;
/// The longest probe a client may ask for.
///
/// A UDP-only location pays a QUIC handshake before the probe itself answers,
/// and the clients give those locations 15 s for it. A ceiling below that budget
/// made the request an `invalid request`, so every Hysteria2 location read as
/// unpingable while its node was healthy.
pub const MAX_PING_TIMEOUT_MS: u32 = 15_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    Tun,
    Proxy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub mode: ConnectionMode,
    pub xray_config: String,
    pub validation_config: String,
    pub server_ips: Vec<IpAddr>,
    pub excluded_apps: Vec<String>,
    pub killswitch: bool,
    pub allow_lan: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpPingRequest {
    pub host: String,
    pub port: u16,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyPingRequest {
    pub xray_config: String,
    pub socks_port: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socks_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_probe_urls: Vec<String>,
    pub timeout_ms: u32,
}

impl ProxyPingRequest {
    pub fn effective_socks_ports(&self) -> Vec<u16> {
        if self.socks_ports.is_empty() {
            vec![self.socks_port]
        } else {
            self.socks_ports.clone()
        }
    }

    pub fn effective_dns_probe_urls(&self) -> Vec<String> {
        effective_dns_probe_urls(&self.dns_probe_urls)
    }
}

fn effective_dns_probe_urls(urls: &[String]) -> Vec<String> {
    urls.to_vec()
}

fn dns_probe_urls_are_valid(urls: &[String]) -> bool {
    urls.len() <= MAX_DNS_PROBE_URLS
        && urls.iter().all(|raw| {
            raw.len() <= MAX_DNS_PROBE_URL_BYTES
                && reqwest::Url::parse(raw).is_ok_and(|url| {
                    url.scheme() == "https"
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.fragment().is_none()
                        && url
                            .host_str()
                            .and_then(|host| host.parse::<IpAddr>().ok())
                            .is_some()
                })
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonCommand {
    Status,
    Connect(ConnectRequest),
    Disconnect,
    TcpPing(TcpPingRequest),
    ProxyPing(ProxyPingRequest),
    LogTail,
    ClearLog,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub version: u16,
    pub operation_id: u64,
    pub command: DaemonCommand,
}

impl RequestEnvelope {
    pub fn new(version: u16, operation_id: u64, command: DaemonCommand) -> Self {
        Self {
            version,
            operation_id,
            command,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPhase {
    Disconnected,
    Preparing,
    Connected,
    Blocking,
    Reconnecting,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonState {
    pub phase: ConnectionPhase,
    pub split_active: bool,
    pub dns_protected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_tail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonErrorCode {
    UnsupportedVersion,
    FrameTooLarge,
    InvalidFrame,
    Unauthorized,
    HoldBlockFailed,
    HoldBlockVerificationFailed,
    HoldBlockRemovalFailed,
    TunnelPreparationFailed,
    TunnelCommitFailed,
    TunnelCleanupFailed,
    DnsInstallFailed,
    DnsVerificationFailed,
    InvalidRequest,
    XrayUnavailable,
    XrayValidationFailed,
    XrayStartFailed,
    SplitUnavailable,
    PingFailed,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonError {
    pub code: DaemonErrorCode,
    pub message: String,
}

impl DaemonError {
    pub fn new(code: DaemonErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub version: u16,
    pub operation_id: u64,
    pub result: Result<DaemonState, DaemonError>,
}

pub fn validate_request(request: &RequestEnvelope) -> Result<(), DaemonErrorCode> {
    if request.version != PROTOCOL_VERSION {
        return Err(DaemonErrorCode::UnsupportedVersion);
    }
    match &request.command {
        DaemonCommand::Connect(connect) => validate_connect_request(connect)?,
        DaemonCommand::TcpPing(ping) => validate_tcp_ping_request(ping)?,
        DaemonCommand::ProxyPing(ping) => validate_proxy_ping_request(ping)?,
        DaemonCommand::Status
        | DaemonCommand::Disconnect
        | DaemonCommand::LogTail
        | DaemonCommand::ClearLog => {}
    }
    Ok(())
}

pub fn validate_connect_request(request: &ConnectRequest) -> Result<(), DaemonErrorCode> {
    if request.xray_config.is_empty()
        || request.validation_config.is_empty()
        || request.xray_config.len() > MAX_CONFIG_BYTES
        || request.validation_config.len() > MAX_CONFIG_BYTES
        || request.server_ips.is_empty()
        || request.server_ips.len() > MAX_SERVER_IPS
        || request.excluded_apps.len() > MAX_EXCLUDED_APPS
        || request.excluded_apps.iter().any(|application| {
            application.trim().is_empty()
                || application.len() > MAX_APP_SELECTOR_BYTES
                || application.contains('\0')
        })
        || (request.mode == ConnectionMode::Proxy && !request.excluded_apps.is_empty())
    {
        return Err(DaemonErrorCode::InvalidRequest);
    }
    Ok(())
}

pub fn validate_tcp_ping_request(request: &TcpPingRequest) -> Result<(), DaemonErrorCode> {
    if request.host.trim().is_empty()
        || request.host.len() > MAX_PING_HOST_BYTES
        || request.host.contains('\0')
        || request.port == 0
        || !(MIN_PING_TIMEOUT_MS..=MAX_PING_TIMEOUT_MS).contains(&request.timeout_ms)
    {
        return Err(DaemonErrorCode::InvalidRequest);
    }
    Ok(())
}

pub fn validate_proxy_ping_request(request: &ProxyPingRequest) -> Result<(), DaemonErrorCode> {
    let ports = request.effective_socks_ports();
    let dns_probe_urls = request.effective_dns_probe_urls();
    if request.xray_config.is_empty()
        || request.xray_config.len() > MAX_CONFIG_BYTES
        || request.socks_port == 0
        || ports.is_empty()
        || ports.len() > MAX_SERVER_IPS
        || ports[0] != request.socks_port
        || ports.contains(&0)
        || ports
            .iter()
            .enumerate()
            .any(|(index, port)| ports[..index].contains(port))
        || !dns_probe_urls_are_valid(&dns_probe_urls)
        || !(MIN_PING_TIMEOUT_MS..=MAX_PING_TIMEOUT_MS).contains(&request.timeout_ms)
    {
        return Err(DaemonErrorCode::InvalidRequest);
    }
    Ok(())
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, DaemonErrorCode> {
    let encoded = serde_json::to_vec(value).map_err(|_| DaemonErrorCode::InvalidFrame)?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(DaemonErrorCode::FrameTooLarge);
    }
    Ok(encoded)
}

pub fn decode_request_frame(bytes: &[u8]) -> Result<RequestEnvelope, DaemonErrorCode> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(DaemonErrorCode::FrameTooLarge);
    }
    let request = serde_json::from_slice(bytes).map_err(|_| DaemonErrorCode::InvalidFrame)?;
    validate_request(&request)?;
    Ok(request)
}

/// The operation id inside a frame the daemon refused to decode.
///
/// A refusal during decoding has no envelope to echo the id from, and clients
/// then report an anonymous "operation ID mismatch" instead of the reason. When
/// the envelope was readable and only the command inside it was not, the id can
/// still be answered with.
pub fn operation_id_of_rejected_request(bytes: &[u8]) -> u64 {
    #[derive(Deserialize)]
    struct EnvelopeId {
        operation_id: u64,
    }
    serde_json::from_slice::<EnvelopeId>(bytes)
        .map(|envelope| envelope.operation_id)
        .unwrap_or(0)
}

pub fn decode_response_frame(bytes: &[u8]) -> Result<ResponseEnvelope, DaemonErrorCode> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(DaemonErrorCode::FrameTooLarge);
    }
    let response: ResponseEnvelope =
        serde_json::from_slice(bytes).map_err(|_| DaemonErrorCode::InvalidFrame)?;
    if response.version != PROTOCOL_VERSION {
        return Err(DaemonErrorCode::UnsupportedVersion);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        decode_response_frame, operation_id_of_rejected_request, validate_connect_request,
        validate_proxy_ping_request,
        validate_tcp_ping_request, ConnectRequest, ConnectionMode, ConnectionPhase,
        DaemonCommand, DaemonErrorCode, ProxyPingRequest, RequestEnvelope, TcpPingRequest,
        MAX_PING_TIMEOUT_MS, PROTOCOL_VERSION,
    };

    #[test]
    fn protocol_version_includes_bounded_log_commands() {
        assert_eq!(PROTOCOL_VERSION, 3);
    }

    fn valid_connect() -> ConnectRequest {
        ConnectRequest {
            mode: ConnectionMode::Tun,
            xray_config: "{}".into(),
            validation_config: "{}".into(),
            server_ips: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))],
            excluded_apps: vec!["cs2".into()],
            killswitch: true,
            allow_lan: false,
        }
    }

    #[test]
    fn connect_request_rejects_unbounded_or_inconsistent_input() {
        let mut request = valid_connect();
        request.server_ips.clear();
        assert_eq!(
            validate_connect_request(&request),
            Err(DaemonErrorCode::InvalidRequest)
        );

        let mut request = valid_connect();
        request.mode = ConnectionMode::Proxy;
        assert_eq!(
            validate_connect_request(&request),
            Err(DaemonErrorCode::InvalidRequest)
        );

        let mut request = valid_connect();
        request.excluded_apps = vec!["../\0escape".into()];
        assert_eq!(
            validate_connect_request(&request),
            Err(DaemonErrorCode::InvalidRequest)
        );
    }

    #[test]
    fn a_refused_request_frame_still_answers_with_its_operation_id() {
        let request = RequestEnvelope::new(PROTOCOL_VERSION, 4242, DaemonCommand::Status);
        let bytes = serde_json::to_vec(&request).unwrap();
        assert_eq!(operation_id_of_rejected_request(&bytes), 4242);
        assert_eq!(operation_id_of_rejected_request(b"not json"), 0);
    }

    #[test]
    fn valid_tun_connect_request_is_accepted() {
        assert_eq!(validate_connect_request(&valid_connect()), Ok(()));
    }

    #[test]
    fn ping_requests_accept_bounded_inputs_and_reject_unsafe_ones() {
        let tcp = TcpPingRequest {
            host: "vpn.example.com".into(),
            port: 443,
            timeout_ms: 2_500,
        };
        assert_eq!(validate_tcp_ping_request(&tcp), Ok(()));

        let mut invalid_tcp = tcp.clone();
        invalid_tcp.host = "\0".into();
        assert_eq!(
            validate_tcp_ping_request(&invalid_tcp),
            Err(DaemonErrorCode::InvalidRequest)
        );
        invalid_tcp = tcp;
        invalid_tcp.timeout_ms = 60_000;
        assert_eq!(
            validate_tcp_ping_request(&invalid_tcp),
            Err(DaemonErrorCode::InvalidRequest)
        );

        let proxy = ProxyPingRequest {
            xray_config: r#"{"log":{"loglevel":"warning"}}"#.into(),
            socks_port: 32_000,
            socks_ports: vec![32_000, 32_001],
            dns_probe_urls: vec!["https://9.9.9.9/dns-query".into()],
            timeout_ms: 5_000,
        };
        assert_eq!(validate_proxy_ping_request(&proxy), Ok(()));

        // The UDP-only budget the desktop client asks for must be accepted.
        let mut udp_proxy = proxy.clone();
        udp_proxy.timeout_ms = MAX_PING_TIMEOUT_MS;
        assert_eq!(validate_proxy_ping_request(&udp_proxy), Ok(()));
        udp_proxy.timeout_ms = MAX_PING_TIMEOUT_MS + 1;
        assert_eq!(
            validate_proxy_ping_request(&udp_proxy),
            Err(DaemonErrorCode::InvalidRequest)
        );

        let mut plain_dns_proxy = proxy.clone();
        plain_dns_proxy.dns_probe_urls.clear();
        assert_eq!(plain_dns_proxy.effective_dns_probe_urls(), Vec::<String>::new());
        assert_eq!(validate_proxy_ping_request(&plain_dns_proxy), Ok(()));

        let mut invalid_dns = proxy.clone();
        invalid_dns.dns_probe_urls = vec!["http://127.0.0.1/dns-query".into()];
        assert_eq!(
            validate_proxy_ping_request(&invalid_dns),
            Err(DaemonErrorCode::InvalidRequest)
        );

        let mut invalid_proxy = proxy;
        invalid_proxy.xray_config.clear();
        assert_eq!(
            validate_proxy_ping_request(&invalid_proxy),
            Err(DaemonErrorCode::InvalidRequest)
        );
    }

    #[test]
    fn new_client_accepts_an_old_daemon_state_without_ping_result() {
        let response = format!(
            r#"{{"version":{PROTOCOL_VERSION},"operation_id":1,"result":{{"Ok":{{"phase":"connected","split_active":true,"dns_protected":true}}}}}}"#
        );
        let decoded = decode_response_frame(response.as_bytes()).unwrap();
        let state = decoded.result.unwrap();
        assert_eq!(state.phase, ConnectionPhase::Connected);
        assert_eq!(state.rtt_ms, None);
    }
}
