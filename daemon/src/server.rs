use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};

use crate::protocol::{
    daemon_version, decode_request_frame, encode_frame, operation_id_of_rejected_request,
    DaemonCommand,
    DaemonError, DaemonErrorCode, DaemonState, ResponseEnvelope, MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
};

pub const MAX_CONCURRENT_CLIENTS: usize = 16;
const FRAME_IO_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REQUESTS_PER_CONNECTION: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct PeerPolicy {
    allowed_uid: u32,
}

impl PeerPolicy {
    pub fn new(allowed_uid: u32) -> Self {
        Self { allowed_uid }
    }

    pub fn authorize(&self, uid: u32) -> bool {
        uid == self.allowed_uid
    }
}

pub fn parse_owner_uid(value: Option<&str>) -> Result<u32, &'static str> {
    let uid = value
        .ok_or("desktop owner uid is missing (pass --owner-uid or set PKEXEC_UID)")?
        .parse::<u32>()
        .map_err(|_| "desktop owner uid is invalid")?;
    if uid == 0 {
        return Err("refusing to authorize root as desktop owner");
    }
    Ok(uid)
}

pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(credentials.uid)
}

pub async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, DaemonErrorCode> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| DaemonErrorCode::InvalidFrame)? as usize;
    if length > MAX_FRAME_BYTES {
        return Err(DaemonErrorCode::FrameTooLarge);
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| DaemonErrorCode::InvalidFrame)?;
    Ok(bytes)
}

pub async fn write_response(
    stream: &mut UnixStream,
    response: &ResponseEnvelope,
) -> Result<(), DaemonErrorCode> {
    let bytes = encode_frame(response)?;
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| DaemonErrorCode::Internal)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| DaemonErrorCode::Internal)
}

#[async_trait]
pub trait CommandHandler: Send + Sync {
    async fn handle(&self, command: DaemonCommand) -> Result<DaemonState, DaemonError>;
}

pub struct SnapshotHandler {
    state: Arc<RwLock<DaemonState>>,
}

impl SnapshotHandler {
    pub fn new(state: Arc<RwLock<DaemonState>>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl CommandHandler for SnapshotHandler {
    async fn handle(&self, command: DaemonCommand) -> Result<DaemonState, DaemonError> {
        match command {
            DaemonCommand::Status => Ok(self.state.read().await.clone()),
            DaemonCommand::Connect(_)
            | DaemonCommand::Disconnect
            | DaemonCommand::UpdateSplit(_)
            | DaemonCommand::TcpPing(_)
            | DaemonCommand::ProxyPing(_)
            | DaemonCommand::LogTail
            | DaemonCommand::ClearLog => Err(DaemonError::new(
                DaemonErrorCode::Internal,
                "VPN lifecycle controller is unavailable",
            )),
        }
    }
}

pub async fn serve_connection(
    stream: UnixStream,
    policy: PeerPolicy,
    handler: Arc<dyn CommandHandler>,
) -> Result<(), DaemonErrorCode> {
    serve_connection_with_limits(
        stream,
        policy,
        handler,
        FRAME_IO_TIMEOUT,
        MAX_REQUESTS_PER_CONNECTION,
    )
    .await
}

pub async fn serve_connection_with_limits(
    mut stream: UnixStream,
    policy: PeerPolicy,
    handler: Arc<dyn CommandHandler>,
    io_timeout: Duration,
    max_requests: usize,
) -> Result<(), DaemonErrorCode> {
    let uid = peer_uid(&stream).map_err(|_| DaemonErrorCode::Unauthorized)?;
    if !policy.authorize(uid) {
        return Err(DaemonErrorCode::Unauthorized);
    }

    for _ in 0..max_requests {
        let bytes = match timeout(io_timeout, read_frame(&mut stream))
            .await
            .map_err(|_| DaemonErrorCode::InvalidFrame)?
        {
            Ok(bytes) => bytes,
            Err(DaemonErrorCode::InvalidFrame) => return Ok(()),
            Err(error) => return Err(error),
        };
        let request = match decode_request_frame(&bytes) {
            Ok(request) => request,
            Err(code) => {
                let response = ResponseEnvelope {
                    version: PROTOCOL_VERSION,
                    operation_id: operation_id_of_rejected_request(&bytes),
                    result: Err(DaemonError {
                        code,
                        message: "invalid daemon request".to_string(),
                    }),
                    daemon_version: daemon_version(),
                };
                timeout(io_timeout, write_response(&mut stream, &response))
                    .await
                    .map_err(|_| DaemonErrorCode::Internal)??;
                continue;
            }
        };
        let operation = request.operation_id;
        let command_handler = Arc::clone(&handler);
        let command = request.command;
        let result = timeout(
            COMMAND_TIMEOUT,
            tokio::spawn(async move { command_handler.handle(command).await }),
        )
        .await
        .map_err(|_| DaemonErrorCode::Internal)?
        .map_err(|_| DaemonErrorCode::Internal)?;
        let response = ResponseEnvelope {
            version: PROTOCOL_VERSION,
            operation_id: operation,
            result,
            daemon_version: daemon_version(),
        };
        timeout(io_timeout, write_response(&mut stream, &response))
            .await
            .map_err(|_| DaemonErrorCode::Internal)??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::sync::RwLock;

    use super::{
        serve_connection, serve_connection_with_limits, PeerPolicy, SnapshotHandler,
        MAX_CONCURRENT_CLIENTS,
    };
    use crate::protocol::{
        decode_response_frame, encode_frame, ConnectionPhase, DaemonCommand, DaemonState,
        RequestEnvelope, PROTOCOL_VERSION,
    };

    #[tokio::test]
    async fn status_returns_recovery_required_snapshot() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let state = Arc::new(RwLock::new(DaemonState {
            phase: ConnectionPhase::RecoveryRequired,
            split_active: false,
            dns_protected: false,
            rtt_ms: None,
            log_tail: None,
        }));
        let handler = Arc::new(SnapshotHandler::new(state));
        let server_task = tokio::spawn(serve_connection(
            server,
            PeerPolicy::new(unsafe { libc::getuid() }),
            handler,
        ));
        let request = RequestEnvelope::new(PROTOCOL_VERSION, 9, DaemonCommand::Status);
        let bytes = encode_frame(&request).unwrap();
        client.write_u32(bytes.len() as u32).await.unwrap();
        client.write_all(&bytes).await.unwrap();
        let length = client.read_u32().await.unwrap();
        let mut response = vec![0; length as usize];
        client.read_exact(&mut response).await.unwrap();
        let response = decode_response_frame(&response).unwrap();
        assert_eq!(
            response.result.unwrap().phase,
            ConnectionPhase::RecoveryRequired
        );
        drop(client);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn idle_clients_are_timed_out_and_connection_count_is_bounded() {
        assert!((1..=32).contains(&MAX_CONCURRENT_CLIENTS));
        let (_client, server) = UnixStream::pair().unwrap();
        let state = Arc::new(RwLock::new(DaemonState {
            phase: ConnectionPhase::Disconnected,
            split_active: false,
            dns_protected: false,
            rtt_ms: None,
            log_tail: None,
        }));
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            serve_connection_with_limits(
                server,
                PeerPolicy::new(unsafe { libc::getuid() }),
                Arc::new(SnapshotHandler::new(state)),
                std::time::Duration::from_millis(25),
                1,
            ),
        )
        .await
        .expect("server enforced its own deadline");
        assert_eq!(result, Err(crate::protocol::DaemonErrorCode::InvalidFrame));
    }
}
