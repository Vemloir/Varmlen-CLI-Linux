use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::time::{sleep, timeout, Duration};
use varmlend::protocol::{
    decode_response_frame, encode_frame, DaemonCommand, DaemonError, DaemonState, RequestEnvelope,
    MAX_FRAME_BYTES, PROTOCOL_VERSION,
};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("daemon I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("daemon protocol: {0:?}")]
    Protocol(varmlend::protocol::DaemonErrorCode),
    #[error("daemon operation: {0:?}: {1}")]
    Daemon(varmlend::protocol::DaemonErrorCode, String),
    #[error("daemon response operation ID mismatch")]
    OperationMismatch,
    #[error("installed daemon is unavailable: {0}")]
    Unavailable(String),
    #[error("restart required: {0}")]
    RestartRequired(String),
    #[error("daemon request timed out while {0}")]
    Timeout(&'static str),
}

impl From<DaemonError> for ClientError {
    fn from(value: DaemonError) -> Self {
        Self::Daemon(value.code, value.message)
    }
}

#[derive(Debug)]
pub struct DaemonClient {
    stream: UnixStream,
    next_operation_id: u64,
}

impl DaemonClient {
    pub fn installed_socket_path() -> PathBuf {
        PathBuf::from(format!("/run/varmlen/daemon-{}.sock", unsafe {
            libc::getuid()
        }))
    }

    pub async fn connect(path: &Path) -> Result<Self, ClientError> {
        Ok(Self {
            stream: timeout(Duration::from_secs(5), UnixStream::connect(path))
                .await
                .map_err(|_| ClientError::Timeout("connecting"))??,
            next_operation_id: 1,
        })
    }

    pub async fn connect_installed() -> Result<Self, ClientError> {
        Self::connect_compatible(&Self::installed_socket_path()).await
    }

    async fn connect_compatible(path: &Path) -> Result<Self, ClientError> {
        let mut client = Self::connect(path).await?;
        match client.request(DaemonCommand::Status).await {
            Ok(_) => Ok(client),
            Err(ClientError::Protocol(
                varmlend::protocol::DaemonErrorCode::UnsupportedVersion,
            ))
            | Err(ClientError::Daemon(
                varmlend::protocol::DaemonErrorCode::UnsupportedVersion,
                _,
            )) => Err(ClientError::RestartRequired(
                "an outdated Varmlen background daemon is still running; reboot once before connecting this build"
                    .into(),
            )),
            Err(error) => Err(error),
        }
    }

    pub async fn connect_or_start_installed() -> Result<Self, ClientError> {
        match Self::connect_installed().await {
            Ok(client) => return Ok(client),
            Err(error @ ClientError::RestartRequired(_)) => return Err(error),
            Err(_) => {}
        }
        const DAEMON: &str = "/usr/libexec/varmlen/varmlend";
        if !Path::new(DAEMON).is_file() {
            return Err(ClientError::Unavailable(format!(
                "{DAEMON} is not installed"
            )));
        }
        let mut child = Command::new("pkexec")
            .arg(DAEMON)
            .spawn()
            .map_err(|error| {
                ClientError::Unavailable(format!("could not start pkexec: {error}"))
            })?;
        for _ in 0..150 {
            match Self::connect_installed().await {
                Ok(client) => {
                    tokio::spawn(async move {
                        let _ = child.wait().await;
                    });
                    return Ok(client);
                }
                Err(error @ ClientError::RestartRequired(_)) => return Err(error),
                Err(_) => {}
            }
            if let Some(status) = child.try_wait()? {
                return Err(ClientError::Unavailable(format!(
                    "daemon startup was cancelled or failed ({status})"
                )));
            }
            sleep(Duration::from_millis(100)).await;
        }
        Err(ClientError::Unavailable(
            "timed out waiting for the daemon socket".into(),
        ))
    }

    pub async fn request(&mut self, command: DaemonCommand) -> Result<DaemonState, ClientError> {
        let operation_id = self.next_operation_id;
        self.next_operation_id = self.next_operation_id.wrapping_add(1).max(1);
        let request = RequestEnvelope::new(PROTOCOL_VERSION, operation_id, command);
        let bytes = encode_frame(&request).map_err(ClientError::Protocol)?;

        timeout(Duration::from_secs(5), async {
            self.stream.write_u32(bytes.len() as u32).await?;
            self.stream.write_all(&bytes).await
        })
        .await
        .map_err(|_| ClientError::Timeout("writing"))??;

        let length = timeout(Duration::from_secs(60), self.stream.read_u32())
            .await
            .map_err(|_| ClientError::Timeout("waiting for a response"))??
            as usize;
        if length > MAX_FRAME_BYTES {
            return Err(ClientError::Protocol(
                varmlend::protocol::DaemonErrorCode::FrameTooLarge,
            ));
        }
        let mut response_bytes = vec![0; length];
        timeout(
            Duration::from_secs(5),
            self.stream.read_exact(&mut response_bytes),
        )
        .await
        .map_err(|_| ClientError::Timeout("reading a response"))??;
        let response = decode_response_frame(&response_bytes).map_err(ClientError::Protocol)?;
        if response.operation_id != operation_id {
            return Err(ClientError::OperationMismatch);
        }
        response.result.map_err(ClientError::from)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::net::UnixListener;
    use varmlend::protocol::{
        ConnectionPhase, DaemonCommand, DaemonState, ResponseEnvelope, PROTOCOL_VERSION,
    };
    use varmlend::server::{read_frame, write_response};

    use super::{ClientError, DaemonClient};

    #[tokio::test]
    async fn client_round_trip_preserves_operation_id() {
        let socket = unique_socket_path();
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let bytes = read_frame(&mut stream).await.unwrap();
            let request = varmlend::protocol::decode_request_frame(&bytes).unwrap();
            write_response(
                &mut stream,
                &ResponseEnvelope {
                    version: PROTOCOL_VERSION,
                    operation_id: request.operation_id,
                    result: Ok(DaemonState {
                        phase: ConnectionPhase::Disconnected,
                        split_active: false,
                        dns_protected: false,
                        rtt_ms: None,
                        log_tail: None,
                    }),
                },
            )
            .await
            .unwrap();
        });

        let mut client = DaemonClient::connect(&socket).await.unwrap();
        let state = client.request(DaemonCommand::Status).await.unwrap();
        assert_eq!(state.phase, ConnectionPhase::Disconnected);
        server.await.unwrap();
        let _ = std::fs::remove_file(socket);
    }

    #[tokio::test]
    async fn compatibility_probe_requires_reboot_for_an_old_daemon() {
        let socket = unique_socket_path();
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let bytes = read_frame(&mut stream).await.unwrap();
            let request: varmlend::protocol::RequestEnvelope =
                serde_json::from_slice(&bytes).unwrap();
            assert_eq!(request.command, DaemonCommand::Status);
            write_response(
                &mut stream,
                &ResponseEnvelope {
                    version: PROTOCOL_VERSION - 1,
                    operation_id: request.operation_id,
                    result: Err(varmlend::protocol::DaemonError::new(
                        varmlend::protocol::DaemonErrorCode::UnsupportedVersion,
                        "old daemon",
                    )),
                },
            )
            .await
            .unwrap();
        });

        let error = DaemonClient::connect_compatible(&socket).await.unwrap_err();
        assert!(matches!(error, ClientError::RestartRequired(_)));
        assert!(error.to_string().contains("reboot"));
        server.await.unwrap();
        let _ = std::fs::remove_file(socket);
    }

    fn unique_socket_path() -> PathBuf {
        static NEXT_SOCKET: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "vd-{}-{}.sock",
            std::process::id(),
            NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        path
    }
}
