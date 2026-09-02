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
    /// The version the daemon reported in its last response, empty when it is
    /// too old to report one. See `varmlend::protocol::daemon_version`.
    daemon_version: String,
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
            daemon_version: String::new(),
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
                "an outdated Varmlen background daemon is still running; update it with `varmlen-cli update`"
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

/// The version of the daemon this connection is talking to, taken from its
    /// last response. Empty for a daemon that predates version reporting,
    /// which is itself a finding: installing over curl left that daemon serving
    /// a client newer than it.
    pub fn daemon_version(&self) -> &str {
        &self.daemon_version
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
        // Remember who answered, whoever that turns out to be: a refused
        // request is still an answer from the same daemon, and its version is
        // what the caller needs in order to explain the refusal.
        self.daemon_version = response.daemon_version;
        if response.operation_id != operation_id {
            // A daemon that refuses a request while decoding it answers with the
            // id it could salvage, which for an older daemon is 0. Its error
            // code is the only explanation the user gets, so prefer it over an
            // anonymous mismatch.
            return match response.result {
                Err(error) => Err(ClientError::from(error)),
                Ok(_) => Err(ClientError::OperationMismatch),
            };
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
                    daemon_version: "0.1.2".to_string(),
                },
            )
            .await
            .unwrap();
        });

        let mut client = DaemonClient::connect(&socket).await.unwrap();
        let state = client.request(DaemonCommand::Status).await.unwrap();
        assert_eq!(state.phase, ConnectionPhase::Disconnected);
        assert_eq!(client.daemon_version(), "0.1.2");
        server.await.unwrap();
        let _ = std::fs::remove_file(socket);
    }

    #[tokio::test]
    async fn compatibility_probe_points_an_old_daemon_at_an_update() {
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
                    daemon_version: String::new(),
                },
            )
            .await
            .unwrap();
        });

        let error = DaemonClient::connect_compatible(&socket).await.unwrap_err();
        assert!(matches!(error, ClientError::RestartRequired(_)));
        // A reboot is not what is missing: the daemon binary has to be
        // replaced and the service restarted, which the client can do.
        assert!(error.to_string().contains("varmlen-cli update"));
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
