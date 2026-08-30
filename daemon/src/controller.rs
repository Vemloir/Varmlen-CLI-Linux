use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::lifecycle::LifecycleManager;
use crate::log_store::{LogStore, MAX_LOG_TAIL_BYTES};
use crate::protocol::{ConnectionPhase, DaemonCommand, DaemonError, DaemonErrorCode, DaemonState};
use crate::server::CommandHandler;
use crate::state::{PersistedState, StateStore};
use crate::system::SystemLifecycleBackend;

pub struct SystemController {
    owner_uid: u32,
    manager: Mutex<LifecycleManager<SystemLifecycleBackend>>,
    state_path: PathBuf,
    log_store: Arc<Mutex<LogStore>>,
}

impl SystemController {
    pub fn new(owner_uid: u32, phase: ConnectionPhase, state_path: PathBuf) -> Self {
        let backend = SystemLifecycleBackend::installed(owner_uid);
        let log_store = backend.log_store();
        Self {
            owner_uid,
            manager: Mutex::new(LifecycleManager::new(backend, phase)),
            state_path,
            log_store,
        }
    }

    pub async fn poll_health(&self) -> Result<DaemonState, DaemonError> {
        let mut manager = self.manager.lock().await;
        let before = manager.state().clone();
        let result = manager.reconcile_health().await;
        if manager.state() != &before {
            self.persist(&mut manager)?;
        }
        result
    }

    fn persist(
        &self,
        manager: &mut LifecycleManager<SystemLifecycleBackend>,
    ) -> Result<(), DaemonError> {
        let mut persisted = PersistedState::new(self.owner_uid, manager.state().phase);
        persisted.xray = manager.backend().xray_identity();
        if let Err(error) = StateStore::new(self.state_path.clone()).write(&persisted) {
            manager.mark_recovery_required();
            return Err(DaemonError::new(
                DaemonErrorCode::Internal,
                format!("could not persist daemon recovery state: {error}"),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl CommandHandler for SystemController {
    async fn handle(&self, command: DaemonCommand) -> Result<DaemonState, DaemonError> {
        match command {
            DaemonCommand::LogTail => {
                let log_tail = self
                    .log_store
                    .lock()
                    .await
                    .tail(MAX_LOG_TAIL_BYTES)
                    .map_err(|error| {
                        DaemonError::new(
                            DaemonErrorCode::Internal,
                            format!("could not read Xray log: {error}"),
                        )
                    })?;
                let mut state = self.manager.lock().await.state().clone();
                state.log_tail = Some(log_tail);
                return Ok(state);
            }
            DaemonCommand::ClearLog => {
                self.log_store.lock().await.clear().map_err(|error| {
                    DaemonError::new(
                        DaemonErrorCode::Internal,
                        format!("could not clear Xray log: {error}"),
                    )
                })?;
                return Ok(self.manager.lock().await.state().clone());
            }
            DaemonCommand::TcpPing(request) => {
                let rtt = crate::system::run_tcp_ping(&request).await?;
                let mut state = self.manager.lock().await.state().clone();
                state.rtt_ms = Some(rtt);
                return Ok(state);
            }
            DaemonCommand::ProxyPing(request) => {
                let rtt = crate::system::run_proxy_ping(self.owner_uid, &request).await?;
                let mut state = self.manager.lock().await.state().clone();
                state.rtt_ms = Some(rtt);
                return Ok(state);
            }
            _ => {}
        }

        let mut manager = self.manager.lock().await;
        let result = match command {
            DaemonCommand::Status => manager.reconcile_health().await,
            DaemonCommand::Connect(request) => manager.connect(request).await,
            DaemonCommand::Disconnect => manager.disconnect().await,
            DaemonCommand::UpdateSplit(applications) => {
                manager.update_split(applications.applications).await
            }
            DaemonCommand::TcpPing(_)
            | DaemonCommand::ProxyPing(_)
            | DaemonCommand::LogTail
            | DaemonCommand::ClearLog => unreachable!(),
        };
        self.persist(&mut manager)?;
        result
    }
}
