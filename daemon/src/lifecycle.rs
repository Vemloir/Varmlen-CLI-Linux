use async_trait::async_trait;

use crate::protocol::{
    ConnectRequest, ConnectionMode, ConnectionPhase, DaemonError, DaemonErrorCode, DaemonState,
};

#[async_trait]
pub trait LifecycleBackend {
    fn data_plane_alive(&mut self) -> bool;
    async fn validate(&mut self, request: &ConnectRequest) -> Result<(), DaemonError>;
    async fn install_hold_block(&mut self, request: &ConnectRequest) -> Result<(), DaemonError>;
    async fn verify_hold_block(&mut self) -> Result<(), DaemonError>;
    async fn stop_data_plane(&mut self, preserve_split: bool) -> Result<(), DaemonError>;
    async fn start_data_plane(&mut self, request: &ConnectRequest) -> Result<(), DaemonError>;
    async fn activate_network(&mut self, request: &ConnectRequest) -> Result<(), DaemonError>;
    /// Re-resolve the per-app exception list against a tunnel that is already
    /// up.  Returns whether split tunnelling is live afterwards.
    async fn update_split(&mut self, applications: Vec<String>) -> Result<bool, DaemonError>;
    async fn verify_connection(&mut self, request: &ConnectRequest) -> Result<(), DaemonError>;
    async fn remove_hold_block(&mut self) -> Result<(), DaemonError>;
}

pub struct LifecycleManager<B> {
    backend: B,
    state: DaemonState,
    block_on_failure: bool,
}

impl<B: LifecycleBackend> LifecycleManager<B> {
    pub fn new(backend: B, phase: ConnectionPhase) -> Self {
        Self {
            backend,
            state: DaemonState {
                phase,
                split_active: false,
                dns_protected: false,
                rtt_ms: None,
                log_tail: None,
            },
            block_on_failure: false,
        }
    }

    pub fn state(&self) -> &DaemonState {
        &self.state
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn mark_recovery_required(&mut self) {
        self.state.phase = ConnectionPhase::RecoveryRequired;
        self.state.split_active = false;
        self.state.dns_protected = false;
    }

    pub async fn connect(&mut self, request: ConnectRequest) -> Result<DaemonState, DaemonError> {
        let was_connected = self.state.phase == ConnectionPhase::Connected;
        self.state.phase = if was_connected {
            ConnectionPhase::Reconnecting
        } else {
            ConnectionPhase::Preparing
        };
        self.state.split_active = false;
        self.state.dns_protected = false;

        if let Err(error) = self.backend.validate(&request).await {
            self.state.phase = if was_connected {
                ConnectionPhase::Connected
            } else {
                ConnectionPhase::Disconnected
            };
            return Err(error);
        }

        let guarded = request.mode == ConnectionMode::Tun;
        if guarded {
            if let Err(error) = self.backend.install_hold_block(&request).await {
                self.state.phase = if was_connected {
                    ConnectionPhase::Connected
                } else {
                    ConnectionPhase::Disconnected
                };
                return Err(error);
            }
            if let Err(error) = self.backend.verify_hold_block().await {
                self.state.phase = if self.backend.remove_hold_block().await.is_ok() {
                    if was_connected {
                        ConnectionPhase::Connected
                    } else {
                        ConnectionPhase::Disconnected
                    }
                } else {
                    ConnectionPhase::RecoveryRequired
                };
                return Err(error);
            }
            self.state.phase = ConnectionPhase::Blocking;
        }

        if was_connected {
            if let Err(error) = self.backend.stop_data_plane(true).await {
                self.state.phase = if guarded {
                    ConnectionPhase::Blocking
                } else {
                    ConnectionPhase::RecoveryRequired
                };
                return Err(error);
            }
        }

        let result = async {
            self.backend.start_data_plane(&request).await?;
            self.backend.activate_network(&request).await?;
            self.backend.verify_connection(&request).await
        }
        .await;

        if let Err(error) = result {
            let cleanup_failed = self.backend.stop_data_plane(false).await.is_err();
            if cleanup_failed {
                self.state.phase = ConnectionPhase::RecoveryRequired;
            } else if guarded && (was_connected || request.killswitch) {
                self.state.phase = ConnectionPhase::Blocking;
            } else {
                if guarded {
                    let _ = self.backend.remove_hold_block().await;
                }
                self.state.phase = ConnectionPhase::Disconnected;
            }
            return Err(error);
        }

        if guarded && !request.killswitch {
            if let Err(error) = self.backend.remove_hold_block().await {
                self.state.phase = ConnectionPhase::RecoveryRequired;
                return Err(error);
            }
        }
        self.state = DaemonState {
            phase: ConnectionPhase::Connected,
            split_active: !request.excluded_apps.is_empty(),
            dns_protected: guarded,
            rtt_ms: None,
            log_tail: None,
        };
        self.block_on_failure = guarded && request.killswitch;
        Ok(self.state.clone())
    }

    /// Apply an edited exception list without dropping the tunnel.
    ///
    /// Split rules used to be read at connect only, so `varmlen-cli split apps
    /// add` looked inert until the tunnel was cycled, and an application that
    /// had been removed from the list kept bypassing.
    pub async fn update_split(
        &mut self,
        applications: Vec<String>,
    ) -> Result<DaemonState, DaemonError> {
        if !matches!(self.state.phase, ConnectionPhase::Connected) {
            return Err(DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "the tunnel is not connected",
            ));
        }
        let split_active = self.backend.update_split(applications).await?;
        self.state.split_active = split_active;
        Ok(self.state.clone())
    }

    pub async fn disconnect(&mut self) -> Result<DaemonState, DaemonError> {
        let data_plane = self.backend.stop_data_plane(false).await;
        let hold_block = self.backend.remove_hold_block().await;
        if data_plane.is_err() || hold_block.is_err() {
            self.state.phase = ConnectionPhase::RecoveryRequired;
            return Err(DaemonError::new(
                DaemonErrorCode::TunnelCleanupFailed,
                "VPN cleanup did not reach a verified empty state",
            ));
        }
        self.state = DaemonState {
            phase: ConnectionPhase::Disconnected,
            split_active: false,
            dns_protected: false,
            rtt_ms: None,
            log_tail: None,
        };
        self.block_on_failure = false;
        Ok(self.state.clone())
    }

    pub async fn reconcile_health(&mut self) -> Result<DaemonState, DaemonError> {
        if self.state.phase != ConnectionPhase::Connected || self.backend.data_plane_alive() {
            return Ok(self.state.clone());
        }
        let cleanup = self.backend.stop_data_plane(false).await;
        if cleanup.is_err() {
            self.mark_recovery_required();
            return Err(DaemonError::new(
                DaemonErrorCode::TunnelCleanupFailed,
                "Xray exited and stale network state could not be removed",
            ));
        }
        self.state = DaemonState {
            phase: if self.block_on_failure {
                ConnectionPhase::Blocking
            } else {
                ConnectionPhase::Disconnected
            },
            split_active: false,
            dns_protected: false,
            rtt_ms: None,
            log_tail: None,
        };
        Ok(self.state.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};

    use async_trait::async_trait;

    use super::{LifecycleBackend, LifecycleManager};
    use crate::protocol::{
        ConnectRequest, ConnectionMode, ConnectionPhase, DaemonError, DaemonErrorCode,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Action {
        Validate,
        InstallHold,
        VerifyHold,
        StopPreservingSplit,
        StopFully,
        Start,
        Activate,
        UpdateSplit,
        VerifyConnection,
        RemoveHold,
    }

    struct FakeBackend {
        actions: VecDeque<Action>,
        fail_on: Option<Action>,
        alive: bool,
    }

    impl FakeBackend {
        fn healthy() -> Self {
            Self {
                actions: VecDeque::new(),
                fail_on: None,
                alive: true,
            }
        }

        fn failing(action: Action) -> Self {
            Self {
                actions: VecDeque::new(),
                fail_on: Some(action),
                alive: true,
            }
        }

        fn record(&mut self, action: Action) -> Result<(), DaemonError> {
            self.actions.push_back(action);
            if self.fail_on == Some(action) {
                Err(DaemonError::new(
                    DaemonErrorCode::Internal,
                    "injected lifecycle failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl LifecycleBackend for FakeBackend {
        fn data_plane_alive(&mut self) -> bool {
            self.alive
        }

        async fn validate(&mut self, _request: &ConnectRequest) -> Result<(), DaemonError> {
            self.record(Action::Validate)
        }

        async fn install_hold_block(
            &mut self,
            _request: &ConnectRequest,
        ) -> Result<(), DaemonError> {
            self.record(Action::InstallHold)
        }

        async fn verify_hold_block(&mut self) -> Result<(), DaemonError> {
            self.record(Action::VerifyHold)
        }

        async fn stop_data_plane(&mut self, preserve_split: bool) -> Result<(), DaemonError> {
            self.record(if preserve_split {
                Action::StopPreservingSplit
            } else {
                Action::StopFully
            })
        }

        async fn start_data_plane(&mut self, _request: &ConnectRequest) -> Result<(), DaemonError> {
            self.record(Action::Start)
        }

        async fn activate_network(&mut self, _request: &ConnectRequest) -> Result<(), DaemonError> {
            self.record(Action::Activate)
        }

        async fn update_split(&mut self, applications: Vec<String>) -> Result<bool, DaemonError> {
            self.record(Action::UpdateSplit)?;
            Ok(!applications.is_empty())
        }

        async fn verify_connection(
            &mut self,
            _request: &ConnectRequest,
        ) -> Result<(), DaemonError> {
            self.record(Action::VerifyConnection)
        }

        async fn remove_hold_block(&mut self) -> Result<(), DaemonError> {
            self.record(Action::RemoveHold)
        }
    }

    fn request(killswitch: bool) -> ConnectRequest {
        ConnectRequest {
            mode: ConnectionMode::Tun,
            xray_config: "{}".into(),
            validation_config: "{}".into(),
            server_ips: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))],
            excluded_apps: vec!["cs2".into()],
            killswitch,
            allow_lan: false,
        }
    }

    #[tokio::test]
    async fn reconnect_verifies_block_before_stopping_old_data_plane() {
        let mut manager = LifecycleManager::new(FakeBackend::healthy(), ConnectionPhase::Connected);
        manager.connect(request(false)).await.unwrap();
        assert_eq!(
            manager.backend().actions,
            VecDeque::from([
                Action::Validate,
                Action::InstallHold,
                Action::VerifyHold,
                Action::StopPreservingSplit,
                Action::Start,
                Action::Activate,
                Action::VerifyConnection,
                Action::RemoveHold,
            ])
        );
    }

    #[tokio::test]
    async fn failed_reconnect_stays_blocked_after_old_tunnel_was_stopped() {
        let mut manager = LifecycleManager::new(
            FakeBackend::failing(Action::Activate),
            ConnectionPhase::Connected,
        );
        manager.connect(request(false)).await.unwrap_err();
        assert_eq!(manager.state().phase, ConnectionPhase::Blocking);
        assert_eq!(manager.backend().actions.back(), Some(&Action::StopFully));
    }

    #[tokio::test]
    async fn failed_initial_connect_without_killswitch_restores_direct_network() {
        let mut manager = LifecycleManager::new(
            FakeBackend::failing(Action::Start),
            ConnectionPhase::Disconnected,
        );
        manager.connect(request(false)).await.unwrap_err();
        assert_eq!(manager.state().phase, ConnectionPhase::Disconnected);
        assert_eq!(manager.backend().actions.back(), Some(&Action::RemoveHold));
    }

    #[tokio::test]
    async fn unexpected_xray_exit_keeps_user_killswitch_blocking() {
        let mut manager =
            LifecycleManager::new(FakeBackend::healthy(), ConnectionPhase::Disconnected);
        manager.connect(request(true)).await.unwrap();
        manager.backend_mut().alive = false;
        let state = manager.reconcile_health().await.unwrap();
        assert_eq!(state.phase, ConnectionPhase::Blocking);
        assert!(!state.dns_protected);
        assert!(!state.split_active);
    }
}
