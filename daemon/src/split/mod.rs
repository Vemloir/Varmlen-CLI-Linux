pub mod bpf;
pub mod cgroup;
pub mod process;
pub mod routing;
pub mod system;
pub mod watcher;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPlan {
    pub uid: u32,
    pub applications: Vec<String>,
}

impl SplitPlan {
    pub fn new(uid: u32, applications: Vec<String>) -> Self {
        Self { uid, applications }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitStatus {
    Disabled,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SplitError {
    #[error("invalid split application: {0}")]
    InvalidApplication(String),
    #[error("could not create the bypass cgroup")]
    CgroupUnavailable,
    #[error("could not attach the socket-mark BPF program")]
    BpfUnavailable,
    #[error("could not install split routing")]
    RoutingUnavailable,
    #[error("could not start direct DNS for excluded applications")]
    DirectDnsUnavailable,
    #[error("the application permission watcher is unavailable")]
    WatcherUnavailable,
    #[error("could not reconcile existing application processes")]
    ReconciliationFailed,
    #[error("split rollback failed")]
    RollbackFailed,
}

#[async_trait]
pub trait SplitBackend {
    async fn create_cgroup(&mut self, uid: u32) -> Result<(), SplitError>;
    async fn attach_socket_mark_bpf(&mut self) -> Result<(), SplitError>;
    async fn install_route_rules(&mut self) -> Result<(), SplitError>;
    async fn start_permission_watcher(&mut self, plan: &SplitPlan) -> Result<(), SplitError>;
    async fn reconcile_existing(&mut self, plan: &SplitPlan) -> Result<(), SplitError>;
    async fn rollback(&mut self) -> Result<(), SplitError>;
}

pub struct SplitManager<B> {
    backend: B,
    status: SplitStatus,
}

impl<B: SplitBackend> SplitManager<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            status: SplitStatus::Disabled,
        }
    }

    pub fn status(&self) -> SplitStatus {
        self.status
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub async fn apply(&mut self, plan: SplitPlan) -> Result<(), SplitError> {
        let result = async {
            self.backend.create_cgroup(plan.uid).await?;
            self.backend.attach_socket_mark_bpf().await?;
            self.backend.install_route_rules().await?;
            self.backend.start_permission_watcher(&plan).await?;
            self.backend.reconcile_existing(&plan).await?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            let _ = self.backend.rollback().await;
            self.status = SplitStatus::Disabled;
            return Err(error);
        }
        self.status = SplitStatus::Active;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::{SplitBackend, SplitError, SplitManager, SplitPlan, SplitStatus};

    #[derive(Default)]
    struct FakeSplitBackend {
        fail_watcher: bool,
        cgroup_created: bool,
        bpf_attached: bool,
        routes_installed: bool,
        rolled_back: bool,
    }

    #[async_trait]
    impl SplitBackend for FakeSplitBackend {
        async fn create_cgroup(&mut self, _uid: u32) -> Result<(), SplitError> {
            self.cgroup_created = true;
            Ok(())
        }

        async fn attach_socket_mark_bpf(&mut self) -> Result<(), SplitError> {
            self.bpf_attached = true;
            Ok(())
        }

        async fn install_route_rules(&mut self) -> Result<(), SplitError> {
            self.routes_installed = true;
            Ok(())
        }

        async fn start_permission_watcher(&mut self, _plan: &SplitPlan) -> Result<(), SplitError> {
            if self.fail_watcher {
                return Err(SplitError::WatcherUnavailable);
            }
            Ok(())
        }

        async fn reconcile_existing(&mut self, _plan: &SplitPlan) -> Result<(), SplitError> {
            Ok(())
        }

        async fn rollback(&mut self) -> Result<(), SplitError> {
            self.rolled_back = true;
            self.bpf_attached = false;
            self.routes_installed = false;
            Ok(())
        }
    }

    #[tokio::test]
    async fn watcher_failure_never_reports_active() {
        let backend = FakeSplitBackend {
            fail_watcher: true,
            ..Default::default()
        };
        let mut manager = SplitManager::new(backend);
        let error = manager
            .apply(SplitPlan::new(1000, vec!["/games/cs2".into()]))
            .await
            .unwrap_err();
        assert_eq!(error, SplitError::WatcherUnavailable);
        assert_eq!(manager.status(), SplitStatus::Disabled);
        assert!(manager.backend().rolled_back);
        assert!(!manager.backend().bpf_attached);
        assert!(!manager.backend().routes_installed);
    }

    #[tokio::test]
    async fn all_verified_layers_are_required_for_active_status() {
        let mut manager = SplitManager::new(FakeSplitBackend::default());
        manager
            .apply(SplitPlan::new(1000, vec!["/games/cs2".into()]))
            .await
            .unwrap();
        assert_eq!(manager.status(), SplitStatus::Active);
        assert!(manager.backend().cgroup_created);
        assert!(manager.backend().bpf_attached);
        assert!(manager.backend().routes_installed);
    }
}
