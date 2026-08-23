use async_trait::async_trait;

use crate::direct_dns::DirectDnsProxy;

use super::bpf::{attach_socket_mark, detach_socket_mark};
use super::cgroup::BypassCgroup;
use super::process::{mark_existing_sockets, real_uid, snapshot, AppSelector};
use super::routing::{detect_default_route, install_routing, remove_routing};
use super::watcher::PermissionWatcher;
use super::{SplitBackend, SplitError, SplitPlan};

pub struct SystemSplitBackend {
    owner_uid: u32,
    cgroup: Option<BypassCgroup>,
    selectors: Vec<AppSelector>,
    watcher: Option<PermissionWatcher>,
    routing_active: bool,
    direct_dns: Option<DirectDnsProxy>,
}

impl SystemSplitBackend {
    pub fn new(owner_uid: u32) -> Self {
        Self {
            owner_uid,
            cgroup: None,
            selectors: Vec::new(),
            watcher: None,
            routing_active: false,
            direct_dns: None,
        }
    }

    fn cgroup(&self) -> Result<&BypassCgroup, SplitError> {
        self.cgroup.as_ref().ok_or(SplitError::CgroupUnavailable)
    }

    pub fn is_healthy(&self) -> bool {
        self.routing_active
            && self
                .direct_dns
                .as_ref()
                .is_some_and(DirectDnsProxy::is_healthy)
            && self
                .watcher
                .as_ref()
                .is_some_and(PermissionWatcher::is_healthy)
    }

    fn selectors(plan: &SplitPlan) -> Result<Vec<AppSelector>, SplitError> {
        plan.applications
            .iter()
            .map(|value| {
                let selector = AppSelector::parse(value)?;
                match selector {
                    AppSelector::ExactPath(path) => {
                        let canonical = std::fs::canonicalize(&path).map_err(|_| {
                            SplitError::InvalidApplication(path.display().to_string())
                        })?;
                        Ok(AppSelector::ExactPath(canonical))
                    }
                    name => Ok(name),
                }
            })
            .collect()
    }
}

#[async_trait]
impl SplitBackend for SystemSplitBackend {
    async fn create_cgroup(&mut self, uid: u32) -> Result<(), SplitError> {
        if uid != self.owner_uid {
            return Err(SplitError::CgroupUnavailable);
        }
        self.cgroup = Some(BypassCgroup::create(uid)?);
        Ok(())
    }

    async fn attach_socket_mark_bpf(&mut self) -> Result<(), SplitError> {
        attach_socket_mark(self.cgroup()?.directory())
    }

    async fn install_route_rules(&mut self) -> Result<(), SplitError> {
        let route = detect_default_route().await?;
        install_routing(&self.cgroup()?.relative_path(), &route).await?;
        self.routing_active = true;
        self.direct_dns = Some(DirectDnsProxy::start().await?);
        Ok(())
    }

    async fn start_permission_watcher(&mut self, plan: &SplitPlan) -> Result<(), SplitError> {
        let selectors = Self::selectors(plan)?;
        if selectors.is_empty() {
            return Err(SplitError::InvalidApplication(
                "split application list is empty".into(),
            ));
        }
        let watcher = PermissionWatcher::start(
            self.owner_uid,
            selectors.clone(),
            self.cgroup()?.procs_path(),
        )?;
        if !watcher.is_healthy() {
            return Err(SplitError::WatcherUnavailable);
        }
        self.selectors = selectors;
        self.watcher = Some(watcher);
        Ok(())
    }

    async fn reconcile_existing(&mut self, _plan: &SplitPlan) -> Result<(), SplitError> {
        let entries = std::fs::read_dir("/proc").map_err(|_| SplitError::ReconciliationFailed)?;
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            if real_uid(pid).ok() != Some(self.owner_uid) {
                continue;
            }
            let Ok(process) = snapshot(pid) else {
                continue;
            };
            if self
                .selectors
                .iter()
                .any(|selector| selector.matches(&process))
            {
                self.cgroup()?.move_pid(pid)?;
                mark_existing_sockets(pid, super::bpf::BYPASS_MARK)?;
            }
        }
        if !self
            .watcher
            .as_ref()
            .is_some_and(PermissionWatcher::is_healthy)
        {
            return Err(SplitError::WatcherUnavailable);
        }
        Ok(())
    }

    async fn rollback(&mut self) -> Result<(), SplitError> {
        self.watcher.take();
        let mut first_error = None;
        if let Some(mut direct_dns) = self.direct_dns.take() {
            if let Err(error) = direct_dns.stop().await {
                first_error = Some(error);
            }
        }
        if self.routing_active {
            if let Err(error) = remove_routing().await {
                first_error.get_or_insert(error);
            }
            self.routing_active = false;
        }
        if let Some(cgroup) = self.cgroup.as_ref() {
            let _ = detach_socket_mark(cgroup.directory());
        }
        self.selectors.clear();
        first_error.map_or(Ok(()), Err)
    }
}
