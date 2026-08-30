use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use async_trait::async_trait;

use crate::direct_dns::DirectDnsProxy;

use super::bpf::{attach_socket_mark, detach_socket_mark, BYPASS_MARK};
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
    reconcile_stop: Arc<AtomicBool>,
    /// Pids this split moved, and the rule that moved each: membership of the
    /// bypass cgroup is inherited, so this is the only record of which
    /// processes are ours to take back.
    owned: Arc<Mutex<HashMap<u32, AppSelector>>>,
    reconciler: Option<JoinHandle<()>>,
    reconciling: bool,
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
            reconcile_stop: Arc::new(AtomicBool::new(false)),
            owned: Arc::new(Mutex::new(HashMap::new())),
            reconciler: None,
            reconciling: false,
        }
    }

    fn cgroup(&self) -> Result<&BypassCgroup, SplitError> {
        self.cgroup.as_ref().ok_or(SplitError::CgroupUnavailable)
    }

    /// One pass of the process tree against the current rules.
    ///
    /// The permission watcher only sees an exec on a marked mount, which a
    /// Flatpak or Snap sandbox does not do: it runs its application from a
    /// mount namespace the daemon's marks cannot cover. Re-reading /proc is
    /// how those processes, and any process that started between the plan
    /// being written and the watcher being armed, are still found.
    ///
    /// It is also the only place a *removed* rule is undone: a process the
    /// plan no longer names leaves the bypass cgroup, so taking an application
    /// out of the exception list stops its traffic going direct.
    fn reconcile_once(&self) -> Result<(), SplitError> {
        let mut owned = self
            .owned
            .lock()
            .map_err(|_| SplitError::ReconciliationFailed)?;
        reconcile_with(self.cgroup()?, self.owner_uid, &self.selectors, &mut owned)
    }

    /// Watch /proc for the applications the plan names, next to the watcher.
    fn start_reconciler(&mut self) {
        if self.reconciling {
            return;
        }
        if self.cgroup().is_err() {
            return;
        }
        let stop = Arc::clone(&self.reconcile_stop);
        let owned = Arc::clone(&self.owned);
        let selectors = self.selectors.clone();
        let owner_uid = self.owner_uid;
        let spawned = std::thread::Builder::new()
            .name("varmlen-split-r".to_string())
            .spawn(move || {
                // The thread keeps its own handle on the cgroup, which is the
                // cheap way to outlive the backend that started it.
                let Ok(cgroup) = BypassCgroup::create(owner_uid) else {
                    return;
                };
                while !stop.load(Ordering::Acquire) {
                    std::thread::sleep(RECONCILE_INTERVAL);
                    let Ok(mut owned) = owned.lock() else {
                        return;
                    };
                    let _ = reconcile_with(&cgroup, owner_uid, &selectors, &mut owned);
                }
            })
            .ok();
        let Some(spawned) = spawned else {
            return;
        };
        self.reconciler = Some(spawned);
        self.reconciling = true;
    }

    fn stop_reconciler(&mut self) {
        self.reconcile_stop.store(true, Ordering::Release);
        if let Some(handle) = self.reconciler.take() {
            let _ = handle.join();
        }
        self.reconciling = false;
        self.reconcile_stop.store(false, Ordering::Release);
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

/// How often the process tree is re-read for sandboxed and late arrivals.
const RECONCILE_INTERVAL: Duration = Duration::from_millis(1_000);

/// The same pass as [`SystemSplitBackend::reconcile_once`] for the thread,
/// which cannot borrow the backend.
fn reconcile_with(
    cgroup: &BypassCgroup,
    owner_uid: u32,
    selectors: &[AppSelector],
    owned: &mut HashMap<u32, AppSelector>,
) -> Result<(), SplitError> {
    let entries = std::fs::read_dir("/proc").map_err(|_| SplitError::ReconciliationFailed)?;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if real_uid(pid).ok() != Some(owner_uid) || cgroup.contains_pid(pid) {
            continue;
        }
        let Ok(process) = snapshot(pid) else {
            continue;
        };
        let Some(selector) = selectors.iter().find(|selector| {
            selector.matches(&process) || selector.matched_application_id(&process).is_some()
        }) else {
            continue;
        };
        cgroup.move_pid(pid)?;
        // Sockets opened before the move carry no mark and would keep going
        // through the tunnel; a process we may not ptrace still gets every new
        // socket marked, which is the larger half of the fix.
        let _ = mark_existing_sockets(pid, BYPASS_MARK);
        if owned.len() < MAX_OWNED_PIDS {
            owned.insert(pid, selector.clone());
        }
    }

    // Only the processes this split moved itself may be taken back: every
    // other member of the cgroup is there because it was born to something
    // that is, and ejecting those cuts a sandbox in half.  A process goes back
    // when the rule that moved it is gone from the plan, and it takes its
    // descendants with it, which is what "this application is no longer an
    // exception" has to mean.
    let members = cgroup.member_pids();
    owned.retain(|pid, _| members.contains(pid));
    // The permission watcher moves processes too, and it leaves no record.
    // Attributing a member to the rule that matches it now is the same rule
    // that would have moved it here, and without it a process the watcher
    // caught could never be handed back.
    let unattributed: Vec<u32> = members
        .iter()
        .filter(|pid| !owned.contains_key(pid))
        .copied()
        .collect();
    for pid in unattributed {
        if let Ok(process) = snapshot(pid) {
            if let Some(selector) = selectors.iter().find(|selector| selector.matches(&process)) {
                if owned.len() < MAX_OWNED_PIDS {
                    owned.insert(pid, selector.clone());
                }
            }
        }
    }
    let stale: Vec<u32> = owned
        .iter()
        .filter(|(_, selector)| !selectors.contains(selector))
        .map(|(pid, _)| *pid)
        .collect();
    if !stale.is_empty() {
        let tree = process_tree(owner_uid);
        for root in stale {
            for pid in subtree(&tree, root) {
                if members.contains(&pid) {
                    let _ = cgroup.move_out(pid);
                }
                owned.remove(&pid);
            }
        }
    }
    Ok(())
}

/// Every process of the user, mapped to its children.
fn process_tree(owner_uid: u32) -> HashMap<u32, Vec<u32>> {
    let mut tree: HashMap<u32, Vec<u32>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return tree;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if real_uid(pid).ok() != Some(owner_uid) {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        if let Some(ppid) = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|value| value.trim().parse::<u32>().ok())
        {
            tree.entry(ppid).or_default().push(pid);
        }
    }
    tree
}

/// A process and everything below it.
fn subtree(tree: &HashMap<u32, Vec<u32>>, root: u32) -> Vec<u32> {
    let mut found = vec![root];
    let mut queue = vec![root];
    while let Some(pid) = queue.pop() {
        if let Some(children) = tree.get(&pid) {
            for child in children {
                if !found.contains(child) {
                    found.push(*child);
                    queue.push(*child);
                }
            }
        }
    }
    found
}

/// How many moved processes to remember a rule for.
const MAX_OWNED_PIDS: usize = 8_192;

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
        self.reconcile_once()?;
        self.start_reconciler();
        if !self
            .watcher
            .as_ref()
            .is_some_and(PermissionWatcher::is_healthy)
        {
            return Err(SplitError::WatcherUnavailable);
        }
        Ok(())
    }

    async fn update_plan(&mut self, plan: &SplitPlan) -> Result<(), SplitError> {
        let selectors = Self::selectors(plan)?;
        self.stop_reconciler();
        // Dropping the watcher stops the old rules from being applied a moment
        // later from a queued event.
        self.watcher = None;
        self.selectors = selectors;
        if self.selectors.is_empty() {
            self.reconcile_once()?;
            return Ok(());
        }
        let watcher = PermissionWatcher::start(
            self.owner_uid,
            self.selectors.clone(),
            self.cgroup()?.procs_path(),
        )?;
        if !watcher.is_healthy() {
            return Err(SplitError::WatcherUnavailable);
        }
        self.watcher = Some(watcher);
        self.reconcile_once()?;
        self.start_reconciler();
        Ok(())
    }

    async fn rollback(&mut self) -> Result<(), SplitError> {
        self.stop_reconciler();
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
