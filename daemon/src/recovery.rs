use std::collections::BTreeSet;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::time::{sleep, Duration};

use crate::protocol::ConnectionPhase;
use crate::split::bpf::detach_socket_mark;
use crate::state::StateStore;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time_ticks: u64,
    pub executable: PathBuf,
}

impl ProcessIdentity {
    pub fn new(pid: u32, start_time_ticks: u64, executable: impl Into<PathBuf>) -> Self {
        Self {
            pid,
            start_time_ticks,
            executable: executable.into(),
        }
    }

    pub fn matches(&self, live: &Self) -> bool {
        self.pid == live.pid
            && self.start_time_ticks == live.start_time_ticks
            && self.executable == live.executable
    }

    pub fn from_pid(pid: u32) -> Result<Self, String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|error| format!("read process stat: {error}"))?;
        let start_time_ticks =
            parse_start_time_ticks(&stat).ok_or_else(|| "invalid process stat".to_string())?;
        let executable = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|error| format!("read process executable: {error}"))?;
        Ok(Self::new(pid, start_time_ticks, executable))
    }
}

pub fn parse_start_time_ticks(stat: &str) -> Option<u64> {
    let command_end = stat.rfind(')')?;
    stat.get(command_end + 1..)?
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Resource {
    XrayProcess(ProcessIdentity),
    TunInterface(String),
    RouteTable(String),
    NftTable(String),
    SplitBpf(PathBuf),
    RuntimeFile(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupReport {
    pub removed: BTreeSet<Resource>,
    pub remaining: BTreeSet<Resource>,
}

impl CleanupReport {
    pub fn phase(&self) -> ConnectionPhase {
        if self.remaining.is_empty() {
            ConnectionPhase::Disconnected
        } else {
            ConnectionPhase::RecoveryRequired
        }
    }
}

#[async_trait]
pub trait CleanupBackend {
    async fn inspect(&mut self) -> Result<BTreeSet<Resource>, String>;
    async fn remove(&mut self, resource: &Resource) -> Result<(), String>;
}

pub struct RecoveryManager<B> {
    backend: B,
}

pub struct SystemCleanupBackend {
    owner_uid: u32,
    state_path: PathBuf,
}

impl SystemCleanupBackend {
    pub fn new(owner_uid: u32, state_path: PathBuf) -> Self {
        Self {
            owner_uid,
            state_path,
        }
    }

    async fn nft_table_exists(name: &str) -> bool {
        Command::new("nft")
            .args(["list", "table", "inet", name])
            .output()
            .await
            .is_ok_and(|output| output.status.success())
    }
}

fn route_resources(rules_text: &str, routes_text: &str) -> BTreeSet<Resource> {
    let mut resources = BTreeSet::new();
    if rules_text.contains("0x2023") || rules_text.contains("0x00002023") {
        resources.insert(Resource::RouteTable("101".into()));
    }
    if rules_text.contains("0x2024")
        || rules_text.contains("0x00002024")
        || rules_text.contains("0x2025")
        || rules_text.contains("0x00002025")
        || routes_text.contains("0.0.0.0/1")
        || routes_text.contains("128.0.0.0/1")
        || routes_text.contains("blackhole ::/1")
        || routes_text.contains("blackhole 8000::/1")
    {
        resources.insert(Resource::RouteTable("100".into()));
    }
    resources
}

#[async_trait]
impl CleanupBackend for SystemCleanupBackend {
    async fn inspect(&mut self) -> Result<BTreeSet<Resource>, String> {
        let mut resources = BTreeSet::new();
        if let Some(state) = StateStore::new(self.state_path.clone())
            .read()
            .map_err(|error| format!("read recovery state: {error}"))?
        {
            if state.owner_uid != self.owner_uid {
                return Err("recovery state belongs to another user".into());
            }
            if let Some(saved) = state.xray {
                if ProcessIdentity::from_pid(saved.pid).is_ok_and(|live| saved.matches(&live)) {
                    resources.insert(Resource::XrayProcess(saved));
                }
            }
            resources.insert(Resource::RuntimeFile(self.state_path.clone()));
        }
        if PathBuf::from("/sys/class/net/varmlen0").exists() {
            resources.insert(Resource::TunInterface("varmlen0".into()));
        }
        let rules = Command::new("ip")
            .args(["rule", "show"])
            .output()
            .await
            .map_err(|error| format!("inspect policy rules: {error}"))?;
        let rules_text = String::from_utf8_lossy(&rules.stdout);
        let routes_v4 = Command::new("ip")
            .args(["route", "show"])
            .output()
            .await
            .map_err(|error| format!("inspect IPv4 routes: {error}"))?;
        let routes_v6 = Command::new("ip")
            .args(["-6", "route", "show"])
            .output()
            .await
            .map_err(|error| format!("inspect IPv6 routes: {error}"))?;
        let routes_text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&routes_v4.stdout),
            String::from_utf8_lossy(&routes_v6.stdout)
        );
        resources.extend(route_resources(&rules_text, &routes_text));
        for table in [
            "varmlen_dns",
            "varmlen_split_dns",
            "varmlen_split",
            "varmlen_ks",
        ] {
            if Self::nft_table_exists(table).await {
                resources.insert(Resource::NftTable(table.into()));
            }
        }
        let split_cgroup = PathBuf::from(format!(
            "/sys/fs/cgroup/varmlen/user-{}/bypass",
            self.owner_uid
        ));
        if split_cgroup.exists() {
            resources.insert(Resource::SplitBpf(split_cgroup));
        }
        Ok(resources)
    }

    async fn remove(&mut self, resource: &Resource) -> Result<(), String> {
        match resource {
            Resource::XrayProcess(saved) => terminate_process(saved).await,
            Resource::TunInterface(interface) if interface == "varmlen0" => {
                command_success("ip", &["link", "delete", "dev", interface]).await
            }
            Resource::RouteTable(table) if matches!(table.as_str(), "100" | "101") => {
                if table == "100" {
                    let _ = command_success("/usr/libexec/varmlen/varmlen-net", &["cleanup"]).await;
                }
                let marks: &[&str] = if table == "100" {
                    &["0x2024", "0x2025"]
                } else {
                    &["0x2023"]
                };
                for mark in marks {
                    for family in ["-4", "-6"] {
                        for _ in 0..4 {
                            if command_success(
                                "ip",
                                &[family, "rule", "del", "fwmark", mark, "lookup", table],
                            )
                            .await
                            .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                command_success("ip", &["route", "flush", "table", table]).await
            }
            Resource::NftTable(table)
                if matches!(
                    table.as_str(),
                    "varmlen_dns" | "varmlen_split_dns" | "varmlen_split" | "varmlen_ks"
                ) =>
            {
                command_success("nft", &["delete", "table", "inet", table]).await
            }
            Resource::SplitBpf(path)
                if path
                    == &PathBuf::from(format!(
                        "/sys/fs/cgroup/varmlen/user-{}/bypass",
                        self.owner_uid
                    )) =>
            {
                cleanup_split_cgroup(path)
            }
            Resource::RuntimeFile(path) if path == &self.state_path => {
                std::fs::remove_file(path).map_err(|error| format!("remove state: {error}"))
            }
            _ => Err("refusing to remove an unrecognized recovery resource".into()),
        }
    }
}

async fn terminate_process(saved: &ProcessIdentity) -> Result<(), String> {
    let live = ProcessIdentity::from_pid(saved.pid)?;
    if !saved.matches(&live) {
        return Err("refusing to terminate a reused PID".into());
    }
    unsafe {
        libc::kill(saved.pid as libc::pid_t, libc::SIGTERM);
    }
    for _ in 0..20 {
        if ProcessIdentity::from_pid(saved.pid).is_err() {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    let live = ProcessIdentity::from_pid(saved.pid)?;
    if !saved.matches(&live) {
        return Err("refusing to kill a reused PID".into());
    }
    if unsafe { libc::kill(saved.pid as libc::pid_t, libc::SIGKILL) } != 0 {
        return Err(format!(
            "kill stale Xray: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn cleanup_split_cgroup(path: &std::path::Path) -> Result<(), String> {
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("open split cgroup: {error}"))?;
    let _ = detach_socket_mark(&directory);
    let parent_procs = path
        .parent()
        .ok_or("split cgroup has no parent")?
        .join("cgroup.procs");
    let pids = std::fs::read_to_string(path.join("cgroup.procs"))
        .map_err(|error| format!("read split processes: {error}"))?;
    for pid in pids.lines().filter(|line| !line.is_empty()) {
        std::fs::write(&parent_procs, pid)
            .map_err(|error| format!("restore split process: {error}"))?;
    }
    std::fs::remove_dir(path).map_err(|error| format!("remove split cgroup: {error}"))
}

async fn command_success(program: &str, arguments: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .await
        .map_err(|error| format!("{program}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

impl<B: CleanupBackend> RecoveryManager<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub async fn cleanup(&mut self) -> Result<CleanupReport, String> {
        let before = self.backend.inspect().await?;
        for resource in &before {
            let _ = self.backend.remove(resource).await;
        }
        let remaining = self.backend.inspect().await?;
        let removed = before.difference(&remaining).cloned().collect();
        Ok(CleanupReport { removed, remaining })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use async_trait::async_trait;

    use super::{
        parse_start_time_ticks, route_resources, CleanupBackend, ProcessIdentity, RecoveryManager,
        Resource,
    };
    use crate::protocol::ConnectionPhase;

    #[test]
    fn pid_reuse_does_not_match_unrelated_process() {
        let saved = ProcessIdentity::new(42, 100, "/usr/libexec/varmlen/xray");
        let reused = ProcessIdentity::new(42, 101, "/usr/bin/unrelated");
        assert!(!saved.matches(&reused));
        assert!(saved.matches(&ProcessIdentity::new(42, 100, "/usr/libexec/varmlen/xray")));
    }

    #[test]
    fn proc_stat_parser_handles_spaces_inside_comm() {
        let stat = "42 (Xray worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98765 21";
        assert_eq!(parse_start_time_ticks(stat), Some(98765));
        assert_eq!(parse_start_time_ticks("broken"), None);
    }

    #[test]
    fn dns_policy_route_is_recovered_independently() {
        let resources = route_resources(
            "90: from all fwmark 0x2023 lookup 101",
            "default dev varmlen0 table 101",
        );
        assert_eq!(
            resources,
            BTreeSet::from([Resource::RouteTable("101".into())])
        );
    }

    struct FakeCleanup {
        resources: BTreeSet<Resource>,
        stubborn: Option<Resource>,
    }

    #[async_trait]
    impl CleanupBackend for FakeCleanup {
        async fn inspect(&mut self) -> Result<BTreeSet<Resource>, String> {
            Ok(self.resources.clone())
        }

        async fn remove(&mut self, resource: &Resource) -> Result<(), String> {
            if self.stubborn.as_ref() != Some(resource) {
                self.resources.remove(resource);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn remaining_kernel_state_reports_recovery_required() {
        let backend = FakeCleanup {
            resources: BTreeSet::from([Resource::NftTable("varmlen_dns".into())]),
            stubborn: Some(Resource::NftTable("varmlen_dns".into())),
        };
        let mut manager = RecoveryManager::new(backend);
        let report = manager.cleanup().await.unwrap();
        assert_eq!(
            report.remaining,
            BTreeSet::from([Resource::NftTable("varmlen_dns".into())])
        );
        assert_eq!(report.phase(), ConnectionPhase::RecoveryRequired);
    }

    #[tokio::test]
    async fn verified_empty_state_reports_disconnected() {
        let backend = FakeCleanup {
            resources: BTreeSet::from([
                Resource::TunInterface("varmlen0".into()),
                Resource::RuntimeFile(PathBuf::from("/run/varmlen/stale")),
            ]),
            stubborn: None,
        };
        let mut manager = RecoveryManager::new(backend);
        let report = manager.cleanup().await.unwrap();
        assert!(report.remaining.is_empty());
        assert_eq!(report.phase(), ConnectionPhase::Disconnected);
    }
}
