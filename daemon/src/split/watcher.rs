use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
};

use crate::split::process::{real_uid, snapshot, AppSelector, ProcessSnapshot};
use crate::split::SplitError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionDecision {
    Allow,
    MoveAndAllow,
    Deny,
}

pub fn permission_decision(
    process_uid: u32,
    owner_uid: u32,
    target: &Path,
    process: &ProcessSnapshot,
    selectors: &[AppSelector],
    move_succeeded: bool,
) -> PermissionDecision {
    if process_uid != owner_uid
        || !selectors
            .iter()
            .any(|selector| selector.matches_target(target) || selector.matches(process))
    {
        return PermissionDecision::Allow;
    }
    if move_succeeded {
        PermissionDecision::MoveAndAllow
    } else {
        PermissionDecision::Deny
    }
}

pub struct PermissionWatcher {
    stop: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl PermissionWatcher {
    pub fn start(
        owner_uid: u32,
        selectors: Vec<AppSelector>,
        cgroup_procs: PathBuf,
    ) -> Result<Self, SplitError> {
        let fanotify = Fanotify::init(
            InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_CLOEXEC | InitFlags::FAN_NONBLOCK,
            EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC,
        )
        .map_err(|_| SplitError::WatcherUnavailable)?;
        install_marks(&fanotify, &selectors)?;

        let stop = Arc::new(AtomicBool::new(false));
        let healthy = Arc::new(AtomicBool::new(true));
        let thread_stop = Arc::clone(&stop);
        let thread_healthy = Arc::clone(&healthy);
        let thread = thread::Builder::new()
            .name("varmlen-split-permission".into())
            .spawn(move || {
                run_permission_loop(
                    fanotify,
                    owner_uid,
                    selectors,
                    cgroup_procs,
                    &thread_stop,
                    &thread_healthy,
                );
            })
            .map_err(|_| SplitError::WatcherUnavailable)?;
        Ok(Self {
            stop,
            healthy,
            thread: Some(thread),
        })
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
            && self
                .thread
                .as_ref()
                .is_some_and(|thread| !thread.is_finished())
    }
}

impl Drop for PermissionWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn install_marks(fanotify: &Fanotify, selectors: &[AppSelector]) -> Result<(), SplitError> {
    let root = File::open("/").map_err(|_| SplitError::WatcherUnavailable)?;
    let has_names = selectors
        .iter()
        .any(|selector| matches!(selector, AppSelector::ProcessName(_)));
    if has_names {
        let mut marked = 0_usize;
        for mount in executable_mount_points() {
            if fanotify
                .mark(
                    MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
                    MaskFlags::FAN_OPEN_EXEC_PERM,
                    &root,
                    Some(mount.as_path()),
                )
                .is_ok()
            {
                marked += 1;
            }
        }
        if marked == 0 {
            return Err(SplitError::WatcherUnavailable);
        }
    }
    for selector in selectors {
        let AppSelector::ExactPath(path) = selector else {
            continue;
        };
        let canonical = std::fs::canonicalize(path)
            .map_err(|_| SplitError::InvalidApplication(path.display().to_string()))?;
        let mask = if is_portable_executable(&canonical) {
            MaskFlags::FAN_OPEN_PERM | MaskFlags::FAN_OPEN_EXEC_PERM
        } else {
            MaskFlags::FAN_OPEN_EXEC_PERM
        };
        fanotify
            .mark(
                MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_DONT_FOLLOW,
                mask,
                &root,
                Some(canonical.as_path()),
            )
            .map_err(|_| SplitError::WatcherUnavailable)?;
    }
    Ok(())
}

fn executable_mount_points() -> Vec<PathBuf> {
    let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return vec![PathBuf::from("/")];
    };
    mountinfo
        .lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let fields: Vec<&str> = left.split_whitespace().collect();
            let fs_type = right.split_whitespace().next()?;
            if fields.len() < 6
                || fields[5].split(',').any(|option| option == "noexec")
                || matches!(
                    fs_type,
                    "proc"
                        | "sysfs"
                        | "cgroup2"
                        | "devpts"
                        | "mqueue"
                        | "securityfs"
                        | "debugfs"
                        | "tracefs"
                )
            {
                return None;
            }
            Some(PathBuf::from(fields[4].replace("\\040", " ")))
        })
        .collect()
}

fn is_portable_executable(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut magic = [0_u8; 2];
    file.read_exact(&mut magic).is_ok() && magic == *b"MZ"
}

fn run_permission_loop(
    fanotify: Fanotify,
    owner_uid: u32,
    selectors: Vec<AppSelector>,
    cgroup_procs: PathBuf,
    stop: &AtomicBool,
    healthy: &AtomicBool,
) {
    while !stop.load(Ordering::Acquire) {
        match fanotify.read_events() {
            Ok(events) => {
                for event in events {
                    if !event.check_version() {
                        healthy.store(false, Ordering::Release);
                        return;
                    }
                    let Some(fd) = event.fd() else {
                        healthy.store(false, Ordering::Release);
                        continue;
                    };
                    let pid = match u32::try_from(event.pid()) {
                        Ok(pid) => pid,
                        Err(_) => {
                            let _ = fanotify
                                .write_response(FanotifyResponse::new(fd, Response::FAN_ALLOW));
                            continue;
                        }
                    };
                    let target = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                        .unwrap_or_default();
                    let process_uid = real_uid(pid).unwrap_or(u32::MAX);
                    let process = snapshot(pid).unwrap_or(ProcessSnapshot {
                        comm: String::new(),
                        executable: PathBuf::new(),
                        argument_zero: String::new(),
                    });
                    let is_match = process_uid == owner_uid
                        && selectors.iter().any(|selector| {
                            selector.matches_target(&target) || selector.matches(&process)
                        });
                    let moved = !is_match || std::fs::write(&cgroup_procs, pid.to_string()).is_ok();
                    let decision = permission_decision(
                        process_uid,
                        owner_uid,
                        &target,
                        &process,
                        &selectors,
                        moved,
                    );
                    let response = match decision {
                        PermissionDecision::Allow | PermissionDecision::MoveAndAllow => {
                            Response::FAN_ALLOW
                        }
                        PermissionDecision::Deny => {
                            healthy.store(false, Ordering::Release);
                            Response::FAN_DENY
                        }
                    };
                    if fanotify
                        .write_response(FanotifyResponse::new(fd, response))
                        .is_err()
                    {
                        healthy.store(false, Ordering::Release);
                        return;
                    }
                }
            }
            Err(Errno::EAGAIN) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                healthy.store(false, Ordering::Release);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{permission_decision, PermissionDecision};
    use crate::split::process::{AppSelector, ProcessSnapshot};

    fn process() -> ProcessSnapshot {
        ProcessSnapshot {
            comm: "cs2".into(),
            executable: PathBuf::from("/games/cs2"),
            argument_zero: "/games/cs2".into(),
        }
    }

    #[test]
    fn matching_owner_is_moved_before_permission_is_allowed() {
        let selectors = vec![AppSelector::parse("/games/cs2").unwrap()];
        assert_eq!(
            permission_decision(
                1000,
                1000,
                &PathBuf::from("/games/cs2"),
                &process(),
                &selectors,
                true,
            ),
            PermissionDecision::MoveAndAllow
        );
    }

    #[test]
    fn failed_move_denies_matching_exec_instead_of_leaking() {
        let selectors = vec![AppSelector::parse("/games/cs2").unwrap()];
        assert_eq!(
            permission_decision(
                1000,
                1000,
                &PathBuf::from("/games/cs2"),
                &process(),
                &selectors,
                false,
            ),
            PermissionDecision::Deny
        );
    }

    #[test]
    fn another_users_process_is_never_moved() {
        let selectors = vec![AppSelector::parse("/games/cs2").unwrap()];
        assert_eq!(
            permission_decision(
                1001,
                1000,
                &PathBuf::from("/games/cs2"),
                &process(),
                &selectors,
                true,
            ),
            PermissionDecision::Allow
        );
    }

    #[test]
    fn exec_target_matches_before_launcher_image_is_replaced() {
        let selectors = vec![AppSelector::parse("cs2").unwrap()];
        let launcher = ProcessSnapshot {
            comm: "steam".into(),
            executable: PathBuf::from("/usr/bin/steam"),
            argument_zero: "steam".into(),
        };
        assert_eq!(
            permission_decision(
                1000,
                1000,
                &PathBuf::from("/games/CounterStrike/cs2"),
                &launcher,
                &selectors,
                true,
            ),
            PermissionDecision::MoveAndAllow
        );
    }
}
