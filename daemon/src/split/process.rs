use std::path::{Path, PathBuf};

use super::SplitError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppSelector {
    ExactPath(PathBuf),
    ProcessName(String),
}

impl AppSelector {
    pub fn parse(value: &str) -> Result<Self, SplitError> {
        let value = value.trim();
        if value.is_empty() || value.len() > 4096 || value.contains('\0') {
            return Err(SplitError::InvalidApplication(value.to_string()));
        }
        let path = Path::new(value);
        if path.is_absolute() {
            return Ok(Self::ExactPath(path.to_path_buf()));
        }
        if value.contains('/') || value.contains('\\') {
            return Err(SplitError::InvalidApplication(value.to_string()));
        }
        Ok(Self::ProcessName(value.to_string()))
    }

    pub fn matches(&self, process: &ProcessSnapshot) -> bool {
        match self {
            Self::ExactPath(path) => process.executable == *path,
            Self::ProcessName(name) => {
                let executable_name = process
                    .executable
                    .file_name()
                    .and_then(|part| part.to_str())
                    .unwrap_or_default();
                let argument_name = process
                    .argument_zero
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or_default();
                process.comm.eq_ignore_ascii_case(name)
                    || executable_name.eq_ignore_ascii_case(name)
                    || argument_name.eq_ignore_ascii_case(name)
            }
        }
    }

    pub fn matches_target(&self, target: &Path) -> bool {
        match self {
            Self::ExactPath(path) => path == target,
            Self::ProcessName(name) => target
                .file_name()
                .and_then(|part| part.to_str())
                .is_some_and(|part| part.eq_ignore_ascii_case(name)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub comm: String,
    pub executable: PathBuf,
    pub argument_zero: String,
}

pub fn parse_real_uid(status: &str) -> Option<u32> {
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

pub fn snapshot(pid: u32) -> Result<ProcessSnapshot, SplitError> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map_err(|_| SplitError::ReconciliationFailed)?;
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|_| SplitError::ReconciliationFailed)?;
    let command_line = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map_err(|_| SplitError::ReconciliationFailed)?;
    let argument_zero = command_line
        .split(|byte| *byte == 0)
        .next()
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default();
    Ok(ProcessSnapshot {
        comm: comm.trim().to_string(),
        executable,
        argument_zero,
    })
}

pub fn real_uid(pid: u32) -> Result<u32, SplitError> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| SplitError::ReconciliationFailed)?;
    parse_real_uid(&status).ok_or(SplitError::ReconciliationFailed)
}

pub fn fd_number(value: &str) -> Option<i32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

pub fn is_transient_fd_error(code: Option<i32>) -> bool {
    matches!(
        code,
        Some(libc::EBADF) | Some(libc::ENOENT) | Some(libc::ESRCH)
    )
}

pub fn mark_existing_sockets(pid: u32, mark: u32) -> Result<usize, SplitError> {
    let pidfd =
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0_u32) as libc::c_int };
    if pidfd < 0 {
        return Err(SplitError::ReconciliationFailed);
    }
    let result = (|| {
        let entries = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .map_err(|_| SplitError::ReconciliationFailed)?;
        let mut marked = 0_usize;
        for entry in entries.flatten() {
            let Some(target_fd) = entry.file_name().to_str().and_then(fd_number) else {
                continue;
            };
            let duplicate = unsafe {
                libc::syscall(libc::SYS_pidfd_getfd, pidfd, target_fd, 0_u32) as libc::c_int
            };
            if duplicate < 0 {
                let error = std::io::Error::last_os_error();
                if is_transient_fd_error(error.raw_os_error()) {
                    continue;
                }
                return Err(SplitError::ReconciliationFailed);
            }
            let mut socket_type = 0_i32;
            let mut socket_type_length = std::mem::size_of::<i32>() as libc::socklen_t;
            let is_socket = unsafe {
                libc::getsockopt(
                    duplicate,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    std::ptr::addr_of_mut!(socket_type).cast(),
                    &mut socket_type_length,
                )
            } == 0;
            if is_socket {
                let set_result = unsafe {
                    libc::setsockopt(
                        duplicate,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        std::ptr::addr_of!(mark).cast(),
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    )
                };
                if set_result != 0 {
                    unsafe {
                        libc::close(duplicate);
                    }
                    return Err(SplitError::ReconciliationFailed);
                }
                marked += 1;
            }
            unsafe {
                libc::close(duplicate);
            }
        }
        Ok(marked)
    })();
    unsafe {
        libc::close(pidfd);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{fd_number, is_transient_fd_error, parse_real_uid, AppSelector, ProcessSnapshot};

    #[test]
    fn parses_real_uid_from_proc_status() {
        let status = "Name:\tcs2\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_real_uid(status), Some(1000));
        assert_eq!(parse_real_uid("Name:\tcs2\n"), None);
    }

    #[test]
    fn exact_native_binary_and_proton_arg0_match() {
        let selector = AppSelector::parse("/games/CounterStrike/cs2").unwrap();
        let native = ProcessSnapshot {
            comm: "cs2".into(),
            executable: PathBuf::from("/games/CounterStrike/cs2"),
            argument_zero: "/games/CounterStrike/cs2".into(),
        };
        assert!(selector.matches(&native));

        let proton_selector = AppSelector::parse("Cyberpunk2077.exe").unwrap();
        let proton = ProcessSnapshot {
            comm: "wine64-preloader".into(),
            executable: PathBuf::from("/usr/bin/wine64-preloader"),
            argument_zero: "Z:\\games\\Cyberpunk2077.exe".into(),
        };
        assert!(proton_selector.matches(&proton));
    }

    #[test]
    fn long_kernel_comm_prefix_is_not_enough_without_matching_name() {
        let selector = AppSelector::parse("Cyberpunk2077.exe").unwrap();
        let unrelated = ProcessSnapshot {
            comm: "Cyberpunk2077.e".into(),
            executable: PathBuf::from("/tmp/unrelated"),
            argument_zero: "/tmp/unrelated".into(),
        };
        assert!(!selector.matches(&unrelated));
    }

    #[test]
    fn only_numeric_proc_fd_names_are_accepted() {
        assert_eq!(fd_number("0"), Some(0));
        assert_eq!(fd_number("1024"), Some(1024));
        assert_eq!(fd_number("../3"), None);
        assert_eq!(fd_number("3x"), None);
    }

    #[test]
    fn only_process_exit_and_fd_races_are_transient() {
        assert!(is_transient_fd_error(Some(libc::EBADF)));
        assert!(is_transient_fd_error(Some(libc::ENOENT)));
        assert!(is_transient_fd_error(Some(libc::ESRCH)));
        assert!(!is_transient_fd_error(Some(libc::EPERM)));
        assert!(!is_transient_fd_error(None));
    }
}
