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
                if process.comm.eq_ignore_ascii_case(name)
                    || executable_name.eq_ignore_ascii_case(name)
                    || argument_is_named(&process.argument_zero, name)
                {
                    return true;
                }
                // A Windows rule is the one case where the name is not the
                // process: Proton and Wine exec their loader (`wine64`,
                // `wine64-preloader`) and carry the game as a later argument
                // (`Z:\games\R.E.P.O.\REPO.exe`). Only a `.exe` rule looks
                // further into the command line, and only at whole arguments,
                // so `firefox` can never pick up `ng_firefox` and `REPO.exe`
                // cannot pick up `XREPO.exe`.
                if is_windows_image(name) {
                    return command_words(&process.arguments)
                        .any(|word| argument_is_named(word, name));
                }
                // A rule that reads like an application id matches the sandbox
                // scope that Flatpak, Snap and systemd name every member of
                // the application after, which is the only identity a
                // sandboxed app reliably has: its processes are `sobrun`,
                // `WebCore` and `VulkanAppHost`, and its scope is
                // `app-flatpak-org.vinegarhq.Sober-<pid>.scope`.
                if is_application_id(name) {
                    return process.cgroup_paths_contain(name);
                }
                false
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

/// The words a command line can name a program with.
///
/// Steam launches a Proton game through `/bin/sh -c "… proton … REPO.exe"`, so
/// the name is a word *inside* one argv entry rather than an entry of its own.
fn command_words(arguments: &[String]) -> impl Iterator<Item = &str> {
    arguments
        .iter()
        .flat_map(|argument| std::iter::once(argument.as_str()).chain(argument.split_whitespace()))
}

/// The last component of a Unix or Windows path, compared case-insensitively.
fn argument_is_named(argument: &str, name: &str) -> bool {
    argument
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .eq_ignore_ascii_case(name)
}

/// Whether a rule names a Windows image, which is the signal that it was
/// typed for a game running under Proton or Wine.
fn is_windows_image(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("exe"))
}

/// Whether a rule reads like a Flatpak or Snap application id rather than a
/// program name (`org.vinegarhq.Sober`, `com.valvesoftware.Steam`).
fn is_application_id(name: &str) -> bool {
    name.contains('.') && !name.contains('-')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub comm: String,
    pub executable: PathBuf,
    pub argument_zero: String,
    /// The whole command line, argv[0] first.
    pub arguments: Vec<String>,
    /// The cgroup the process lives in, which is where a sandbox names it.
    pub cgroup: String,
}

impl ProcessSnapshot {
    fn cgroup_paths_contain(&self, id: &str) -> bool {
        self.cgroup
            .rsplit('/')
            .any(|component| component.contains(id))
    }

    pub fn empty() -> Self {
        Self {
            comm: String::new(),
            executable: PathBuf::new(),
            argument_zero: String::new(),
            arguments: Vec::new(),
            cgroup: String::new(),
        }
    }
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
    let arguments = parse_command_line(&command_line);
    Ok(ProcessSnapshot {
        comm: comm.trim().to_string(),
        executable,
        argument_zero: arguments.first().cloned().unwrap_or_default(),
        arguments,
        cgroup: cgroup(pid).unwrap_or_default(),
    })
}

pub fn parse_command_line(command_line: &[u8]) -> Vec<String> {
    command_line
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
        .map(|value| String::from_utf8_lossy(value).to_string())
        .collect()
}

/// The cgroup path of a process, which is where a sandbox such as Flatpak
/// records which application the process belongs to.
pub fn cgroup(pid: u32) -> Result<String, SplitError> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|_| SplitError::ReconciliationFailed)?;
    Ok(cgroup_from_raw(&raw))
}

fn cgroup_from_raw(raw: &str) -> String {
    // v1 lists one line per controller; v2 has the single `0::` line, which is
    // the only hierarchy the split cgroup lives in.
    raw.lines()
        .find_map(|line| {
            let (_, path) = line.split_once("::")?;
            Some(path.to_string())
        })
        .unwrap_or_default()
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

    use super::{
        cgroup_from_raw, fd_number, is_transient_fd_error, parse_real_uid, AppSelector,
        ProcessSnapshot,
    };

    #[test]
    fn parses_real_uid_from_proc_status() {
        let status = "Name:\tcs2\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_real_uid(status), Some(1000));
        assert_eq!(parse_real_uid("Name:\tcs2\n"), None);
    }

    fn process(comm: &str, executable: &str, arguments: &[&str], cgroup: &str) -> ProcessSnapshot {
        ProcessSnapshot {
            comm: comm.into(),
            executable: PathBuf::from(executable),
            argument_zero: arguments.first().copied().unwrap_or_default().into(),
            arguments: arguments.iter().map(|value| value.to_string()).collect(),
            cgroup: cgroup.into(),
        }
    }

    fn matches(rule: &str, snapshot: &ProcessSnapshot) -> bool {
        AppSelector::parse(rule).unwrap().matches(snapshot)
    }

    #[test]
    fn exact_native_binary_and_proton_arg0_match() {
        let selector = AppSelector::parse("/games/CounterStrike/cs2").unwrap();
        let native = process(
            "cs2",
            "/games/CounterStrike/cs2",
            &["/games/CounterStrike/cs2"],
            "/user.slice/app.scope",
        );
        assert!(selector.matches(&native));

        let proton = process(
            "wine64-preloader",
            "/usr/bin/wine64-preloader",
            &["/usr/bin/wine64-preloader", "Z:\\games\\Cyberpunk2077.exe"],
            "/user.slice/app.scope",
        );
        assert!(matches("Cyberpunk2077.exe", &proton));
    }

    #[test]
    fn a_name_rule_never_matches_another_name_that_contains_it() {
        // `firefox` must not capture a different program, however its argv is
        // spelled; only the exact identity counts for a non-Windows rule.
        let other = process(
            "ng_firefox",
            "/usr/bin/ng_firefox",
            &["ng_firefox", "--profile", "firefox"],
            "/user.slice/app.slice/app-ng_firefox.scope",
        );
        assert!(!matches("firefox", &other));
        assert!(matches("ng_firefox", &other));
    }

    #[test]
    fn a_windows_rule_follows_the_game_through_a_launcher_chain() {
        // Steam -> sh -c -> proton -> wine64: the game is a word in someone's
        // arguments, and the socket ends up owned by one of these processes.
        let steam_shell = process(
            "sh",
            "/usr/bin/sh",
            &[
                "/usr/bin/sh",
                "-c",
                "...proton run .../R.E.P.O./REPO.exe -pipeline -nographics",
            ],
            "/user.slice/app.slice/app-steam.scope",
        );
        assert!(matches("REPO.exe", &steam_shell));

        let wine = process(
            "wine64",
            "/usr/bin/wine64",
            &["/usr/bin/wine64", "Z:\\games\\R.E.P.O.\\REPO.exe"],
            "/user.slice/app.slice/app-steam.scope",
        );
        assert!(matches("repo.exe", &wine));

        // A different game, or a substring of the name, stays out.
        let other_game = process(
            "wine64",
            "/usr/bin/wine64",
            &["/usr/bin/wine64", "Z:\\games\\Other\\Other.exe"],
            "/user.slice/app.slice/app-steam.scope",
        );
        assert!(!matches("REPO.exe", &other_game));
        let longer = process(
            "wine64",
            "/usr/bin/wine64",
            &["/usr/bin/wine64", "Z:\\XREPO.exe".into()],
            "/user.slice/app.slice/app-steam.scope",
        );
        assert!(!matches("REPO.exe", &longer));
    }

    #[test]
    fn an_application_id_matches_the_sandbox_scope() {
        let sandboxed = process(
            "sobrun",
            "/home/daniil/.var/app/org.vinegarhq.Sober/data/sober/versions/1/sobrun",
            &["/home/daniil/.var/app/org.vinegarhq.Sober/data/sober/versions/1/sobrun"],
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.vinegarhq.Sober-2094669190.scope",
        );
        assert!(matches("org.vinegarhq.Sober", &sandboxed));
        // The same sandbox must not answer to a different application id.
        assert!(!matches("org.mozilla.Firefox", &sandboxed));
        // And the bare name still matches the process itself.
        assert!(matches("sobrun", &sandboxed));
    }

    #[test]
    fn long_kernel_comm_prefix_is_not_enough_without_matching_name() {
        let unrelated = process(
            "Cyberpunk2077.e",
            "/tmp/unrelated",
            &["/tmp/unrelated"],
            "/user.slice/app.scope",
        );
        assert!(!matches("Cyberpunk2077.exe", &unrelated));
    }

    #[test]
    fn parses_the_v2_cgroup_line_only() {
        let raw = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.vinegarhq.Sober-1.scope\nname=systemd:/foo\n";
        assert!(cgroup_from_raw(raw.trim()).ends_with(".scope"));
        assert_eq!(cgroup_from_raw("name=systemd:/foo"), "");
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
