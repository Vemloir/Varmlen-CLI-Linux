use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::process::real_uid;
use super::SplitError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedComponent(String);

impl ValidatedComponent {
    pub fn new(value: &str) -> Result<Self, SplitError> {
        if value.is_empty()
            || value == "."
            || value == ".."
            || value.len() > 128
            || value.contains('/')
            || value.contains('\\')
            || value.contains('\0')
        {
            return Err(SplitError::InvalidApplication(value.to_string()));
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn bypass_cgroup_path(uid: u32) -> PathBuf {
    PathBuf::from("/sys/fs/cgroup/varmlen")
        .join(format!("user-{uid}"))
        .join("bypass")
}

pub struct BypassCgroup {
    owner_uid: u32,
    path: PathBuf,
    directory: File,
}

impl BypassCgroup {
    pub fn create(owner_uid: u32) -> Result<Self, SplitError> {
        if owner_uid == 0 || !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            return Err(SplitError::CgroupUnavailable);
        }
        let root = Path::new("/sys/fs/cgroup/varmlen");
        let user = root.join(format!("user-{owner_uid}"));
        let bypass = user.join("bypass");
        for path in [root, user.as_path(), bypass.as_path()] {
            create_real_directory(path)?;
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&bypass)
            .map_err(|_| SplitError::CgroupUnavailable)?;
        verify_cgroup2(&directory)?;
        Ok(Self {
            owner_uid,
            path: bypass,
            directory,
        })
    }

    pub fn directory(&self) -> &File {
        &self.directory
    }

    pub fn relative_path(&self) -> String {
        self.path
            .strip_prefix("/sys/fs/cgroup")
            .expect("daemon-derived cgroup path")
            .to_string_lossy()
            .trim_start_matches('/')
            .to_string()
    }

    pub fn procs_path(&self) -> PathBuf {
        self.path.join("cgroup.procs")
    }

    pub fn move_pid(&self, pid: u32) -> Result<(), SplitError> {
        self.move_pid_to(&self.procs_path(), pid)
    }

    /// Whether a process is already held by the bypass cgroup.
    pub fn contains_pid(&self, pid: u32) -> bool {
        crate::split::process::cgroup(pid).ok().is_some_and(|path| {
            let path = path.trim_start_matches('/');
            path == self.relative_path().trim_start_matches('/')
        })
    }

    /// The PIDs currently held by the bypass cgroup.
    pub fn member_pids(&self) -> Vec<u32> {
        std::fs::read_to_string(self.procs_path())
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect()
    }

    /// Put a process back on the tunneled path.
    ///
    /// Processes land in a leaf of our own rather than being handed back to
    /// whatever systemd scope they came from: only membership of the bypass
    /// cgroup decides whether a socket is marked, so any other cgroup means
    /// "through the tunnel", and rewriting a sandbox's own scope would leave
    /// systemd tracking a process that is no longer there.
    pub fn move_out(&self, pid: u32) -> Result<(), SplitError> {
        let tunneled = self.path.parent().unwrap_or(&self.path).join("tunneled");
        create_real_directory(&tunneled)?;
        self.move_pid_to(&tunneled.join("cgroup.procs"), pid)
    }

    fn move_pid_to(&self, procs_path: &Path, pid: u32) -> Result<(), SplitError> {
        if real_uid(pid)? != self.owner_uid {
            return Err(SplitError::ReconciliationFailed);
        }
        let mut procs = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(procs_path)
            .map_err(|_| SplitError::ReconciliationFailed)?;
        procs
            .write_all(pid.to_string().as_bytes())
            .map_err(|_| SplitError::ReconciliationFailed)
    }
}

fn create_real_directory(path: &Path) -> Result<(), SplitError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(SplitError::CgroupUnavailable),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path).map_err(|_| SplitError::CgroupUnavailable)
        }
        Err(_) => Err(SplitError::CgroupUnavailable),
    }
}

fn verify_cgroup2(directory: &File) -> Result<(), SplitError> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let result = unsafe {
        libc::fstatfs(
            std::os::fd::AsRawFd::as_raw_fd(directory),
            stats.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(SplitError::CgroupUnavailable);
    }
    let stats = unsafe { stats.assume_init() };
    // statfs::f_type is signed under glibc and unsigned under musl, so the
    // comparison is made in one width rather than relying on the libc's choice.
    const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
    if stats.f_type as u64 != CGROUP2_SUPER_MAGIC {
        return Err(SplitError::CgroupUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{bypass_cgroup_path, ValidatedComponent};

    #[test]
    fn component_rejects_parent_separator_and_empty_values() {
        assert!(ValidatedComponent::new("..").is_err());
        assert!(ValidatedComponent::new(".").is_err());
        assert!(ValidatedComponent::new("steam/../system.slice").is_err());
        assert!(ValidatedComponent::new("/system.slice").is_err());
        assert!(ValidatedComponent::new("").is_err());
        assert!(ValidatedComponent::new("user-1000").is_ok());
    }

    #[test]
    fn bypass_path_is_derived_only_from_numeric_uid() {
        assert_eq!(
            bypass_cgroup_path(1000).to_string_lossy(),
            "/sys/fs/cgroup/varmlen/user-1000/bypass"
        );
    }
}
