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
        if real_uid(pid)? != self.owner_uid {
            return Err(SplitError::ReconciliationFailed);
        }
        let mut procs = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.procs_path())
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
    const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
    if stats.f_type != CGROUP2_SUPER_MAGIC {
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
