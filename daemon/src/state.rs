use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::protocol::ConnectionPhase;
use crate::recovery::ProcessIdentity;

const STATE_VERSION: u16 = 1;
const MAX_STATE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedState {
    pub version: u16,
    pub owner_uid: u32,
    pub phase: ConnectionPhase,
    pub xray: Option<ProcessIdentity>,
}

impl PersistedState {
    pub fn new(owner_uid: u32, phase: ConnectionPhase) -> Self {
        Self {
            version: STATE_VERSION,
            owner_uid,
            phase,
            xray: None,
        }
    }
}

pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn read(&self) -> io::Result<Option<PersistedState>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if file.metadata()?.len() > MAX_STATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varmlen state file is too large",
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Varmlen state file is too large",
            ));
        }
        let state: PersistedState = serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if state.version != STATE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported Varmlen state version",
            ));
        }
        Ok(Some(state))
    }

    pub fn write(&self, state: &PersistedState) -> io::Result<()> {
        if state.version != STATE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported Varmlen state version",
            ));
        }
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "state destination must not be a symlink",
            ));
        }
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "state path has no parent")
        })?;
        let temporary = temporary_path(parent);
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            let bytes = serde_json::to_vec(state)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

fn temporary_path(parent: &Path) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    parent.join(format!(
        ".state-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::{PersistedState, StateStore};
    use crate::protocol::ConnectionPhase;

    #[test]
    fn state_round_trip_is_atomic_and_versioned() {
        let directory = tempdir().unwrap();
        let store = StateStore::new(directory.path().join("state.json"));
        let state = PersistedState::new(1000, ConnectionPhase::Connected);
        store.write(&state).unwrap();
        assert_eq!(store.read().unwrap(), Some(state));
        assert!(!directory.path().join("state.json.tmp").exists());
    }

    #[test]
    fn state_store_refuses_symlink_destination() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, b"do not touch").unwrap();
        let state_path = directory.path().join("state.json");
        symlink(&target, &state_path).unwrap();
        let store = StateStore::new(state_path);
        assert!(store
            .write(&PersistedState::new(1000, ConnectionPhase::Disconnected))
            .is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not touch");
    }
}
