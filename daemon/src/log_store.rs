use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
pub const MAX_LOG_TAIL_BYTES: usize = 256 * 1024;
const ROTATED_LOGS: usize = 3;

#[derive(Debug, Clone)]
pub struct LogStore {
    path: PathBuf,
}

impl LogStore {
    pub fn for_owner(owner_uid: u32) -> Self {
        Self::new(PathBuf::from(format!("/run/varmlen/xray-{owner_uid}.log")))
    }

    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn append(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let current_len = fs::metadata(&self.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if current_len.saturating_add(bytes.len() as u64) > MAX_LOG_BYTES {
            self.rotate()?;
        }
        let start = bytes.len().saturating_sub(MAX_LOG_BYTES as usize);
        let mut file = self.open_append()?;
        file.write_all(&bytes[start..])?;
        file.flush()
    }

    pub fn tail(&self, max_bytes: usize) -> io::Result<String> {
        let max_bytes = max_bytes.min(MAX_LOG_TAIL_BYTES);
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
            Err(error) => return Err(error),
        };
        let len = file.metadata()?.len();
        let start = len.saturating_sub(max_bytes as u64);
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::with_capacity((len - start) as usize);
        file.read_to_end(&mut bytes)?;
        if start > 0 {
            if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
                bytes.drain(..=newline);
            }
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn clear(&self) -> io::Result<()> {
        for index in 0..=ROTATED_LOGS {
            let path = self.rotated_path(index);
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn open_append(&self) -> io::Result<fs::File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
    }

    fn rotate(&self) -> io::Result<()> {
        let oldest = self.rotated_path(ROTATED_LOGS);
        match fs::remove_file(oldest) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        for index in (1..ROTATED_LOGS).rev() {
            rename_if_exists(&self.rotated_path(index), &self.rotated_path(index + 1))?;
        }
        rename_if_exists(&self.path, &self.rotated_path(1))
    }

    fn rotated_path(&self, index: usize) -> PathBuf {
        if index == 0 {
            return self.path.clone();
        }
        PathBuf::from(format!("{}.{}", self.path.display(), index))
    }
}

fn rename_if_exists(from: &Path, to: &Path) -> io::Result<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{LogStore, MAX_LOG_BYTES, MAX_LOG_TAIL_BYTES};

    #[test]
    fn rotates_large_logs_and_returns_a_bounded_tail() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("xray.log");
        let store = LogStore::new(path.clone());
        store.append(&vec![b'a'; MAX_LOG_BYTES as usize]).unwrap();
        store.append(b"old\nnew line\n").unwrap();

        assert!(path.with_file_name("xray.log.1").is_file());
        assert_eq!(store.tail(MAX_LOG_TAIL_BYTES).unwrap(), "old\nnew line\n");
        assert!(std::fs::metadata(path).unwrap().len() <= MAX_LOG_BYTES);
    }

    #[test]
    fn tail_drops_a_partial_first_line() {
        let directory = tempfile::tempdir().unwrap();
        let store = LogStore::new(directory.path().join("xray.log"));
        store.append(b"first line\nsecond line\n").unwrap();
        assert_eq!(store.tail(17).unwrap(), "second line\n");
        store.clear().unwrap();
        assert_eq!(store.tail(MAX_LOG_TAIL_BYTES).unwrap(), "");
    }
}
