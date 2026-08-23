use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{chown, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::{
    sync::Semaphore,
    time::{sleep, Duration},
};
use varmlend::controller::SystemController;
use varmlend::protocol::ConnectionPhase;
use varmlend::recovery::{RecoveryManager, SystemCleanupBackend};
use varmlend::server::{
    parse_owner_uid, serve_connection, CommandHandler, PeerPolicy, MAX_CONCURRENT_CLIENTS,
};
use varmlend::state::{PersistedState, StateStore};

fn runtime_paths(uid: u32) -> (PathBuf, PathBuf) {
    let root = PathBuf::from("/run/varmlen");
    (
        root.join(format!("daemon-{uid}.sock")),
        root.join("daemon.lock"),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("varmlend must run as root".into());
    }
    let owner_uid = parse_owner_uid(std::env::var("PKEXEC_UID").ok().as_deref())?;
    let (socket_path, lock_path) = runtime_paths(owner_uid);

    fs::create_dir_all("/run/varmlen")?;
    fs::set_permissions("/run/varmlen", fs::Permissions::from_mode(0o711))?;
    fs::create_dir_all("/var/lib/varmlen")?;
    fs::set_permissions("/var/lib/varmlen", fs::Permissions::from_mode(0o700))?;

    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another Varmlen daemon already owns the network".into());
    }

    if socket_path.exists() {
        fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    chown(&socket_path, Some(owner_uid), Some(owner_uid))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

    let state_path = PathBuf::from(format!("/var/lib/varmlen/state-{owner_uid}.json"));
    let mut recovery =
        RecoveryManager::new(SystemCleanupBackend::new(owner_uid, state_path.clone()));
    let phase = recovery
        .cleanup()
        .await
        .map(|report| report.phase())
        .unwrap_or(ConnectionPhase::RecoveryRequired);
    StateStore::new(state_path.clone()).write(&PersistedState::new(owner_uid, phase))?;
    let controller = Arc::new(SystemController::new(owner_uid, phase, state_path));
    let monitor = Arc::clone(&controller);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(1)).await;
            let _ = monitor.poll_health().await;
        }
    });
    let handler: Arc<dyn CommandHandler> = controller;

    let policy = PeerPolicy::new(owner_uid);
    let client_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(slot) = Arc::clone(&client_slots).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let _slot = slot;
            let _ = serve_connection(stream, policy, handler).await;
        });
    }
}
