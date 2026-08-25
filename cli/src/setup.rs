//! Getting the daemon onto the system the first time it is needed.
//!
//! The CLI installs without root: it lands in ~/.local/bin and stages the
//! daemon, the helper and xray under ~/.local/share/varmlen/stage. None of that
//! can serve a tunnel — the daemon must run as root, and it refuses to execute
//! components that are not root-owned and unwritable by anyone else
//! (`ensure_trusted_binary`). So the staged copies are moved into
//! /opt/varmlen-cli the first time a command actually needs the daemon,
//! which is the first moment root is genuinely required.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

/// Deliberately not /usr/libexec/varmlen: that belongs to the distribution
/// package of the desktop client, and two installers writing the same files
/// would each silently undo the other. /opt is where FHS puts add-on software
/// and exists on every distribution.
pub const SYSTEM_DIR: &str = "/opt/varmlen-cli";
pub const UNIT_PATH: &str = "/etc/systemd/system/varmlen-cli@.service";
const COMPONENTS: [&str; 3] = ["varmlend", "varmlen-net", "xray"];

pub fn stage_dir() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
        })
        .join("varmlen/stage")
}

/// Whether the daemon is already on the system. Says nothing about it running.
fn installed() -> bool {
    COMPONENTS
        .iter()
        .all(|name| Path::new(SYSTEM_DIR).join(name).is_file())
        && Path::new(UNIT_PATH).is_file()
}

/// Elevate and install, then wait for the daemon to answer.
///
/// Runs `sudo` against this same binary rather than shipping a separate
/// privileged helper: there is then only one artefact to trust, and what root
/// runs is the executable the user already invoked.
pub fn elevate_and_install(socket_ready: impl Fn() -> bool) -> Result<()> {
    let stage = stage_dir();
    for name in COMPONENTS {
        if !stage.join(name).is_file() {
            bail!(
                "the daemon is not installed and {} is missing — reinstall with:\n  \
                 curl -fsSL https://aegisvpn.org/varmlen-cli-linux/install.sh | sh",
                stage.join(name).display()
            );
        }
    }

    let executable = std::env::current_exe().context("locating this executable")?;
    let uid = unsafe { libc::getuid() };

    // Reinstalling is harmless and re-enables the unit, so the same path
    // handles a daemon that was never installed and one that is simply not
    // running. Only the explanation differs.
    eprintln!(
        "{}",
        if installed() {
            "The Varmlen daemon is installed but not running. Starting it needs sudo:"
        } else {
            "The Varmlen daemon is not installed yet. It runs as root, so this needs sudo:"
        }
    );
    eprintln!(
        "  sudo {} __install-daemon --stage {} --owner-uid {uid}",
        executable.display(),
        stage.display()
    );

    let status = Command::new("sudo")
        .arg(&executable)
        .arg("__install-daemon")
        .arg("--stage")
        .arg(&stage)
        .arg("--owner-uid")
        .arg(uid.to_string())
        .status()
        .context("running sudo — install it, or run this command as root")?;
    if !status.success() {
        bail!("installing the daemon failed");
    }

    // systemd returns as soon as the unit is started; the socket appears a
    // moment later, once the daemon has finished its own startup recovery.
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if socket_ready() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    bail!("the daemon was installed but never opened its socket; check `systemctl status varmlen-cli@{uid}`")
}

/// The privileged half. Only ever invoked by `elevate_and_install` through
/// sudo, which is why it is hidden from the command list.
pub fn install_as_root(stage: &Path, owner_uid: u32) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("__install-daemon must run as root");
    }
    if owner_uid == 0 {
        bail!("refusing to install for uid 0");
    }

    std::fs::create_dir_all(SYSTEM_DIR)
        .with_context(|| format!("creating {SYSTEM_DIR}"))?;
    set_mode(Path::new(SYSTEM_DIR), 0o755)?;

    for name in COMPONENTS {
        let source = stage.join(name);
        let target = PathBuf::from(SYSTEM_DIR).join(name);
        // Replace rather than overwrite: a running daemon keeps the inode it
        // started from, so nothing is pulled out from under it mid-connection.
        let temporary = target.with_extension("new");
        std::fs::copy(&source, &temporary)
            .with_context(|| format!("copying {} to {}", source.display(), temporary.display()))?;
        set_owner_root(&temporary)?;
        // The daemon rejects components that are group- or world-writable.
        set_mode(&temporary, 0o755)?;
        std::fs::rename(&temporary, &target)
            .with_context(|| format!("installing {}", target.display()))?;
    }

    let unit = stage.join("varmlen-cli@.service");
    std::fs::copy(&unit, UNIT_PATH).with_context(|| format!("installing {UNIT_PATH}"))?;
    set_owner_root(Path::new(UNIT_PATH))?;
    set_mode(Path::new(UNIT_PATH), 0o644)?;

    run("systemctl", &["daemon-reload".into()])?;
    run(
        "systemctl",
        &[
            "enable".into(),
            "--now".into(),
            format!("varmlen-cli@{owner_uid}"),
        ],
    )?;
    Ok(())
}

fn set_owner_root(path: &Path) -> Result<()> {
    std::os::unix::fs::chown(path, Some(0), Some(0))
        .with_context(|| format!("setting root ownership on {}", path.display()))
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode on {}", path.display()))
}

fn run(program: &str, args: &[String]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("running {program}"))?;
    if !status.success() {
        bail!("{program} {} failed", args.join(" "));
    }
    Ok(())
}
