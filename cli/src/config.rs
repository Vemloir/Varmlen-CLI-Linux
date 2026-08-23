//! On-disk CLI state.
//!
//! The GUI keeps locations and settings in WebKit localStorage, which a
//! headless client cannot read, so the CLI owns its own store. It holds proxy
//! credentials (UUIDs, passwords, Reality keys), so the file is created 0600
//! and the directory 0700.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use varmlen_core::split::SplitInput;
use varmlen_core::subscription::VlessServer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub url: String,
    #[serde(default)]
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// "tun" (system-wide) or "proxy" (local SOCKS only).
    pub mode: String,
    pub killswitch: bool,
    pub allow_lan: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: "tun".to_string(),
            killswitch: false,
            allow_lan: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub servers: Vec<VlessServer>,
    pub subscriptions: Vec<Subscription>,
    /// Label of the location `connect` uses when none is named.
    pub active: Option<String>,
    pub split: SplitInput,
    pub settings: Settings,
}

pub fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        })
        .join("varmlen")
}

pub fn config_path() -> PathBuf {
    config_dir().join("cli.json")
}

impl Config {
    pub fn load() -> io::Result<Self> {
        match fs::read(config_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error),
        }
    }

    /// Write atomically: a crash mid-write must not leave a truncated store
    /// that would silently lose every configured location.
    pub fn save(&self) -> io::Result<()> {
        let dir = config_dir();
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;

        let path = config_path();
        let temporary = path.with_extension("json.tmp");
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        bytes.push(b'\n');
        fs::write(&temporary, &bytes)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        fs::rename(&temporary, &path)
    }

    /// Find a location by exact label, then by case-insensitive prefix, so
    /// `connect nether` works for "Netherlands 01" while an exact name always
    /// wins over a prefix that would otherwise be ambiguous.
    pub fn find(&self, name: &str) -> Result<&VlessServer, String> {
        if let Some(server) = self.servers.iter().find(|server| server.label == name) {
            return Ok(server);
        }
        let needle = name.to_lowercase();
        let matches: Vec<&VlessServer> = self
            .servers
            .iter()
            .filter(|server| server.label.to_lowercase().starts_with(&needle))
            .collect();
        match matches.as_slice() {
            [server] => Ok(server),
            [] => Err(format!("no location matches {name:?}")),
            many => Err(format!(
                "{name:?} is ambiguous between: {}",
                many.iter()
                    .map(|server| server.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    /// The location `connect` should use with no argument.
    pub fn active_server(&self) -> Result<&VlessServer, String> {
        match &self.active {
            Some(label) => self.find(label),
            None => match self.servers.as_slice() {
                [server] => Ok(server),
                [] => Err("no locations configured; add one with `varmlen-cli add <uri>`".into()),
                _ => Err("no active location; pick one with `varmlen-cli use <name>`".into()),
            },
        }
    }
}
