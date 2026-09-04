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
use varmlen_core::subscription::{SubscriptionMeta, VlessServer};

/// Identity of a location that survives a subscription refresh and does not
/// collide when two providers ship the same display name.
///
/// Deliberately a struct rather than a joined string: display names routinely
/// contain punctuation ("Finland | Helsinki"), so any separator that looks
/// unlikely is one the data will eventually contain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationKey {
    pub label: String,
    pub host: String,
    pub port: u16,
}

/// A label reduced to what a person would type.
///
/// Providers prefix labels with a flag emoji, so anchoring a prefix search at
/// the true start of the string means it never matches anything the user would
/// think to type.
fn searchable(label: &str) -> String {
    label
        .trim_start_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase()
}

pub fn location_key(server: &VlessServer) -> LocationKey {
    LocationKey {
        label: server.label.clone(),
        host: server.host.clone(),
        port: server.port,
    }
}

/// `active` as stored on disk. Pre-0.2 wrote a bare display name; both forms
/// are read, only the structured one is written back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActiveRef {
    Key(LocationKey),
    Legacy(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub server: VlessServer,
    /// URL of the subscription this came from; `None` for a manually added URI.
    #[serde(default)]
    pub source: Option<String>,
}

impl Location {
    /// Whether this holds the provider's own payload rather than one parsed URI:
    /// the JSON profile (with its fallback outbounds, balancer and profile DNS),
    /// the extracted outbound, or the source the editor shows under `JSON`.
    fn carries_provider_payload(&self) -> bool {
        self.server.raw_profile.is_some()
            || self.server.raw_outbound.is_some()
            || self.server.source_json.is_some()
    }
}

/// What `Config::merge` did with one incoming location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Nothing had this identity.
    Added,
    /// The stored location was replaced by the incoming one.
    Replaced,
    /// The stored location was left untouched because the incoming bare link
    /// can only take away from it. `subscription` is its `source`, and
    /// `provider_payload` says whether it carries the provider's own JSON.
    Kept {
        subscription: Option<String>,
        provider_payload: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub url: String,
    #[serde(default)]
    pub meta: SubscriptionMeta,
    /// Leading `# …` comments from the subscription body.
    #[serde(default)]
    pub description: Option<String>,
}

impl Subscription {
    /// What to call this subscription in listings.
    ///
    /// Falls back to the host, never the full URL: a subscription URL carries
    /// the account token, and a listing is exactly the thing people paste into
    /// screenshots and support chats.
    pub fn display_name(&self) -> String {
        if let Some(title) = self
            .meta
            .title
            .as_deref()
            .map(str::trim)
            .filter(|title| !title.is_empty())
        {
            return title.to_string();
        }
        url::Url::parse(&self.url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .unwrap_or_else(|| "subscription".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// "tun" (system-wide) or "proxy" (local SOCKS only).
    pub mode: String,
    pub killswitch: bool,
    pub allow_lan: bool,
    /// Tunnel MTU. See `varmlen_core::xray::TUN_MTU`.
    pub mtu: u32,
    /// Which client to present as when fetching subscriptions. Panels serve
    /// different payloads per client, so this selects what the provider sends.
    /// `None` means Varmlen's own.
    pub user_agent: Option<String>,
    /// Whether the terminal can draw emoji. VTE-based terminals cannot compose
    /// flag sequences, so labels are shown with country codes instead.
    pub emoji: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: "tun".to_string(),
            killswitch: false,
            allow_lan: true,
            mtu: varmlen_core::xray::TUN_MTU,
            user_agent: None,
            emoji: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub locations: Vec<Location>,
    pub subscriptions: Vec<Subscription>,
    /// The location `connect` uses when none is named.
    pub active: Option<ActiveRef>,
    pub split: SplitInput,
    pub settings: Settings,

    /// Pre-0.2 flat list of locations. Read once, migrated into `locations`,
    /// and never written back.
    #[serde(skip_serializing)]
    servers: Vec<VlessServer>,
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
        let mut config: Self = match fs::read(config_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(error) => return Err(error),
        };
        config.migrate();
        Ok(config)
    }

    /// Fold any pre-0.2 state into the current shape. Dropping it silently
    /// would look like the user's locations had vanished.
    fn migrate(&mut self) {
        // The old schema did not record where a location came from. With a
        // single subscription configured every location almost certainly came
        // from it, so attribute them rather than filing them all as manual;
        // with several there is nothing to go on, and `sub update` is what
        // settles it authoritatively either way.
        let inferred_source = match self.subscriptions.as_slice() {
            [only] => Some(only.url.clone()),
            _ => None,
        };
        for server in std::mem::take(&mut self.servers) {
            if !self
                .locations
                .iter()
                .any(|existing| location_key(&existing.server) == location_key(&server))
            {
                self.locations.push(Location {
                    server,
                    source: inferred_source.clone(),
                });
            }
        }
        if let Some(ActiveRef::Legacy(label)) = self.active.clone() {
            self.active = self
                .locations
                .iter()
                .find(|location| location.server.label == label)
                .map(|location| ActiveRef::Key(location_key(&location.server)));
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

    /// Resolve a user-supplied selector to a position in `locations`.
    ///
    /// Providers reuse display names, so a label is not an identity: a 1-based
    /// index from `list` always works, an exact label works while it is unique,
    /// and an ambiguous one reports the indices to choose between rather than
    /// silently picking the first.
    pub fn find(&self, needle: &str) -> Result<usize, String> {
        if let Ok(index) = needle.parse::<usize>() {
            return match index.checked_sub(1).filter(|i| *i < self.locations.len()) {
                Some(index) => Ok(index),
                None => Err(format!(
                    "no location {index}; there are {}",
                    self.locations.len()
                )),
            };
        }
        let exact: Vec<usize> = self
            .positions(|location| location.server.label == needle)
            .collect();
        if !exact.is_empty() {
            return self.single(exact, needle);
        }
        let lowered = needle.to_lowercase();
        let prefixed: Vec<usize> = self
            .positions(|location| searchable(&location.server.label).starts_with(&lowered))
            .collect();
        if !prefixed.is_empty() {
            return self.single(prefixed, needle);
        }
        let contained: Vec<usize> = self
            .positions(|location| location.server.label.to_lowercase().contains(&lowered))
            .collect();
        if contained.is_empty() {
            return Err(format!("no location matches {needle:?}"));
        }
        self.single(contained, needle)
    }

    fn positions<'a>(
        &'a self,
        predicate: impl Fn(&Location) -> bool + 'a,
    ) -> impl Iterator<Item = usize> + 'a {
        self.locations
            .iter()
            .enumerate()
            .filter(move |(_, location)| predicate(location))
            .map(|(index, _)| index)
    }

    fn single(&self, matches: Vec<usize>, needle: &str) -> Result<usize, String> {
        match matches.as_slice() {
            [index] => Ok(*index),
            many => Err(format!(
                "{needle:?} matches {} locations — select by number: {}",
                many.len(),
                many.iter()
                    .map(|index| format!(
                        "{} ({}:{})",
                        index + 1,
                        self.locations[*index].server.host,
                        self.locations[*index].server.port
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    /// Whether `server` is the one `connect` would use by default.
    pub fn is_active(&self, server: &VlessServer) -> bool {
        matches!(&self.active, Some(ActiveRef::Key(key)) if *key == location_key(server))
    }

    pub fn set_active(&mut self, server: &VlessServer) {
        self.active = Some(ActiveRef::Key(location_key(server)));
    }

    /// The location `connect` should use with no argument.
    pub fn active_index(&self) -> Result<usize, String> {
        match &self.active {
            Some(ActiveRef::Key(key)) => self
                .locations
                .iter()
                .position(|location| location_key(&location.server) == *key)
                .ok_or_else(|| {
                    "the last location connected to is gone; name one: `varmlen-cli connect <name>`".into()
                }),
            Some(ActiveRef::Legacy(_)) => {
                Err("the last location connected to is gone; name one: `varmlen-cli connect <name>`".into())
            }
            None => match self.locations.len() {
                1 => Ok(0),
                0 => Err("no locations configured; add one with `varmlen-cli add <uri>`".into()),
                _ => Err("no location chosen yet; name one: `varmlen-cli connect <name>`".into()),
            },
        }
    }

    /// Refresh locations that came back with the same identity, add the rest.
    ///
    /// Keyed on `location_key` rather than the display name: providers reuse
    /// names across locations, and matching on one would collapse distinct
    /// servers into a single entry.
    ///
    /// A bare link never replaces a location that carries more than a link.
    /// `add` parses a single URI: it has no provider profile, no fallback
    /// outbounds, no profile DNS, and no subscription of its own. Copying it
    /// over a subscription location used to delete all of that -- including the
    /// `source` that ties the location to its subscription, so no later
    /// `sub update` could bring the profile back -- while reporting a plain
    /// "added". The link states nothing the profile does not already state, so
    /// the location is kept and the caller says so.
    ///
    /// An incoming location that does carry a `source` is the provider's own
    /// payload for that identity and replaces what was stored: being current is
    /// the whole point of `sub update`.
    pub fn merge(
        &mut self,
        incoming: Vec<VlessServer>,
        source: Option<&str>,
    ) -> Vec<MergeOutcome> {
        let mut outcomes = Vec::with_capacity(incoming.len());
        for server in incoming {
            let key = location_key(&server);
            let stored = self
                .locations
                .iter()
                .position(|existing| location_key(&existing.server) == key);
            let Some(index) = stored else {
                self.locations.push(Location {
                    server,
                    source: source.map(str::to_string),
                });
                outcomes.push(MergeOutcome::Added);
                continue;
            };
            let existing = &self.locations[index];
            if source.is_none()
                && (existing.carries_provider_payload() || existing.source.is_some())
            {
                outcomes.push(MergeOutcome::Kept {
                    subscription: existing.source.clone(),
                    provider_payload: existing.carries_provider_payload(),
                });
                continue;
            }
            let existing = &mut self.locations[index];
            existing.server = server;
            existing.source = source.map(str::to_string);
            outcomes.push(MergeOutcome::Replaced);
        }
        outcomes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(label: &str, host: &str, port: u16) -> VlessServer {
        let mut server = varmlen_core::subscription::parse_proxy_uri(
            "vless://11111111-1111-1111-1111-111111111111@placeholder:443?type=tcp#x",
        )
        .expect("uri parses");
        server.label = label.to_string();
        server.host = host.to_string();
        server.port = port;
        server
    }

    fn with_locations(servers: Vec<VlessServer>, active: Option<ActiveRef>) -> Config {
        Config {
            locations: servers
                .into_iter()
                .map(|server| Location {
                    server,
                    source: None,
                })
                .collect(),
            active,
            ..Config::default()
        }
    }

    /// Providers put separators inside display names, which is why the legacy
    /// key format was ambiguous and this migration cannot sniff the format.
    #[test]
    fn a_legacy_active_name_containing_a_pipe_still_migrates() {
        let mut config = with_locations(
            vec![server("Finland | Helsinki", "fi.example", 443)],
            Some(ActiveRef::Legacy("Finland | Helsinki".to_string())),
        );
        config.migrate();
        assert!(config.is_active(&config.locations[0].server));
        assert_eq!(config.active_index(), Ok(0));
    }

    #[test]
    fn a_flag_emoji_does_not_hide_the_name() {
        let config = with_locations(
            vec![
                server("\u{1F1EB}\u{1F1EE} Finland | Helsinki", "fi.example", 443),
                server("\u{1F1E9}\u{1F1EA} Germany | Limburg", "de.example", 443),
            ],
            None,
        );
        assert_eq!(config.find("Finland"), Ok(0));
        assert_eq!(config.find("germany"), Ok(1));
        // Substring still reaches the part after the separator.
        assert_eq!(config.find("Helsinki"), Ok(0));
    }

    /// The same endpoint as a JSON subscription serves it: profile, extracted
    /// outbound and the source text the editor shows as `JSON`.
    fn provider_location(label: &str, host: &str, port: u16) -> VlessServer {
        let mut server = server(label, host, port);
        server.raw_outbound = Some(serde_json::json!({
            "tag": "proxy",
            "protocol": "vless",
            "settings": { "vnext": [{ "address": host, "port": port }] }
        }));
        server.raw_profile = Some(serde_json::json!({
            "remarks": label,
            "outbounds": [
                { "tag": "proxy", "protocol": "vless" },
                { "tag": "proxy-2", "protocol": "vless" }
            ],
            "routing": { "balancers": [{ "tag": "balancer" }] }
        }));
        server.source_json = Some("{\"remarks\":\"provider\"}".to_string());
        server
    }

    fn from_subscription(url: &str) -> Vec<Subscription> {
        vec![Subscription {
            url: url.to_string(),
            meta: Default::default(),
            description: None,
        }]
    }

    /// The regression: pasting one share link for a location that came from a
    /// JSON subscription replaced it with the bare link. The profile (fallback
    /// outbounds, balancer, profile DNS), the `JSON` marker and the `source` all
    /// went, and because `source` went, no later `sub update` could restore the
    /// profile -- the location had quietly become a manually added URI.
    #[test]
    fn a_bare_link_never_buries_a_subscription_profile() {
        const SUB: &str = "https://provider.example/sub/TOKEN";
        let mut config = Config {
            locations: vec![Location {
                server: provider_location("\u{1F1EA}\u{1F1F8} Germany", "de.example", 443),
                source: Some(SUB.to_string()),
            }],
            subscriptions: from_subscription(SUB),
            ..Config::default()
        };

        let outcomes = config.merge(
            vec![server("\u{1F1EA}\u{1F1F8} Germany", "de.example", 443)],
            None,
        );

        assert_eq!(
            outcomes,
            vec![MergeOutcome::Kept {
                subscription: Some(SUB.to_string()),
                provider_payload: true,
            }]
        );
        assert_eq!(config.locations.len(), 1, "the link must not append a twin");
        let kept = &config.locations[0];
        assert!(kept.server.raw_profile.is_some(), "the provider profile survived");
        assert!(kept.server.raw_outbound.is_some(), "the exact outbound survived");
        assert!(kept.server.source_json.is_some(), "the JSON source survived");
        assert_eq!(kept.source.as_deref(), Some(SUB), "still a subscription member");
    }

    /// A subscription location without a profile is still not the user's manual
    /// property: overwriting it unfiles it, and it never files itself back.
    #[test]
    fn a_bare_link_does_not_unfile_a_subscription_location() {
        const SUB: &str = "https://provider.example/sub/TOKEN";
        let mut config = Config {
            locations: vec![Location {
                server: server("Netherlands", "nl.example", 8443),
                source: Some(SUB.to_string()),
            }],
            subscriptions: from_subscription(SUB),
            ..Config::default()
        };

        let mut pasted = server("Netherlands", "nl.example", 8443);
        pasted.uuid = "22222222-2222-2222-2222-222222222222".to_string();
        let outcomes = config.merge(vec![pasted], None);

        assert_eq!(
            outcomes,
            vec![MergeOutcome::Kept {
                subscription: Some(SUB.to_string()),
                provider_payload: false,
            }]
        );
        assert_eq!(
            config.locations[0].server.uuid,
            "11111111-1111-1111-1111-111111111111",
            "the pasted link did not reach the stored location"
        );
    }

    /// The other half: `sub update` carries a source, and being current is the
    /// point of it, so the provider's payload keeps replacing what is stored.
    #[test]
    fn a_subscription_fetch_still_replaces_what_it_returns() {
        const OLD: &str = "https://provider.example/sub/OLD";
        const NEW: &str = "https://provider.example/sub/NEW";
        let mut config = Config {
            locations: vec![Location {
                server: provider_location("Estonia", "ee.example", 443),
                source: Some(OLD.to_string()),
            }],
            subscriptions: from_subscription(OLD),
            ..Config::default()
        };

        let outcomes = config.merge(vec![server("Estonia", "ee.example", 443)], Some(NEW));

        assert_eq!(outcomes, vec![MergeOutcome::Replaced]);
        let updated = &config.locations[0];
        assert!(updated.server.raw_profile.is_none(), "the provider no longer ships a profile");
        assert_eq!(updated.source.as_deref(), Some(NEW));
    }

    /// Two manual links for one endpoint are the user's own business: the later
    /// one wins, as it did before.
    #[test]
    fn a_manual_link_still_updates_a_manual_link() {
        let mut config = with_locations(vec![server("Home", "home.example", 443)], None);
        let mut edited = server("Home", "home.example", 443);
        edited.password = Some("rotated".to_string());

        let outcomes = config.merge(vec![edited], None);

        assert_eq!(outcomes, vec![MergeOutcome::Replaced]);
        assert_eq!(config.locations.len(), 1);
        assert_eq!(config.locations[0].server.password.as_deref(), Some("rotated"));
    }

    #[test]
    fn an_unknown_identity_is_appended() {
        let mut config = with_locations(vec![server("Finland", "fi.example", 443)], None);
        let outcomes = config.merge(vec![server("Japan", "jp.example", 443)], None);
        assert_eq!(outcomes, vec![MergeOutcome::Added]);
        assert_eq!(config.locations.len(), 2);
    }

    #[test]
    fn same_name_on_different_hosts_stays_distinct() {
        let config = with_locations(
            vec![
                server("Auto", "a.example", 443),
                server("Auto", "b.example", 443),
            ],
            None,
        );
        assert_ne!(
            location_key(&config.locations[0].server),
            location_key(&config.locations[1].server)
        );
        assert!(config.find("Auto").is_err(), "ambiguous name must not resolve");
        assert_eq!(config.find("2"), Ok(1));
    }
}
