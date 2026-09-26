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

/// A label as the chosen location is re-found by after a refresh: flag,
/// surrounding space and case ignored, as the desktop client compares them.
fn normalized_label(label: &str) -> String {
    searchable(label).trim_end().to_string()
}

/// Recorded when an update fetched fine but parsed to nothing — the usual sign
/// of a provider answering with an error page or a format we cannot read.
pub const NO_LOCATIONS_ERROR: &str = "subscription returned no locations";

pub fn location_key(server: &VlessServer) -> LocationKey {
    LocationKey {
        label: server.label.clone(),
        host: server.host.clone(),
        port: server.port,
    }
}

/// Everything that tells one endpoint from another, as the desktop client's
/// `serverKey` has it. Providers put several locations on one host and port and
/// separate them by transport, path, SNI or flow, so host and port alone would
/// re-find a choice on a location the user never picked.
fn endpoint(server: &VlessServer) -> (u16, [&str; 12]) {
    fn optional(value: &Option<String>) -> &str {
        value.as_deref().unwrap_or("")
    }
    (
        server.port,
        [
            &server.protocol,
            &server.host,
            &server.uuid,
            optional(&server.password),
            optional(&server.method),
            &server.transport,
            &server.security,
            optional(&server.sni),
            optional(&server.flow),
            optional(&server.path),
            optional(&server.public_key),
            optional(&server.short_id),
        ],
    )
}

/// What `remove` takes away; see [`Config::removal`].
#[derive(Debug, PartialEq, Eq)]
pub enum Removal {
    /// A location added by hand, by position in `locations`.
    Location(usize),
    /// A subscription with all its locations, by position in `subscriptions`.
    Subscription(usize),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub url: String,
    #[serde(default)]
    pub meta: SubscriptionMeta,
    /// Leading `# …` comments from the subscription body.
    #[serde(default)]
    pub description: Option<String>,
    /// Why the last update failed, or `None` when it worked. A failed update
    /// keeps the previous locations, so without this the subscription simply
    /// grows stale with no trace of why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
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

    /// Take a successful update's metadata. The latest response is
    /// authoritative for usage, quota, expiry and links — what it does not carry
    /// is gone, not kept from last time — but a provider that stops sending a
    /// title, an interval or a description keeps the ones it had, as in the
    /// desktop client.
    pub fn apply_update(&mut self, mut meta: SubscriptionMeta, description: Option<String>) {
        if meta.title.is_none() {
            meta.title = self.meta.title.take();
        }
        if meta.update_interval_hours.is_none() {
            meta.update_interval_hours = self.meta.update_interval_hours;
        }
        self.meta = meta;
        if description.is_some() {
            self.description = description;
        }
        self.last_error = None;
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
    /// URL of the subscription `active` was chosen from; `None` for a manual
    /// location. A refresh re-finds the choice inside this subscription only:
    /// the same endpoint can sit in two of them, and searching everywhere is
    /// how updating one subscription would move the choice into another.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_source: Option<String>,
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

        // Up to 0.1.2 `sub remove` kept the subscription's locations, still
        // attributed to a URL nothing listed any more, so `list` never showed
        // them. They were promised to stay: file them with the manual ones.
        for location in &mut self.locations {
            if location
                .source
                .as_ref()
                .is_some_and(|url| !self.subscriptions.iter().any(|sub| &sub.url == url))
            {
                location.source = None;
            }
        }

        // The choice's subscription was not recorded before; where the chosen
        // location still exists, it is the one it sits in.
        if self.active_source.is_none() {
            if let Some(ActiveRef::Key(key)) = &self.active {
                self.active_source = self
                    .locations
                    .iter()
                    .find(|location| location_key(&location.server) == *key)
                    .and_then(|location| location.source.clone());
            }
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
        let matches = self.matching(needle, |_| true);
        if matches.is_empty() {
            return Err(format!("no location matches {needle:?}"));
        }
        self.single(matches, needle)
    }

    /// Locations within `scope` whose label matches `needle`, from the most
    /// specific way of matching that finds any: the exact label, a prefix past
    /// the flag, then a substring.
    fn matching(&self, needle: &str, scope: impl Fn(&Location) -> bool) -> Vec<usize> {
        let exact: Vec<usize> = self
            .positions(|location| scope(location) && location.server.label == needle)
            .collect();
        if !exact.is_empty() {
            return exact;
        }
        let lowered = needle.to_lowercase();
        let prefixed: Vec<usize> = self
            .positions(|location| {
                scope(location) && searchable(&location.server.label).starts_with(&lowered)
            })
            .collect();
        if !prefixed.is_empty() {
            return prefixed;
        }
        self.positions(|location| {
            scope(location) && location.server.label.to_lowercase().contains(&lowered)
        })
        .collect()
    }

    /// Resolve a subscription by its number in `sub list` or by name, so nobody
    /// has to paste a URL that carries their token just to name one.
    pub fn find_subscription(&self, needle: &str) -> Result<usize, String> {
        if let Ok(number) = needle.parse::<usize>() {
            return number
                .checked_sub(1)
                .filter(|index| *index < self.subscriptions.len())
                .ok_or_else(|| {
                    format!(
                        "no subscription {number}; there are {}",
                        self.subscriptions.len()
                    )
                });
        }
        match self.subscription_matches(needle).as_slice() {
            [index] => Ok(*index),
            [] => Err(format!("no subscription matches {needle:?}")),
            many => Err(format!(
                "{needle:?} matches {} subscriptions — select by number",
                many.len()
            )),
        }
    }

    fn subscription_matches(&self, needle: &str) -> Vec<usize> {
        let lowered = needle.to_lowercase();
        self.subscriptions
            .iter()
            .enumerate()
            .filter(|(_, sub)| {
                sub.display_name().to_lowercase().contains(&lowered) || sub.url == needle
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// What `remove <target>` takes away. A location added by hand or a whole
    /// subscription, never one location out of a subscription: that belongs to
    /// the provider and the next update would bring it back, so the desktop
    /// client does not delete it either.
    ///
    /// A number is a location from `list`; `sub <number|name>` is a
    /// subscription from `sub list`; a bare name may be either, and is refused
    /// when it would be both rather than guessing which one goes.
    pub fn removal(&self, target: &str) -> Result<Removal, String> {
        let target = target.trim();
        if target == "sub" {
            return Err("name a subscription: `remove sub <number|name>`, or see `sub list`".into());
        }
        if let Some(rest) = target.strip_prefix("sub ") {
            return self.find_subscription(rest.trim()).map(Removal::Subscription);
        }
        if target.parse::<usize>().is_ok() {
            let index = self.find(target)?;
            return self.manual_only(index).map(Removal::Location);
        }

        let manual = self.matching(target, |location| location.source.is_none());
        let subscriptions = self.subscription_matches(target);
        match (manual.is_empty(), subscriptions.as_slice()) {
            (false, [_, ..]) => Err(format!(
                "{target:?} names both a location added by hand and a subscription — \
                 `remove <number>` for the location (see `list`), `remove sub {target}` \
                 for the subscription"
            )),
            (false, []) => self.single(manual, target).map(Removal::Location),
            (true, [index]) => Ok(Removal::Subscription(*index)),
            (true, [_, _, ..]) => Err(format!(
                "{target:?} matches {} subscriptions — select by number: \
                 `remove sub <number>`, see `sub list`",
                subscriptions.len()
            )),
            (true, []) => {
                match self.matching(target, |location| location.source.is_some()).first() {
                    Some(index) => self.manual_only(*index).map(Removal::Location),
                    None => Err(format!(
                        "no location added by hand or subscription matches {target:?}"
                    )),
                }
            }
        }
    }

    /// `index` when it is a location added by hand; otherwise why it cannot be
    /// removed on its own, and what can be.
    fn manual_only(&self, index: usize) -> Result<usize, String> {
        let Some(url) = &self.locations[index].source else {
            return Ok(index);
        };
        let label = &self.locations[index].server.label;
        Err(match self.subscriptions.iter().position(|sub| &sub.url == url) {
            Some(sub) => format!(
                "{label:?} comes from the subscription {}, and its next update would bring \
                 it back; remove the whole subscription with `remove sub {}`",
                self.subscriptions[sub].display_name(),
                sub + 1
            ),
            None => format!("{label:?} comes from a subscription and cannot be removed on its own"),
        })
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

    /// Whether the location at `index` is the one `connect` would use by
    /// default.
    pub fn is_active(&self, index: usize) -> bool {
        self.active_position() == Some(index)
    }

    pub fn set_active(&mut self, location: &Location) {
        self.active = Some(ActiveRef::Key(location_key(&location.server)));
        self.active_source = location.source.clone();
    }

    pub fn clear_active(&mut self) {
        self.active = None;
        self.active_source = None;
    }

    /// Add a location typed in by hand. Only a manual entry with the same key is
    /// replaced: a subscription's location belongs to the provider, and taking
    /// it over would leave the subscription one location short.
    pub fn add_manual(&mut self, server: VlessServer) {
        let key = location_key(&server);
        match self
            .locations
            .iter_mut()
            .find(|existing| existing.source.is_none() && location_key(&existing.server) == key)
        {
            Some(existing) => existing.server = server,
            None => self.locations.push(Location {
                server,
                source: None,
            }),
        }
    }

    /// Make `url`'s locations exactly what the provider sent now, as the
    /// desktop client does: a location the provider dropped goes, a new one
    /// appears, and nothing another subscription or the user added is touched
    /// even when it shares an endpoint. The new list takes the old one's place,
    /// so the numbers of everything else in `list` stay put.
    ///
    /// Returns how many locations were added and removed.
    pub fn replace_subscription_locations(
        &mut self,
        url: &str,
        fresh: Vec<VlessServer>,
    ) -> (usize, usize) {
        let from = |location: &Location| location.source.as_deref() == Some(url);
        let old: Vec<LocationKey> = self
            .locations
            .iter()
            .filter(|location| from(location))
            .map(|location| location_key(&location.server))
            .collect();
        let new: Vec<LocationKey> = fresh.iter().map(location_key).collect();
        let added = new.iter().filter(|key| !old.contains(key)).count();
        let removed = old.iter().filter(|key| !new.contains(key)).count();

        let previous = self
            .active_location()
            .map(|location| location.server.clone());
        let at = self
            .locations
            .iter()
            .position(from)
            .unwrap_or(self.locations.len());
        self.locations.retain(|location| !from(location));
        self.locations.splice(
            at..at,
            fresh.into_iter().map(|server| Location {
                server,
                source: Some(url.to_string()),
            }),
        );
        self.reconcile_active(previous.as_ref());
        (added, removed)
    }

    /// Remove a subscription together with its locations — nothing would ever
    /// update them again.
    pub fn remove_subscription(&mut self, index: usize) -> Subscription {
        let previous = self
            .active_location()
            .map(|location| location.server.clone());
        let removed = self.subscriptions.remove(index);
        self.locations
            .retain(|location| location.source.as_deref() != Some(removed.url.as_str()));
        self.reconcile_active(previous.as_ref());
        removed
    }

    /// The subscription the choice was made in, while it still exists. Only
    /// then is the choice confined to it.
    fn active_home(&self) -> Option<&str> {
        self.active_source
            .as_deref()
            .filter(|url| self.subscriptions.iter().any(|sub| sub.url == *url))
    }

    /// Where the location `active` names sits right now. Inside its own
    /// subscription only: the same location in another one is a different
    /// choice.
    fn active_position(&self) -> Option<usize> {
        let Some(ActiveRef::Key(key)) = &self.active else {
            return None;
        };
        let home = self.active_home();
        let matching: Vec<usize> = self
            .positions(|location| {
                location_key(&location.server) == *key
                    && (home.is_none() || location.source.as_deref() == home)
            })
            .collect();
        matching
            .iter()
            .copied()
            .find(|index| self.locations[*index].source == self.active_source)
            .or(matching.first().copied())
    }

    fn active_location(&self) -> Option<&Location> {
        self.active_position().map(|index| &self.locations[index])
    }

    /// Keep the chosen location chosen after its subscription changed, the way
    /// the desktop client does: the same key, then the same endpoint (a provider
    /// renamed it), then the same label (a provider moved it to another host) —
    /// all inside the subscription it was chosen from while that still exists.
    ///
    /// Never picks a different location. When nothing matches, the choice is
    /// left as it was: `connect` says it is gone instead of taking the user to
    /// another country, and a later update that brings it back restores it.
    fn reconcile_active(&mut self, previous: Option<&VlessServer>) {
        let Some(ActiveRef::Key(key)) = self.active.clone() else {
            return;
        };
        let home = self.active_home();
        let pool: Vec<&Location> = self
            .locations
            .iter()
            .filter(|location| home.is_none() || location.source.as_deref() == home)
            .collect();
        let wanted = normalized_label(&key.label);
        let same_label = |location: &&&Location| normalized_label(&location.server.label) == wanted;

        let exact = |location: &&&Location| location_key(&location.server) == key;
        let found = pool
            .iter()
            .filter(exact)
            .find(|location| location.source == self.active_source)
            .or_else(|| pool.iter().find(exact))
            .or_else(|| {
                // Several locations can share one endpoint and differ only by
                // label (an "auto choice" in front of the same servers), so the
                // label decides between them.
                let previous = previous?;
                let shared: Vec<&&Location> = pool
                    .iter()
                    .filter(|location| endpoint(&location.server) == endpoint(previous))
                    .collect();
                shared
                    .iter()
                    .find(|location| same_label(location))
                    .or(shared.first())
                    .copied()
            })
            .or_else(|| pool.iter().find(same_label))
            .map(|location| (*location).clone());
        if let Some(location) = found {
            self.set_active(&location);
        }
    }

    /// The location `connect` should use with no argument.
    pub fn active_index(&self) -> Result<usize, String> {
        match &self.active {
            Some(ActiveRef::Key(_)) => self.active_position().ok_or_else(|| {
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
        assert!(config.is_active(0));
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

    const A: &str = "https://a.example/sub/token";
    const B: &str = "https://b.example/sub/token";

    fn subscription(url: &str) -> Subscription {
        Subscription {
            url: url.to_string(),
            meta: SubscriptionMeta::default(),
            description: None,
            last_error: None,
        }
    }

    fn located(server: VlessServer, source: Option<&str>) -> Location {
        Location {
            server,
            source: source.map(str::to_string),
        }
    }

    fn two_subscriptions() -> Config {
        Config {
            subscriptions: vec![subscription(A), subscription(B)],
            locations: vec![
                located(server("Finland", "fi.a", 443), Some(A)),
                located(server("Germany", "de.a", 443), Some(A)),
                located(server("Manual", "m.example", 443), None),
                located(server("Finland", "fi.a", 443), Some(B)),
            ],
            ..Config::default()
        }
    }

    fn labels(config: &Config, source: Option<&str>) -> Vec<String> {
        config
            .locations
            .iter()
            .filter(|location| location.source.as_deref() == source)
            .map(|location| location.server.label.clone())
            .collect()
    }

    #[test]
    fn an_update_drops_what_the_provider_dropped_and_adds_what_is_new() {
        let mut config = two_subscriptions();
        let (added, removed) = config.replace_subscription_locations(
            A,
            vec![
                server("Finland", "fi.a", 443),
                server("Sweden", "se.a", 443),
            ],
        );
        assert_eq!((added, removed), (1, 1));
        assert_eq!(labels(&config, Some(A)), ["Finland", "Sweden"]);
        // The other subscription and the manual location are untouched, and
        // keep their place in the numbering.
        assert_eq!(labels(&config, Some(B)), ["Finland"]);
        assert_eq!(config.locations[2].server.label, "Manual");
    }

    #[test]
    fn an_endpoint_shared_by_two_subscriptions_stays_in_both() {
        let mut config = two_subscriptions();
        config.replace_subscription_locations(B, vec![server("Finland", "fi.a", 443)]);
        assert_eq!(labels(&config, Some(A)), ["Finland", "Germany"]);
        assert_eq!(labels(&config, Some(B)), ["Finland"]);
    }

    #[test]
    fn a_provider_shipping_one_key_twice_keeps_both_rows() {
        let mut config = two_subscriptions();
        config.replace_subscription_locations(
            A,
            vec![server("Auto", "x.a", 443), server("Auto", "x.a", 443)],
        );
        assert_eq!(labels(&config, Some(A)), ["Auto", "Auto"]);
    }

    #[test]
    fn a_manual_add_does_not_take_a_location_from_a_subscription() {
        let mut config = two_subscriptions();
        config.add_manual(server("Finland", "fi.a", 443));
        assert_eq!(labels(&config, Some(A)), ["Finland", "Germany"]);
        assert_eq!(labels(&config, None), ["Manual", "Finland"]);
        // The same location typed in twice is still one.
        config.add_manual(server("Finland", "fi.a", 443));
        assert_eq!(labels(&config, None), ["Manual", "Finland"]);
    }

    #[test]
    fn the_choice_follows_its_label_to_a_new_host_inside_its_subscription() {
        let mut config = two_subscriptions();
        let chosen = config.locations[0].clone();
        config.set_active(&chosen);
        config.replace_subscription_locations(
            A,
            vec![
                server("🇫🇮 Finland", "fi2.a", 443),
                server("Germany", "de.a", 443),
            ],
        );
        let index = config.active_index().expect("choice re-found");
        assert_eq!(config.locations[index].server.host, "fi2.a");
        assert_eq!(config.locations[index].source.as_deref(), Some(A));
    }

    #[test]
    fn a_renamed_location_on_the_same_endpoint_stays_chosen() {
        let mut config = two_subscriptions();
        let chosen = config.locations[1].clone();
        config.set_active(&chosen);
        config.replace_subscription_locations(
            A,
            vec![
                server("Finland", "fi.a", 443),
                server("Germany | Limburg", "de.a", 443),
            ],
        );
        let index = config.active_index().expect("choice re-found");
        assert_eq!(config.locations[index].server.label, "Germany | Limburg");
    }

    #[test]
    fn locations_on_one_endpoint_are_told_apart_by_label() {
        let mut config = two_subscriptions();
        config.replace_subscription_locations(
            A,
            vec![server("Auto", "x.a", 443), server("Finland", "x.a", 443)],
        );
        let chosen = config.locations[1].clone();
        config.set_active(&chosen);
        // Something else about the endpoint changed, so the exact key is gone.
        config.replace_subscription_locations(
            A,
            vec![server("Auto", "x.a", 8443), server("Finland", "x.a", 8443)],
        );
        // Port is part of the endpoint too: nothing matches it any more, so the
        // label alone re-finds the choice.
        let index = config.active_index().expect("choice re-found");
        assert_eq!(config.locations[index].server.label, "Finland");
    }

    #[test]
    fn a_vanished_choice_is_reported_not_replaced_and_comes_back_with_it() {
        let mut config = two_subscriptions();
        let chosen = config.locations[0].clone();
        config.set_active(&chosen);
        config.replace_subscription_locations(A, vec![server("Germany", "de.a", 443)]);
        // Finland still exists in B, but the choice was made in A.
        assert!(config.active_index().is_err());
        config.replace_subscription_locations(
            A,
            vec![
                server("Finland", "fi.a", 443),
                server("Germany", "de.a", 443),
            ],
        );
        let index = config.active_index().expect("choice restored");
        assert_eq!(config.locations[index].source.as_deref(), Some(A));
    }

    #[test]
    fn removing_a_subscription_takes_its_locations_with_it() {
        let mut config = two_subscriptions();
        let chosen = config.locations[0].clone();
        config.set_active(&chosen);
        let removed = config.remove_subscription(0);
        assert_eq!(removed.url, A);
        assert!(labels(&config, Some(A)).is_empty());
        assert_eq!(labels(&config, None), ["Manual"]);
        // With its subscription gone, the same location elsewhere is the choice.
        let index = config.active_index().expect("choice re-found elsewhere");
        assert_eq!(config.locations[index].source.as_deref(), Some(B));
    }

    #[test]
    fn locations_left_behind_by_an_old_sub_remove_become_manual() {
        let mut config = Config {
            subscriptions: vec![subscription(B)],
            locations: vec![
                located(server("Finland", "fi.a", 443), Some(A)),
                located(server("Finland", "fi.a", 443), Some(B)),
            ],
            active: Some(ActiveRef::Key(LocationKey {
                label: "Finland".to_string(),
                host: "fi.a".to_string(),
                port: 443,
            })),
            ..Config::default()
        };
        config.migrate();
        assert_eq!(config.locations[0].source, None);
        assert_eq!(config.locations[1].source.as_deref(), Some(B));
        assert_eq!(config.active_source, None);
    }

    fn titled(mut config: Config) -> Config {
        config.subscriptions[0].meta.title = Some("AegisVPN".to_string());
        config.subscriptions[1].meta.title = Some("Proxen".to_string());
        config
    }

    #[test]
    fn remove_takes_a_manual_location_by_number_or_name() {
        let config = titled(two_subscriptions());
        assert_eq!(config.removal("3"), Ok(Removal::Location(2)));
        assert_eq!(config.removal("Manual"), Ok(Removal::Location(2)));
    }

    #[test]
    fn remove_refuses_a_location_inside_a_subscription() {
        let config = titled(two_subscriptions());
        let by_number = config.removal("2").expect_err("subscription location");
        assert!(by_number.contains("AegisVPN"), "{by_number}");
        assert!(by_number.contains("remove sub 1"), "{by_number}");
        // Only subscriptions carry "Germany", so the name is refused too.
        assert!(config.removal("Germany").is_err());
    }

    #[test]
    fn remove_takes_a_whole_subscription_by_name_or_sub_number() {
        let config = titled(two_subscriptions());
        assert_eq!(config.removal("Proxen"), Ok(Removal::Subscription(1)));
        assert_eq!(config.removal("sub 1"), Ok(Removal::Subscription(0)));
        assert_eq!(config.removal("sub aegis"), Ok(Removal::Subscription(0)));
        assert!(config.removal("sub").is_err());
    }

    #[test]
    fn remove_does_not_guess_between_a_location_and_a_subscription() {
        let mut config = titled(two_subscriptions());
        config.locations[2].server.label = "Proxen backup".to_string();
        assert!(config.removal("Proxen").is_err());
        assert_eq!(config.removal("sub Proxen"), Ok(Removal::Subscription(1)));
        assert_eq!(config.removal("3"), Ok(Removal::Location(2)));
    }

    #[test]
    fn an_update_keeps_the_title_but_not_stale_usage() {
        let mut sub = subscription(A);
        sub.meta.title = Some("AegisVPN".to_string());
        sub.meta.total_bytes = Some(100);
        sub.last_error = Some("timed out".to_string());
        sub.apply_update(SubscriptionMeta::default(), None);
        assert_eq!(sub.meta.title.as_deref(), Some("AegisVPN"));
        assert_eq!(sub.meta.total_bytes, None);
        assert_eq!(sub.last_error, None);
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
        assert!(
            config.find("Auto").is_err(),
            "ambiguous name must not resolve"
        );
        assert_eq!(config.find("2"), Ok(1));
    }
}
