//! Headless Varmlen client.
//!
//! Talks to the same `varmlend` daemon as the GUI over the same unix socket and
//! wire protocol, and builds the xray configuration with the same `varmlen-core`
//! code, so the two clients cannot drift apart in what they ask the daemon to do.
//!
//! It never starts the daemon itself: `pkexec` needs a polkit agent bound to a
//! graphical session, which a headless environment does not have. Run the daemon
//! under systemd instead (see `packaging/varmlend.service`).

mod config;
mod display;


use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use varmlen_core::daemon_client::DaemonClient;
use varmlen_core::endpoint::resolve_server_ips;
use varmlen_core::fetch::fetch_subscription;
use varmlen_core::label::transport_summary;
use varmlen_core::split::SplitInput;
use varmlen_core::subscription::{parse_proxy_uri, VlessServer};
use varmlen_core::xray::{
    build_connection_probe_config, build_ping_config, generate_xray_config,
    ping_placeholder_ports, TUN_MTU_MAX, TUN_MTU_MIN,
};
use varmlend::protocol::{
    ConnectRequest, ConnectionMode, DaemonCommand, DaemonState, ProxyPingRequest, TcpPingRequest,
};

use config::{location_key, Config, Location, Subscription};
use display::{bold, bytes, date, dim, label};

#[derive(Parser)]
#[command(
    name = "varmlen-cli",
    about = "Headless client for the Varmlen xray daemon",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the daemon's current state.
    Status,
    /// Bring the tunnel up.
    Connect(ConnectArgs),
    /// Tear the tunnel down.
    Disconnect,
    /// List configured locations.
    List,
    /// Add a location from a vless:// / vmess:// / trojan:// / ss:// URI.
    Add { uri: String },
    /// Remove a location by its number from `list`, or by name.
    Remove {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        name: Vec<String>,
    },
    /// Manage subscriptions.
    #[command(subcommand)]
    Sub(SubCommand),
    /// Show the daemon's xray log.
    Log {
        /// Clear the log instead of printing it.
        #[arg(long)]
        clear: bool,
    },
    /// Change connection settings.
    #[command(subcommand)]
    Set(SetCommand),
    /// Measure latency to a location.
    Ping(PingArgs),
    /// Choose which apps and sites go through the tunnel.
    Split {
        #[command(subcommand)]
        action: Option<SplitCommand>,
    },
    /// Print the path of the CLI's config file.
    ConfigPath,
}

#[derive(Args)]
struct ConnectArgs {
    /// Location to connect to: its number from `list`, or its name. Everything
    /// after `connect` is taken as the name, so it needs no quoting. Omit it to
    /// reuse the last location connected to.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    name: Vec<String>,
}

#[derive(Subcommand)]
enum SubCommand {
    /// Add a subscription URL and import its locations.
    Add { url: String },
    /// List subscriptions.
    List,
    /// Re-fetch every subscription, replacing its locations.
    Update,
    /// Remove a subscription (its locations are kept).
    Remove { url: String },
}

#[derive(Args)]
struct PingArgs {
    /// Probe every configured location instead of just one.
    #[arg(long)]
    all: bool,
    /// Measure a plain TCP handshake to the endpoint instead of probing
    /// through the proxy. Faster, but says nothing about the proxy itself.
    #[arg(long)]
    tcp: bool,
    /// Timeout per probe, in milliseconds.
    #[arg(long, default_value_t = 5000, value_parser = clap::value_parser!(u32).range(100..=10_000))]
    timeout: u32,
    /// Location to probe; defaults to the last one connected to.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    name: Vec<String>,
}

#[derive(Subcommand)]
enum SplitCommand {
    /// Apps, matched on process or binary name.
    Apps {
        #[command(subcommand)]
        action: Option<ListCommand>,
    },
    /// Sites, e.g. `example.com` or `*.example.com`.
    Sites {
        #[command(subcommand)]
        action: Option<ListCommand>,
    },
}

#[derive(Subcommand)]
enum ListCommand {
    /// `selective` tunnels only what is listed; `general` tunnels everything
    /// except what is listed.
    Mode { value: String },
    /// Add entries to the list.
    Add {
        #[arg(required = true)]
        values: Vec<String>,
    },
    /// Remove entries from the list.
    Remove {
        #[arg(required = true)]
        values: Vec<String>,
    },
    /// Empty the list, leaving the mode alone.
    Clear,
}

#[derive(Subcommand)]
enum SetCommand {
    /// "tun" routes the whole system; "proxy" only exposes a local SOCKS port.
    Mode { value: String },
    /// Block traffic if the tunnel drops.
    Killswitch { value: String },
    /// Keep LAN reachable while connected.
    AllowLan { value: String },
    /// Tunnel MTU (1280-1500).
    Mtu { value: u32 },
    /// Which client to present as when fetching subscriptions:
    /// varmlen, happ or incy. Panels serve different payloads per client.
    UserAgent { value: String },
    /// Show emoji in location names. Turn off for terminals that cannot draw
    /// them: flags become country codes rather than disappearing.
    Emoji { value: String },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let mut config = Config::load().context("reading the CLI config")?;

    match cli.command {
        Command::Status => print_state(&daemon().await?.request(DaemonCommand::Status).await?),
        Command::Connect(args) => {
            let name = args.name.join(" ");
            let name = name.trim();
            connect(&mut config, (!name.is_empty()).then_some(name)).await?
        }
        Command::Disconnect => {
            print_state(&daemon().await?.request(DaemonCommand::Disconnect).await?)
        }
        Command::List => list(&config),
        Command::Add { uri } => {
            let server = parse_proxy_uri(&uri).map_err(|error| anyhow::anyhow!("{error}"))?;
            let label = server.label.clone();
            merge(&mut config, vec![server], None);
            config.save()?;
            println!("added {}", display::label(&label, config.settings.emoji));
        }
        Command::Remove { name } => {
            let index = config
                .find(name.join(" ").trim())
                .map_err(anyhow::Error::msg)?;
            let removed = config.locations.remove(index);
            if config.is_active(&removed.server) {
                config.active = None;
            }
            let name = label(&removed.server.label, config.settings.emoji);
            config.save()?;
            println!("removed {name}");
        }
        Command::Sub(command) => subscriptions(&mut config, command).await?,
        Command::Log { clear } => {
            let command = if clear {
                DaemonCommand::ClearLog
            } else {
                DaemonCommand::LogTail
            };
            let state = daemon().await?.request(command).await?;
            match state.log_tail {
                Some(log) if !clear => println!("{log}"),
                _ => println!("(log cleared)"),
            }
        }
        Command::Set(command) => {
            settings(&mut config, command)?;
            config.save()?;
        }
        Command::Ping(args) => ping(&config, args).await?,
        Command::Split { action } => {
            let section = match action {
                Some(action) => {
                    let section = split(&mut config, action)?;
                    config.save()?;
                    Some(section)
                }
                None => None,
            };
            print_split(&config.split, section);
        }
        Command::ConfigPath => println!("{}", config::config_path().display()),
    }
    Ok(())
}

/// Connect to the running daemon, translating "no socket" into the actionable
/// cause rather than a bare ENOENT.
async fn daemon() -> Result<DaemonClient> {
    DaemonClient::connect_installed().await.map_err(|error| {
        anyhow::anyhow!(
            "{error}\n\nThe varmlend daemon does not appear to be running. Start it with:\n  \
             sudo systemctl start varmlend"
        )
    })
}

async fn connect(config: &mut Config, name: Option<&str>) -> Result<()> {
    let index = match name {
        Some(name) => config.find(name).map_err(anyhow::Error::msg)?,
        None => config.active_index().map_err(anyhow::Error::msg)?,
    };
    // Naming a location is also choosing it: a later bare `connect` reuses it.
    if name.is_some() {
        let chosen = config.locations[index].server.clone();
        config.set_active(&chosen);
        config.save()?;
    }
    let server: &VlessServer = &config.locations[index].server;

    let mode = match config.settings.mode.as_str() {
        "tun" => ConnectionMode::Tun,
        "proxy" => ConnectionMode::Proxy,
        other => bail!("unknown mode {other:?}; expected \"tun\" or \"proxy\""),
    };

    let xray_config = generate_xray_config(
        server.clone(),
        config.split.clone(),
        config.settings.mode.clone(),
        config.settings.allow_lan,
        config.settings.mtu,
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let validation_config = serde_json::to_string(
        &build_connection_probe_config(server).map_err(|error| anyhow::anyhow!("{error}"))?,
    )?;
    // In general (blacklist) mode the listed apps are the ones kept OUT of the
    // tunnel; in selective mode the daemon tunnels them instead, so it must not
    // also receive them as exclusions.
    let excluded_apps = if mode == ConnectionMode::Tun && !config.split.apps_selective() {
        config.split.enabled_apps()
    } else {
        Vec::new()
    };
    let server_ips = resolve_server_ips(server)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    let request = ConnectRequest {
        mode,
        xray_config,
        validation_config,
        server_ips,
        excluded_apps,
        killswitch: config.settings.killswitch,
        allow_lan: config.settings.allow_lan,
    };
    println!(
        "connecting to {}…",
        label(&server.label, config.settings.emoji)
    );
    print_state(&daemon().await?.request(DaemonCommand::Connect(request)).await?);
    Ok(())
}

async fn subscriptions(config: &mut Config, command: SubCommand) -> Result<()> {
    match command {
        SubCommand::Add { url } => {
            if config.subscriptions.iter().any(|sub| sub.url == url) {
                bail!("that subscription is already configured");
            }
            let result = fetch_subscription(url.clone(), config.settings.user_agent.clone())
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            let count = result.servers.len();
            merge(config, result.servers, Some(&url));
            config.subscriptions.push(Subscription {
                url,
                meta: result.meta,
                description: result.description,
            });
            config.save()?;
            println!("imported {count} location(s)");
        }
        SubCommand::List => {
            for sub in &config.subscriptions {
                println!("{}", bold(&sub.display_name()));
                println!("{}", dim(&format!("  {}", sub.url)));
            }
        }
        SubCommand::Update => {
            let urls: Vec<String> = config.subscriptions.iter().map(|s| s.url.clone()).collect();
            if urls.is_empty() {
                bail!("no subscriptions configured");
            }
            for url in urls {
                let result = fetch_subscription(url.clone(), config.settings.user_agent.clone())
                    .await
                    .map_err(|error| anyhow::anyhow!("updating {url}: {error}"))?;
                let count = result.servers.len();
                merge(config, result.servers, Some(&url));
                if let Some(sub) = config.subscriptions.iter_mut().find(|s| s.url == url) {
                    sub.meta = result.meta;
                    sub.description = result.description;
                }
                println!("{url}: {count} location(s)");
            }
            config.save()?;
        }
        SubCommand::Remove { url } => {
            let before = config.subscriptions.len();
            config.subscriptions.retain(|sub| sub.url != url);
            if config.subscriptions.len() == before {
                bail!("no such subscription");
            }
            config.save()?;
            println!("removed");
        }
    }
    Ok(())
}

fn settings(config: &mut Config, command: SetCommand) -> Result<()> {
    fn flag(value: &str) -> Result<bool> {
        match value {
            "on" | "true" | "yes" => Ok(true),
            "off" | "false" | "no" => Ok(false),
            other => bail!("expected on/off, got {other:?}"),
        }
    }
    match command {
        SetCommand::Mode { value } => {
            if value != "tun" && value != "proxy" {
                bail!("expected \"tun\" or \"proxy\", got {value:?}");
            }
            config.settings.mode = value;
        }
        SetCommand::Killswitch { value } => config.settings.killswitch = flag(&value)?,
        SetCommand::AllowLan { value } => config.settings.allow_lan = flag(&value)?,
        SetCommand::Mtu { value } => {
            // Below 1280 the tunnel stops carrying IPv6 rather than fragmenting
            // it, and above the Ethernet payload limit the path will fragment.
            if !(TUN_MTU_MIN..=TUN_MTU_MAX).contains(&value) {
                bail!("MTU must be between {TUN_MTU_MIN} and {TUN_MTU_MAX}");
            }
            config.settings.mtu = value;
        }
        SetCommand::Emoji { value } => config.settings.emoji = flag(&value)?,
        SetCommand::UserAgent { value } => {
            config.settings.user_agent = match value.as_str() {
                "varmlen" => None,
                "happ" | "incy" => Some(value),
                other => bail!("unknown client {other:?}; expected varmlen, happ or incy"),
            };
        }
    }
    println!(
        "mode={} killswitch={} allow-lan={} mtu={} user-agent={} emoji={}",
        config.settings.mode,
        config.settings.killswitch,
        config.settings.allow_lan,
        config.settings.mtu,
        config.settings.user_agent.as_deref().unwrap_or("varmlen"),
        config.settings.emoji,
    );
    Ok(())
}

/// Accept `.example.com` as a spelling of `*.example.com`.
///
/// The wildcard form is what the config stores and what rule generation
/// expects, but `*` is a glob character: typing it unquoted makes the shell
/// try to match files and fail before the CLI ever runs. The leading-dot form
/// means the same thing and survives the shell.
fn normalise_entry(section: Section, value: &str) -> String {
    match section {
        Section::Sites => match value.strip_prefix('.') {
            Some(suffix) if !suffix.is_empty() => format!("*.{suffix}"),
            _ => value.to_string(),
        },
        Section::Apps => value.to_string(),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Section {
    Apps,
    Sites,
}

/// Apply one edit and report which section it touched, so only that one is
/// echoed back.
/// Probe one or more locations.
///
/// A probe that fails is reported against its location and the run continues:
/// with `--all` the interesting result is usually which locations answer at
/// all, and aborting on the first dead one would hide that.
async fn ping(config: &Config, args: PingArgs) -> Result<()> {
    let indices: Vec<usize> = if args.all {
        (0..config.locations.len()).collect()
    } else {
        let name = args.name.join(" ");
        let name = name.trim();
        vec![if name.is_empty() {
            config.active_index().map_err(anyhow::Error::msg)?
        } else {
            config.find(name).map_err(anyhow::Error::msg)?
        }]
    };
    if indices.is_empty() {
        bail!("no locations configured");
    }

    let names: Vec<String> = indices
        .iter()
        .map(|index| {
            label(
                &config.locations[*index].server.label,
                config.settings.emoji,
            )
        })
        .collect();
    let width = names.iter().map(|name| name.chars().count()).max().unwrap_or(0);

    for (index, name) in indices.into_iter().zip(names) {
        let server = &config.locations[index].server;
        print!("{name:<width$}  ", width = width);
        use std::io::Write;
        let _ = std::io::stdout().flush();

        match probe(server, &args).await {
            Ok(rtt) => println!("{rtt} ms"),
            Err(error) => println!("{}", dim(&compact(&error))),
        }
    }
    Ok(())
}

/// The daemon wraps a probe failure in several layers of context
/// ("daemon operation: PingFailed: TCP ping failed: connect: timed out"); in a
/// column of results only the innermost cause carries information.
fn compact(error: &anyhow::Error) -> String {
    let text = format!("{error:#}");
    text.rsplit(": ").next().unwrap_or(&text).to_string()
}

async fn probe(server: &VlessServer, args: &PingArgs) -> Result<u32> {
    let command = if args.tcp {
        DaemonCommand::TcpPing(TcpPingRequest {
            host: server.host.clone(),
            port: server.port,
            timeout_ms: args.timeout,
        })
    } else {
        // The daemon reserves real loopback ports and rewrites the template,
        // so these are placeholders that only have to be distinct.
        let ports = ping_placeholder_ports(server).map_err(|error| anyhow::anyhow!("{error}"))?;
        let config = build_ping_config(server, &ports).map_err(|error| anyhow::anyhow!("{error}"))?;
        DaemonCommand::ProxyPing(ProxyPingRequest {
            xray_config: serde_json::to_string(&config)?,
            socks_port: ports[0],
            socks_ports: ports,
            dns_probe_urls: Vec::new(),
            timeout_ms: args.timeout,
        })
    };
    // A fresh connection per probe: a daemon-side failure must not leave the
    // rest of an --all run talking over a connection in an unknown state.
    let state = daemon().await?.request(command).await?;
    state
        .rtt_ms
        .ok_or_else(|| anyhow::anyhow!("daemon returned no round-trip time"))
}

fn split(config: &mut Config, command: SplitCommand) -> Result<Section> {
    let (section, action, mode, list) = match command {
        SplitCommand::Apps { action } => (
            Section::Apps,
            action,
            &mut config.split.apps_mode,
            &mut config.split.apps,
        ),
        SplitCommand::Sites { action } => (
            Section::Sites,
            action,
            &mut config.split.sites_mode,
            &mut config.split.sites,
        ),
    };
    let Some(action) = action else {
        return Ok(section);
    };
    match action {
        ListCommand::Mode { value } => {
            if value != "selective" && value != "general" {
                bail!("expected \"selective\" or \"general\", got {value:?}");
            }
            *mode = value;
        }
        ListCommand::Add { values } => {
            for value in values {
                let value = normalise_entry(section, value.trim());
                if value.is_empty() || list.contains(&value) {
                    continue;
                }
                list.push(value);
            }
        }
        ListCommand::Remove { values } => {
            let before = list.len();
            let wanted: Vec<String> = values
                .iter()
                .map(|value| normalise_entry(section, value.trim()))
                .collect();
            list.retain(|entry| !wanted.contains(entry));
            if list.len() == before {
                bail!("nothing matched");
            }
        }
        ListCommand::Clear => list.clear(),
    }
    Ok(section)
}

/// Spell out which way each list points: "selective" and "general" invert the
/// meaning of the entries under them, and getting that backwards is the
/// difference between tunnelling one app and tunnelling everything but it.
fn print_split(split: &SplitInput, only: Option<Section>) {
    for (section, caption, mode, entries, selective) in [
        (
            Section::Apps,
            "Apps",
            &split.apps_mode,
            &split.apps,
            split.apps_selective(),
        ),
        (
            Section::Sites,
            "Sites",
            &split.sites_mode,
            &split.sites,
            split.sites_selective(),
        ),
    ] {
        if only.is_some_and(|wanted| wanted != section) {
            continue;
        }
        let mode = if mode.is_empty() { "general" } else { mode };
        println!("{} {}", bold(caption), dim(&format!("({mode})")));
        println!(
            "{}",
            dim(&format!(
                "  {}",
                if selective {
                    "only these go through the tunnel"
                } else {
                    "everything goes through the tunnel except these"
                }
            ))
        );
        if entries.is_empty() {
            println!("{}", dim("  (empty)"));
        } else {
            for entry in entries {
                println!("  {entry}");
            }
        }
    }
}

/// Refresh locations that came back with the same identity, add the rest.
///
/// Keyed on `location_key` rather than the display name: providers reuse names
/// across locations, and matching on one would collapse distinct servers into
/// a single entry.
fn merge(config: &mut Config, incoming: Vec<VlessServer>, source: Option<&str>) {
    for server in incoming {
        let key = location_key(&server);
        match config
            .locations
            .iter_mut()
            .find(|existing| location_key(&existing.server) == key)
        {
            Some(existing) => {
                existing.server = server;
                existing.source = source.map(str::to_string);
            }
            None => config.locations.push(Location {
                server,
                source: source.map(str::to_string),
            }),
        }
    }
}

fn list(config: &Config) {
    if config.locations.is_empty() {
        println!("no locations configured");
        return;
    }

    // Providers reuse display names, so a name alone can be ambiguous. Only
    // then is the endpoint worth the extra noise on the line.
    let duplicated: Vec<&str> = config
        .locations
        .iter()
        .filter(|location| {
            config
                .locations
                .iter()
                .filter(|other| other.server.label == location.server.label)
                .count()
                > 1
        })
        .map(|location| location.server.label.as_str())
        .collect();

    let mut first = true;
    for subscription in &config.subscriptions {
        let members: Vec<usize> = config
            .locations
            .iter()
            .enumerate()
            .filter(|(_, location)| location.source.as_deref() == Some(subscription.url.as_str()))
            .map(|(index, _)| index)
            .collect();
        if members.is_empty() {
            continue;
        }
        if !std::mem::take(&mut first) {
            println!();
        }
        print_subscription(subscription);
        for index in members {
            print_location(config, index, &duplicated);
        }
    }

    let manual: Vec<usize> = config
        .locations
        .iter()
        .enumerate()
        .filter(|(_, location)| location.source.is_none())
        .map(|(index, _)| index)
        .collect();
    if !manual.is_empty() {
        if !std::mem::take(&mut first) {
            println!();
        }
        println!("{}", bold("Added manually"));
        for index in manual {
            print_location(config, index, &duplicated);
        }
    }
}

/// Subscription header: name, then whatever metadata the provider actually
/// sent. Nothing is invented — absent fields simply do not appear.
fn print_subscription(subscription: &Subscription) {
    println!("{}", bold(&subscription.display_name()));

    if let Some(description) = subscription
        .description
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
    {
        for line in description.lines() {
            println!("{}", dim(&format!("  {line}")));
        }
    }

    let meta = &subscription.meta;
    let used = meta.upload_bytes.unwrap_or(0) + meta.download_bytes.unwrap_or(0);
    let mut facts = Vec::new();
    if meta.upload_bytes.is_some() || meta.download_bytes.is_some() {
        facts.push(match meta.total_bytes {
            Some(total) => format!("{} of {} used", bytes(used), bytes(total)),
            None => format!("{} used", bytes(used)),
        });
    }
    if let Some(expiry) = meta.expires_at_unix {
        facts.push(format!("expires {}", date(expiry)));
    }
    if !facts.is_empty() {
        println!("{}", dim(&format!("  {}", facts.join("  ·  "))));
    }

    for (caption, url) in [
        ("support", meta.support_url.as_deref()),
        ("info", meta.web_page_url.as_deref()),
    ] {
        if let Some(url) = url.map(str::trim).filter(|url| !url.is_empty()) {
            println!("{}", dim(&format!("  {caption}: {url}")));
        }
    }
}

fn print_location(config: &Config, index: usize, duplicated: &[&str]) {
    let server = &config.locations[index].server;
    let marker = if config.is_active(server) { "*" } else { " " };
    println!(
        "{marker} {:>3}  {}",
        index + 1,
        label(&server.label, config.settings.emoji)
    );

    let mut summary = transport_summary(server);
    if duplicated.contains(&server.label.as_str()) {
        summary.push_str(&format!("  ·  {}:{}", server.host, server.port));
    }
    println!("{}", dim(&format!("       {summary}")));
}

/// Phase on its own line, with whatever qualifies it underneath: the phase is
/// the answer to "am I connected", and the rest is detail about how.
fn print_state(state: &DaemonState) {
    println!("{:?}", state.phase);

    let mut details = Vec::new();
    if state.split_active {
        details.push("split tunnelling active".to_string());
    }
    if state.dns_protected {
        details.push("DNS protected".to_string());
    }
    if let Some(rtt) = state.rtt_ms {
        details.push(format!("{rtt} ms"));
    }
    if !details.is_empty() {
        println!("{}", dim(&format!("  {}", details.join("  ·  "))));
    }
}
