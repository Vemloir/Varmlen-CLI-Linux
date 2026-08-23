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
use varmlen_core::subscription::{parse_proxy_uri, VlessServer};
use varmlen_core::xray::{build_connection_probe_config, generate_xray_config};
use varmlend::protocol::{ConnectRequest, ConnectionMode, DaemonCommand, DaemonState};

use config::{location_key, Config, Location, Subscription};
use display::{bold, bytes, date, dim};

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
    /// Choose the location used by `connect` with no argument.
    Use { name: String },
    /// Add a location from a vless:// / vmess:// / trojan:// / ss:// URI.
    Add { uri: String },
    /// Remove a location by name.
    Remove { name: String },
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
    /// Print the path of the CLI's config file.
    ConfigPath,
}

#[derive(Args)]
struct ConnectArgs {
    /// Location to connect to; defaults to the active one.
    name: Option<String>,
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

#[derive(Subcommand)]
enum SetCommand {
    /// "tun" routes the whole system; "proxy" only exposes a local SOCKS port.
    Mode { value: String },
    /// Block traffic if the tunnel drops.
    Killswitch { value: String },
    /// Keep LAN reachable while connected.
    AllowLan { value: String },
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
        Command::Connect(args) => connect(&config, args.name.as_deref()).await?,
        Command::Disconnect => {
            print_state(&daemon().await?.request(DaemonCommand::Disconnect).await?)
        }
        Command::List => list(&config),
        Command::Use { name } => {
            let index = config.find(&name).map_err(anyhow::Error::msg)?;
            let server = config.locations[index].server.clone();
            let label = server.label.clone();
            config.set_active(&server);
            config.save()?;
            println!("active location: {label}");
        }
        Command::Add { uri } => {
            let server = parse_proxy_uri(&uri).map_err(|error| anyhow::anyhow!("{error}"))?;
            let label = server.label.clone();
            merge(&mut config, vec![server], None);
            config.save()?;
            println!("added {label}");
        }
        Command::Remove { name } => {
            let index = config.find(&name).map_err(anyhow::Error::msg)?;
            let removed = config.locations.remove(index);
            if config.is_active(&removed.server) {
                config.active = None;
            }
            config.save()?;
            println!("removed {}", removed.server.label);
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

async fn connect(config: &Config, name: Option<&str>) -> Result<()> {
    let index = match name {
        Some(name) => config.find(name).map_err(anyhow::Error::msg)?,
        None => config.active_index().map_err(anyhow::Error::msg)?,
    };
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
    println!("connecting to {}…", server.label);
    print_state(&daemon().await?.request(DaemonCommand::Connect(request)).await?);
    Ok(())
}

async fn subscriptions(config: &mut Config, command: SubCommand) -> Result<()> {
    match command {
        SubCommand::Add { url } => {
            if config.subscriptions.iter().any(|sub| sub.url == url) {
                bail!("that subscription is already configured");
            }
            let result = fetch_subscription(url.clone(), None)
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
                let result = fetch_subscription(url.clone(), None)
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
    }
    println!(
        "mode={} killswitch={} allow-lan={}",
        config.settings.mode, config.settings.killswitch, config.settings.allow_lan
    );
    Ok(())
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
    println!("{marker} {:>3}  {}", index + 1, server.label);

    let mut summary = transport_summary(server);
    if duplicated.contains(&server.label.as_str()) {
        summary.push_str(&format!("  ·  {}:{}", server.host, server.port));
    }
    println!("{}", dim(&format!("       {summary}")));
}

fn print_state(state: &DaemonState) {
    print!("{:?}", state.phase);
    if state.split_active {
        print!("  split");
    }
    if state.dns_protected {
        print!("  dns-protected");
    }
    if let Some(rtt) = state.rtt_ms {
        print!("  {rtt}ms");
    }
    println!();
}
