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

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use varmlen_core::daemon_client::DaemonClient;
use varmlen_core::endpoint::resolve_server_ips;
use varmlen_core::fetch::fetch_subscription;
use varmlen_core::subscription::{parse_proxy_uri, VlessServer};
use varmlen_core::xray::{build_connection_probe_config, generate_xray_config};
use varmlend::protocol::{ConnectRequest, ConnectionMode, DaemonCommand, DaemonState};

use config::{Config, Subscription};

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
            let label = config.find(&name).map_err(anyhow::Error::msg)?.label.clone();
            config.active = Some(label.clone());
            config.save()?;
            println!("active location: {label}");
        }
        Command::Add { uri } => {
            let server = parse_proxy_uri(&uri).map_err(|error| anyhow::anyhow!("{error}"))?;
            let label = server.label.clone();
            merge(&mut config, vec![server]);
            config.save()?;
            println!("added {label}");
        }
        Command::Remove { name } => {
            let label = config.find(&name).map_err(anyhow::Error::msg)?.label.clone();
            config.servers.retain(|server| server.label != label);
            if config.active.as_deref() == Some(label.as_str()) {
                config.active = None;
            }
            config.save()?;
            println!("removed {label}");
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
    let server: &VlessServer = match name {
        Some(name) => config.find(name).map_err(anyhow::Error::msg)?,
        None => config.active_server().map_err(anyhow::Error::msg)?,
    };

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
            let title = result.meta.title.clone();
            merge(config, result.servers);
            config.subscriptions.push(Subscription { url, title });
            config.save()?;
            println!("imported {count} location(s)");
        }
        SubCommand::List => {
            for sub in &config.subscriptions {
                match &sub.title {
                    Some(title) => println!("{title}  {}", sub.url),
                    None => println!("{}", sub.url),
                }
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
                merge(config, result.servers);
                if let Some(sub) = config.subscriptions.iter_mut().find(|s| s.url == url) {
                    sub.title = result.meta.title.clone();
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

/// Replace locations that came back with the same identity, keep the rest.
fn merge(config: &mut Config, incoming: Vec<VlessServer>) {
    for server in incoming {
        match config
            .servers
            .iter_mut()
            .find(|existing| existing.label == server.label)
        {
            Some(existing) => *existing = server,
            None => config.servers.push(server),
        }
    }
}

fn list(config: &Config) {
    if config.servers.is_empty() {
        println!("no locations configured");
        return;
    }
    for server in &config.servers {
        let marker = if config.active.as_deref() == Some(server.label.as_str()) {
            "*"
        } else {
            " "
        };
        println!(
            "{marker} {:<32} {}://{}:{}",
            server.label, server.protocol, server.host, server.port
        );
    }
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
