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
mod setup;

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use varmlen_core::daemon_client::{ClientError, DaemonClient};
use varmlen_core::endpoint::resolve_server_ips;
use varmlen_core::fetch::fetch_subscription;
use varmlen_core::label::transport_summary;
use varmlen_core::ping::{
    proxy_ping_timeout_ms, supports_tcp_endpoint_ping, PROXY_PING_TIMEOUT_MS,
};
use varmlen_core::split::SplitInput;
use varmlen_core::subscription::{parse_proxy_uri, VlessServer};
use varmlen_core::xray::{
    build_connection_probe_config, build_ping_config, generate_xray_config, ping_placeholder_ports,
};
use varmlend::protocol::{
    ApplicationsRequest, ConnectRequest, ConnectionMode, ConnectionPhase, DaemonCommand,
    DaemonErrorCode, DaemonState, ProxyPingRequest, TcpPingRequest,
};

use config::{Config, MergeOutcome, Subscription};
use display::{bold, bytes, date, dim, label, redacted_url};

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
    /// Replace a running daemon with the one that shipped with this client.
    ///
    /// Installing over curl replaces the client binary only: a daemon already
    /// running keeps answering from the files it started with, and the two then
    /// disagree in ways that look like broken features. Restarting drops the
    /// tunnel, so a connected tunnel has to come down first or the update has
    /// to be confirmed with --yes.
    Update {
        /// Restart the daemon even while the tunnel is up.
        #[arg(long)]
        yes: bool,
    },
    /// List configured locations.
    List,
    /// Add a location from a vless:// / vmess:// / trojan:// / ss:// URI.
    Add { uri: String },
    /// Remove a location by its number from `list`, or by name.
    Remove {
        #[arg(num_args = 1.., required = true)]
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
    /// Show or change connection settings. Run without arguments to see the
    /// current values and what each accepts.
    Set {
        #[command(subcommand)]
        action: Option<SetCommand>,
    },
    /// Measure latency to a location.
    Ping(PingArgs),
    /// Choose which apps and sites go through the tunnel.
    Split {
        #[command(subcommand)]
        action: Option<SplitCommand>,
    },
    /// Print the path of the CLI's config file.
    ConfigPath,
    /// Install the daemon. Invoked by the CLI itself through sudo when a
    /// command first needs the daemon; not meant to be run by hand.
    #[command(name = "__install-daemon", hide = true)]
    InstallDaemon {
        #[arg(long)]
        stage: std::path::PathBuf,
        #[arg(long)]
        owner_uid: u32,
        /// Restart the service after installing, to replace a running daemon.
        #[arg(long)]
        restart: bool,
    },
}

#[derive(Args)]
struct ConnectArgs {
    /// Location to connect to: its number from `list`, or its name. Everything
    /// after `connect` is taken as the name, so it needs no quoting. Omit it to
    /// reuse the last location connected to.
    #[arg(num_args = 1..)]
    name: Vec<String>,
}

#[derive(Subcommand)]
enum SubCommand {
    /// Add a subscription URL and import its locations.
    Add { url: String },
    /// List subscriptions.
    List {
        /// Print the full URLs. They contain your account token — only do this
        /// somewhere the output will not be seen or stored.
        #[arg(long)]
        reveal: bool,
    },
    /// Re-fetch subscriptions, replacing their locations.
    Update {
        /// Which one, by number from `sub list` or by name. All of them if
        /// omitted.
        #[arg(num_args = 1..)]
        name: Vec<String>,
    },
    /// Measure latency to every location in a subscription.
    Ping(PingArgs),
    /// Remove a subscription by number from `sub list` or by name. Its
    /// locations are kept.
    Remove {
        #[arg(num_args = 1.., required = true)]
        name: Vec<String>,
    },
}

#[derive(Args)]
struct PingArgs {
    /// Measure a plain TCP handshake to the endpoint instead of probing
    /// through the proxy. Faster, but says nothing about the proxy itself.
    #[arg(long)]
    tcp: bool,
    /// Timeout per probe round, in milliseconds. Defaults to 5000, or 15000 for
    /// a UDP transport (Hysteria2 and QUIC pay a handshake on top of the probe).
    /// A location is only declared dead after two rounds, so the ceiling keeps
    /// the pair inside the daemon's own command timeout.
    #[arg(long, value_parser = clap::value_parser!(u32).range(100..=20_000))]
    timeout: Option<u32>,
    /// What to probe: a location (by number from `list` or by name), a
    /// subscription name to cover everything in it, or `all`. Defaults to the
    /// last location connected to.
    #[arg(num_args = 1..)]
    target: Vec<String>,
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

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Switch {
    On,
    Off,
}

impl From<Switch> for bool {
    fn from(value: Switch) -> Self {
        value == Switch::On
    }
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Mode {
    /// Route the whole system through the tunnel.
    Tun,
    /// Expose a local SOCKS port only; nothing else is redirected.
    Proxy,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Client {
    Varmlen,
    Happ,
    Incy,
}

#[derive(Subcommand)]
enum SetCommand {
    /// How traffic reaches the tunnel.
    Mode { value: Mode },
    /// Block all traffic if the tunnel drops.
    Killswitch { value: Switch },
    /// Keep the local network reachable while connected.
    AllowLan { value: Switch },
    /// Tunnel MTU. Below 1280 the tunnel stops carrying IPv6; above 1500 the
    /// path fragments.
    Mtu {
        #[arg(value_parser = clap::value_parser!(u32).range(1280..=1500))]
        value: u32,
    },
    /// Which client to present as when fetching subscriptions. Panels serve
    /// different payloads per client.
    UserAgent { value: Client },
    /// Show emoji in location names. Turn off for terminals that cannot draw
    /// them; flags become country codes rather than disappearing.
    Emoji { value: Switch },
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
        Command::Status => {
            let mut client = daemon().await?;
            let state = client.request(DaemonCommand::Status).await?;
            print_state(&state);
            print_version_hint(client.daemon_version());
        }
        Command::Connect(args) => {
            let name = args.name.join(" ");
            let name = name.trim();
            connect(&mut config, (!name.is_empty()).then_some(name)).await?
        }
        Command::Disconnect => {
            print_state(&daemon().await?.request(DaemonCommand::Disconnect).await?)
        }
        Command::Update { yes } => update(yes).await?,
        Command::List => list(&config),
        Command::Add { uri } => {
            let server = parse_proxy_uri(&uri).map_err(|error| anyhow::anyhow!("{error}"))?;
            let label = server.label.clone();
            let outcome = config.merge(vec![server], None).remove(0);
            config.save()?;
            report_add(&config, &label, outcome);
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
        Command::Set { action } => {
            if let Some(action) = action {
                settings(&mut config, action)?;
                config.save()?;
            }
            print_settings(&config.settings);
        }
        Command::Ping(args) => ping(&config, args, Scope::Auto).await?,
        Command::Split { action } => {
            let section = match action {
                Some(action) => {
                    let section = split(&mut config, action)?;
                    config.save()?;
                    if section == Section::Apps {
                        apply_split_live(&config).await;
                    }
                    Some(section)
                }
                None => None,
            };
            print_split(&config.split, section);
        }
        Command::ConfigPath => println!("{}", config::config_path().display()),
        Command::InstallDaemon {
            stage,
            owner_uid,
            restart,
        } => setup::install_as_root(&stage, owner_uid, restart)?,
    }
    Ok(())
}

/// Hand an edited app list to a tunnel that is already up.
///
/// Split rules used to be read at connect only, so `split apps add` looked like
/// it had done nothing until the tunnel was cycled, and a rule that had been
/// removed kept the application going direct.  Not being connected, or a
/// daemon that predates this command, is normal here: the list is applied when
/// the tunnel comes up, which is what the line says.
async fn apply_split_live(config: &Config) {
    let applications = if config.split.apps_selective() {
        Vec::new()
    } else {
        config.split.enabled_apps()
    };
    let note = match daemon().await {
        Err(error) => format!("will apply on connect: {error}"),
        Ok(mut client) => {
            match client
                .request(DaemonCommand::UpdateSplit(ApplicationsRequest {
                    applications,
                }))
                .await
            {
                Ok(_) => "applied to the running tunnel".to_string(),
                Err(error) => format!("will apply on connect: {error}"),
            }
        }
    };
    println!("{}", dim(&note));
}

/// Replace a daemon that is older than this client.
///
/// Client and daemon ship from one tree, but installing replaces the client
/// alone: a daemon that was already running keeps answering from the files it
/// started from, and nothing about a working `status` says it is stale. The
/// difference surfaces as a command the daemon refuses to understand.
async fn update(yes: bool) -> Result<()> {
    let mut client = daemon().await?;
    let state = client.request(DaemonCommand::Status).await?;
    let running = client.daemon_version().to_string();
    // The version of the daemon this client was built alongside, not the
    // client's own: the two are released together but are separately versioned
    // crates, and it is the daemon being replaced here.
    let shipped = varmlend::protocol::daemon_version();
    if running == shipped {
        println!("The daemon is already {shipped}.");
        return Ok(());
    }
    println!(
        "{}",
        if running.is_empty() {
            format!("The running daemon predates version reporting; this client ships {shipped}.")
        } else {
            format!("The running daemon is {running}; this client ships {shipped}.")
        }
    );
    if state.phase == ConnectionPhase::Connected && !yes {
        bail!("replacing the daemon brings the tunnel down; disconnect first, or re-run with --yes");
    }

    let socket = DaemonClient::installed_socket_path();
    tokio::task::spawn_blocking(move || {
        setup::elevate_and_install(
            || std::os::unix::net::UnixStream::connect(&socket).is_ok(),
            setup::Install::Outdated,
        )
    })
    .await??;
    println!("Daemon replaced with {shipped}.");
    if state.phase == ConnectionPhase::Connected {
        println!("The tunnel went down with the old daemon: varmlen-cli connect");
    }
    Ok(())
}

/// Say so when the daemon answering is not the daemon this client was built
/// with, rather than leaving the user to discover it from a refused command.
fn print_version_hint(daemon_version: &str) {
    let shipped = varmlend::protocol::daemon_version();
    if daemon_version == shipped {
        return;
    }
    let stale = if daemon_version.is_empty() {
        "daemon reports no version, so it predates this client — run: varmlen-cli update".to_string()
    } else {
        format!("daemon {daemon_version}, client {shipped} — run: varmlen-cli update")
    };
    println!("{}", dim(&stale));
}

/// Connect to the daemon, installing and starting it if this is the first time.
///
/// Installation is deferred to here rather than done by the installer so that
/// getting the client needs no privileges at all; root is asked for at the
/// first moment it is actually required, and only then.
async fn daemon() -> Result<DaemonClient> {
    if let Ok(client) = DaemonClient::connect_installed().await {
        return Ok(client);
    }

    let socket = DaemonClient::installed_socket_path();
    let reason = if setup::installed() {
        setup::Install::Stopped
    } else {
        setup::Install::Missing
    };
    tokio::task::spawn_blocking(move || {
        setup::elevate_and_install(
            || std::os::unix::net::UnixStream::connect(&socket).is_ok(),
            reason,
        )
    })
    .await??;

    DaemonClient::connect_installed()
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))
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
    print_state(
        &daemon()
            .await?
            .request(DaemonCommand::Connect(request))
            .await?,
    );
    Ok(())
}

/// Resolve a subscription by its number in `sub list` or by name, so nobody has
/// to paste a URL that carries their token just to name one.
fn find_subscription(config: &Config, needle: &str) -> Result<usize> {
    if let Ok(number) = needle.parse::<usize>() {
        return number
            .checked_sub(1)
            .filter(|index| *index < config.subscriptions.len())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no subscription {number}; there are {}",
                    config.subscriptions.len()
                )
            });
    }
    let lowered = needle.to_lowercase();
    let matches: Vec<usize> = config
        .subscriptions
        .iter()
        .enumerate()
        .filter(|(_, sub)| {
            sub.display_name().to_lowercase().contains(&lowered) || sub.url == needle
        })
        .map(|(index, _)| index)
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => bail!("no subscription matches {needle:?}"),
        many => bail!(
            "{needle:?} matches {} subscriptions — select by number",
            many.len()
        ),
    }
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
            config.merge(result.servers, Some(&url));
            config.subscriptions.push(Subscription {
                url,
                meta: result.meta,
                description: result.description,
            });
            config.save()?;
            println!("imported {count} location(s)");
        }
        SubCommand::Ping(args) => return ping(config, args, Scope::Subscription).await,
        SubCommand::List { reveal } => {
            if config.subscriptions.is_empty() {
                println!("no subscriptions configured");
                return Ok(());
            }
            for (index, sub) in config.subscriptions.iter().enumerate() {
                println!("{:>3}  {}", index + 1, bold(&sub.display_name()));
                let url = if reveal {
                    sub.url.clone()
                } else {
                    redacted_url(&sub.url)
                };
                println!("{}", dim(&format!("     {url}")));
                println!(
                    "{}",
                    dim(&format!(
                        "     {} location(s)",
                        config
                            .locations
                            .iter()
                            .filter(|l| l.source.as_deref() == Some(sub.url.as_str()))
                            .count()
                    ))
                );
            }
        }
        SubCommand::Update { name } => {
            let name = name.join(" ");
            let urls: Vec<String> = match name.trim() {
                "" => config.subscriptions.iter().map(|s| s.url.clone()).collect(),
                needle => vec![config.subscriptions[find_subscription(config, needle)?]
                    .url
                    .clone()],
            };
            if urls.is_empty() {
                bail!("no subscriptions configured");
            }
            for url in urls {
                let result = fetch_subscription(url.clone(), config.settings.user_agent.clone())
                    .await
                    .map_err(|error| anyhow::anyhow!("updating {}: {error}", redacted_url(&url)))?;
                let count = result.servers.len();
                config.merge(result.servers, Some(&url));
                if let Some(sub) = config.subscriptions.iter_mut().find(|s| s.url == url) {
                    sub.meta = result.meta;
                    sub.description = result.description;
                }
                let name = config
                    .subscriptions
                    .iter()
                    .find(|s| s.url == url)
                    .map(|s| s.display_name())
                    .unwrap_or_else(|| redacted_url(&url));
                println!("{name}: {count} location(s)");
            }
            config.save()?;
        }
        SubCommand::Remove { name } => {
            let index = find_subscription(config, name.join(" ").trim())?;
            let removed = config.subscriptions.remove(index);
            config.save()?;
            println!("removed {}", removed.display_name());
        }
    }
    Ok(())
}

fn settings(config: &mut Config, command: SetCommand) -> Result<()> {
    match command {
        SetCommand::Mode { value } => {
            config.settings.mode = match value {
                Mode::Tun => "tun",
                Mode::Proxy => "proxy",
            }
            .to_string();
        }
        SetCommand::Killswitch { value } => config.settings.killswitch = value.into(),
        SetCommand::AllowLan { value } => config.settings.allow_lan = value.into(),
        SetCommand::Emoji { value } => config.settings.emoji = value.into(),
        SetCommand::UserAgent { value } => {
            config.settings.user_agent = match value {
                Client::Varmlen => None,
                Client::Happ => Some("happ".to_string()),
                Client::Incy => Some("incy".to_string()),
            };
        }
        SetCommand::Mtu { value } => config.settings.mtu = value,
    }
    Ok(())
}

/// Show every setting with its current value and what it accepts, so the answer
/// to "what can I put here" comes from the same command that changes it.
fn print_settings(settings: &config::Settings) {
    let on_off = |value: bool| if value { "on" } else { "off" };
    let rows = [
        ("mode", settings.mode.clone(), "tun | proxy"),
        (
            "killswitch",
            on_off(settings.killswitch).to_string(),
            "on | off",
        ),
        (
            "allow-lan",
            on_off(settings.allow_lan).to_string(),
            "on | off",
        ),
        ("mtu", settings.mtu.to_string(), "1280-1500"),
        (
            "user-agent",
            settings
                .user_agent
                .clone()
                .unwrap_or_else(|| "varmlen".to_string()),
            "varmlen | happ | incy",
        ),
        ("emoji", on_off(settings.emoji).to_string(), "on | off"),
    ];
    let name_width = rows
        .iter()
        .map(|(name, _, _)| name.len())
        .max()
        .unwrap_or(0);
    let value_width = rows
        .iter()
        .map(|(_, value, _)| value.chars().count())
        .max()
        .unwrap_or(0);
    for (name, value, accepts) in rows {
        println!(
            "  {name:<name_width$}  {value:<value_width$}  {}",
            dim(&format!("({accepts})"))
        );
    }
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
/// Whether the target names a subscription for certain, or has to be worked out.
#[derive(Clone, Copy, PartialEq)]
enum Scope {
    Auto,
    Subscription,
}

async fn ping(config: &Config, args: PingArgs, scope: Scope) -> Result<()> {
    let target = args.target.join(" ");
    let indices = ping_targets(config, target.trim(), scope)?;
    if indices.is_empty() {
        bail!("nothing to probe");
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
    let width = names
        .iter()
        .map(|name| name.chars().count())
        .max()
        .unwrap_or(0);

    // Probes are independent, and a sequential sweep of a whole subscription is
    // dominated by the timeouts of whichever locations are down. Proxy probes
    // each cost the daemon a throwaway xray process, so they run far fewer at a
    // time than bare handshakes.
    // `--tcp` still has to fall back to a proxy probe on the UDP locations, and
    // those are the expensive kind, so the wide window only applies when every
    // target really answers a bare handshake.
    let bare_tcp = args.tcp
        && indices
            .iter()
            .all(|index| supports_tcp_endpoint_ping(&config.locations[*index].server));
    let limit = if bare_tcp { 16 } else { 4 };
    let permits = Arc::new(Semaphore::new(limit));
    let mut tasks = JoinSet::new();
    for (position, index) in indices.iter().enumerate() {
        let server = config.locations[*index].server.clone();
        let permits = Arc::clone(&permits);
        let (tcp, timeout) = (args.tcp, args.timeout);
        tasks.spawn(async move {
            let _permit = permits.acquire().await;
            (position, probe(&server, tcp, timeout).await)
        });
    }

    let mut results: Vec<Option<Result<u32>>> = (0..indices.len()).map(|_| None).collect();
    while let Some(finished) = tasks.join_next().await {
        let (position, outcome) = finished?;
        results[position] = Some(outcome);
    }

    // Reported in list order rather than by latency, so the number beside a
    // result is the number to hand to `connect`.
    for (name, outcome) in names.into_iter().zip(results) {
        print!("{name:<width$}  ", width = width);
        match outcome {
            Some(Ok(rtt)) => println!("{rtt} ms"),
            Some(Err(error)) => println!("{}", dim(&compact(&error))),
            None => println!("{}", dim("not probed")),
        }
    }
    Ok(())
}

/// Resolve what to probe.
///
/// With no qualifier a location wins over a subscription of the same name,
/// since numbers and location names are what `list` puts in front of the user.
/// `ping sub <n>` (and `sub ping <n>`) say which was meant when both would
/// match, and are also just easier to reach for.
fn ping_targets(config: &Config, target: &str, scope: Scope) -> Result<Vec<usize>> {
    let mut scope = scope;
    let mut target = target;

    if let Some(rest) = target.strip_prefix("sub ") {
        scope = Scope::Subscription;
        target = rest.trim();
    } else if target == "sub" {
        bail!("name a subscription: `ping sub <number|name>`, or see `sub list`");
    }

    if scope == Scope::Subscription {
        if target.is_empty() {
            bail!("name a subscription: `ping sub <number|name>`, or see `sub list`");
        }
        return Ok(subscription_locations(config, target)?);
    }
    if target.eq_ignore_ascii_case("all") {
        return Ok((0..config.locations.len()).collect());
    }
    if target.is_empty() {
        return Ok(vec![config.active_index().map_err(anyhow::Error::msg)?]);
    }
    if let Ok(index) = config.find(target) {
        return Ok(vec![index]);
    }
    subscription_locations(config, target)
        .map_err(|_| anyhow::anyhow!("no location or subscription matches {target:?}; try `all`"))
}

fn subscription_locations(config: &Config, target: &str) -> Result<Vec<usize>> {
    let subscription = find_subscription(config, target)?;
    let url = config.subscriptions[subscription].url.as_str();
    let indices: Vec<usize> = config
        .locations
        .iter()
        .enumerate()
        .filter(|(_, location)| location.source.as_deref() == Some(url))
        .map(|(index, _)| index)
        .collect();
    if indices.is_empty() {
        bail!(
            "{} has no locations yet — run `sub update {target}`",
            config.subscriptions[subscription].display_name()
        );
    }
    Ok(indices)
}

/// The daemon wraps a probe failure in several layers of context
/// ("daemon operation: PingFailed: TCP ping failed: connect: timed out"); in a
/// column of results only the innermost cause carries information.
fn compact(error: &anyhow::Error) -> String {
    let text = format!("{error:#}");
    text.rsplit(": ").next().unwrap_or(&text).to_string()
}

/// The ping ceiling of a daemon built before UDP probes were given 15 s.
///
/// Upgrading the client never interrupts a running tunnel, so the daemon that
/// is still answering may be the old one. Its ceiling used to turn every
/// Hysteria2 probe into a rejection, so step down to it instead of reporting a
/// live location as unpingable.
const LEGACY_MAX_PING_TIMEOUT_MS: u32 = 10_000;

fn proxy_ping_command(server: &VlessServer, timeout: u32) -> Result<DaemonCommand> {
    // The daemon reserves real loopback ports and rewrites the template, so
    // these are placeholders that only have to be distinct.
    let ports = ping_placeholder_ports(server).map_err(|error| anyhow::anyhow!("{error}"))?;
    let config = build_ping_config(server, &ports).map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(DaemonCommand::ProxyPing(ProxyPingRequest {
        xray_config: serde_json::to_string(&config)?,
        socks_port: ports[0],
        socks_ports: ports,
        dns_probe_urls: Vec::new(),
        timeout_ms: timeout,
    }))
}

/// Ask the daemon one thing and read the round-trip time back.
///
/// A fresh connection per probe: a daemon-side failure must not leave the rest
/// of an `--all` run talking over a connection in an unknown state.
async fn send(command: DaemonCommand) -> Result<u32> {
    let state = daemon().await?.request(command).await?;
    state
        .rtt_ms
        .ok_or_else(|| anyhow::anyhow!("daemon returned no round-trip time"))
}

async fn probe(server: &VlessServer, tcp: bool, timeout: Option<u32>) -> Result<u32> {
    // A UDP endpoint listens on UDP, so a bare TCP handshake there measures the
    // absence of a protocol rather than the location. Probe the proxy instead,
    // exactly as the desktop client does.
    let tcp = tcp && supports_tcp_endpoint_ping(server);
    let timeout = timeout.unwrap_or(if tcp {
        PROXY_PING_TIMEOUT_MS
    } else {
        proxy_ping_timeout_ms(server)
    });
    if tcp {
        return send(DaemonCommand::TcpPing(TcpPingRequest {
            host: server.host.clone(),
            port: server.port,
            timeout_ms: timeout,
        }))
        .await;
    }
    let error = match send(proxy_ping_command(server, timeout)?).await {
        Ok(rtt) => return Ok(rtt),
        Err(error) => error,
    };
    let rejected_by_an_old_daemon = matches!(
        error.downcast_ref::<ClientError>(),
        Some(ClientError::Daemon(DaemonErrorCode::InvalidRequest, _))
    );
    if rejected_by_an_old_daemon && timeout > LEGACY_MAX_PING_TIMEOUT_MS {
        return send(proxy_ping_command(server, LEGACY_MAX_PING_TIMEOUT_MS)?).await;
    }
    Err(error)
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

/// Tell the user what `add` did, because more than one thing is possible and
/// only one of them is called "added".
fn report_add(config: &Config, label: &str, outcome: MergeOutcome) {
    let shown = display::label(label, config.settings.emoji);
    match outcome {
        MergeOutcome::Added => println!("added {shown}"),
        MergeOutcome::Replaced => println!("updated {shown}"),
        MergeOutcome::Kept {
            subscription: Some(url),
            provider_payload,
        } => {
            let owner = config
                .subscriptions
                .iter()
                .find(|sub| sub.url == url)
                .map(Subscription::display_name)
                .unwrap_or_else(|| redacted_url(&url));
            let kept = if provider_payload {
                "kept its provider profile and its place in the subscription"
            } else {
                "kept as the subscription's own location"
            };
            println!(
                "{shown} already comes from {owner} -- {kept}.\n  \
                 Refresh it with `varmlen-cli sub update`"
            );
        }
        MergeOutcome::Kept {
            subscription: None,
            provider_payload: true,
        } => println!(
            "{shown} already holds the provider's own JSON -- kept it.\n  \
             Remove it first to replace it with this link"
        ),
        MergeOutcome::Kept {
            subscription: None,
            provider_payload: false,
        } => println!(
            "{shown} is already configured -- kept it.\n  \
             Remove it first to replace it with this link"
        ),
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
