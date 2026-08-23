use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::stream::{FuturesUnordered, StreamExt};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Duration, Instant};

use crate::dns::{DnsBackend, DnsGuard, SystemDnsBackend};
use crate::lifecycle::LifecycleBackend;
use crate::log_store::LogStore;
use crate::protocol::{
    ConnectRequest, ConnectionMode, DaemonError, DaemonErrorCode, ProxyPingRequest, TcpPingRequest,
    MAX_SERVER_IPS,
};
use crate::recovery::ProcessIdentity;
use crate::split::system::SystemSplitBackend;
use crate::split::{SplitBackend, SplitManager, SplitPlan};

pub const INSTALLED_XRAY: &str = "/usr/libexec/varmlen/xray";
pub const INSTALLED_NET_HELPER: &str = "/usr/libexec/varmlen/varmlen-net";
const TUN_INTERFACE: &str = "varmlen0";
const PROXY_PORT: u16 = 2081;
const XRAY_DIAL_MARK: u64 = 0x2024;
static PING_CONFIG_ID: AtomicU64 = AtomicU64::new(1);
const PROXY_PING_URLS: &[&str] = &[
    "http://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
];
const DNS_PROBE_QUERY: &[u8] = &[
    0x56, 0x4d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w', b'w',
    0x07, b'g', b's', b't', b'a', b't', b'i', b'c', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
    0x01,
];

fn build_proxy_ping_request(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    client.head(url)
}

fn build_proxy_dns_probe_request(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    client
        .post(url)
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .body(DNS_PROBE_QUERY)
}

fn validate_dns_probe_response(body: &[u8]) -> Result<(), DaemonError> {
    let failed = |message| DaemonError::new(DaemonErrorCode::PingFailed, message);
    if body.len() < 12 {
        return Err(failed("DNS probe returned a truncated response"));
    }
    if body[0..2] != DNS_PROBE_QUERY[0..2] {
        return Err(failed("DNS probe returned a mismatched transaction"));
    }
    if body[2] & 0x80 == 0 {
        return Err(failed("DNS probe did not return a response packet"));
    }
    if body[3] & 0x0f != 0 {
        return Err(DaemonError::new(
            DaemonErrorCode::PingFailed,
            format!("DNS probe failed with RCODE {}", body[3] & 0x0f),
        ));
    }
    Ok(())
}

async fn probe_http_url_through_proxy(
    client: &reqwest::Client,
    url: &str,
) -> Result<u32, DaemonError> {
    let started = Instant::now();
    let response = build_proxy_ping_request(client, url)
        .send()
        .await
        .map_err(|error| {
            DaemonError::new(
                DaemonErrorCode::PingFailed,
                format!("HTTP ping {url} failed: {error}"),
            )
        })?;
    if response.status().as_u16() != 204 {
        return Err(DaemonError::new(
            DaemonErrorCode::PingFailed,
            format!("HTTP ping {url} returned status {}", response.status()),
        ));
    }
    Ok(started.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

async fn probe_http_through_proxy(client: &reqwest::Client) -> Result<u32, DaemonError> {
    first_success(
        PROXY_PING_URLS
            .iter()
            .map(|url| probe_http_url_through_proxy(client, url)),
    )
    .await
    .ok_or_else(|| {
        DaemonError::new(
            DaemonErrorCode::PingFailed,
            "every HTTP connectivity probe failed through the proxy",
        )
    })
}

async fn probe_dns_url_through_proxy(
    client: &reqwest::Client,
    url: &str,
) -> Result<(), DaemonError> {
    let response = build_proxy_dns_probe_request(client, url)
        .send()
        .await
        .map_err(|error| {
            DaemonError::new(
                DaemonErrorCode::PingFailed,
                format!("DNS probe {url} failed: {error}"),
            )
        })?;
    if response.status().as_u16() != 200 {
        return Err(DaemonError::new(
            DaemonErrorCode::PingFailed,
            format!("DNS probe returned HTTP {}", response.status()),
        ));
    }
    let body = response.bytes().await.map_err(|error| {
        DaemonError::new(
            DaemonErrorCode::PingFailed,
            format!("could not read DNS probe response: {error}"),
        )
    })?;
    validate_dns_probe_response(&body)
}

async fn probe_dns_through_proxy(
    client: &reqwest::Client,
    urls: &[String],
) -> Result<(), DaemonError> {
    first_success(
        urls.iter()
            .map(|url| probe_dns_url_through_proxy(client, url)),
    )
    .await
    .ok_or_else(|| {
        DaemonError::new(
            DaemonErrorCode::PingFailed,
            "every configured DNS resolver failed through the proxy",
        )
    })
}

fn proxy_probe_client(
    port: u16,
    timeout_duration: Duration,
) -> Result<reqwest::Client, DaemonError> {
    reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).map_err(|error| {
                DaemonError::new(
                    DaemonErrorCode::PingFailed,
                    format!("could not configure ping proxy: {error}"),
                )
            })?,
        )
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout_duration)
        .build()
        .map_err(|error| {
            DaemonError::new(
                DaemonErrorCode::PingFailed,
                format!("could not build ping HTTP client: {error}"),
            )
        })
}

async fn probe_http_port(port: u16, timeout_duration: Duration) -> Result<u32, DaemonError> {
    let client = proxy_probe_client(port, timeout_duration)?;
    probe_http_through_proxy(&client).await
}

async fn probe_proxy_port(
    port: u16,
    timeout_duration: Duration,
    dns_probe_urls: &[String],
) -> Result<u32, DaemonError> {
    let client = proxy_probe_client(port, timeout_duration)?;
    if dns_probe_urls.is_empty() {
        return probe_http_through_proxy(&client).await;
    }
    let (http_rtt, ()) = tokio::try_join!(
        probe_http_through_proxy(&client),
        probe_dns_through_proxy(&client, dns_probe_urls),
    )?;
    Ok(http_rtt)
}

async fn first_success<T, E, I, F>(futures: I) -> Option<T>
where
    I: IntoIterator<Item = F>,
    F: std::future::Future<Output = Result<T, E>>,
{
    let mut pending = futures.into_iter().collect::<FuturesUnordered<_>>();
    while let Some(result) = pending.next().await {
        if let Ok(value) = result {
            return Some(value);
        }
    }
    None
}

pub async fn run_tcp_ping(request: &TcpPingRequest) -> Result<u32, DaemonError> {
    let helper = Path::new(INSTALLED_NET_HELPER);
    ensure_trusted_binary(helper)?;
    let output = timeout(
        Duration::from_millis(request.timeout_ms as u64 + 500),
        Command::new(helper)
            .args([
                "tcp",
                &request.host,
                &request.port.to_string(),
                &request.timeout_ms.to_string(),
            ])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output(),
    )
    .await
    .map_err(|_| DaemonError::new(DaemonErrorCode::PingFailed, "TCP ping timed out"))?
    .map_err(|error| {
        DaemonError::new(
            DaemonErrorCode::PingFailed,
            format!("could not start network ping helper: {error}"),
        )
    })?;
    if !output.status.success() {
        return Err(DaemonError::new(
            DaemonErrorCode::PingFailed,
            format!(
                "TCP ping failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|_| {
            DaemonError::new(
                DaemonErrorCode::PingFailed,
                "network ping helper returned an invalid RTT",
            )
        })
}

pub async fn run_proxy_ping(
    owner_uid: u32,
    request: &ProxyPingRequest,
) -> Result<u32, DaemonError> {
    let xray = Path::new(INSTALLED_XRAY);
    ensure_trusted_binary(xray)?;
    let template_ports = request.effective_socks_ports();
    let dns_probe_urls = request.effective_dns_probe_urls();
    validate_ping_xray_document(&request.xray_config, &template_ports)?;

    let runtime_dir = PathBuf::from(format!("/run/varmlen/user-{owner_uid}"));
    fs::create_dir_all(&runtime_dir).map_err(internal_io("create ping runtime directory"))?;
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700))
        .map_err(internal_io("secure ping runtime directory"))?;
    let sequence = PING_CONFIG_ID.fetch_add(1, Ordering::Relaxed);
    let mut last_start_error = None;
    for attempt in 0..4 {
        let reservations = (0..template_ports.len())
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                DaemonError::new(
                    DaemonErrorCode::PingFailed,
                    format!("could not reserve ping ports: {error}"),
                )
            })?;
        let ports = reservations
            .iter()
            .map(|listener| listener.local_addr().map(|address| address.port()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal_io("read reserved ping port"))?;
        let config = validation_config_with_ports(&request.xray_config, &ports)?;
        validate_ping_xray_document(&config, &ports)?;
        let config_path = runtime_dir.join(format!(
            "ping-{}-{}-{sequence}-{attempt}.json",
            ports[0],
            std::process::id()
        ));
        write_private_file(&config_path, &config)?;

        // Xray cannot inherit the reserved sockets. If another local process
        // wins the tiny release/spawn window, Xray exits and the daemon owns
        // the complete retry instead of trusting stale ports from the GUI.
        drop(reservations);
        let mut child = match Command::new(xray)
            .args(["run", "-c"])
            .arg(&config_path)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                let _ = fs::remove_file(&config_path);
                last_start_error = Some(DaemonError::new(
                    DaemonErrorCode::PingFailed,
                    format!("could not start ping Xray: {error}"),
                ));
                continue;
            }
        };

        let readiness = timeout(
            Duration::from_millis(request.timeout_ms.min(2_000).into()),
            async {
                loop {
                    if child.try_wait().is_ok_and(|status| status.is_some()) {
                        return Err(DaemonError::new(
                            DaemonErrorCode::PingFailed,
                            "ping Xray exited before its SOCKS listeners were ready",
                        ));
                    }
                    let checks = ports.iter().copied().map(|port| async move {
                        timeout(
                            Duration::from_millis(100),
                            tokio::net::TcpStream::connect(("127.0.0.1", port)),
                        )
                        .await
                        .is_ok_and(|result| result.is_ok())
                    });
                    if futures_util::future::join_all(checks)
                        .await
                        .into_iter()
                        .all(|ready| ready)
                    {
                        return Ok(());
                    }
                    sleep(Duration::from_millis(50)).await;
                }
            },
        )
        .await
        .map_err(|_| {
            DaemonError::new(
                DaemonErrorCode::PingFailed,
                "ping Xray listener startup timed out",
            )
        })
        .and_then(|result| result);

        if let Err(error) = readiness {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = fs::remove_file(&config_path);
            last_start_error = Some(error);
            continue;
        }

        let result = first_success(ports.iter().copied().map(|port| {
            probe_proxy_port(
                port,
                Duration::from_millis(request.timeout_ms.into()),
                &dns_probe_urls,
            )
        }))
        .await
        .ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::PingFailed,
                "HTTP ping failed through every proxy path",
            )
        });
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = fs::remove_file(&config_path);
        return result;
    }

    Err(last_start_error.unwrap_or_else(|| {
        DaemonError::new(
            DaemonErrorCode::PingFailed,
            "could not start ping Xray on daemon-owned ports",
        )
    }))
}

fn write_private_file(path: &Path, content: &str) -> Result<(), DaemonError> {
    let temporary = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        PING_CONFIG_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, content.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(internal_io("write private ping configuration"))
}

pub struct SystemLifecycleBackend {
    owner_uid: u32,
    xray_path: PathBuf,
    net_helper_path: PathBuf,
    runtime_dir: PathBuf,
    xray: Option<Child>,
    xray_identity: Option<ProcessIdentity>,
    mode: Option<ConnectionMode>,
    dns_active: bool,
    split: Option<SplitManager<SystemSplitBackend>>,
    split_apps: Vec<String>,
    log_store: Arc<Mutex<LogStore>>,
    log_tasks: Vec<JoinHandle<()>>,
}

impl SystemLifecycleBackend {
    pub fn installed(owner_uid: u32) -> Self {
        Self::new(
            owner_uid,
            PathBuf::from(INSTALLED_XRAY),
            PathBuf::from(INSTALLED_NET_HELPER),
            PathBuf::from(format!("/run/varmlen/user-{owner_uid}")),
        )
    }

    pub fn new(
        owner_uid: u32,
        xray_path: PathBuf,
        net_helper_path: PathBuf,
        runtime_dir: PathBuf,
    ) -> Self {
        Self {
            owner_uid,
            xray_path,
            net_helper_path,
            runtime_dir,
            xray: None,
            xray_identity: None,
            mode: None,
            dns_active: false,
            split: None,
            split_apps: Vec::new(),
            log_store: Arc::new(Mutex::new(LogStore::for_owner(owner_uid))),
            log_tasks: Vec::new(),
        }
    }

    pub fn xray_identity(&self) -> Option<ProcessIdentity> {
        self.xray_identity.clone()
    }

    pub fn log_store(&self) -> Arc<Mutex<LogStore>> {
        Arc::clone(&self.log_store)
    }

    pub fn child_is_running(&mut self) -> bool {
        self.xray
            .as_mut()
            .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_none()))
    }

    fn config_path(&self) -> PathBuf {
        self.runtime_dir.join("xray.json")
    }

    fn validation_path(&self) -> PathBuf {
        self.runtime_dir.join("xray-validation.json")
    }

    fn prepare_runtime_dir(&self) -> Result<(), DaemonError> {
        fs::create_dir_all(&self.runtime_dir).map_err(internal_io("create runtime directory"))?;
        fs::set_permissions(&self.runtime_dir, fs::Permissions::from_mode(0o700))
            .map_err(internal_io("secure runtime directory"))?;
        Ok(())
    }

    fn write_private(&self, path: &Path, content: &str) -> Result<(), DaemonError> {
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            std::io::Write::write_all(&mut file, content.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            Ok::<(), std::io::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(internal_io("write private Xray configuration"))
    }

    async fn run_xray_validation(&self, path: &Path) -> Result<(), DaemonError> {
        let output = Command::new(&self.xray_path)
            .args(["run", "-test", "-c"])
            .arg(path)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output()
            .await
            .map_err(|error| {
                DaemonError::new(
                    DaemonErrorCode::XrayValidationFailed,
                    format!("could not start Xray validation: {error}"),
                )
            })?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(DaemonError::new(
            DaemonErrorCode::XrayValidationFailed,
            format!(
                "Xray rejected the generated configuration: {}",
                stderr.trim()
            ),
        ))
    }

    async fn run_validation_egress_probe(&self, config: &str) -> Result<(), DaemonError> {
        let template_ports = validation_config_ports(config)?;
        let mut last_error = None;
        for _ in 0..4 {
            let reservations = (0..template_ports.len())
                .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    DaemonError::new(
                        DaemonErrorCode::XrayValidationFailed,
                        format!("could not reserve validation ports: {error}"),
                    )
                })?;
            let ports = reservations
                .iter()
                .map(|reservation| {
                    reservation
                        .local_addr()
                        .map(|address| address.port())
                        .map_err(internal_io("read validation port"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let config = validation_config_with_ports(config, &ports)?;
            validate_ping_xray_document(&config, &ports)?;
            self.write_private(&self.validation_path(), &config)?;
            self.run_xray_validation(&self.validation_path()).await?;
            drop(reservations);

            let mut child = Command::new(&self.xray_path)
                .args(["run", "-c"])
                .arg(self.validation_path())
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| {
                    DaemonError::new(
                        DaemonErrorCode::XrayValidationFailed,
                        format!("could not start Xray egress validation: {error}"),
                    )
                })?;
            let result = timeout(Duration::from_secs(12), async {
                loop {
                    if child.try_wait().is_ok_and(|status| status.is_some()) {
                        return Err(DaemonError::new(
                            DaemonErrorCode::XrayValidationFailed,
                            "validation Xray exited before its proxy became ready",
                        ));
                    }
                    let readiness = ports.iter().copied().map(|port| async move {
                        timeout(
                            Duration::from_millis(100),
                            tokio::net::TcpStream::connect(("127.0.0.1", port)),
                        )
                        .await
                        .is_ok_and(|result| result.is_ok())
                    });
                    if futures_util::future::join_all(readiness)
                        .await
                        .into_iter()
                        .all(|ready| ready)
                    {
                        break;
                    }
                    sleep(Duration::from_millis(50)).await;
                }
                let results = futures_util::future::join_all(
                    ports
                        .iter()
                        .copied()
                        .map(|port| probe_http_port(port, Duration::from_secs(8))),
                )
                .await;
                if results.iter().all(Result::is_ok) {
                    Ok(())
                } else {
                    Err(DaemonError::new(
                        DaemonErrorCode::XrayValidationFailed,
                        "candidate's effective route has no verified remote egress",
                    ))
                }
            })
            .await
            .map_err(|_| {
                DaemonError::new(
                    DaemonErrorCode::XrayValidationFailed,
                    "candidate remote egress validation timed out",
                )
            })
            .and_then(|result| result);
            let _ = child.kill().await;
            let _ = child.wait().await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::XrayValidationFailed,
                "candidate remote egress validation failed",
            )
        }))
    }

    async fn run_net_helper(&self, arguments: &[String]) -> Result<(), DaemonError> {
        let output = Command::new(&self.net_helper_path)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output()
            .await
            .map_err(|error| {
                DaemonError::new(
                    DaemonErrorCode::TunnelCommitFailed,
                    format!("could not start installed network helper: {error}"),
                )
            })?;
        if output.status.success() {
            return Ok(());
        }
        Err(DaemonError::new(
            DaemonErrorCode::TunnelCommitFailed,
            format!(
                "network setup failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
    }

    async fn route_up(&self, request: &ConnectRequest) -> Result<(), DaemonError> {
        let mut arguments = vec!["route-up".to_string()];
        for address in &request.server_ips {
            arguments.push("--server".into());
            arguments.push(address.to_string());
        }
        self.run_net_helper(&arguments).await
    }

    async fn route_down(&self) -> Result<(), DaemonError> {
        self.run_net_helper(&["route-down".into()]).await
    }

    async fn terminate_xray(&mut self) -> Result<(), DaemonError> {
        let Some(mut child) = self.xray.take() else {
            self.xray_identity = None;
            self.stop_log_tasks().await;
            return Ok(());
        };
        if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        if timeout(Duration::from_secs(3), child.wait()).await.is_err() {
            child.kill().await.map_err(|error| {
                DaemonError::new(
                    DaemonErrorCode::TunnelCleanupFailed,
                    format!("could not terminate Xray: {error}"),
                )
            })?;
            let _ = child.wait().await;
        }
        self.stop_log_tasks().await;
        self.xray_identity = None;
        Ok(())
    }

    async fn stop_log_tasks(&mut self) {
        for task in self.log_tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
    }

    async fn wait_until_ready(&mut self, mode: ConnectionMode) -> Result<(), DaemonError> {
        for _ in 0..50 {
            if !self.child_is_running() {
                return Err(DaemonError::new(
                    DaemonErrorCode::XrayStartFailed,
                    "Xray exited before the data plane became ready",
                ));
            }
            let ready = match mode {
                ConnectionMode::Tun => Path::new("/sys/class/net/varmlen0").exists(),
                ConnectionMode::Proxy => tokio::net::TcpStream::connect(("127.0.0.1", PROXY_PORT))
                    .await
                    .is_ok(),
            };
            if ready {
                return Ok(());
            }
            sleep(Duration::from_millis(100)).await;
        }
        Err(DaemonError::new(
            DaemonErrorCode::XrayStartFailed,
            "timed out waiting for Xray",
        ))
    }

    async fn remove_dns(&mut self) -> Result<(), DaemonError> {
        if !self.dns_active {
            return Ok(());
        }
        let mut backend = SystemDnsBackend::new();
        backend.remove().await?;
        self.dns_active = false;
        Ok(())
    }

    async fn remove_split(&mut self) -> Result<(), DaemonError> {
        let Some(mut split) = self.split.take() else {
            self.split_apps.clear();
            return Ok(());
        };
        let result = split.backend_mut().rollback().await.map_err(|error| {
            DaemonError::new(
                DaemonErrorCode::TunnelCleanupFailed,
                format!("split-tunnel cleanup failed: {error}"),
            )
        });
        self.split_apps.clear();
        result
    }
}

#[async_trait]
impl LifecycleBackend for SystemLifecycleBackend {
    fn data_plane_alive(&mut self) -> bool {
        self.child_is_running()
    }

    async fn validate(&mut self, request: &ConnectRequest) -> Result<(), DaemonError> {
        ensure_trusted_binary(&self.xray_path)?;
        ensure_trusted_binary(&self.net_helper_path)?;
        validate_xray_document(&request.xray_config, request.mode == ConnectionMode::Tun)?;
        let validation_ports = validation_config_ports(&request.validation_config)?;
        validate_ping_xray_document(&request.validation_config, &validation_ports)?;
        self.prepare_runtime_dir()?;
        self.write_private(&self.validation_path(), &request.validation_config)?;
        self.write_private(&self.config_path(), &request.xray_config)?;
        self.run_xray_validation(&self.config_path()).await?;
        self.run_validation_egress_probe(&request.validation_config)
            .await
    }

    async fn install_hold_block(&mut self, request: &ConnectRequest) -> Result<(), DaemonError> {
        let mut arguments = vec!["killswitch-up".to_string()];
        if request.allow_lan {
            arguments.push("--allow-lan".into());
        }
        arguments.extend(request.server_ips.iter().map(ToString::to_string));
        self.run_net_helper(&arguments)
            .await
            .map_err(|error| DaemonError::new(DaemonErrorCode::HoldBlockFailed, error.message))
    }

    async fn verify_hold_block(&mut self) -> Result<(), DaemonError> {
        let output = Command::new("nft")
            .args(["list", "table", "inet", "varmlen_ks"])
            .output()
            .await
            .map_err(|error| {
                DaemonError::new(
                    DaemonErrorCode::HoldBlockVerificationFailed,
                    format!("could not inspect hold block: {error}"),
                )
            })?;
        let rules = String::from_utf8_lossy(&output.stdout);
        let has_dial_mark = rules.contains("0x2024") || rules.contains("0x00002024");
        let has_split_mark = rules.contains("0x2025") || rules.contains("0x00002025");
        if output.status.success()
            && rules.contains("policy drop")
            && has_dial_mark
            && has_split_mark
        {
            Ok(())
        } else {
            Err(DaemonError::new(
                DaemonErrorCode::HoldBlockVerificationFailed,
                "hold block was not installed with the required drop policy",
            ))
        }
    }

    async fn stop_data_plane(&mut self, preserve_split: bool) -> Result<(), DaemonError> {
        let mut first_error = None;
        if !preserve_split {
            if let Err(error) = self.remove_split().await {
                first_error = Some(error);
            }
        }
        if let Err(error) = self.remove_dns().await {
            first_error.get_or_insert(error);
        }
        if self.mode == Some(ConnectionMode::Tun) && self.net_helper_path.exists() {
            if let Err(error) = self.route_down().await {
                first_error.get_or_insert(error);
            }
        }
        if let Err(error) = self.terminate_xray().await {
            first_error.get_or_insert(error);
        }
        self.mode = None;
        let _ = fs::remove_file(self.config_path());
        let _ = fs::remove_file(self.validation_path());
        first_error.map_or(Ok(()), Err)
    }

    async fn start_data_plane(&mut self, request: &ConnectRequest) -> Result<(), DaemonError> {
        self.prepare_runtime_dir()?;
        self.write_private(&self.config_path(), &request.xray_config)?;
        self.log_store
            .lock()
            .await
            .clear()
            .map_err(internal_io("clear Xray log"))?;
        let mut child = Command::new(&self.xray_path)
            .args(["run", "-c"])
            .arg(self.config_path())
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                DaemonError::new(
                    DaemonErrorCode::XrayStartFailed,
                    format!("could not start installed Xray: {error}"),
                )
            })?;
        if let Some(stdout) = child.stdout.take() {
            self.log_tasks
                .push(tokio::spawn(pump_xray_log(stdout, self.log_store())));
        }
        if let Some(stderr) = child.stderr.take() {
            self.log_tasks
                .push(tokio::spawn(pump_xray_log(stderr, self.log_store())));
        }
        let pid = child.id().ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::XrayStartFailed,
                "Xray did not expose a process ID",
            )
        })?;
        self.xray = Some(child);
        self.xray_identity = ProcessIdentity::from_pid(pid).ok();
        self.mode = Some(request.mode);
        self.wait_until_ready(request.mode).await
    }

    async fn activate_network(&mut self, request: &ConnectRequest) -> Result<(), DaemonError> {
        if request.mode == ConnectionMode::Proxy {
            return Ok(());
        }
        self.route_up(request).await?;

        let split_changed = self.split_apps != request.excluded_apps;
        if self.split.is_some() && (request.excluded_apps.is_empty() || split_changed) {
            self.remove_split().await?;
        }
        if !request.excluded_apps.is_empty() && self.split.is_none() {
            let mut split = SplitManager::new(SystemSplitBackend::new(self.owner_uid));
            split
                .apply(SplitPlan::new(
                    self.owner_uid,
                    request.excluded_apps.clone(),
                ))
                .await
                .map_err(|error| {
                    DaemonError::new(
                        DaemonErrorCode::SplitUnavailable,
                        format!("per-app split tunnelling is unavailable: {error}"),
                    )
                })?;
            self.split = Some(split);
            self.split_apps = request.excluded_apps.clone();
        }

        let mut dns = DnsGuard::new(SystemDnsBackend::new());
        // Arm lifecycle cleanup before installation so a failed verification
        // still gets a second, fail-closed attempt to remove the nft table.
        self.dns_active = true;
        dns.install().await?;
        Ok(())
    }

    async fn verify_connection(&mut self, request: &ConnectRequest) -> Result<(), DaemonError> {
        if !self.child_is_running() {
            return Err(DaemonError::new(
                DaemonErrorCode::XrayStartFailed,
                "Xray is not running",
            ));
        }
        if request.mode == ConnectionMode::Proxy {
            return Ok(());
        }
        if !Path::new("/sys/class/net/varmlen0").exists() || !self.dns_active {
            return Err(DaemonError::new(
                DaemonErrorCode::TunnelCommitFailed,
                "TUN or DNS protection disappeared during activation",
            ));
        }
        if let Some(split) = self.split.as_ref() {
            if !split.backend().is_healthy() {
                return Err(DaemonError::new(
                    DaemonErrorCode::SplitUnavailable,
                    "per-app split watcher stopped",
                ));
            }
        }
        let route = Command::new("ip")
            .args(["route", "get", "1.0.0.1"])
            .output()
            .await
            .map_err(|error| {
                DaemonError::new(
                    DaemonErrorCode::TunnelCommitFailed,
                    format!("could not verify tunnel route: {error}"),
                )
            })?;
        if route.status.success() && String::from_utf8_lossy(&route.stdout).contains(TUN_INTERFACE)
        {
            Ok(())
        } else {
            Err(DaemonError::new(
                DaemonErrorCode::TunnelCommitFailed,
                "the default IPv4 path does not use varmlen0",
            ))
        }
    }

    async fn remove_hold_block(&mut self) -> Result<(), DaemonError> {
        self.run_net_helper(&["killswitch-down".into()])
            .await
            .map_err(|error| {
                DaemonError::new(DaemonErrorCode::HoldBlockRemovalFailed, error.message)
            })
    }
}

fn internal_io(context: &'static str) -> impl FnOnce(std::io::Error) -> DaemonError {
    move |error| DaemonError::new(DaemonErrorCode::Internal, format!("{context}: {error}"))
}

pub fn ensure_trusted_binary(path: &Path) -> Result<(), DaemonError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        DaemonError::new(
            DaemonErrorCode::XrayUnavailable,
            format!(
                "installed component {} is unavailable: {error}",
                path.display()
            ),
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(DaemonError::new(
            DaemonErrorCode::XrayUnavailable,
            format!(
                "installed component {} is not a trusted root-owned executable",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn validation_config_ports(raw: &str) -> Result<Vec<u16>, DaemonError> {
    let document: Value = serde_json::from_str(raw).map_err(|error| {
        DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            format!("invalid validation Xray JSON: {error}"),
        )
    })?;
    let inbounds = document
        .get("inbounds")
        .and_then(Value::as_array)
        .filter(|inbounds| (1..=MAX_SERVER_IPS).contains(&inbounds.len()))
        .ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "validation config must contain between one and 64 loopback inbounds",
            )
        })?;
    inbounds
        .iter()
        .map(|inbound| {
            inbound
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port >= 1024)
                .ok_or_else(|| {
                    DaemonError::new(
                        DaemonErrorCode::InvalidRequest,
                        "validation config contains an invalid port",
                    )
                })
        })
        .collect()
}

fn validation_config_with_ports(raw: &str, ports: &[u16]) -> Result<String, DaemonError> {
    if ports.is_empty()
        || ports.len() > MAX_SERVER_IPS
        || ports.iter().any(|port| *port < 1024)
        || ports.iter().collect::<HashSet<_>>().len() != ports.len()
    {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "validation ports must be unique and unprivileged",
        ));
    }
    let mut document: Value = serde_json::from_str(raw).map_err(|error| {
        DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            format!("invalid validation Xray JSON: {error}"),
        )
    })?;
    let inbounds = document
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .filter(|inbounds| inbounds.len() == ports.len())
        .ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "validation config port count does not match its inbounds",
            )
        })?;
    for (inbound, port) in inbounds.iter_mut().zip(ports) {
        inbound["port"] = serde_json::json!(port);
    }
    serde_json::to_string(&document).map_err(|error| {
        DaemonError::new(
            DaemonErrorCode::Internal,
            format!("could not serialize validation Xray JSON: {error}"),
        )
    })
}

pub fn validate_xray_document(raw: &str, expects_tun: bool) -> Result<(), DaemonError> {
    let document: Value = serde_json::from_str(raw).map_err(|error| {
        DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            format!("invalid generated Xray JSON: {error}"),
        )
    })?;
    let object = document.as_object().ok_or_else(|| {
        DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "Xray configuration must be an object",
        )
    })?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "log"
                | "dns"
                | "inbounds"
                | "outbounds"
                | "routing"
                | "observatory"
                | "burstObservatory"
        )
    }) {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "Xray configuration contains an unsupported privileged section",
        ));
    }
    let log = object
        .get("log")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "Xray log section is missing",
            )
        })?;
    if log.keys().any(|key| key != "loglevel") {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "Xray file logging is not permitted",
        ));
    }

    let inbounds = object
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DaemonError::new(DaemonErrorCode::InvalidRequest, "Xray inbounds are missing")
        })?;
    if inbounds.len() != 1 {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "Xray must contain exactly one data inbound",
        ));
    }
    let data_tag = if expects_tun { "tun-in" } else { "socks-in" };
    let data_protocol = if expects_tun { "tun" } else { "socks" };
    let data = inbound_by_tag(inbounds, data_tag, data_protocol)?;
    if expects_tun {
        if data.pointer("/settings/name").and_then(Value::as_str) != Some(TUN_INTERFACE) {
            return Err(DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "Xray TUN interface name is not permitted",
            ));
        }
    } else if data.get("listen").and_then(Value::as_str) != Some("127.0.0.1")
        || data.get("port").and_then(Value::as_u64) != Some(PROXY_PORT.into())
    {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "Xray SOCKS inbound must remain loopback-only",
        ));
    }
    let outbounds = object
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "Xray outbounds are missing",
            )
        })?;
    let mut tags = HashSet::new();
    let valid_tags = outbounds.iter().all(|outbound| {
        outbound
            .get("tag")
            .and_then(Value::as_str)
            .is_some_and(|tag| !tag.is_empty() && tags.insert(tag))
    });
    let proxy_count = outbounds
        .iter()
        .filter(|outbound| {
            matches!(
                outbound.get("protocol").and_then(Value::as_str),
                Some(
                    "http"
                        | "socks"
                        | "shadowsocks"
                        | "vmess"
                        | "vless"
                        | "trojan"
                        | "hysteria"
                        | "wireguard"
                )
            )
        })
        .count();
    let required_system_outbounds = [
        ("direct", "freedom"),
        ("dns-out", "dns"),
        ("block", "blackhole"),
    ];
    let system_outbounds_are_exact = required_system_outbounds.iter().all(|(tag, protocol)| {
        outbounds
            .iter()
            .filter(|outbound| {
                outbound.get("tag").and_then(Value::as_str) == Some(*tag)
                    && outbound.get("protocol").and_then(Value::as_str) == Some(*protocol)
            })
            .count()
            == 1
    });
    if !valid_tags
        || !(1..=MAX_SERVER_IPS).contains(&proxy_count)
        || outbounds.len() != proxy_count + required_system_outbounds.len()
        || !system_outbounds_are_exact
    {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "Xray outbound set is not permitted",
        ));
    }
    if object.get("dns").and_then(Value::as_object).is_none()
        || object.get("routing").and_then(Value::as_object).is_none()
    {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "Xray DNS or routing section is missing",
        ));
    }
    if contains_forbidden_file_key(&document) {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "Xray configuration may not reference privileged files",
        ));
    }
    Ok(())
}

pub fn validate_ping_xray_document(raw: &str, socks_ports: &[u16]) -> Result<(), DaemonError> {
    let document: Value = serde_json::from_str(raw).map_err(|error| {
        DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            format!("invalid ping Xray JSON: {error}"),
        )
    })?;
    let object = document.as_object().ok_or_else(|| {
        DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "ping Xray configuration must be an object",
        )
    })?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "log" | "inbounds" | "outbounds" | "routing" | "observatory" | "burstObservatory"
        )
    }) {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "ping Xray configuration contains an unsupported privileged section",
        ));
    }
    let log = object
        .get("log")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            DaemonError::new(DaemonErrorCode::InvalidRequest, "ping Xray log is missing")
        })?;
    if log.keys().any(|key| key != "loglevel") {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "ping Xray file logging is not permitted",
        ));
    }

    let inbounds = object
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "ping Xray inbound is missing",
            )
        })?;
    if inbounds.len() != socks_ports.len() {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "ping Xray must contain one inbound per requested port",
        ));
    }
    let mut inbound_tags = Vec::with_capacity(inbounds.len());
    for (index, (inbound, socks_port)) in inbounds.iter().zip(socks_ports).enumerate() {
        let tag = inbound.get("tag").and_then(Value::as_str);
        let expected_tag = format!("socks-in-{index}");
        let legacy_tag = socks_ports.len() == 1 && tag == Some("socks-in");
        if (!legacy_tag && tag != Some(expected_tag.as_str()))
            || inbound.get("protocol").and_then(Value::as_str) != Some("socks")
            || inbound.get("listen").and_then(Value::as_str) != Some("127.0.0.1")
            || inbound.get("port").and_then(Value::as_u64) != Some((*socks_port).into())
            || inbound.pointer("/settings/auth").and_then(Value::as_str) != Some("noauth")
            || inbound.pointer("/settings/udp").and_then(Value::as_bool) != Some(false)
        {
            return Err(DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "ping Xray SOCKS inbound must be loopback-only on the requested port",
            ));
        }
        inbound_tags.push(tag.unwrap().to_string());
    }

    let outbounds = object
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "ping Xray outbounds are missing",
            )
        })?;
    if !(2..=MAX_SERVER_IPS + 1).contains(&outbounds.len())
        || outbounds
            .last()
            .and_then(|outbound| outbound.get("tag"))
            .and_then(Value::as_str)
            != Some("direct")
        || outbounds
            .last()
            .and_then(|outbound| outbound.get("protocol"))
            .and_then(Value::as_str)
            != Some("freedom")
    {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "ping Xray outbound set or bypass mark is not permitted",
        ));
    }
    let mut proxy_tags = HashSet::new();
    for outbound in &outbounds[..outbounds.len() - 1] {
        let protocol = outbound.get("protocol").and_then(Value::as_str);
        let tag = outbound
            .get("tag")
            .and_then(Value::as_str)
            .filter(|tag| !tag.is_empty());
        let marked = outbound
            .pointer("/streamSettings/sockopt/mark")
            .and_then(Value::as_u64)
            == Some(XRAY_DIAL_MARK);
        if !matches!(
            protocol,
            Some(
                "http"
                    | "socks"
                    | "shadowsocks"
                    | "vmess"
                    | "vless"
                    | "trojan"
                    | "hysteria"
                    | "wireguard"
            )
        ) || tag.is_none()
            || !proxy_tags.insert(tag.unwrap())
            || (protocol != Some("wireguard") && !marked)
        {
            return Err(DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "ping Xray proxy outbound or bypass mark is not permitted",
            ));
        }
    }

    let routing = document
        .get("routing")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "ping Xray routing section is missing",
            )
        })?;
    if routing
        .keys()
        .any(|key| !matches!(key.as_str(), "rules" | "balancers"))
    {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "ping Xray routing contains unsupported policy",
        ));
    }
    let balancer_tags = routing
        .get("balancers")
        .map(|value| {
            let items = value.as_array().ok_or_else(|| {
                DaemonError::new(
                    DaemonErrorCode::InvalidRequest,
                    "ping Xray balancers must be an array",
                )
            })?;
            if items.len() > MAX_SERVER_IPS {
                return Err(DaemonError::new(
                    DaemonErrorCode::InvalidRequest,
                    "ping Xray has too many balancers",
                ));
            }
            let mut tags = HashSet::new();
            for balancer in items {
                let tag = balancer
                    .get("tag")
                    .and_then(Value::as_str)
                    .filter(|tag| !tag.is_empty())
                    .ok_or_else(|| {
                        DaemonError::new(
                            DaemonErrorCode::InvalidRequest,
                            "ping Xray balancer tag is missing",
                        )
                    })?;
                let selectors = balancer
                    .get("selector")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        DaemonError::new(
                            DaemonErrorCode::InvalidRequest,
                            "ping Xray balancer selector is missing",
                        )
                    })?;
                if !tags.insert(tag)
                    || selectors.is_empty()
                    || !selectors.iter().filter_map(Value::as_str).any(|selector| {
                        proxy_tags
                            .iter()
                            .any(|proxy_tag| proxy_tag.starts_with(selector))
                    })
                {
                    return Err(DaemonError::new(
                        DaemonErrorCode::InvalidRequest,
                        "ping Xray balancer does not select a proxy",
                    ));
                }
            }
            Ok(tags)
        })
        .transpose()?
        .unwrap_or_default();
    let rules = routing
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "ping Xray routing rule is missing",
            )
        })?;
    if rules.len() != socks_ports.len() {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "ping Xray must contain one routing rule per requested port",
        ));
    }
    for (index, rule) in rules.iter().enumerate() {
        let target_is_proxy = rule
            .get("outboundTag")
            .and_then(Value::as_str)
            .is_some_and(|tag| proxy_tags.contains(tag));
        let target_is_balancer = rule
            .get("balancerTag")
            .and_then(Value::as_str)
            .is_some_and(|tag| balancer_tags.contains(tag));
        let inbound_matches = match rule.get("inboundTag") {
            Some(Value::Array(tags)) => {
                tags.len() == 1 && tags[0].as_str() == Some(inbound_tags[index].as_str())
            }
            None => socks_ports.len() == 1,
            _ => false,
        };
        if rule.get("type").and_then(Value::as_str) != Some("field")
            || rule.get("network").and_then(Value::as_str) != Some("tcp,udp")
            || !inbound_matches
            || target_is_proxy == target_is_balancer
        {
            return Err(DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                "ping Xray must route every request through its measured server",
            ));
        }
    }
    if contains_forbidden_file_key(&document) {
        return Err(DaemonError::new(
            DaemonErrorCode::InvalidRequest,
            "ping Xray configuration may not reference privileged files",
        ));
    }
    Ok(())
}

fn inbound_by_tag<'a>(
    inbounds: &'a [Value],
    tag: &str,
    protocol: &str,
) -> Result<&'a Value, DaemonError> {
    inbounds
        .iter()
        .find(|inbound| {
            inbound.get("tag").and_then(Value::as_str) == Some(tag)
                && inbound.get("protocol").and_then(Value::as_str) == Some(protocol)
        })
        .ok_or_else(|| {
            DaemonError::new(
                DaemonErrorCode::InvalidRequest,
                format!("required Xray inbound {tag} is missing"),
            )
        })
}

fn contains_forbidden_file_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "certificateFile" | "keyFile" | "certificatePath" | "keyPath"
            ) || contains_forbidden_file_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_file_key),
        _ => false,
    }
}

async fn pump_xray_log<R>(mut reader: R, store: Arc<Mutex<LogStore>>)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; 8192];
    loop {
        let count = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        if store.lock().await.append(&buffer[..count]).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::{
        build_proxy_dns_probe_request, build_proxy_ping_request, first_success,
        validate_dns_probe_response, validate_ping_xray_document, validate_xray_document,
        validation_config_ports, validation_config_with_ports, DNS_PROBE_QUERY, PROXY_PING_URLS,
    };
    use crate::protocol::DaemonErrorCode;

    fn config(data: serde_json::Value) -> String {
        json!({
            "log": {"loglevel": "warning"},
            "dns": {"servers": ["https://1.1.1.1/dns-query"]},
            "inbounds": [data],
            "outbounds": [
                {"tag": "proxy", "protocol": "vless"},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "dns-out", "protocol": "dns"},
                {"tag": "block", "protocol": "blackhole"}
            ],
            "routing": {"rules": []}
        })
        .to_string()
    }

    #[test]
    fn daemon_owns_every_ephemeral_validation_port() {
        let original = json!({
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"tag":"socks-in-0", "listen":"127.0.0.1", "port":2081,
                 "protocol":"socks", "settings":{"auth":"noauth", "udp":false}},
                {"tag":"socks-in-1", "listen":"127.0.0.1", "port":2082,
                 "protocol":"socks", "settings":{"auth":"noauth", "udp":false}}
            ],
            "outbounds": [
                {"tag":"proxy", "protocol":"vless", "streamSettings":{"sockopt":{"mark":0x2024}}},
                {"tag":"proxy-2", "protocol":"vless", "streamSettings":{"sockopt":{"mark":0x2024}}},
                {"tag":"direct", "protocol":"freedom"}
            ],
            "routing": {"rules": [
                {"type":"field", "inboundTag":["socks-in-0"], "outboundTag":"proxy"},
                {"type":"field", "inboundTag":["socks-in-1"], "outboundTag":"proxy-2"}
            ]}
        })
        .to_string();
        assert_eq!(
            validation_config_ports(&original).unwrap(),
            vec![2081, 2082]
        );
        let rewritten = validation_config_with_ports(&original, &[43123, 43124]).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        assert_eq!(value["inbounds"][0]["port"], 43123);
        assert_eq!(value["inbounds"][1]["port"], 43124);
        assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
    }

    #[test]
    fn accepts_fixed_tun_with_no_local_dns_inbound() {
        let raw = config(json!({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {"name": "varmlen0", "mtu": 1500}
        }));
        assert!(validate_xray_document(&raw, true).is_ok());
    }

    #[test]
    fn accepts_composite_profiles_with_every_supported_xray_proxy() {
        let mut value: serde_json::Value = serde_json::from_str(&config(json!({
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {"name": "varmlen0", "mtu": 1500}
        })))
        .unwrap();
        value["outbounds"] = json!([
            {"tag":"p-http", "protocol":"http"},
            {"tag":"p-socks", "protocol":"socks"},
            {"tag":"p-ss", "protocol":"shadowsocks"},
            {"tag":"p-vmess", "protocol":"vmess"},
            {"tag":"p-vless", "protocol":"vless"},
            {"tag":"p-trojan", "protocol":"trojan"},
            {"tag":"p-hysteria", "protocol":"hysteria"},
            {"tag":"p-wireguard", "protocol":"wireguard"},
            {"tag":"direct", "protocol":"freedom"},
            {"tag":"dns-out", "protocol":"dns"},
            {"tag":"block", "protocol":"blackhole"}
        ]);
        value["observatory"] = json!({"subjectSelector":["p-"]});
        assert!(validate_xray_document(&value.to_string(), true).is_ok());
    }

    #[test]
    fn rejects_privileged_file_logging_and_non_loopback_listener() {
        let mut value: serde_json::Value = serde_json::from_str(&config(json!({
            "tag": "socks-in",
            "listen": "0.0.0.0",
            "port": 2081,
            "protocol": "socks",
            "settings": {"udp": true}
        })))
        .unwrap();
        value["log"]["access"] = json!("/etc/shadow");
        let error = validate_xray_document(&value.to_string(), false).unwrap_err();
        assert_eq!(error.code, DaemonErrorCode::InvalidRequest);
    }

    #[test]
    fn rejects_certificate_paths_from_authenticated_but_untrusted_gui() {
        let mut value: serde_json::Value = serde_json::from_str(&config(json!({
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": 2081,
            "protocol": "socks",
            "settings": {"udp": true}
        })))
        .unwrap();
        value["outbounds"][0]["streamSettings"] =
            json!({"tlsSettings": {"certificateFile": "/root/private.pem"}});
        let error = validate_xray_document(&value.to_string(), false).unwrap_err();
        assert_eq!(error.code, DaemonErrorCode::InvalidRequest);
    }

    #[test]
    fn ping_config_is_loopback_only_and_requires_the_dial_mark() {
        let raw = json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 32000,
                "protocol": "socks",
                "settings": {"udp": false, "auth": "noauth"}
            }],
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "vless",
                    "streamSettings": {"sockopt": {"mark": 0x2024}}
                },
                {"tag": "direct", "protocol": "freedom"}
            ],
            "routing": {"rules": [
                {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}
            ]}
        });
        assert!(validate_ping_xray_document(&raw.to_string(), &[32_000]).is_ok());

        let mut unmarked = raw.clone();
        unmarked["outbounds"][0]["streamSettings"]["sockopt"]["mark"] = json!(0);
        let error = validate_ping_xray_document(&unmarked.to_string(), &[32_000]).unwrap_err();
        assert_eq!(error.code, DaemonErrorCode::InvalidRequest);

        let mut exposed = raw;
        exposed["inbounds"][0]["listen"] = json!("0.0.0.0");
        let error = validate_ping_xray_document(&exposed.to_string(), &[32_000]).unwrap_err();
        assert_eq!(error.code, DaemonErrorCode::InvalidRequest);
    }

    #[test]
    fn ping_config_accepts_a_bounded_balanced_profile() {
        let proxy = |tag: &str| {
            json!({
                "tag": tag,
                "protocol": "vless",
                "streamSettings": {"sockopt": {"mark": 0x2024}}
            })
        };
        let raw = json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 32000,
                "protocol": "socks",
                "settings": {"udp": false, "auth": "noauth"}
            }],
            "outbounds": [
                proxy("estonia-1"),
                proxy("estonia-2"),
                {"tag": "direct", "protocol": "freedom"}
            ],
            "routing": {
                "balancers": [{
                    "tag": "estonia-balancer",
                    "selector": ["estonia-"],
                    "strategy": {"type": "leastPing"}
                }],
                "rules": [{
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "estonia-balancer"
                }]
            },
            "burstObservatory": {
                "subjectSelector": ["estonia-"],
                "pingConfig": {
                    "destination": "https://example.com/generate_204",
                    "interval": "1m",
                    "timeout": "5s",
                    "sampling": 3
                }
            }
        });

        assert!(validate_ping_xray_document(&raw.to_string(), &[32_000]).is_ok());
    }

    #[test]
    fn proxy_ping_matches_xray_health_check_request() {
        let client = reqwest::Client::new();
        assert_eq!(PROXY_PING_URLS.len(), 2);
        for url in PROXY_PING_URLS {
            let request = build_proxy_ping_request(&client, url).build().unwrap();
            assert_eq!(request.method(), reqwest::Method::HEAD);
            assert_eq!(request.url().as_str(), *url);
        }
    }

    #[test]
    fn proxy_ping_checks_the_effective_dns_path() {
        let client = reqwest::Client::new();
        let request = build_proxy_dns_probe_request(&client, "https://9.9.9.9/dns-query")
            .build()
            .unwrap();

        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().as_str(), "https://9.9.9.9/dns-query");
        assert_eq!(
            request.headers()[reqwest::header::CONTENT_TYPE],
            "application/dns-message"
        );
        assert_eq!(request.body().unwrap().as_bytes().unwrap(), DNS_PROBE_QUERY);

        let mut response = [0_u8; 12];
        response[0..2].copy_from_slice(&DNS_PROBE_QUERY[0..2]);
        response[2] = 0x80;
        assert!(validate_dns_probe_response(&response).is_ok());
        response[3] = 2;
        assert!(validate_dns_probe_response(&response).is_err());
    }

    #[tokio::test]
    async fn composite_ping_returns_without_waiting_for_slower_variants() {
        let probes = [(200_u64, Err("slow")), (5, Ok(37_u32))].into_iter().map(
            |(delay_ms, result)| async move {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                result
            },
        );

        let result = tokio::time::timeout(Duration::from_millis(100), first_success(probes))
            .await
            .expect("fast successful path should finish before the slow path");

        assert_eq!(result, Some(37));
    }
}
