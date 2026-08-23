use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

use crate::nft::apply_ruleset_with_code;
use crate::protocol::DaemonErrorCode;
use crate::split::bpf::BYPASS_MARK;
use crate::split::SplitError;

pub const DIRECT_DNS_PORT: u16 = 15_353;
const MAX_DNS_PACKET: usize = u16::MAX as usize;
const MAX_IN_FLIGHT: usize = 128;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(4);
const FALLBACK_UPSTREAMS: [SocketAddr; 3] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
];

pub struct DirectDnsProxy {
    tasks: Vec<JoinHandle<()>>,
}

impl DirectDnsProxy {
    pub async fn start() -> Result<Self, SplitError> {
        let udp4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, DIRECT_DNS_PORT))
            .await
            .map_err(|_| SplitError::DirectDnsUnavailable)?;
        let tcp4 = TcpListener::bind((Ipv4Addr::LOCALHOST, DIRECT_DNS_PORT))
            .await
            .map_err(|_| SplitError::DirectDnsUnavailable)?;

        let udp6 = optional_udp6_listener().await?;
        let tcp6 = optional_tcp6_listener().await?;
        let capacity = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
        let upstreams = Arc::new(discover_upstreams());
        let mut tasks = vec![
            tokio::spawn(serve_udp(
                udp4,
                Arc::clone(&capacity),
                Arc::clone(&upstreams),
            )),
            tokio::spawn(serve_tcp(
                tcp4,
                Arc::clone(&capacity),
                Arc::clone(&upstreams),
            )),
        ];
        if let Some(listener) = udp6 {
            tasks.push(tokio::spawn(serve_udp(
                listener,
                Arc::clone(&capacity),
                Arc::clone(&upstreams),
            )));
        }
        if let Some(listener) = tcp6 {
            tasks.push(tokio::spawn(serve_tcp(
                listener,
                Arc::clone(&capacity),
                Arc::clone(&upstreams),
            )));
        }

        if apply_ruleset_with_code(
            &render_direct_dns_rules(DIRECT_DNS_PORT),
            DaemonErrorCode::SplitUnavailable,
        )
        .await
        .is_err()
        {
            for task in &tasks {
                task.abort();
            }
            return Err(SplitError::DirectDnsUnavailable);
        }

        Ok(Self { tasks })
    }

    pub fn is_healthy(&self) -> bool {
        !self.tasks.is_empty() && self.tasks.iter().all(|task| !task.is_finished())
    }

    pub async fn stop(&mut self) -> Result<(), SplitError> {
        remove_direct_dns_rules().await?;
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        Ok(())
    }
}

impl Drop for DirectDnsProxy {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub fn render_direct_dns_rules(port: u16) -> String {
    format!(
        r#"table inet varmlen_split_dns {{
  chain redirect_output {{
    type nat hook output priority dstnat; policy accept;
    meta mark & 0x0000ffff == 0x2025 ip daddr 127.0.0.0/8 udp dport 53 redirect to :{port}
    meta mark & 0x0000ffff == 0x2025 ip daddr 127.0.0.0/8 tcp dport 53 redirect to :{port}
    meta mark & 0x0000ffff == 0x2025 ip6 daddr ::1 udp dport 53 redirect to :{port}
    meta mark & 0x0000ffff == 0x2025 ip6 daddr ::1 tcp dport 53 redirect to :{port}
  }}
  chain guard_output {{
    type filter hook output priority filter - 20; policy accept;
    ip daddr 127.0.0.0/8 udp dport {port} meta mark & 0x0000ffff != 0x2025 reject
    ip daddr 127.0.0.0/8 tcp dport {port} meta mark & 0x0000ffff != 0x2025 reject
    ip6 daddr ::1 udp dport {port} meta mark & 0x0000ffff != 0x2025 reject
    ip6 daddr ::1 tcp dport {port} meta mark & 0x0000ffff != 0x2025 reject
  }}
}}
"#
    )
}

async fn remove_direct_dns_rules() -> Result<(), SplitError> {
    let output = tokio::process::Command::new("nft")
        .args(["delete", "table", "inet", "varmlen_split_dns"])
        .output()
        .await
        .map_err(|_| SplitError::RollbackFailed)?;
    if output.status.success()
        || String::from_utf8_lossy(&output.stderr).contains("No such file or directory")
    {
        Ok(())
    } else {
        Err(SplitError::RollbackFailed)
    }
}

async fn optional_udp6_listener() -> Result<Option<UdpSocket>, SplitError> {
    match UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, DIRECT_DNS_PORT)).await {
        Ok(listener) => Ok(Some(listener)),
        Err(error) if ipv6_is_unavailable(&error) => Ok(None),
        Err(_) => Err(SplitError::DirectDnsUnavailable),
    }
}

async fn optional_tcp6_listener() -> Result<Option<TcpListener>, SplitError> {
    match TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, DIRECT_DNS_PORT)).await {
        Ok(listener) => Ok(Some(listener)),
        Err(error) if ipv6_is_unavailable(&error) => Ok(None),
        Err(_) => Err(SplitError::DirectDnsUnavailable),
    }
}

fn ipv6_is_unavailable(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL | libc::EPROTONOSUPPORT)
    )
}

fn discover_upstreams() -> Vec<SocketAddr> {
    let mut upstreams = Vec::new();
    let mut seen = HashSet::new();
    for path in [
        "/run/systemd/resolve/resolv.conf",
        "/run/NetworkManager/no-stub-resolv.conf",
        "/run/NetworkManager/resolv.conf",
        "/run/resolvconf/resolv.conf",
        "/etc/resolv.conf",
    ] {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for upstream in parse_nameservers(&contents) {
            if seen.insert(upstream) {
                upstreams.push(upstream);
            }
        }
    }
    for upstream in FALLBACK_UPSTREAMS {
        if seen.insert(upstream) {
            upstreams.push(upstream);
        }
    }
    upstreams
}

fn parse_nameservers(contents: &str) -> Vec<SocketAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.split_once('#').map_or(line, |(value, _)| value);
            let mut fields = line.split_whitespace();
            if fields.next()? != "nameserver" {
                return None;
            }
            let address = fields.next()?.parse::<IpAddr>().ok()?;
            if address.is_loopback() || address.is_unspecified() || address.is_multicast() {
                return None;
            }
            Some(SocketAddr::new(address, 53))
        })
        .collect()
}

async fn serve_udp(listener: UdpSocket, capacity: Arc<Semaphore>, upstreams: Arc<Vec<SocketAddr>>) {
    let listener = Arc::new(listener);
    loop {
        let mut packet = vec![0_u8; MAX_DNS_PACKET];
        let Ok((size, peer)) = listener.recv_from(&mut packet).await else {
            return;
        };
        packet.truncate(size);
        if !valid_dns_query(&packet) {
            continue;
        }
        let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
            continue;
        };
        let listener = Arc::clone(&listener);
        let upstreams = Arc::clone(&upstreams);
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(response) = first_udp_response(&packet, &upstreams).await {
                let _ = listener.send_to(&response, peer).await;
            }
        });
    }
}

async fn serve_tcp(
    listener: TcpListener,
    capacity: Arc<Semaphore>,
    upstreams: Arc<Vec<SocketAddr>>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
            continue;
        };
        let upstreams = Arc::clone(&upstreams);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_tcp_client(stream, &upstreams).await;
        });
    }
}

async fn handle_tcp_client(mut client: TcpStream, upstreams: &[SocketAddr]) -> io::Result<()> {
    loop {
        let size = match client.read_u16().await {
            Ok(size) => usize::from(size),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        if !(12..=MAX_DNS_PACKET).contains(&size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DNS-over-TCP frame",
            ));
        }
        let mut query = vec![0_u8; size];
        client.read_exact(&mut query).await?;
        if !valid_dns_query(&query) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DNS query",
            ));
        }
        let Some(response) = first_tcp_response(&query, upstreams).await else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "direct DNS upstreams timed out",
            ));
        };
        client.write_u16(response.len() as u16).await?;
        client.write_all(&response).await?;
    }
}

async fn first_udp_response(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    let mut pending = upstreams
        .iter()
        .copied()
        .map(|upstream| udp_query(upstream, query))
        .collect::<FuturesUnordered<_>>();
    while let Some(result) = pending.next().await {
        if let Ok(response) = result {
            if valid_dns_response(query, &response) {
                return Some(response);
            }
        }
    }
    None
}

async fn first_tcp_response(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    let mut pending = upstreams
        .iter()
        .copied()
        .map(|upstream| tcp_query(upstream, query))
        .collect::<FuturesUnordered<_>>();
    while let Some(result) = pending.next().await {
        if let Ok(response) = result {
            if valid_dns_response(query, &response) {
                return Some(response);
            }
        }
    }
    None
}

async fn udp_query(upstream: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let bind = match upstream {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).await?;
    set_bypass_mark(&socket)?;
    socket.connect(upstream).await?;
    socket.send(query).await?;
    let mut response = vec![0_u8; MAX_DNS_PACKET];
    let size = timeout(UPSTREAM_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream timed out"))??;
    response.truncate(size);
    Ok(response)
}

async fn tcp_query(upstream: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let socket = match upstream {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    set_bypass_mark(&socket)?;
    let mut stream = timeout(UPSTREAM_TIMEOUT, socket.connect(upstream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream timed out"))??;
    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query).await?;
    let size = timeout(UPSTREAM_TIMEOUT, stream.read_u16())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream timed out"))??;
    let mut response = vec![0_u8; usize::from(size)];
    timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream timed out"))??;
    Ok(response)
}

fn set_bypass_mark(socket: &impl AsRawFd) -> io::Result<()> {
    let mark = BYPASS_MARK as libc::c_uint;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const libc::c_uint).cast(),
            std::mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn valid_dns_query(packet: &[u8]) -> bool {
    packet.len() >= 12 && packet[2] & 0x80 == 0
}

fn valid_dns_response(query: &[u8], response: &[u8]) -> bool {
    response.len() >= 12
        && query.len() >= 2
        && response[0..2] == query[0..2]
        && response[2] & 0x80 != 0
}

#[cfg(test)]
mod tests {
    use super::{
        parse_nameservers, render_direct_dns_rules, valid_dns_query, valid_dns_response,
        DIRECT_DNS_PORT,
    };

    #[test]
    fn only_bypass_dns_to_loopback_is_redirected() {
        let rules = render_direct_dns_rules(DIRECT_DNS_PORT);
        assert!(rules.contains("meta mark & 0x0000ffff == 0x2025"));
        assert!(rules.contains("ip daddr 127.0.0.0/8 udp dport 53 redirect to :15353"));
        assert!(rules.contains("ip6 daddr ::1 tcp dport 53 redirect to :15353"));
        assert!(rules.contains("udp dport 15353 meta mark & 0x0000ffff != 0x2025 reject"));
        assert!(!rules.contains("0x2023"));
        assert!(!rules.contains("varmlen0"));
    }

    #[test]
    fn dns_packets_require_query_and_matching_response_headers() {
        let query = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let response = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        assert!(valid_dns_query(&query));
        assert!(valid_dns_response(&query, &response));
        assert!(!valid_dns_query(&response));
        let mut wrong = response;
        wrong[1] = 0x35;
        assert!(!valid_dns_response(&query, &wrong));
    }

    #[test]
    fn configured_physical_resolvers_are_used_without_loopback_stubs() {
        let resolvers = parse_nameservers(
            "nameserver 127.0.0.53\nnameserver 192.168.1.1 # router\nnameserver 2001:db8::53\n",
        );
        assert_eq!(resolvers[0].to_string(), "192.168.1.1:53");
        assert_eq!(resolvers[1].to_string(), "[2001:db8::53]:53");
        assert_eq!(resolvers.len(), 2);
    }
}
