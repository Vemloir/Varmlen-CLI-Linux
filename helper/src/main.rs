//! varmlen-net — root-invoked network transactions for `varmlend`.
//!
//! It is not reachable from the GUI and carries no file capabilities. The
//! root-owned daemon invokes it by a fixed root-owned path:
//!   - cap_net_admin: SO_MARK, nftables, ip routes/rules, net sysctls
//!   - cap_net_raw:   SO_BINDTODEVICE for the bypass probes
//!   - cap_dac_override: write the root-owned rp_filter sysctl + /run state
//!
//! Privileged operations:
//!   - `tcp`/`icmp`     latency probes that bypass the active tunnel
//!   - `killswitch-up`  apply the nftables drop table
//!   - `killswitch-down`remove it
//!   - `route-up` lay the routing xray's native tun needs: default route into
//!     the tun, a physical bypass table and policy rule for xray's own marked
//!     dials, the anti-loop server route, and loose rp_filter. DNS is owned by
//!     `varmlend`.
//!   - `route-down`     tear that routing down (idempotent)
//!   - `cleanup`        crash-recovery superset (killswitch + routing + stray TUN)
//!
//! The GUI owns the xray process directly; xray's native tun is the data plane.
//! Per-app + per-site split live in xray's routing (native `process`/`domain`
//! matchers); the helper only sets up the kernel routing the tun requires, since
//! xray's tun inbound manages no routes/DNS itself.
//!
//! Usage:
//!   varmlen-net tcp  <host> <port> <timeout_ms>      -> prints RTT ms
//!   varmlen-net icmp <host> <timeout_ms>             -> prints RTT ms
//!   varmlen-net killswitch-up [--allow-lan] <ip>...
//!   varmlen-net killswitch-down
//!   varmlen-net route-up [--server <ip>]...
//!   varmlen-net route-down
//!   varmlen-net cleanup

use std::io::Write;
use std::process::{Command, Stdio};

const KS_TABLE: &str = "varmlen_ks";
const TUN_IFACE: &str = "varmlen0";
const TUN_ADDR: &str = "172.19.0.1/30";

/// xray's own dials (proxy + direct outbounds) carry this mark via SO_MARK /
/// `sockopt.mark` so they bypass the tun (anti-loop). Accepted by the killswitch.
const XRAY_DIAL_MARK: u32 = 0x2024;
const DNS_MARK: &str = "0x2023";
const DNS_TABLE: &str = "101";

/// Custom routing table that egresses via the physical gateway — the bypass for
/// xray's own marked dials.
const PHYS_TABLE: &str = "100";

/// Per-app split: traffic from processes the user excluded carries this mark
/// (set by nft on cgroup membership, since an app can't SO_MARK itself). Routed
/// via PHYS_TABLE + masqueraded so it bypasses the tun entirely — robust where
/// xray's tun-inbound `process` matcher can't attribute a connection (UDP games,
/// Proton/wine). A SEPARATE mark from the xray dial mark so the masquerade never
/// touches the VPN tunnel's own connection.
const BYPASS_MARK: u32 = 0x2025;
const BYPASS_TABLE: &str = "varmlen_bypass";

// Kernel process-event connector (netlink) — lets the bypass watcher react to a
// process exec / comm-change the instant it happens, instead of polling /proc.
const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_COMM: u32 = 0x0000_0200;

/// Teardown state (rp_filter / state writes need cap_dac_override).
const RP_STATE: &str = "/run/varmlen/rp_filter_all.orig";
const SERVERS_STATE: &str = "/run/varmlen/servers";
const SERVERS6_STATE: &str = "/run/varmlen/servers6";
/// LEGACY (cleanup only): an older dev build pinned excluded apps' peers with
/// /32 routes recorded here. Pins are nft mark rules in the bypass table now.
const BYPASS_PINS_STATE: &str = "/run/varmlen/bypass_pins";

fn main() {
    // Harden the environment BEFORE any privileged child spawn. This binary
    // carries file caps and raises CAP_NET_ADMIN into the ambient set, which is
    // inherited across execve — so it must never resolve ip/nft/ping via an
    // attacker-controlled $PATH (e.g. `PATH=/tmp/evil varmlen-net ...` would run
    // /tmp/evil/nft with CAP_NET_ADMIN). Pin PATH to root-owned dirs. (LD_* is
    // already neutralised by the loader's secure-execution mode for fcaps.)
    std::env::set_var("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rc = run(&args);
    std::process::exit(rc);
}

/// Raise CAP_NET_ADMIN into the AMBIENT set so the `ip`/`nft` child processes we
/// spawn inherit it. File capabilities do NOT cross execve to children; the
/// ambient set is the mechanism that does. Best-effort: under root (sudo) the
/// children already inherit privilege, and a failure here surfaces later as an
/// `ip`/`nft` permission error rather than a silent wrong state.
fn raise_ambient_net_admin() {
    use caps::{CapSet, Capability};
    // Ambient requires the cap in BOTH Permitted (granted by file caps) and
    // Inheritable, so add it to Inheritable first.
    let _ = caps::raise(None, CapSet::Inheritable, Capability::CAP_NET_ADMIN);
    let _ = caps::raise(None, CapSet::Ambient, Capability::CAP_NET_ADMIN);
}

fn run(args: &[String]) -> i32 {
    // ip/nft children must inherit CAP_NET_ADMIN (file caps don't cross exec).
    raise_ambient_net_admin();
    match args.first().map(String::as_str) {
        Some("tcp") => {
            // tcp <host> <port> <timeout_ms>
            let (Some(host), Some(port), Some(tmo)) = (args.get(1), args.get(2), args.get(3))
            else {
                eprintln!("usage: varmlen-net tcp <host> <port> <timeout_ms>");
                return 2;
            };
            let port: u16 = match port.parse() {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("bad port");
                    return 2;
                }
            };
            let tmo: u32 = tmo.parse().unwrap_or(2500);
            match tcp_ping_bypass(host, port, tmo) {
                Ok(ms) => {
                    println!("{ms}");
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        Some("icmp") => {
            let (Some(host), Some(tmo)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: varmlen-net icmp <host> <timeout_ms>");
                return 2;
            };
            let tmo: u32 = tmo.parse().unwrap_or(2000);
            match icmp_ping(host, tmo) {
                Ok(ms) => {
                    println!("{ms}");
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        Some("killswitch-up") => {
            let mut allow_lan = false;
            let mut ips = Vec::new();
            for a in &args[1..] {
                if a == "--allow-lan" {
                    allow_lan = true;
                } else if let Ok(ip) = a.parse::<std::net::IpAddr>() {
                    ips.push(ip);
                }
            }
            match apply_killswitch(&ips, allow_lan) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        Some("killswitch-down") => {
            remove_killswitch();
            0
        }
        Some("route-up") => {
            // route-up [--server <ip>]... [--bypass-cgroup <rel>] [--bypass-app <id>]...
            let mut servers = Vec::new();
            let mut bypass_cgroup: Option<String> = None;
            let mut bypass_apps: Vec<String> = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--server" => {
                        if let Some(ip) = args
                            .get(i + 1)
                            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                        {
                            servers.push(ip);
                        }
                        i += 1;
                    }
                    "--bypass-cgroup" => {
                        if let Some(c) = args.get(i + 1) {
                            bypass_cgroup = Some(c.clone());
                        }
                        i += 1;
                    }
                    "--bypass-app" => {
                        if let Some(a) = args.get(i + 1) {
                            bypass_apps.push(a.clone());
                        }
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }
            match route_up(&servers, bypass_cgroup.as_deref(), &bypass_apps) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        Some("route-down") => {
            // --keep-bypass: reconnect path — leave the per-app bypass table up
            // so excluded apps' marked flows survive the gap.
            let keep = args[1..].iter().any(|a| a == "--keep-bypass");
            route_down(keep);
            0
        }
        Some("bypass-up") => {
            // bypass-up <cgroup-path>
            let Some(path) = args.get(1) else {
                eprintln!("usage: varmlen-net bypass-up <cgroup-path>");
                return 2;
            };
            match bypass_up(path, None) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        // bypass-down [cgroup-rel] — the optional path also detaches the
        // socket-mark BPF program from that cgroup.
        Some("bypass-down") => {
            bypass_down(args.get(1).map(String::as_str));
            0
        }
        Some("bypass-watch") => {
            // bypass-watch <cgroup-path> <excluded-id>...  (runs until killed)
            let Some(path) = args.get(1) else {
                eprintln!("usage: varmlen-net bypass-watch <cgroup-path> <id>...");
                return 2;
            };
            let excluded: Vec<String> = args[2..].to_vec();
            bypass_watch(path, &excluded)
        }
        Some("cleanup") => {
            remove_killswitch();
            route_down(false);
            delete_tun();
            0
        }
        _ => {
            eprintln!("usage: varmlen-net <tcp|icmp|killswitch-up|killswitch-down|route-up|route-down|cleanup> ...");
            2
        }
    }
}

// --- latency probes --------------------------------------------------------

/// First non-virtual interface with an IPv4 address. SO_BINDTODEVICE to this
/// makes probes bypass the tun's default route (which catches by destination,
/// not source — a plain bind to a phys-iface IP isn't enough).
fn pick_physical_iface() -> Option<String> {
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return None;
        }
        let mut found = None;
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                    .to_string_lossy()
                    .into_owned();
                let virt = name.starts_with("lo")
                    || name.starts_with("tun")
                    || name.starts_with("tap")
                    || name.starts_with("wg")
                    || name.starts_with("docker")
                    || name.starts_with("br-")
                    || name.starts_with("veth")
                    || name.starts_with("vmnet")
                    || name.starts_with("varmlen");
                let sa = &*ifa.ifa_addr;
                if !virt && sa.sa_family as i32 == libc::AF_INET {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                        found = Some(name);
                        break;
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
        found
    }
}

/// TCP-connect RTT in ms, source-bound + marked so it bypasses the tunnel.
fn tcp_ping_bypass(host: &str, port: u16, timeout_ms: u32) -> Result<u32, String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::{SocketAddr, ToSocketAddrs};
    use std::time::{Duration, Instant};

    if host.trim().is_empty() {
        return Err("empty host".into());
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_'))
    {
        return Err("invalid host".into());
    }
    let dst: SocketAddr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve: {e}"))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| "no ipv4".to_string())?;

    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| format!("socket: {e}"))?;
    let _ = sock.set_mark(XRAY_DIAL_MARK);
    if let Some(iface) = pick_physical_iface() {
        let _ = sock.bind_device(Some(iface.as_bytes()));
    }
    let timeout = Duration::from_millis(timeout_ms as u64);
    let started = Instant::now();
    sock.connect_timeout(&SockAddr::from(dst), timeout)
        .map_err(|e| format!("connect: {e}"))?;
    Ok(started.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

/// ICMP RTT via the system `ping` tool.
fn icmp_ping(host: &str, timeout_ms: u32) -> Result<u32, String> {
    if host.trim().is_empty() {
        return Err("empty host".into());
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_'))
    {
        return Err("invalid host".into());
    }
    let timeout_s = timeout_ms.div_ceil(1000).clamp(1, 10);
    let out = Command::new("ping")
        .arg("-n")
        .arg("-c")
        .arg("1")
        .arg("-W")
        .arg(timeout_s.to_string())
        .arg(host)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("spawn ping: {e}"))?;
    if !out.status.success() {
        return Err("ping failed".into());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(idx) = line.find("time=") {
            let rest = &line[idx + 5..];
            let num: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(ms) = num.parse::<f64>() {
                return Ok(ms.round().max(1.0).min(u32::MAX as f64) as u32);
            }
        }
    }
    Err("no RTT in ping output".into())
}

// --- killswitch ------------------------------------------------------------

/// Build the killswitch ruleset: drop all output except loopback, the tunnel,
/// xray's own marked dials (0x2024), the per-app bypass (0x2025), the proxy
/// server, DNS bootstrap, and (optionally) LAN.
fn killswitch_ruleset(server_ips: &[std::net::IpAddr], allow_lan: bool) -> String {
    let mut r = String::new();
    r.push_str(&format!("add table inet {KS_TABLE}\n"));
    r.push_str(&format!("delete table inet {KS_TABLE}\n"));
    r.push_str(&format!("table inet {KS_TABLE} {{\n"));
    r.push_str("  chain out {\n");
    r.push_str("    type filter hook output priority 0; policy drop;\n");
    r.push_str("    oifname \"lo\" counter accept\n");
    r.push_str(&format!("    oifname \"{TUN_IFACE}\" counter accept\n"));
    // REPLY direction only: keeps inbound services (SSH etc.) working. A bare
    // `established,related` accept let OUTBOUND pre-VPN flows resume on the
    // physical NIC the instant the tun vanished mid-reconnect — QUIC sessions
    // migrate addresses seamlessly, flashing the real IP even with the kill
    // switch on. Sanctioned outbound flows all carry marks (tun / 0x2024 dial /
    // 0x2025 bypass) and never need this rule.
    r.push_str("    ct state established,related ct direction reply counter accept\n");
    r.push_str("    fib daddr type local counter accept\n");
    r.push_str("    meta mark & 0x0000ffff == 0x2023 counter accept\n");
    r.push_str("    meta mark & 0x0000ffff == 0x2024 counter accept\n");
    r.push_str("    meta mark & 0x0000ffff == 0x2025 counter accept\n");
    r.push_str("    ct mark & 0x0000ffff == 0x2023 counter accept\n");
    r.push_str("    ct mark & 0x0000ffff == 0x2024 counter accept\n");
    r.push_str("    ct mark & 0x0000ffff == 0x2025 counter accept\n");
    r.push_str("    ip daddr 1.1.1.1 udp dport 53 counter accept\n");
    r.push_str("    ip daddr 1.1.1.1 tcp dport 53 counter accept\n");
    r.push_str("    ip daddr 1.1.1.1 tcp dport 443 counter accept\n");
    for ip in server_ips {
        match ip {
            std::net::IpAddr::V4(v4) => r.push_str(&format!("    ip daddr {v4} counter accept\n")),
            std::net::IpAddr::V6(v6) => r.push_str(&format!("    ip6 daddr {v6} counter accept\n")),
        }
    }
    // Defense in depth: never let DNS (port 53) reach a LAN peer, even with
    // `allow_lan` — that's the anti-leak invariant (configure_dns routes all
    // system DNS through the tun to 1.1.1.1; this is the backstop if it ever
    // doesn't). BEFORE the allow_lan accept block below so it wins on a match.
    r.push_str("    udp dport 53 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } counter drop\n");
    r.push_str("    tcp dport 53 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } counter drop\n");
    r.push_str("    udp dport 53 ip6 daddr { fe80::/10, fc00::/7 } counter drop\n");
    r.push_str("    tcp dport 53 ip6 daddr { fe80::/10, fc00::/7 } counter drop\n");
    if allow_lan {
        r.push_str("    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } counter accept\n");
        r.push_str("    ip6 daddr { fe80::/10, fc00::/7 } counter accept\n");
    }
    r.push_str("    limit rate 30/second log prefix \"varmlen_ks_drop \" level info\n");
    r.push_str("    counter drop\n");
    r.push_str("  }\n}\n");
    r
}

/// Apply the killswitch atomically via a single `nft -f` transaction.
fn apply_killswitch(server_ips: &[std::net::IpAddr], allow_lan: bool) -> Result<(), String> {
    nft_apply(&killswitch_ruleset(server_ips, allow_lan))
}

/// Pipe a ruleset into `nft -f -` (atomic transaction).
fn nft_apply(ruleset: &str) -> Result<(), String> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(ruleset.as_bytes())
            .map_err(|e| format!("nft write: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("nft wait: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("nft apply failed".to_string())
    }
}

fn remove_killswitch() {
    let _ = Command::new("nft")
        .arg("delete")
        .arg("table")
        .arg("inet")
        .arg(KS_TABLE)
        .stderr(Stdio::null())
        .status();
}

/// Per-app split bypass: tag traffic from the given (user-owned, cgroup-v2)
/// cgroup with BYPASS_MARK so it egresses the physical NIC (route_up adds the
/// fwmark rule) and masquerade it (the app picked the tun source at connect, so
/// the marked re-route alone leaves replies unroutable). `cgroup_path` is the
/// path relative to the cgroup-v2 root, no leading slash.
fn bypass_up(cgroup_path: &str, iface_override: Option<&str>) -> Result<(), String> {
    // This string is interpolated into an nft ruleset — allow only cgroup-path
    // characters so it can't break out of the quoted token.
    if cgroup_path.is_empty()
        || cgroup_path.len() > 512
        || !cgroup_path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'@'))
    {
        return Err("invalid cgroup path".into());
    }
    let level = cgroup_path.split('/').filter(|s| !s.is_empty()).count();
    if level == 0 {
        return Err("empty cgroup path".into());
    }
    // The masquerade oifname MUST be the same device the bypass table (100)
    // egresses on — i.e. the physical default route's dev — or a marked packet
    // leaves an iface the masquerade rule doesn't match and keeps its martian tun
    // source. route_up passes that dev; the standalone command falls back to a
    // best-guess physical iface.
    let iface = match iface_override {
        Some(i) => i.to_string(),
        None => pick_physical_iface().ok_or("no physical interface")?,
    };
    if iface.is_empty()
        || !iface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("bad interface name".into());
    }
    let ruleset = format!(
        "add table inet {tbl}\n\
         delete table inet {tbl}\n\
         table inet {tbl} {{\n\
         \tchain mangle {{\n\
         \t\ttype route hook output priority mangle; policy accept;\n\
         \t\tsocket cgroupv2 level {level} \"{path}\" meta mark set {mark:#x}\n\
         \t}}\n\
         \tchain nat {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\tmeta mark {mark:#x} oifname \"{iface}\" masquerade\n\
         \t}}\n\
         }}\n",
        tbl = BYPASS_TABLE,
        level = level,
        path = cgroup_path,
        mark = BYPASS_MARK,
        iface = iface,
    );
    nft_apply(&ruleset)?;
    // Mark sockets at CREATION via cgroup BPF (best-effort): they then connect
    // with the physical route + REAL source, so the app's flows survive VPN
    // disconnect. The nft packet-mark + masquerade above stay as the fallback
    // (old kernels / no cap_bpf) and as a no-op safety net otherwise.
    if let Err(e) = bypass_bpf(cgroup_path, true) {
        eprintln!("bypass: cgroup socket-mark BPF unavailable ({e}); masquerade fallback only");
    }
    Ok(())
}

/// Tear the bypass tagging down. `cgroup_rel`, when known, also detaches the
/// cgroup socket-mark BPF program (without it the program stays attached but is
/// inert once the mark rules are gone, and the next attach replaces it).
fn bypass_down(cgroup_rel: Option<&str>) {
    let _ = Command::new("nft")
        .arg("delete")
        .arg("table")
        .arg("inet")
        .arg(BYPASS_TABLE)
        .stderr(Stdio::null())
        .status();
    if let Some(rel) = cgroup_rel {
        if cg_valid(rel) {
            let _ = bypass_bpf(rel, false);
        }
    }
}

// --- cgroup BPF: mark sockets at creation -----------------------------------
//
// The nft `socket cgroupv2` tag marks PACKETS, after the socket already picked
// its source via the main table (the tun address) — that's why the masquerade
// exists, and why such flows die the moment the VPN disconnects and the tun
// address vanishes. A BPF_PROG_TYPE_CGROUP_SOCK program attached to the bypass
// cgroup instead sets sk_mark AT SOCKET CREATION: connect()'s route lookup then
// resolves via PHYS_TABLE straight to the physical NIC and the REAL source
// address. Masquerade becomes a no-op, and the app's connections survive both
// VPN connect and disconnect. Requires CAP_BPF (kernel >= 5.8); best-effort —
// without it the packet-mark + masquerade path still applies.

const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_PROG_ATTACH: libc::c_int = 8;
const BPF_PROG_DETACH: libc::c_int = 9;
const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
const BPF_CGROUP_INET_SOCK_CREATE: u32 = 2;

/// One BPF instruction: {code u8, dst:4|src:4, off s16, imm s32}.
fn bpf_insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = code;
    b[1] = (src << 4) | (dst & 0x0f);
    b[2..4].copy_from_slice(&off.to_ne_bytes());
    b[4..8].copy_from_slice(&imm.to_ne_bytes());
    b
}

/// The socket-mark program:  ctx->mark = BYPASS_MARK; return 1 (allow).
/// `mark` sits at offset 16 of `struct bpf_sock` (bound_dev_if, family, type,
/// protocol, mark) and is writable from cgroup/sock programs.
fn bypass_sock_prog() -> Vec<u8> {
    let mut p = Vec::with_capacity(4 * 8);
    p.extend_from_slice(&bpf_insn(0xb4, 2, 0, 0, BYPASS_MARK as i32)); // w2 = mark
    p.extend_from_slice(&bpf_insn(0x63, 1, 2, 16, 0)); // *(u32*)(r1+16) = w2
    p.extend_from_slice(&bpf_insn(0xb4, 0, 0, 0, 1)); // w0 = 1 (allow socket)
    p.extend_from_slice(&bpf_insn(0x95, 0, 0, 0, 0)); // exit
    p
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}
fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_ne_bytes());
}

fn bpf_call(cmd: libc::c_int, attr: &mut [u8]) -> Result<i64, String> {
    let rc = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.as_mut_ptr(), attr.len()) };
    if rc < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(rc)
    }
}

/// Attach (or detach) the socket-mark program to the bypass cgroup.
/// Attach flags 0 = exclusive per (cgroup, attach-type); re-attaching simply
/// REPLACES a previous instance, so this is idempotent across reconnects.
fn bypass_bpf(cgroup_rel: &str, attach: bool) -> Result<(), String> {
    let dir = format!("/sys/fs/cgroup/{}", cgroup_rel.trim_start_matches('/'));
    let cdir = std::ffi::CString::new(dir).map_err(|_| "bad path")?;
    let cg = unsafe {
        libc::open(
            cdir.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY,
        )
    };
    if cg < 0 {
        return Err(format!("open cgroup: {}", std::io::Error::last_os_error()));
    }
    let res = (|| {
        if !attach {
            // union bpf_attr (detach): target_fd @0, attach_bpf_fd @4, type @8.
            let mut attr = vec![0u8; 16];
            put_u32(&mut attr, 0, cg as u32);
            put_u32(&mut attr, 8, BPF_CGROUP_INET_SOCK_CREATE);
            return bpf_call(BPF_PROG_DETACH, &mut attr).map(|_| ());
        }
        // union bpf_attr (prog load): prog_type @0, insn_cnt @4, insns @8,
        // license @16, expected_attach_type @68.
        let insns = bypass_sock_prog();
        let license = b"Dual MIT/GPL\0";
        let mut attr = vec![0u8; 128];
        put_u32(&mut attr, 0, BPF_PROG_TYPE_CGROUP_SOCK);
        put_u32(&mut attr, 4, (insns.len() / 8) as u32);
        put_u64(&mut attr, 8, insns.as_ptr() as u64);
        put_u64(&mut attr, 16, license.as_ptr() as u64);
        put_u32(&mut attr, 68, BPF_CGROUP_INET_SOCK_CREATE);
        let prog =
            bpf_call(BPF_PROG_LOAD, &mut attr).map_err(|e| format!("prog load: {e}"))? as i32;
        // union bpf_attr (attach): target_fd @0, attach_bpf_fd @4, type @8, flags @12.
        let mut attr = vec![0u8; 16];
        put_u32(&mut attr, 0, cg as u32);
        put_u32(&mut attr, 4, prog as u32);
        put_u32(&mut attr, 8, BPF_CGROUP_INET_SOCK_CREATE);
        let r = bpf_call(BPF_PROG_ATTACH, &mut attr)
            .map(|_| ())
            .map_err(|e| format!("attach: {e}"));
        unsafe { libc::close(prog) }; // the attachment holds its own reference
        r
    })();
    unsafe { libc::close(cg) };
    res
}

// --- per-app bypass watcher (event-driven) ---------------------------------

fn cg_valid(rel: &str) -> bool {
    !rel.is_empty()
        && rel.len() <= 512
        && rel
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'@'))
}

/// comm is truncated by the kernel to TASK_COMM_LEN - 1 bytes.
const COMM_MAX: usize = 15;

fn id_matches(id: &str, comm: &str, exe: &str, exe_base: &str, arg0_base: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    // Trailing slash = a folder: match any process whose executable lives under
    // it (a whole Steam library at once, native + Proton).
    if id.ends_with('/') {
        return !exe.is_empty() && exe.starts_with(id);
    }
    // Case-insensitive: Windows filenames (Proton games) are case-insensitive,
    // and wine may report a different case in cmdline than the file the user
    // picked. arg0 covers wine/Proton, whose /proc/pid/exe is the preloader.
    if comm.eq_ignore_ascii_case(id)
        || exe_base.eq_ignore_ascii_case(id)
        || exe == id
        || (!arg0_base.is_empty() && arg0_base.eq_ignore_ascii_case(id))
    {
        return true;
    }
    // comm is truncated to 15 bytes, so an id longer than that (e.g.
    // "Cyberpunk2077.exe" → comm "Cyberpunk2077.e") must match by prefix.
    id.len() > COMM_MAX
        && comm.len() == COMM_MAX
        && id.as_bytes()[..COMM_MAX].eq_ignore_ascii_case(comm.as_bytes())
}

/// Basename of cmdline's argv[0]. Handles both unix and Windows separators —
/// under wine/Proton argv[0] is the game's Windows path ("Z:\...\Game.exe")
/// while /proc/pid/exe points at the wine preloader.
fn arg0_basename(cmdline: &[u8]) -> String {
    let first = cmdline.split(|&c| c == 0).next().unwrap_or(&[]);
    let s = String::from_utf8_lossy(first);
    s.rsplit(['/', '\\']).next().unwrap_or("").to_string()
}

/// Whether `pid`'s name/exe/argv[0] matches any excluded id.
fn pid_matches_excluded(pid: u32, excluded: &[String]) -> bool {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    let comm = comm.trim();
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    let exe_str = exe
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let exe_base = exe
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let arg0 = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| arg0_basename(&b))
        .unwrap_or_default();
    excluded
        .iter()
        .any(|id| id_matches(id, comm, &exe_str, &exe_base, &arg0))
}

/// Move `pid` into the bypass cgroup if its name/exe matches an excluded id.
fn bypass_move_if_match(procs: &str, pid: u32, excluded: &[String]) {
    if pid_matches_excluded(pid, excluded) {
        let _ = std::fs::write(procs, pid.to_string());
    }
}

/// `/proc/net/*` prints an address as the host-order value of its `__be32`
/// word(s); on little-endian that is the network bytes in memory order, i.e. the
/// value's little-endian bytes. (Verified: `DCA79A95` → 149.154.167.220.)
fn hex_to_ipv4(hex: &str) -> Option<std::net::Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    Some(std::net::Ipv4Addr::from(
        u32::from_str_radix(hex, 16).ok()?.to_le_bytes(),
    ))
}

fn hex_to_ipv6(hex: &str) -> Option<std::net::Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for w in 0..4 {
        let word = u32::from_str_radix(&hex[w * 8..w * 8 + 8], 16).ok()?;
        bytes[w * 4..w * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(std::net::Ipv6Addr::from(bytes))
}

/// nft batch pinning existing flows to the physical path via BYPASS_MARK:
/// destination rules for known peers, source-port rules for unconnected-UDP
/// game sockets. Appended to the bypass table's mangle chain, so the mark both
/// routes them out the physical NIC (fwmark rule → PHYS_TABLE) and passes the
/// killswitch — which no longer accepts outbound `established` flows, so a
/// bare destination ROUTE pin would get its packets dropped there.
fn pin_rules_batch(
    peers4: &std::collections::BTreeSet<std::net::Ipv4Addr>,
    peers6: &std::collections::BTreeSet<std::net::Ipv6Addr>,
    udp_sports: &std::collections::BTreeSet<u16>,
) -> String {
    let mark = format!("{BYPASS_MARK:#x}");
    let mut b = String::new();
    // NOTE: a daddr pin is destination-only — ALL host traffic to that IP goes
    // physical for the session. Correct for the excluded app; for a SHARED peer
    // IP it would also divert a non-excluded app's traffic there. Fine for
    // games (dedicated server IPs), the intended use of the per-app bypass.
    for ip in peers4 {
        b.push_str(&format!(
            "add rule inet {BYPASS_TABLE} mangle ip daddr {ip} meta mark set {mark}\n"
        ));
    }
    for ip in peers6 {
        b.push_str(&format!(
            "add rule inet {BYPASS_TABLE} mangle ip6 daddr {ip} meta mark set {mark}\n"
        ));
    }
    // Marks any UDP from this local port — over-reach is bounded to that exact
    // port number, narrower than a shared-IP pin.
    for p in udp_sports {
        b.push_str(&format!(
            "add rule inet {BYPASS_TABLE} mangle udp sport {p} meta mark set {mark}\n"
        ));
    }
    b
}

/// Pin the CURRENT flows of every already-running excluded app to the physical
/// path, by tagging them with BYPASS_MARK in the bypass table (nft rules by
/// remote peer / by bound UDP source port).
///
/// Why this is needed in addition to the cgroup tag: `socket cgroupv2` classifies
/// by the socket's CREATION-time cgroup, which the kernel never updates when a
/// running task is moved between cgroups — so moving an in-match game into the
/// bypass cgroup tags none of its open sockets, and the flip into the tun would
/// otherwise swallow that flow. The pre-existing socket already holds the real
/// physical source, so the masquerade is a no-op for it. The pins live in the
/// bypass nft table and die with it (route-down / bypass-down) — no extra
/// teardown state. Snapshot only: new connections are covered by the cgroup
/// tag. Best-effort. MUST run after `bypass_up` (the table/chain must exist).
fn pin_existing_excluded_flows(excluded: &[String]) {
    // Socket inodes owned by currently-running excluded processes.
    let mut inodes = std::collections::HashSet::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            if !pid_matches_excluded(pid, excluded) {
                continue;
            }
            if let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
                for fd in fds.flatten() {
                    if let Ok(t) = std::fs::read_link(fd.path()) {
                        if let Some(ino) = t
                            .to_str()
                            .and_then(|s| s.strip_prefix("socket:["))
                            .and_then(|s| s.strip_suffix(']'))
                        {
                            inodes.insert(ino.to_string());
                        }
                    }
                }
            }
        }
    }
    if inodes.is_empty() {
        return;
    }
    // Map those sockets to their remote peers (col 1 = local_address, col 2 =
    // rem_address, col 9 = inode in /proc/net/{tcp,udp,...}).
    //   - TCP / connect()ed UDP: pin the remote peer to physical by /32 route.
    //   - UNCONNECTED UDP (rem port 0): the Source/CS2 netcode uses one bound
    //     sendto/recvfrom socket with NO remote in /proc/net/udp, so there is no
    //     peer to route to. Mark its outgoing packets by BOUND LOCAL PORT instead
    //     (nft, below) so the live game flow stays physical too. (Reading the peer
    //     from conntrack is unreliable here — on a fresh connect the flow may not
    //     be tracked yet.)
    let mut peers4 = std::collections::BTreeSet::new();
    let mut peers6 = std::collections::BTreeSet::new();
    let mut udp_sports: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    for (path, is6) in [
        ("/proc/net/tcp", false),
        ("/proc/net/udp", false),
        ("/proc/net/tcp6", true),
        ("/proc/net/udp6", true),
    ] {
        let is_udp = path.contains("udp");
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 || !inodes.contains(cols[9]) {
                continue;
            }
            let Some((ip_hex, port_hex)) = cols[2].split_once(':') else {
                continue;
            };
            if u16::from_str_radix(port_hex, 16).unwrap_or(0) == 0 {
                // No remote peer. For UDP that means an unconnected socket — keep
                // its bound local port physical by source-port mark. (TCP with no
                // peer is a listener: nothing to send, skip.)
                if is_udp {
                    if let Some((_, lport_hex)) = cols[1].split_once(':') {
                        if let Ok(lp) = u16::from_str_radix(lport_hex, 16) {
                            if lp != 0 {
                                udp_sports.insert(lp);
                            }
                        }
                    }
                }
                continue;
            }
            if is6 {
                if let Some(ip) = hex_to_ipv6(ip_hex) {
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        peers6.insert(ip);
                    }
                }
            } else if let Some(ip) = hex_to_ipv4(ip_hex) {
                if !ip.is_loopback() && !ip.is_unspecified() {
                    peers4.insert(ip);
                }
            }
        }
    }

    // One atomic nft batch into the (already created) bypass table.
    let batch = pin_rules_batch(&peers4, &peers6, &udp_sports);
    if !batch.is_empty() {
        let _ = nft_apply(&batch);
    }
}

fn bypass_sweep(procs: &str, excluded: &[String]) {
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            if let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                bypass_move_if_match(procs, pid, excluded);
            }
        }
    }
}

/// Long-running (until killed by the GUI) watcher: subscribe to the kernel proc
/// connector and, on every exec / comm-change, move a matching process into the
/// bypass cgroup immediately. An initial sweep catches already-running matches.
fn bypass_watch(cgroup_rel: &str, excluded: &[String]) -> i32 {
    if !cg_valid(cgroup_rel) {
        eprintln!("invalid cgroup path");
        return 2;
    }
    // Exit if the spawning GUI goes away (checked on each recv timeout). NOTE:
    // PR_SET_PDEATHSIG is wrong here — it fires on the parent THREAD's death, and
    // the GUI spawns us from a short-lived tokio worker, which would kill us
    // almost immediately.
    let gui_pid = unsafe { libc::getppid() };
    let procs = format!(
        "/sys/fs/cgroup/{}/cgroup.procs",
        cgroup_rel.trim_start_matches('/')
    );

    bypass_sweep(&procs, excluded);

    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_CONNECTOR,
        )
    };
    if fd < 0 {
        eprintln!("netlink socket: {}", std::io::Error::last_os_error());
        return 1;
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = CN_IDX_PROC;
    let alen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
    if unsafe { libc::bind(fd, &addr as *const _ as *const libc::sockaddr, alen) } < 0 {
        eprintln!("netlink bind: {}", std::io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return 1;
    }
    // Wake recv every 2s so we can notice the GUI exiting and stop.
    let tv = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    // Subscribe: nlmsghdr(16) + cn_msg(20) + op(4).
    let mut listen = [0u8; 40];
    listen[0..4].copy_from_slice(&40u32.to_ne_bytes());
    listen[4..6].copy_from_slice(&3u16.to_ne_bytes()); // NLMSG_DONE
    listen[12..16].copy_from_slice(&std::process::id().to_ne_bytes());
    listen[16..20].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
    listen[20..24].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
    listen[32..34].copy_from_slice(&4u16.to_ne_bytes()); // cn_msg.len
    listen[36..40].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
    if unsafe { libc::send(fd, listen.as_ptr() as *const _, listen.len(), 0) } < 0 {
        eprintln!("netlink send: {}", std::io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return 1;
    }

    // proc_event layout in the datagram: nlmsghdr(16) + cn_msg(20) → `what` at
    // 36, exec/comm process_tgid at 56.
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            match e.kind() {
                std::io::ErrorKind::Interrupted => continue,
                // recv timed out: stop if the GUI (our original parent) is gone.
                std::io::ErrorKind::WouldBlock => {
                    if unsafe { libc::getppid() } != gui_pid {
                        break;
                    }
                    continue;
                }
                _ => {
                    eprintln!("bypass-watch recv: {e}");
                    break;
                }
            }
        }
        if (n as usize) < 60 {
            continue;
        }
        let what = u32::from_ne_bytes([buf[36], buf[37], buf[38], buf[39]]);
        if what == PROC_EVENT_EXEC || what == PROC_EVENT_COMM {
            let tgid = u32::from_ne_bytes([buf[56], buf[57], buf[58], buf[59]]);
            if tgid != 0 {
                bypass_move_if_match(&procs, tgid, excluded);
            }
        }
    }
    unsafe { libc::close(fd) };
    0
}

fn delete_tun() {
    let _ = Command::new("ip")
        .arg("link")
        .arg("delete")
        .arg("dev")
        .arg(TUN_IFACE)
        .stderr(Stdio::null())
        .status();
}

// --- routing for xray's native tun -----------------------------------------
//
// xray's native tun creates the device but manages NO routes/DNS, so the helper
// lays: the default route into the tun (all traffic enters; xray's routing then
// does the per-app/site split via its native process/domain matchers), a
// physical bypass table + ip rule for xray's own marked dials (anti-loop), the
// anti-loop server /32, and loose rp_filter. No cgroup — per-app is xray's job.

/// Run `ip <args>`, returning an error with stderr on failure.
fn ip_req(args: &[&str]) -> Result<(), String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Run `ip <args>`, ignoring the result (idempotent teardown / best-effort).
fn ip_quiet(args: &[&str]) {
    let _ = Command::new("ip").args(args).stderr(Stdio::null()).status();
}

fn write_file(path: &str, val: &str) -> Result<(), String> {
    std::fs::write(path, val).map_err(|e| format!("write {path}: {e}"))
}

/// Write a fixed-name state file under /run/varmlen WITHOUT following symlinks.
/// /run is tmpfs with no root pre-creation, so the dir is created by the
/// (unprivileged) invoking user on first run; a same-uid attacker could swap a
/// state file for a symlink to a root-owned target and our cap_dac_override
/// write would clobber it. O_NOFOLLOW + a 0700 dir close that. Best-effort.
fn write_state(path: &str, val: &str) {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let _ = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create("/run/varmlen");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        let _ = f.write_all(val.as_bytes());
    }
}

/// The physical default route `(gateway, iface)`, ignoring our own tun. The
/// gateway is optional: point-to-point/link-scope defaults (PPP/LTE modems,
/// WireGuard-as-default — `default dev ppp0 scope link`) have a `dev` but no
/// `via`, and must still work.
fn detect_default_route() -> Result<(Option<String>, String), String> {
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .map_err(|e| format!("ip route: {e}"))?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.contains(&format!("dev {TUN_IFACE}")) {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        let via = toks
            .iter()
            .position(|&t| t == "via")
            .and_then(|i| toks.get(i + 1));
        let dev = toks
            .iter()
            .position(|&t| t == "dev")
            .and_then(|i| toks.get(i + 1));
        if let Some(d) = dev {
            return Ok((via.map(|g| g.to_string()), d.to_string()));
        }
    }
    Err("no physical default route found".into())
}

/// The physical IPv6 default route `(gateway, iface)`, if the host has v6.
fn detect_default_route6() -> Option<(String, String)> {
    let out = Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()
        .ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.contains(&format!("dev {TUN_IFACE}")) {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        let via = toks
            .iter()
            .position(|&t| t == "via")
            .and_then(|i| toks.get(i + 1));
        let dev = toks
            .iter()
            .position(|&t| t == "dev")
            .and_then(|i| toks.get(i + 1));
        if let (Some(g), Some(d)) = (via, dev) {
            return Some((g.to_string(), d.to_string()));
        }
    }
    None
}

/// Ensure `varmlen0` exists (xray normally creates it; create a persistent device
/// as a fallback), is addressed, and is up.
fn ensure_tun() -> Result<(), String> {
    if !std::path::Path::new(&format!("/sys/class/net/{TUN_IFACE}")).exists() {
        ip_quiet(&["tuntap", "add", "dev", TUN_IFACE, "mode", "tun"]);
    }
    ip_quiet(&["addr", "replace", TUN_ADDR, "dev", TUN_IFACE]);
    ip_req(&["link", "set", TUN_IFACE, "up"])
}

const RP_ALL: &str = "/proc/sys/net/ipv4/conf/all/rp_filter";

/// Loosen reverse-path filtering (RPF) so the asymmetric bypass replies on the
/// physical NIC aren't dropped. Effective RPF = max(all, iface), so setting
/// `all=2` (loose) suffices. Original captured for restore.
fn set_rp_filter_loose() -> Result<(), String> {
    let orig = std::fs::read_to_string(RP_ALL).unwrap_or_default();
    write_state(RP_STATE, orig.trim());
    write_file(RP_ALL, "2")
}

/// Add an `ip [-6] rule fwmark <mark> lookup <table>` idempotently.
fn add_rule_fwmark(v6: bool, mark: u32, table: &str) -> Result<(), String> {
    let m = format!("{mark:#x}");
    let fam = if v6 { "-6" } else { "-4" };
    ip_quiet(&[fam, "rule", "del", "fwmark", &m, "lookup", table]);
    ip_req(&[fam, "rule", "add", "fwmark", &m, "lookup", table])
}

fn dns_policy_setup_commands() -> Vec<Vec<&'static str>> {
    vec![
        vec![
            "route", "replace", "default", "dev", TUN_IFACE, "table", DNS_TABLE,
        ],
        vec![
            "rule", "del", "priority", "90", "fwmark", DNS_MARK, "lookup", DNS_TABLE,
        ],
        vec![
            "rule", "add", "priority", "90", "fwmark", DNS_MARK, "lookup", DNS_TABLE,
        ],
    ]
}

fn dns_policy_teardown_commands() -> Vec<Vec<&'static str>> {
    vec![
        vec![
            "rule", "del", "priority", "90", "fwmark", DNS_MARK, "lookup", DNS_TABLE,
        ],
        vec!["route", "flush", "table", DNS_TABLE],
    ]
}

fn install_dns_policy_route() -> Result<(), String> {
    let commands = dns_policy_setup_commands();
    ip_req(&commands[0])?;
    ip_quiet(&commands[1]);
    ip_req(&commands[2])
}

fn remove_dns_policy_route() {
    for command in dns_policy_teardown_commands() {
        ip_quiet(&command);
    }
}

/// Lay the routing xray's native tun needs. Atomic-ish: rolls back via
/// `route_down` on any error. Mode-independent — the per-app/site split is
/// entirely xray's job (native `process`/`domain` routing); the helper only
/// gets traffic into the tun and keeps xray's own dials out of it.
fn route_up(
    servers: &[std::net::IpAddr],
    bypass_cgroup: Option<&str>,
    bypass_apps: &[String],
) -> Result<(), String> {
    let (gw, iface) = detect_default_route()?;

    let result = (|| -> Result<(), String> {
        // 1. tun device (xray usually created it already; ensure addr + up).
        ensure_tun()?;
        install_dns_policy_route()?;

        // 2. loosen RPF so the asymmetric bypass replies aren't dropped.
        set_rp_filter_loose()?;

        // 3. physical bypass table + rule for xray's own marked dials, so the
        //    proxy/direct outbounds escape the tun instead of looping. The
        //    gateway is omitted on link-scope defaults (PPP/LTE/wg).
        let mut def: Vec<&str> = vec!["route", "replace", "default"];
        if let Some(g) = gw.as_deref() {
            def.push("via");
            def.push(g);
        }
        def.push("dev");
        def.push(&iface);
        def.push("table");
        def.push(PHYS_TABLE);
        ip_req(&def)?;
        // LAN/link-local must NOT hit this table's default (it would bounce
        // local traffic off the gateway): `throw` falls back to the main table,
        // whose subnet routes handle it. Matters for marked-at-creation sockets
        // of excluded apps talking to LAN peers.
        for net in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "224.0.0.0/4",
            "255.255.255.255/32",
        ] {
            ip_req(&["route", "replace", "throw", net, "table", PHYS_TABLE])?;
        }
        add_rule_fwmark(false, XRAY_DIAL_MARK, PHYS_TABLE)?;
        // Same physical bypass for per-app excluded traffic (nft tags it 0x2025).
        add_rule_fwmark(false, BYPASS_MARK, PHYS_TABLE)?;

        // v6 default + fwmark rules too (when the host has v6): marked flows —
        // notably the v6 pins of a running excluded app — must egress the
        // physical NIC, not fall into the main table's v6 blackhole (step 6).
        let v6 = detect_default_route6();
        if let Some((g6, if6)) = v6.as_ref() {
            ip_req(&[
                "-6", "route", "replace", "default", "via", g6, "dev", if6, "table", PHYS_TABLE,
            ])?;
            for net in ["fe80::/10", "fc00::/7", "ff00::/8"] {
                ip_req(&["-6", "route", "replace", "throw", net, "table", PHYS_TABLE])?;
            }
            add_rule_fwmark(true, XRAY_DIAL_MARK, PHYS_TABLE)?;
            add_rule_fwmark(true, BYPASS_MARK, PHYS_TABLE)?;
        }

        // 4. anti-loop FIRST: pin each server IP to the physical path (more
        //    specific than 0/1) so xray's dial escapes the tun even if SO_MARK
        //    no-ops — laid before the default-into-tun route below.
        let mut server_lines = String::new();
        for s in servers {
            if let std::net::IpAddr::V4(v4) = s {
                let dst = format!("{v4}/32");
                let mut r: Vec<&str> = vec!["route", "replace", &dst];
                if let Some(g) = gw.as_deref() {
                    r.push("via");
                    r.push(g);
                }
                r.push("dev");
                r.push(&iface);
                ip_req(&r)?;
                server_lines.push_str(&format!("{v4}\n"));
            }
        }
        write_state(SERVERS_STATE, &server_lines);

        // 4b. Arm the per-app bypass NOW, BEFORE the default flips into the tun
        //     (step 5), via TWO mechanisms with different coverage:
        //       - bypass_up tags the cgroup so NEW connections from excluded apps
        //         egress physical (masquerade rewrites their tun-picked source);
        //         bypass_sweep moves the running excluded processes in.
        //       - pin_existing_excluded_flows marks each running excluded app's
        //         CURRENT flows (by peer / by UDP source port), because a cgroup
        //         move can't re-tag an already-open socket (sk_cgrp_data is fixed
        //         at creation) — without this a live game flow is swallowed by
        //         the tun at the flip.
        //     FATAL on tag failure: a running excluded app must never be silently
        //     flipped into the tun. route_up's caller rolls back via route_down.
        if let Some(cg) = bypass_cgroup {
            bypass_up(cg, Some(&iface)).map_err(|e| {
                format!("per-app bypass setup failed ({e}); turn off app exclusions to connect without it")
            })?;
            let procs = format!("/sys/fs/cgroup/{}/cgroup.procs", cg.trim_start_matches('/'));
            bypass_sweep(&procs, bypass_apps);
            pin_existing_excluded_flows(bypass_apps);
        }

        // 5. default into the tun (0/1 + 128/1 are more specific than the
        //    existing physical default, which stays as fallback). Everything
        //    enters the tun; xray's routing decides proxy vs direct per app/site.
        ip_req(&["route", "replace", "0.0.0.0/1", "dev", TUN_IFACE])?;
        ip_req(&["route", "replace", "128.0.0.0/1", "dev", TUN_IFACE])?;

        // 6. IPv6: the tun is v4-only, so v6 must fail CLOSED — otherwise native
        //    v6 traffic (incl. plaintext v6 DNS) leaks straight out the physical
        //    NIC. Blackhole v6 with /1 routes (more specific than the physical
        //    ::/0 default, left intact for clean teardown). A v6 server dial, if
        //    any, gets a /128 bypass first (longest-prefix wins over the /1).
        let mut s6 = String::new();
        for s in servers {
            if let std::net::IpAddr::V6(addr) = s {
                if let Some((gw6, if6)) = v6.as_ref() {
                    ip_req(&[
                        "-6",
                        "route",
                        "replace",
                        &format!("{addr}/128"),
                        "via",
                        gw6,
                        "dev",
                        if6,
                    ])?;
                    s6.push_str(&format!("{addr}\n"));
                }
            }
        }
        write_state(SERVERS6_STATE, &s6);
        ip_req(&["-6", "route", "replace", "blackhole", "::/1"])?;
        ip_req(&["-6", "route", "replace", "blackhole", "8000::/1"])?;
        Ok(())
    })();

    if result.is_err() {
        route_down(false);
    }
    result
}

/// Tear the tun routing down. Idempotent and best-effort; restores physical
/// reachability FIRST so a partial failure never black-holes the box.
///
/// `keep_bypass`: leave the per-app bypass nft table (cgroup tag + masquerade +
/// existing-flow pins) in place — used across a RECONNECT so an excluded app's
/// live flows keep their 0x2025 mark through the gap (the killswitch accepts
/// only marked/reply traffic, and the next route-up recreates the table anyway).
fn route_down(keep_bypass: bool) {
    // 1. drop the tun default overrides → physical default is reachable again.
    ip_quiet(&["route", "del", "0.0.0.0/1", "dev", TUN_IFACE]);
    ip_quiet(&["route", "del", "128.0.0.0/1", "dev", TUN_IFACE]);
    remove_dns_policy_route();

    // 1b. drop the IPv6 blackholes + any v6 server bypass routes.
    ip_quiet(&["-6", "route", "del", "::/1"]);
    ip_quiet(&["-6", "route", "del", "8000::/1"]);
    if let Ok(list) = std::fs::read_to_string(SERVERS6_STATE) {
        for ip in list.lines().filter(|l| !l.trim().is_empty()) {
            ip_quiet(&["-6", "route", "del", &format!("{}/128", ip.trim())]);
        }
        let _ = std::fs::remove_file(SERVERS6_STATE);
    }

    // 2. remove the dial-mark + bypass-mark policy rules, both families (loop:
    //    a crash may have stacked dups). Marked packets then fall through to
    //    the main table's physical default — still the right egress.
    for mark in [XRAY_DIAL_MARK, BYPASS_MARK] {
        let m = format!("{mark:#x}");
        for fam in ["-4", "-6"] {
            for _ in 0..4 {
                let ok = Command::new("ip")
                    .args([fam, "rule", "del", "fwmark", &m])
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if !ok {
                    break;
                }
            }
        }
    }
    if !keep_bypass {
        // The per-app bypass nft table (mangle marks + pins + masquerade), if
        // up. (The cgroup BPF program, when the GUI doesn't detach it via
        // `bypass-down <rel>`, stays attached but is inert without the rules —
        // the next bypass-up replaces it.)
        bypass_down(None);

        // Legacy: dst-route pins written by an older dev build's state file.
        if let Ok(list) = std::fs::read_to_string(BYPASS_PINS_STATE) {
            for ip in list.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
                if ip.contains(':') {
                    ip_quiet(&["-6", "route", "del", &format!("{ip}/128")]);
                } else {
                    ip_quiet(&["route", "del", &format!("{ip}/32")]);
                }
            }
            let _ = std::fs::remove_file(BYPASS_PINS_STATE);
        }
    }

    // 3. flush the physical bypass table (both families).
    ip_quiet(&["route", "flush", "table", PHYS_TABLE]);
    ip_quiet(&["-6", "route", "flush", "table", PHYS_TABLE]);

    // 4. remove the anti-loop server /32 routes recorded at route-up.
    if let Ok(list) = std::fs::read_to_string(SERVERS_STATE) {
        for ip in list.lines().filter(|l| !l.trim().is_empty()) {
            ip_quiet(&["route", "del", &format!("{}/32", ip.trim())]);
        }
        let _ = std::fs::remove_file(SERVERS_STATE);
    }

    // 5. restore RPF.
    if let Ok(orig) = std::fs::read_to_string(RP_STATE) {
        let v = orig.trim();
        if !v.is_empty() {
            let _ = write_file(RP_ALL, v);
        }
        let _ = std::fs::remove_file(RP_STATE);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        arg0_basename, dns_policy_setup_commands, dns_policy_teardown_commands, hex_to_ipv4,
        hex_to_ipv6, id_matches, killswitch_ruleset, pin_rules_batch,
    };

    #[test]
    fn dns_mark_has_a_dedicated_tun_policy_route() {
        assert_eq!(
            dns_policy_setup_commands(),
            vec![
                vec!["route", "replace", "default", "dev", "varmlen0", "table", "101",],
                vec!["rule", "del", "priority", "90", "fwmark", "0x2023", "lookup", "101",],
                vec!["rule", "add", "priority", "90", "fwmark", "0x2023", "lookup", "101",],
            ]
        );
        assert_eq!(
            dns_policy_teardown_commands(),
            vec![
                vec!["rule", "del", "priority", "90", "fwmark", "0x2023", "lookup", "101",],
                vec!["route", "flush", "table", "101"],
            ]
        );
    }

    #[test]
    fn killswitch_does_not_accept_outbound_established() {
        // The reconnect real-IP leak: a bare `ct state established,related
        // accept` lets PRE-VPN outbound flows (e.g. a browser's QUIC session,
        // which migrates addresses seamlessly) resume on the physical NIC the
        // moment the tun goes away mid-reconnect. Established must be accepted
        // only in the REPLY direction (inbound services like SSH keep working).
        let r = killswitch_ruleset(&[], false);
        assert!(
            r.contains("ct state established,related ct direction reply counter accept"),
            "established accept must be narrowed to ct direction reply:\n{r}"
        );
        assert!(
            !r.contains("ct state established,related counter accept"),
            "bare established accept must be gone:\n{r}"
        );
    }

    #[test]
    fn killswitch_keeps_marks_servers_and_policy() {
        let ips = vec!["1.2.3.4".parse().unwrap(), "2001:db8::5".parse().unwrap()];
        let r = killswitch_ruleset(&ips, true);
        assert!(r.contains("policy drop"));
        assert!(r.contains("meta mark & 0x0000ffff == 0x2024 counter accept"));
        assert!(r.contains("meta mark & 0x0000ffff == 0x2025 counter accept"));
        assert!(r.contains("ip daddr 1.2.3.4 counter accept"));
        assert!(r.contains("ip6 daddr 2001:db8::5 counter accept"));
        assert!(r.contains("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } counter accept")); // allow-lan block present
        let r2 = killswitch_ruleset(&ips, false);
        assert!(!r2.contains("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } counter accept"));
    }

    #[test]
    fn killswitch_blocks_dns_to_lan_even_with_allow_lan() {
        // The DNS leak this fixes: allow_lan previously let port-53 packets to
        // the router through unconditionally. This must hold regardless of the
        // flag — it's the backstop for configure_dns, not gated by it.
        for allow_lan in [true, false] {
            let r = killswitch_ruleset(&[], allow_lan);
            assert!(
                r.contains("udp dport 53 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } counter drop"),
                "allow_lan={allow_lan}:\n{r}"
            );
            assert!(
                r.contains("tcp dport 53 ip daddr { 10.0.0.0/8"),
                "allow_lan={allow_lan}:\n{r}"
            );
            assert!(r.contains("udp dport 53 ip6 daddr { fe80::/10, fc00::/7 } counter drop"));
            // The drop must appear BEFORE any LAN accept block so it wins the match.
            if allow_lan {
                let drop_pos = r.find("udp dport 53 ip daddr {").unwrap();
                let accept_pos = r.find("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } counter accept").unwrap();
                assert!(
                    drop_pos < accept_pos,
                    "dns-drop must precede the lan-accept block"
                );
            }
        }
    }

    #[test]
    fn pin_rules_mark_peers_and_udp_sports() {
        // Existing-flow pins must ride the 0x2025 mark (bypass table), NOT bare
        // /32 routes: the mark both routes them physical (fwmark rule) and lets
        // them pass the killswitch now that outbound established is dropped.
        let peers4 = ["91.92.43.10".parse().unwrap()].into_iter().collect();
        let peers6 = ["2001:db8::7".parse().unwrap()].into_iter().collect();
        let sports = [27015u16].into_iter().collect();
        let batch = pin_rules_batch(&peers4, &peers6, &sports);
        assert!(batch.contains(
            "add rule inet varmlen_bypass mangle ip daddr 91.92.43.10 meta mark set 0x2025"
        ));
        assert!(batch.contains(
            "add rule inet varmlen_bypass mangle ip6 daddr 2001:db8::7 meta mark set 0x2025"
        ));
        assert!(batch
            .contains("add rule inet varmlen_bypass mangle udp sport 27015 meta mark set 0x2025"));
    }

    #[test]
    fn sock_prog_shape() {
        // ctx->mark = 0x2025; return 1 — exactly 4 insns, mark at bpf_sock+16.
        let p = super::bypass_sock_prog();
        assert_eq!(p.len(), 4 * 8);
        assert_eq!(p[0], 0xb4); // ALU32 MOV imm
        assert_eq!(p[1], 0x02); // dst w2
        assert_eq!(&p[4..8], &0x2025i32.to_ne_bytes());
        assert_eq!(p[8], 0x63); // STX word
        assert_eq!(p[9], 0x21); // src r2 -> dst r1
        assert_eq!(&p[10..12], &16i16.to_ne_bytes()); // offsetof(bpf_sock, mark)
        assert_eq!(p[16], 0xb4); // w0 = 1 (allow)
        assert_eq!(&p[20..24], &1i32.to_ne_bytes());
        assert_eq!(p[24], 0x95); // exit
    }

    #[test]
    fn pin_rules_empty_when_nothing_to_pin() {
        let batch = pin_rules_batch(
            &std::collections::BTreeSet::new(),
            &std::collections::BTreeSet::new(),
            &std::collections::BTreeSet::new(),
        );
        assert!(batch.is_empty());
    }

    #[test]
    fn id_matches_plain_names() {
        // Browsers / native apps: comm or exe basename equals the id.
        assert!(id_matches(
            "firefox",
            "firefox",
            "/usr/lib/firefox/firefox",
            "firefox",
            ""
        ));
        assert!(id_matches(
            "cs2",
            "cs2",
            "/home/u/steam/cs2/cs2",
            "cs2",
            "cs2"
        ));
        assert!(!id_matches(
            "firefox",
            "chrome",
            "/opt/chrome/chrome",
            "chrome",
            "chrome"
        ));
        assert!(!id_matches(
            "",
            "firefox",
            "/usr/bin/firefox",
            "firefox",
            "firefox"
        ));
    }

    #[test]
    fn id_matches_truncated_comm() {
        // The kernel truncates comm to 15 bytes (TASK_COMM_LEN - 1). A Proton
        // game "Cyberpunk2077.exe" shows comm "Cyberpunk2077.e" and its
        // /proc/pid/exe is the wine preloader — the truncated comm must match.
        assert!(id_matches(
            "Cyberpunk2077.exe",
            "Cyberpunk2077.e",
            "/usr/lib/wine/wine64-preloader",
            "wine64-preloader",
            ""
        ));
        // But a 15-byte comm that is NOT a prefix of the id must not match.
        assert!(!id_matches(
            "Cyberpunk2077.exe",
            "SomeOtherGame.e",
            "/usr/lib/wine/wine64-preloader",
            "wine64-preloader",
            ""
        ));
        // And a short comm (not truncated) must not prefix-match a longer id.
        assert!(!id_matches("firefox-esr", "firefox", "", "", ""));
    }

    #[test]
    fn id_matches_wine_arg0() {
        // Proton/wine: cmdline[0] is the Windows path of the real game exe;
        // exe points at wine. The arg0 basename must match, case-insensitively
        // (Windows filenames are case-insensitive).
        assert!(id_matches(
            "TslGame.exe",
            "TslGame.exe",
            "/usr/lib/wine/wine64-preloader",
            "wine64-preloader",
            "TslGame.exe"
        ));
        assert!(id_matches(
            "game.exe",
            "wine64",
            "/usr/lib/wine/wine64",
            "wine64",
            "Game.exe"
        ));
    }

    #[test]
    fn id_matches_folder_prefix() {
        // Trailing slash = folder id: any exe under it matches.
        assert!(id_matches(
            "/home/u/.steam/steamapps/common/",
            "eldenring",
            "/home/u/.steam/steamapps/common/ELDEN RING/eldenring",
            "eldenring",
            ""
        ));
        assert!(!id_matches(
            "/home/u/.steam/steamapps/common/",
            "firefox",
            "/usr/lib/firefox/firefox",
            "firefox",
            ""
        ));
    }

    #[test]
    fn arg0_basename_handles_unix_and_windows_paths() {
        assert_eq!(arg0_basename(b"/usr/bin/firefox\0-new-tab\0"), "firefox");
        assert_eq!(
            arg0_basename(b"Z:\\Games\\PUBG\\TslGame.exe\0-windowed\0"),
            "TslGame.exe"
        );
        assert_eq!(arg0_basename(b"C:/Games/Game.exe\0"), "Game.exe");
        assert_eq!(arg0_basename(b"game.exe\0"), "game.exe");
        assert_eq!(arg0_basename(b""), "");
    }

    #[test]
    fn ipv4_from_proc_net_hex() {
        // /proc/net/tcp dumps the address as the host value of its __be32 → the
        // value's little-endian bytes are the dotted octets. (Verified live.)
        let v4 = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        assert_eq!(hex_to_ipv4("DCA79A95").unwrap(), v4("149.154.167.220"));
        assert_eq!(hex_to_ipv4("0100007F").unwrap(), v4("127.0.0.1"));
        assert_eq!(hex_to_ipv4("0A2B5C5B").unwrap(), v4("91.92.43.10"));
        assert_eq!(hex_to_ipv4("00000000").unwrap(), v4("0.0.0.0"));
        assert!(hex_to_ipv4("XYZ").is_none());
        assert!(hex_to_ipv4("DCA79A9").is_none()); // wrong length
    }

    #[test]
    fn ipv6_from_proc_net_hex() {
        // Each 8-hex group is one host-order __be32 word; its LE bytes are the
        // network bytes. 2001:db8::1 → "B80D0120" "00000000" "00000000" "01000000".
        assert_eq!(
            hex_to_ipv6("B80D0120000000000000000001000000").unwrap(),
            "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(
            hex_to_ipv6("00000000000000000000000001000000").unwrap(),
            "::1".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert!(hex_to_ipv6("00").is_none());
    }
}
