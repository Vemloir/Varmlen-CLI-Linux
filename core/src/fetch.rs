//! Subscription fetching, lifted verbatim from the Tauri crate's `lib.rs`.
//!
//! The SSRF guards here are load-bearing: subscription URLs come from the user
//! and are fetched by a privileged-adjacent client, so loopback/private targets,
//! embedded credentials and unbounded redirects are all refused, and the
//! resolved addresses are pinned into the HTTP client so DNS cannot be
//! re-resolved to a different host between the check and the request.

use std::time::Duration;

use crate::subscription::{
    decode_maybe_b64, is_supported_uri, parse_body_meta, parse_headers, parse_json_subscription,
    parse_proxy_uri, parse_subscription, ImportResult, SubscriptionMeta,
};

fn is_blocked_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                || octets[0] >= 240
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(std::net::IpAddr::V4(v4));
            }
            let octets = v6.octets();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (octets[0] & 0xfe) == 0xfc
                || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
                || (octets[0] == 0x20
                    && octets[1] == 0x01
                    && octets[2] == 0x0d
                    && octets[3] == 0xb8)
        }
    }
}

/// True for hosts we refuse to fetch before DNS resolution.
fn is_blocked_host(host: &str) -> bool {
    let h = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    h.parse::<std::net::IpAddr>().is_ok_and(is_blocked_ip)
}

async fn fetch_subscription_response(
    mut url: url::Url,
    user_agent: &str,
    device_os: &str,
) -> Result<reqwest::Response, String> {
    const MAX_REDIRECTS: usize = 5;
    for redirect_count in 0..=MAX_REDIRECTS {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!("unsupported URL scheme: {}", url.scheme()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("subscription URLs with embedded credentials are not permitted".into());
        }
        let host = url
            .host_str()
            .filter(|host| !is_blocked_host(host))
            .ok_or_else(|| "refusing to fetch a loopback/private address".to_string())?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "subscription URL has no usable port".to_string())?;
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| format!("subscription host resolution failed: {error}"))?
            .collect::<Vec<_>>();
        if addresses.is_empty() || addresses.iter().any(|address| is_blocked_ip(address.ip())) {
            return Err("refusing to fetch a host that resolves to a non-public address".into());
        }

        let client = reqwest::Client::builder()
            .user_agent(user_agent)
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|error| format!("http client: {error}"))?;
        let response = client
            .get(url.clone())
            .header("X-Device-OS", device_os)
            .send()
            .await
            .map_err(|error| format!("request failed: {error}"))?;
        if !response.status().is_redirection() {
            return Ok(response);
        }
        if redirect_count == MAX_REDIRECTS {
            return Err("too many redirects".into());
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| "redirect response has no valid Location header".to_string())?;
        url = url
            .join(location)
            .map_err(|error| format!("invalid redirect URL: {error}"))?;
    }
    Err("too many redirects".into())
}

fn target_platform() -> &'static str {
    if cfg!(target_os = "android") {
        "Android"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else {
        std::env::consts::OS
    }
}

fn target_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        other => other,
    }
}

fn subscription_headers(choice: Option<&str>) -> Result<(String, String), String> {
    let brand = match choice.unwrap_or("varmlen") {
        "varmlen" => "Varmlen",
        "happ" => "Happ",
        "incy" => "INCY",
        _ => return Err("unsupported subscription User-Agent".into()),
    };
    Ok((
        format!("{brand}/{}/{}", target_platform(), target_arch()),
        target_platform().to_ascii_lowercase(),
    ))
}

/// Fetch and parse a subscription. Returns servers + server-side metadata
/// (title, update interval, traffic counters, expiry, support URL).
///
/// If `url` is a raw `vless://` link, returns a single-server result with
/// an empty meta block.
pub async fn fetch_subscription(
    url: String,
    subscription_user_agent: Option<String>,
) -> Result<ImportResult, String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err("empty URL".to_string());
    }

    // Pasted JSON: an xray/v2ray config, a single outbound, or an array. The
    // config's `remarks` names the LOCATION (it's applied to the server label
    // inside parse_json_subscription), not the subscription — a pasted config
    // has no subscription title, so the UI labels it "Configuration N".
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let (_name, servers) = parse_json_subscription(trimmed);
        if servers.is_empty() {
            return Err("no servers found in the JSON".to_string());
        }
        return Ok(ImportResult {
            meta: SubscriptionMeta::default(),
            servers,
            description: None,
            source_json: Some(trimmed.to_string()),
        });
    }

    if is_supported_uri(trimmed) {
        // One pasted share-link, or several newline/whitespace-separated.
        if trimmed
            .lines()
            .filter(|l| is_supported_uri(l.trim()))
            .count()
            > 1
        {
            let servers = parse_subscription(trimmed);
            if servers.is_empty() {
                return Err("no servers found".to_string());
            }
            return Ok(ImportResult {
                meta: Default::default(),
                servers,
                description: None,
                source_json: None,
            });
        }
        return parse_proxy_uri(trimmed)
            .map(|s| ImportResult {
                meta: Default::default(),
                servers: vec![s],
                description: None,
                source_json: None,
            })
            .map_err(|e| e.to_string());
    }

    let parsed = url::Url::parse(trimmed).map_err(|e| format!("bad URL: {e}"))?;
    let (user_agent, device_os) = subscription_headers(subscription_user_agent.as_deref())?;
    let resp = fetch_subscription_response(parsed, &user_agent, &device_os).await?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    // Cap the body: subscriptions are KB-scale; bail past the limit so a
    // malicious endpoint can't OOM us with an unbounded response.
    const MAX_SUB_BYTES: usize = 8 * 1024 * 1024;
    if resp
        .content_length()
        .map(|l| l > MAX_SUB_BYTES as u64)
        .unwrap_or(false)
    {
        return Err("subscription too large".to_string());
    }
    let headers = resp.headers().clone();
    let mut buf: Vec<u8> = Vec::new();
    {
        use futures_util::StreamExt;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("read body: {e}"))?;
            buf.extend_from_slice(&chunk);
            if buf.len() > MAX_SUB_BYTES {
                return Err("subscription exceeded size limit".to_string());
            }
        }
    }
    let body = String::from_utf8_lossy(&buf).into_owned();
    let trimmed_body = body.trim_start_matches('\u{feff}').trim();
    let source_json = serde_json::from_str::<serde_json::Value>(trimmed_body)
        .ok()
        .map(|_| trimmed_body.to_string());
    let servers = parse_subscription(&body);

    // Some panels (Marzban / Happ-style) inline the metadata as `#key: value`
    // lines at the top of the body instead of (or in addition to) HTTP headers.
    // Merge both: an HTTP header wins, the inline value is the fallback.
    let (inline, body_desc) = parse_body_meta(&body);
    let meta = parse_headers(|name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| inline.get(name).cloned())
    });

    // Description priority: a real free-text `# …` note, then the `announce`
    // banner (base64), from either the header or the inline block.
    let description = body_desc.or_else(|| {
        headers
            .get("announce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| inline.get("announce").cloned())
            .map(|s| decode_maybe_b64(&s))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    });
    Ok(ImportResult {
        meta,
        servers,
        description,
        source_json,
    })
}
