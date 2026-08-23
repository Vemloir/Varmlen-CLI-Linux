//! Resolving a location's endpoints to the address set the daemon needs.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::subscription::{server_endpoints, VlessServer};

/// Resolve every endpoint of `server` to concrete addresses.
///
/// The daemon needs these to punch the proxy destination through the killswitch
/// and to keep the tunnel's own dials out of the tunnel, so an unresolvable or
/// implausibly large answer is refused rather than passed on.
pub async fn resolve_server_ips(server: &VlessServer) -> Result<Vec<IpAddr>, String> {
    let mut unique = BTreeSet::new();
    for (host, port) in server_endpoints(server) {
        let addresses = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|error| format!("could not resolve VPN endpoint {host}:{port}: {error}"))?;
        unique.extend(addresses.map(|address| address.ip()));
    }
    if unique.is_empty() {
        return Err(format!(
            "VPN location {} did not resolve to an address",
            server.label
        ));
    }
    if unique.len() > varmlend::protocol::MAX_SERVER_IPS {
        return Err(format!(
            "VPN location resolves to {} addresses; the safe limit is {}",
            unique.len(),
            varmlend::protocol::MAX_SERVER_IPS
        ));
    }
    Ok(unique.into_iter().collect())
}
