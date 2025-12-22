use pnet::datalink::{self, NetworkInterface};
use std::net::IpAddr;


/**
 * Gets the default network interface.
 * Returns suitable network interface or None if not found.
 */
pub fn get_default_interface() -> Option<NetworkInterface> {
    // iterate over all available network interfaces and get a valid ipv4 interface
    datalink::interfaces()
        .into_iter()
        .find(|i| { !i.is_loopback() && i.mac.is_some() && i.ips.iter().any(|ip| matches!(ip.ip(), IpAddr::V4(_))) })
}