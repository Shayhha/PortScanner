use pnet::datalink::{self, NetworkInterface};
use std::net::IpAddr;


pub fn get_default_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|i| { !i.is_loopback() && i.mac.is_some() && i.ips.iter().any(|ip| matches!(ip.ip(), IpAddr::V4(_))) })
}