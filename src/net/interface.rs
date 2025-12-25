use anyhow::{anyhow, Result};
use pnet::datalink::{self, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::oneshot;


/**
 * Function that returns the default network interface.
 * Returns suitable network interface or error if not found.
 */
pub fn get_default_interface() -> Result<NetworkInterface> {
    // iterate over all available network interfaces and get a valid ipv4 interface
    datalink::interfaces()
        .into_iter()
        .find(|interface| { !interface.is_loopback() && interface.mac.is_some() && interface.ips.iter().any(|ip| matches!(ip.ip(), IpAddr::V4(_))) })
        .ok_or_else(|| anyhow!("No suitable network interface found."))
}


/**
 * Function that returns the MAC address of the interface.
 * Returns MAC address or error if not found.
 */
pub fn get_mac_address(interface: &NetworkInterface) -> Result<MacAddr> {
    interface
        .mac
        .ok_or_else(|| anyhow!("Interface {} has no MAC address.", interface.name))
}


/**
 * Function that returns the first IPv4 address of the interface.
 * Returns IPv4 address or error if not found.
 */
pub fn get_ipv4_address(interface: &NetworkInterface) -> Result<Ipv4Addr> {
    interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => None
        })
        .ok_or_else(|| anyhow!("Interface {} has no IPv4 address.", interface.name))
}


/**
 * Function that creats new datalink channel socket for sending and receiving packets.
 * Returns DataLinkSender and DataLinkReceiver handles if opened socket successfully, else returns error.
 */
pub fn create_datalink_channel(interface: &NetworkInterface) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    match datalink::channel(interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        _ => Err(anyhow!("Failed to open datalink channel on interface {}.", interface.name))
    }
}


/**
 * Function that creates new task channel IPC for sending and receiving messages between two async tasks.
 * Returns Sender and Receiver handles for IPC communication.
 */
pub fn create_task_channel<T>() -> (oneshot::Sender<T>, oneshot::Receiver<T>) {
    let (tx, rx) = oneshot::channel();
    (tx, rx)
}