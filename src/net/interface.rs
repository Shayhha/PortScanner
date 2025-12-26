use anyhow::{anyhow, Result};
use netdev::{self, NetworkDevice};
use pnet::datalink::{self, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::ipnetwork::IpNetwork;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

use crate::net::arp_builder;


/**
 * Represents our device network interface struct.
 */
#[derive(Debug, Clone)]
pub struct DeviceInterface {
    pub interface: NetworkInterface,
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub default_gateway_ip: Ipv4Addr
}


/**
 * Implementation of device interface struct with methods for handling network interface.
 */
impl DeviceInterface {
    /**
     * Function that returns an instance of DeviceInterface struct for the default network interface.
     * Returns DeviceInterface instance or error if failed.
     */
    pub fn get_device_interface() -> Result<Self> {
        let interface: NetworkInterface = Self::get_default_interface()?;
        let mac: MacAddr = Self::get_interface_mac_address(&interface)?;
        let (ip, netmask): (Ipv4Addr, Ipv4Addr) = Self::get_interface_ip_info(&interface)?;
        let default_gateway_ip: Ipv4Addr = Self::get_default_gateway_ip_address()?;

        Ok(Self { interface, mac, ip, netmask, default_gateway_ip })
    }


    /**
     * Function that returns the default network interface.
     * Returns suitable network interface or error if not found.
     */
    fn get_default_interface() -> Result<NetworkInterface> {
        // iterate over all available network interfaces and get a valid ipv4 interface
        datalink::interfaces()
            .into_iter()
            .find(|interface| { !interface.is_loopback() && interface.mac.is_some() && interface.ips.iter().any(|ip| matches!(ip, IpNetwork::V4(_))) })
            .ok_or_else(|| anyhow!("No suitable network interface found."))
    }


    /**
     * Function that returns the MAC address of the interface.
     * Returns MAC address or error if not found.
     */
    fn get_interface_mac_address(interface: &NetworkInterface) -> Result<MacAddr> {
        interface.mac
            .ok_or_else(|| anyhow!("Interface {} has no MAC address.", interface.name))
    }


    /**
     * Function that returns the first IPv4 address and netmask of the interface.
     * Returns IPv4 address and netmask or error if not found.
     */
    fn get_interface_ip_info(interface: &NetworkInterface) -> Result<(Ipv4Addr, Ipv4Addr)> {
        interface.ips
            .iter()
            .find_map(|ip| match ip {
                IpNetwork::V4(ipv4) => Some((ipv4.ip(), ipv4.mask())),
                _ => None
            })
            .ok_or_else(|| anyhow!("Interface {} has no IPv4 address.", interface.name))
    }


    /**
     * Function that returns the default gateway IPv4 address.
     * Returns IPv4 address of default gateway or error if not found.
     */
    fn get_default_gateway_ip_address() -> Result<Ipv4Addr> {
        let default_gateway: NetworkDevice = netdev::get_default_gateway()
            .map_err(|e| anyhow!("Failed to get default gateway: {}.", e))?;

        let default_gateway_ip: Ipv4Addr = default_gateway.ipv4
            .first()
            .copied()
            .ok_or_else(|| anyhow!("No IPv4 gateway found."))?;
        
        Ok(default_gateway_ip)
    }


    /**
     * Function that creats new datalink channel socket for sending and receiving packets.
     * Returns DataLinkSender and DataLinkReceiver handles if opened socket successfully, else returns error.
     */
    pub fn create_datalink_channel(device_interface: &DeviceInterface) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
        match datalink::channel(&device_interface.interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
            _ => Err(anyhow!("Failed to open datalink channel on interface {}.", device_interface.interface.name))
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
}