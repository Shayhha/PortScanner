use anyhow::{anyhow, Result};
use pnet::datalink::{self, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::ipnetwork::IpNetwork;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use std::fmt::Write;
use tokio::sync::mpsc;

use crate::net::arp_builder;


/**
 * Represents our device network interface struct.
 */
#[derive(Debug, Clone)]
pub struct DeviceInterface {
    pub interface: NetworkInterface,
    pub name: String,
    pub description: String,
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
    pub fn new() -> Result<Self> {
        let interface: NetworkInterface = Self::get_default_interface()?;
        let name: String = interface.name.clone();
        let description: String = Self::get_interface_description(&interface);
        let mac: MacAddr = Self::get_interface_mac_address(&interface)?;
        let (ip, netmask): (Ipv4Addr, Ipv4Addr) = Self::get_interface_ip_info(&interface)?;
        let default_gateway_ip: Ipv4Addr = Self::get_default_gateway_ip_address(&interface)?;

        Ok(Self { interface, name, description, mac, ip, netmask, default_gateway_ip })
    }


    /**
     * Method for printing device interface information.
     */
    pub fn show_info(&self) -> Result<()> {
        // define output string
        let mut output: String = String::new();

        // write device interface information to output string
        writeln!(&mut output, "\n{} Device Interface Info {}", "=".repeat(25), "=".repeat(26))?;
        writeln!(&mut output, "{:<20}: {}", "Interface Name", self.name)?;
        writeln!(&mut output, "{:<20}: {}", "Description", self.description)?;
        writeln!(&mut output, "{:<20}: {}", "MAC Address", self.mac)?;
        writeln!(&mut output, "{:<20}: {}", "IPv4 Address", self.ip)?;
        writeln!(&mut output, "{:<20}: {}", "Netmask", self.netmask)?;
        writeln!(&mut output, "{:<20}: {}", "Default Gateway", self.default_gateway_ip)?;
        writeln!(&mut output, "{}\n", "=".repeat(74))?;

        print!("{}", output);

        Ok(())
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
     * Function that returns the description of the interface.
     * Returns description of interface if present, else default description.
     */
    fn get_interface_description(interface: &NetworkInterface) -> String {
        interface.description.clone().trim().is_empty()
            .then(|| "Default network interface".to_string())
            .unwrap_or_else(|| interface.description.clone())
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
    fn get_default_gateway_ip_address(interface: &NetworkInterface) -> Result<Ipv4Addr> {
        let (ipv4_vec, _) = default_gateway::get_default_gateway(&interface.name)
            .ok_or_else(|| anyhow!("Interface {} has no gateway information.", interface.name))?;

        ipv4_vec
            .first()
            .copied()
            .ok_or_else(|| anyhow!("Interface {} has no IPv4 default gateway.", interface.name))
    }


    /**
     * Function that checks if given target IP is in the same local network as the interface.
     * Returns true if target IP is in the same local network, else returns false.
     */
    pub fn check_local_device(device_interface: &DeviceInterface, target_ip: Ipv4Addr) -> bool {
        // calculate network address for interface and target IP addresses using our interface netmask
        let interface_netmask: u32 = u32::from(device_interface.ip) & u32::from(device_interface.netmask);
        let target_ip_netmask: u32 = u32::from(target_ip) & u32::from(device_interface.netmask);

        // retrun true if both network addresses are same, else return false
        interface_netmask == target_ip_netmask
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
    pub fn create_task_channel<T>() -> (mpsc::Sender<T>, mpsc::Receiver<T>) {
        let (tx, rx) = mpsc::channel::<T>(1024);
        (tx, rx)
    }


    /**
     * Function that performs ARP request to resolve MAC address of given target IP on the network.
     * Returns resolved MAC address or error if failed.
     */
    pub fn resolve_device_mac_address(device_interface: &DeviceInterface, target_ip: Ipv4Addr, timeout: u64) -> Result<MacAddr> {
        // create datalink channel for sending and receiving ARP packets
        let (mut tx_sender, mut rx_receiver) = Self::create_datalink_channel(&device_interface)?;

        // determine if target IP is in our local network, if not we send ARP request to default gateway IP
        let arp_target_ip: Ipv4Addr = if Self::check_local_device(device_interface, target_ip) {
            target_ip
        } 
        else {
            device_interface.default_gateway_ip
        };

        // create ARP request packet for resolving target device MAC address
        let arp_packet_vec: Vec<u8> = arp_builder::_create_arp_request_packet(device_interface.ip, device_interface.mac, arp_target_ip)?;

        // send ARP request and wait for ARP response from target device
        tx_sender.send_to(&arp_packet_vec, None)
            .ok_or_else(|| anyhow!("Failed to send ARP request to target device with IP: {}.", target_ip))??;

        // define our start time and end time for listening for ARP response packets
        let start_time: Instant = Instant::now();
        let end_time: Duration = Duration::from_millis(timeout);

        // listen for incuming ARP response packets
        while start_time.elapsed() < end_time {
            // get packet from rx receiver
            let packet: &[u8] = rx_receiver.next()?;

            // if we received ARP response from target IP, parse the packet and return the MAC address
            if let Some(mac) = arp_builder::_parse_arp_response(packet, device_interface.ip, device_interface.mac, target_ip) {
                return Ok(mac);
            }
        }

        Err(anyhow!("Failed to receive ARP response from target device with IP: {}.", target_ip))
    }
}