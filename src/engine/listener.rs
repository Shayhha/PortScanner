use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;

use crate::engine::scanner::{ProbeMap, RxReciver};
use crate::net::interface::DeviceInterface;
use crate::net::{icmp_builder, tcp_builder, udp_builder};
use crate::utility::scanner_enums::{Mode, PortStatus};


/**
 * Represents packet listener configuration struct.
 */
#[derive(Clone, Debug)]
pub struct PacketListener {
    device_interface: Arc<DeviceInterface>,
    probe_map: ProbeMap,
    target_ip: Ipv4Addr,
    mode: Mode
}


/**
 * Implementation of packet listener struct with methods for handling packets.
 */
impl PacketListener {
    /**
     * Constructor for packet listener struct.
     */
    pub fn new(device_interface: Arc<DeviceInterface>, probe_map: ProbeMap, target_ip: Ipv4Addr, mode: Mode) -> Self {
        Self { device_interface, probe_map, target_ip, mode }
    }


    /**
     * Method for starting the packet listener in thread for capturing response packets.
     */
    pub fn start_listener(self, mut rx_receiver: RxReciver) {
        // create our listener thread for capturing response packets for determining port status
        thread::spawn(move || {
            // listen for incoming packets and handle each packet using our method
            while let Ok(packet) = rx_receiver.next() {
                self.handle_packet(packet);
            }
        });
    }


    /**
     * Method for handling packets captured by listener and sending port status to its probe scanner.
     */
    fn handle_packet(&self, packet: &[u8]) -> Option<()> {
        // parse Ethernet header and check if its IPv4, if so continue
        let eth_header: EthernetPacket = EthernetPacket::new(packet)?;
        if self.mode == Mode::Tcp || eth_header.get_ethertype() != EtherTypes::Ipv4 {
            return None; //return none if mode is tcp or Ethernet header does not have IPv4
        }

        // parse IPv4 header and check if it matches our target and interface IPs, if so continue
        let ip_header: Ipv4Packet = Ipv4Packet::new(eth_header.payload())?;
        if ip_header.get_source() != self.target_ip || ip_header.get_destination() != self.device_interface.ip {
            return None; //return none if doesn't match our target and interface IPs
        }

        // parse the packet based on protocol type
        let parsed_packet = match ip_header.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => udp_builder::_parse_udp_packet(ip_header.payload(), self.mode),
            IpNextHeaderProtocols::Tcp => tcp_builder::_parse_tcp_packet(ip_header.payload(), self.mode),
            IpNextHeaderProtocols::Icmp => icmp_builder::_parse_icmp_packet(ip_header.payload(), self.mode),
            _ => None
        }?;

        // get interface and target ports with the target port status from our parsed packet
        let (interface_port, target_port, status): (u16, u16, PortStatus) = parsed_packet;

        // try to acquire lock on probe map and send port status back to its probe scanner
        if let Ok(probe_map) = self.probe_map.lock() {
            // try to get the tx probe for port and remove it from map
            if let Some(tx_probe) = probe_map.get(&(interface_port, target_port)) {
                let _ = tx_probe.try_send(status).ok(); //send port status back to its probe scanner
            }
        }

        Some(())
    }
}