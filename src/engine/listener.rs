use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;

use crate::engine::scanner::{ProbeMap, RxReciver};
use crate::net::interface::DeviceInterface;
use crate::net::tcp_builder;
use crate::utility::scanner_enums::PortStatus;


/**
 * Represents packet listener configuration struct.
 */
#[derive(Clone, Debug)]
pub struct PacketListener {
    device_interface: Arc<DeviceInterface>,
    probe_map: ProbeMap
}


/**
 * Implementation of packet listener struct with methods for handling packets.
 */
impl PacketListener {
    /**
     * Constructor for packet listener struct.
     */
    pub fn new(device_interface: Arc<DeviceInterface>, probe_map: ProbeMap) -> Self {
        Self { device_interface, probe_map }
    }


    /**
     * Method for starting the packet listener in thread for capturing response packets.
     */
    pub fn start_listener(self, mut rx_receiver: RxReciver, target_ip: Ipv4Addr) {
        // create our listener thread for capturing response packets for determining port status
        thread::spawn(move || {
            // listen for incoming packets and handle each packet using our method
            while let Ok(packet) = rx_receiver.next() {
                self.handle_packet(packet, target_ip);
            }
        });
    }


    /**
     * Method for handling packets captured by listener and sending port status to its probe scanner.
     */
    fn handle_packet(&self, packet: &[u8], target_ip: Ipv4Addr) -> Option<()> {
        // parse ethernet header and check if its IPv4 packet, if so continue
        let eth_header: EthernetPacket = EthernetPacket::new(packet)?;
        if eth_header.get_ethertype() != EtherTypes::Ipv4 {
            return None; //return none if not IPv4
        }

        // parse IP header and check if its TCP packet and matches our target and interface IPs, if so continue
        let ip_header: Ipv4Packet = Ipv4Packet::new(eth_header.payload())?;
        if ip_header.get_next_level_protocol() != IpNextHeaderProtocols::Tcp || ip_header.get_source() != target_ip || 
            ip_header.get_destination() != self.device_interface.ip {
            return None; //return none if not TCP packet and doesn't match our target and interface IPs
        }

        // parse TCP header and extract port and status using flags
        let tcp_header: TcpPacket = TcpPacket::new(ip_header.payload())?;
        let status: PortStatus = tcp_builder::_parse_tcp_status(&tcp_header)?;
        let port: u16 = tcp_header.get_destination();

        // try to acquire lock on probe map and send port status back to its probe scanner
        if let Ok(probe_map) = self.probe_map.lock() {
            // try to get the tx probe for port and remove it from map
            if let Some(tx_probe) = probe_map.get(&port) {
                let _ = tx_probe.try_send(status).ok(); //send port status back to its probe scanner
            }
        }

        Some(())
    }
}