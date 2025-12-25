use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::thread;

use crate::engine::scanner::{ProbeMap, RxReciver};
use crate::net::tcp_builder;
use crate::utility::scanner_enums::PortStatus;


/**
 * Represents packet listener configuration struct.
 */
#[derive(Clone, Debug)]
pub struct PacketListener {
    interface: NetworkInterface,
    probe_map: ProbeMap
}


/**
 * Implementation of packet listener struct with methods for handling packets.
 */
impl PacketListener {
    /**
     * Constructor for packet listener struct.
     */
    pub fn new(interface: NetworkInterface, probe_map: ProbeMap) -> Self {
        Self { interface, probe_map }
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
        // parse ethernet header and check if its IPv4 packet, if so continue
        let eth_header: EthernetPacket = EthernetPacket::new(packet)?;
        if eth_header.get_ethertype() != EtherTypes::Ipv4 {
            return None; //return none if not IPv4
        }

        // parse IP header and check if its TCP packet, if so continue
        let ip_header: Ipv4Packet = Ipv4Packet::new(eth_header.payload())?;
        if ip_header.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return None; //return none if not TCP packet
        }

        // parse TCP header and extract port and status using flags
        let tcp_header: TcpPacket = TcpPacket::new(ip_header.payload())?;
        let port: u16 = tcp_header.get_destination();
        let status: PortStatus = tcp_builder::parse_tcp_status(&tcp_header)?;

        // try to acquire lock on probe map and send port status back to its probe scanner
        if let Ok(mut probe_map) = self.probe_map.lock() {
            // try to get the sender socket for port and remove it from map
            if let Some(tx) = probe_map.remove(&port) {
                let _ = tx.send(status); //send port status back to its probe scanner
            }
        }

        Some(())
    }
}