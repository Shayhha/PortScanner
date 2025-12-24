use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;
use std::thread;

use crate::engine::scanner::ProbeMap;
use crate::utility::scanner_enums::PortStatus;


/**
 * Represents packet listener configuration struct.
 */
#[derive(Clone, Debug)]
pub struct PacketListener {
    interface: NetworkInterface,
    probes: ProbeMap
}


/**
 * Implementation of packet listener struct with methods for handling packets.
 */
impl PacketListener {
    /**
     * Constructor for packet listener struct.
     */
    pub fn new(interface: NetworkInterface, probes: ProbeMap) -> Self {
        Self { interface, probes }
    }

    //TODO
    pub fn start_listener(self) {
    }
}