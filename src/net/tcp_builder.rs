use anyhow::{anyhow, Result};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpPacket, TcpFlags};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use rand::Rng;

use crate::utility::scanner_enums::{Mode, PortStatus};


/**
 * Function that creates a TCP packet with the given parameters.
 * Returns packet vector that represents TCP packet, returns error if failed creating packet.
 */
pub fn _create_tcp_packet(src_ip: Ipv4Addr, src_mac: MacAddr, src_port: u16, dst_ip: Ipv4Addr, dst_mac: MacAddr, dst_port: u16, flags: u8) -> Result<Vec<u8>> {
    // create packet header sizes and buffer vector for packet
    const ETH: usize = 14;
    const IP: usize = 20;
    const TCP: usize = 20;
    let mut packet_vec: Vec<u8> = vec![0u8; ETH + IP + TCP];

    // create ethernet header with source and destination MAC addresses
    let mut eth_header: MutableEthernetPacket = MutableEthernetPacket::new(&mut packet_vec[..ETH])
        .ok_or_else(|| anyhow!("Failed to create Ethernet header for TCP packet."))?;
    eth_header.set_source(src_mac);
    eth_header.set_destination(dst_mac);
    eth_header.set_ethertype(EtherTypes::Ipv4);

    // create ipv4 header source and destination IP addresses and with random ttl
    let mut ip_header: MutableIpv4Packet = MutableIpv4Packet::new(&mut packet_vec[ETH..ETH + IP])
        .ok_or_else(|| anyhow!("Failed to create IPv4 header for TCP packet."))?;
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IP + TCP) as u16);
    ip_header.set_ttl(rand::rng().random_range(32..128));
    ip_header.set_identification(rand::random());
    ip_header.set_flags(2);
    ip_header.set_fragment_offset(0);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ip);
    ip_header.set_destination(dst_ip);
    ip_header.set_checksum(ipv4::checksum(&ip_header.to_immutable()));

    // create tcp header with source and destination ports, flags, and random sequence number
    let mut tcp_header: MutableTcpPacket = MutableTcpPacket::new(&mut packet_vec[ETH + IP..ETH + IP + TCP])
        .ok_or_else(|| anyhow!("Failed to create TCP header for TCP packet."))?;
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rand::random());
    tcp_header.set_flags(flags);
    tcp_header.set_data_offset(5);
    tcp_header.set_acknowledgement(0);
    tcp_header.set_window(64240);
    tcp_header.set_checksum(tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip));

    Ok(packet_vec)
}


/**
 * Function that parses TCP packet flags and determines port status.
 * Returns port status if flags are set, else returns None.
 */
pub fn _parse_tcp_status(tcp_packet: &TcpPacket, mode: Mode) -> Option<PortStatus> {
    // get the TCP flags value from packet
    let flags: u8 = tcp_packet.get_flags();

    // check if SYN and ACK flags are set, if so return open port
    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
        Some(PortStatus::Open)
    }
    // else check if RST flag is set, if so return closed port 
    else if flags & TcpFlags::RST != 0 {
        Some(PortStatus::Closed)
    }
    // else if no relevant flags are set we return none 
    else {
        return None
    }
}