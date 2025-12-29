use anyhow::{anyhow, Result};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

use crate::utility::scanner_enums::{Mode, PortStatus};


/**
 * Function that creates a UDP packet with the given parameters.
 * Returns packet vector that represents UDP packet, returns error if failed creating packet.
 */
pub fn _create_udp_packet(src_ip: Ipv4Addr, src_mac: MacAddr, src_port: u16, dst_ip: Ipv4Addr, dst_mac: MacAddr, dst_port: u16) -> Result<Vec<u8>> {
    // create packet header sizes and buffer vector for packet
    const ETH: usize = 14;
    const IP: usize = 20;
    const UDP: usize = 8;
    let mut packet_vec: Vec<u8> = vec![0u8; ETH + IP + UDP];

   // create Ethernet header with source and destination MAC addresses
    let mut eth_header: MutableEthernetPacket = MutableEthernetPacket::new(&mut packet_vec[..ETH])
        .ok_or_else(|| anyhow!("Failed to create Ethernet header for UDP packet."))?;
    eth_header.set_source(src_mac);
    eth_header.set_destination(dst_mac);
    eth_header.set_ethertype(EtherTypes::Ipv4);

    // create IPv4 header with source and destination IP addresses and with random ttl
    let mut ip_header: MutableIpv4Packet = MutableIpv4Packet::new(&mut packet_vec[ETH..ETH + IP])
        .ok_or_else(|| anyhow!("Failed to create IPv4 header for UDP packet."))?;
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IP + UDP) as u16);
    ip_header.set_ttl(rand::random_range(32..128));
    ip_header.set_identification(rand::random());
    ip_header.set_flags(2);
    ip_header.set_fragment_offset(0);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_header.set_source(src_ip);
    ip_header.set_destination(dst_ip);
    ip_header.set_checksum(ipv4::checksum(&ip_header.to_immutable()));

    // create UDP header with source and destination ports and length
    let mut udp_header: MutableUdpPacket = MutableUdpPacket::new(&mut packet_vec[ETH + IP..ETH + IP + UDP])
        .ok_or_else(|| anyhow!("Failed to create UDP header for UDP packet."))?;
    udp_header.set_source(src_port);
    udp_header.set_destination(dst_port);
    udp_header.set_length(UDP as u16);
    udp_header.set_checksum(udp::ipv4_checksum(&udp_header.to_immutable(), &src_ip, &dst_ip));

    Ok(packet_vec)
}


/**
 * Function that parses UDP packet and determines port status based on its fields.
 * Returns tuple of interface port, target port and port status if parsed successfully, else returns None.
 */
pub fn _parse_udp_packet(packet: &[u8], mode: Mode) -> Option<(u16, u16, PortStatus)> {
    // parse UDP header and get source and destination ports 
    let udp_header: UdpPacket = UdpPacket::new(packet)?;
    let interface_port: u16 = udp_header.get_destination();
    let target_port: u16 = udp_header.get_source();

    // handle result only for UDP scan mode
    match mode {
        Mode::Udp => Some((interface_port, target_port, PortStatus::Open)),
        _ => None
    }
}