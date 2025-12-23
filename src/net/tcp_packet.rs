use anyhow::{anyhow, Result};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use rand::Rng;


/**
 * Creates a TCP packet with the given parameters.
 * Fills the provided buffer with the constructed packet.
 */
pub fn create_tcp_packet(buffer: &mut [u8], src_mac: MacAddr, dst_mac: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, flags: u8) -> Result<()> {
    // create packet header sizes
    const ETH: usize = 14;
    const IP: usize = 20;
    const TCP: usize = 20;

    // create ethernet header with source and destination MAC addresses
    let mut eth_header: MutableEthernetPacket = MutableEthernetPacket::new(&mut buffer[..ETH])
        .ok_or_else(|| anyhow!("Failed to create Ethernet header for TCP packet."))?;
    eth_header.set_source(src_mac);
    eth_header.set_destination(dst_mac);
    eth_header.set_ethertype(EtherTypes::Ipv4);

    // create ipv4 header source and destination IP addresses and with random ttl
    let mut ip_header: MutableIpv4Packet = MutableIpv4Packet::new(&mut buffer[ETH..ETH + IP])
        .ok_or_else(|| anyhow!("Failed to create IPv4 header for TCP packet."))?;
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IP + TCP) as u16);
    ip_header.set_ttl(rand::thread_rng().gen_range(32..128));
    ip_header.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
    ip_header.set_source(src_ip);
    ip_header.set_destination(dst_ip);
    ip_header.set_checksum(pnet::packet::ipv4::checksum(&ip_header.to_immutable()));

    // create tcp header with source and destination ports, flags, and random sequence number
    let mut tcp_header: MutableTcpPacket = MutableTcpPacket::new(&mut buffer[ETH + IP..ETH + IP + TCP])
        .ok_or_else(|| anyhow!("Failed to create TCP header for TCP packet."))?;
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(rand::random());
    tcp_header.set_flags(flags);
    tcp_header.set_window(64240);
    tcp_header.set_checksum(pnet::packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip));

    Ok(())
}