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
pub fn create_tcp_packet(buffer: &mut [u8], src_mac: MacAddr, dst_mac: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, flags: u8) {
    // create packet header sizes
    const ETH: usize = 14;
    const IP: usize = 20;
    const TCP: usize = 20;

    // create ethernet header with source and destination MAC addresses
    let mut eth = MutableEthernetPacket::new(&mut buffer[..ETH]).unwrap();
    eth.set_source(src_mac);
    eth.set_destination(dst_mac);
    eth.set_ethertype(EtherTypes::Ipv4);

    // create ipv4 header source and destination IP addresses and with random ttl
    let mut ip = MutableIpv4Packet::new(&mut buffer[ETH..ETH + IP]).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length((IP + TCP) as u16);
    ip.set_ttl(rand::thread_rng().gen_range(32..128));
    ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);
    ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));

    // create tcp header with source and destination ports, flags, and random sequence number
    let mut tcp = MutableTcpPacket::new(&mut buffer[ETH + IP..ETH + IP + TCP]).unwrap();
    tcp.set_source(src_port);
    tcp.set_destination(dst_port);
    tcp.set_sequence(rand::random());
    tcp.set_flags(flags);
    tcp.set_window(64240);
    tcp.set_checksum(pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip));
}