use anyhow::{anyhow, Result};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet, Ipv4Packet};
use pnet::packet::Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::icmp::{self, IcmpPacket, IcmpTypes};
use pnet::packet::icmp::echo_request::{MutableEchoRequestPacket, IcmpCodes as EchoRequestCodes};
use pnet::packet::icmp::echo_reply::{MutableEchoReplyPacket, IcmpCodes as EchoReplyCodes};
use pnet::packet::icmp::destination_unreachable::{IcmpCodes as DestinationUnreachableCodes};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

use crate::utility::scanner_enums::{Mode, PortStatus};


/**
 * Function that creates a ICMP Echo Request packet with the given parameters.
 * Returns packet vector that represents ICMP Echo Request packet, returns error if failed creating packet.
 */
pub fn _create_icmp_echo_request_packet(src_ip: Ipv4Addr, src_mac: MacAddr, dst_ip: Ipv4Addr, dst_mac: MacAddr) -> Result<Vec<u8>> {
    // create packet header sizes and buffer vector for packet
    const ETH: usize = 14;
    const IP: usize = 20;
    const ICMP: usize = 8;
    let mut packet_vec: Vec<u8> = vec![0u8; ETH + IP + ICMP];

    // create Ethernet header with source and destination MAC addresses
    let mut eth_header: MutableEthernetPacket = MutableEthernetPacket::new(&mut packet_vec[..ETH])
        .ok_or_else(|| anyhow!("Failed to create Ethernet header for ICMP packet."))?;
    eth_header.set_source(src_mac);
    eth_header.set_destination(dst_mac);
    eth_header.set_ethertype(EtherTypes::Ipv4);

    // create IPv4 header with source and destination IP addresses and with random ttl
    let mut ip_header: MutableIpv4Packet = MutableIpv4Packet::new(&mut packet_vec[ETH..ETH + IP])
        .ok_or_else(|| anyhow!("Failed to create IPv4 header for ICMP packet."))?;
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IP + ICMP) as u16);
    ip_header.set_ttl(64);
    ip_header.set_identification(rand::random());
    ip_header.set_flags(2);
    ip_header.set_fragment_offset(0);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_header.set_source(src_ip);
    ip_header.set_destination(dst_ip);
    ip_header.set_checksum(ipv4::checksum(&ip_header.to_immutable()));

    // create ICMP Echo Request header with ICMP type and code and with random identifier and sequence number
    let mut icmp_header: MutableEchoRequestPacket = MutableEchoRequestPacket::new(&mut packet_vec[ETH + IP..ETH + IP + ICMP])
        .ok_or_else(|| anyhow!("Failed to create ICMP Echo Request header for ICMP packet."))?;
    icmp_header.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_header.set_icmp_code(EchoRequestCodes::NoCode);
    icmp_header.set_identifier(rand::random());
    icmp_header.set_sequence_number(rand::random());

    // create ICMP header for calculating ICMP Echo Request header checksum
    let icmp_header_payload: IcmpPacket = IcmpPacket::new(icmp_header.packet())
        .ok_or_else(|| anyhow!("Failed to create ICMP header for ICMP packet."))?;
    icmp_header.set_checksum(icmp::checksum(&icmp_header_payload.to_immutable()));

    Ok(packet_vec)
}


/**
 * Function that creates a ICMP Echo Reply packet with the given parameters.
 * Returns packet vector that represents ICMP Echo Reply packet, returns error if failed creating packet.
 */
pub fn _create_icmp_echo_reply_packet(src_ip: Ipv4Addr, src_mac: MacAddr, dst_ip: Ipv4Addr, dst_mac: MacAddr) -> Result<Vec<u8>> {
    // create packet header sizes and buffer vector for packet
    const ETH: usize = 14;
    const IP: usize = 20;
    const ICMP: usize = 8;
    let mut packet_vec: Vec<u8> = vec![0u8; ETH + IP + ICMP];

    // create Ethernet header with source and destination MAC addresses
    let mut eth_header: MutableEthernetPacket = MutableEthernetPacket::new(&mut packet_vec[..ETH])
        .ok_or_else(|| anyhow!("Failed to create Ethernet header for ICMP packet."))?;
    eth_header.set_source(src_mac);
    eth_header.set_destination(dst_mac);
    eth_header.set_ethertype(EtherTypes::Ipv4);

    // create IPv4 header with source and destination IP addresses and with random ttl
    let mut ip_header: MutableIpv4Packet = MutableIpv4Packet::new(&mut packet_vec[ETH..ETH + IP])
        .ok_or_else(|| anyhow!("Failed to create IPv4 header for ICMP packet."))?;
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length((IP + ICMP) as u16);
    ip_header.set_ttl(64);
    ip_header.set_identification(rand::random());
    ip_header.set_flags(2);
    ip_header.set_fragment_offset(0);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_header.set_source(src_ip);
    ip_header.set_destination(dst_ip);
    ip_header.set_checksum(ipv4::checksum(&ip_header.to_immutable()));

    // create ICMP Echo Reply header with ICMP type and code and with random identifier and sequence number
    let mut icmp_header: MutableEchoReplyPacket = MutableEchoReplyPacket::new(&mut packet_vec[ETH + IP..ETH + IP + ICMP])
        .ok_or_else(|| anyhow!("Failed to create ICMP Echo Reply header for ICMP packet."))?;
    icmp_header.set_icmp_type(IcmpTypes::EchoReply);
    icmp_header.set_icmp_code(EchoReplyCodes::NoCode);
    icmp_header.set_identifier(rand::random());
    icmp_header.set_sequence_number(rand::random());

    // create ICMP header for calculating ICMP Echo Reply header checksum
    let icmp_header_payload: IcmpPacket = IcmpPacket::new(icmp_header.packet())
        .ok_or_else(|| anyhow!("Failed to create ICMP header for ICMP packet."))?;
    icmp_header.set_checksum(icmp::checksum(&icmp_header_payload.to_immutable()));

    Ok(packet_vec)
}


/**
 * Function that parses ICMP packet and determines port status based on its fields.
 * Returns tuple of interface port, target port and port status if parsed successfully, else returns None.
 */
pub fn _parse_icmp_packet(packet: &[u8], mode: Mode) -> Option<(u16, u16, PortStatus)> {
    // create packet header sizes and icmp header
    const IP: usize = 20;
    const ICMP: usize = 8;
    let icmp_header: IcmpPacket = IcmpPacket::new(packet)?;

    // check that ICMP type is Destination Unreachable and that packet length has valid ICMP packet length including IPv4 header
    if mode == Mode::Tcp || icmp_header.get_icmp_type() != IcmpTypes::DestinationUnreachable || packet.len() < ICMP + IP {
        return None; //return none if mode is tcp or ICMP type is not Destination Unreachable
    }

    // extract our original IP packet header that triggered the given ICMP packet
    let icmp_ip_header: Ipv4Packet = Ipv4Packet::new(&packet[ICMP..])?;

    // determine port status based on next level protocol of our original IP packet
    match icmp_ip_header.get_next_level_protocol() {
        // if original packet protocol is TCP, we check for filtered ports
        IpNextHeaderProtocols::Tcp => {
            // create TCP header from our original IP packet and extract interface and target ports
            let tcp_header: TcpPacket = TcpPacket::new(icmp_ip_header.payload())?;
            let interface_port: u16 = tcp_header.get_source();
            let target_port: u16 = tcp_header.get_destination();

            // check if ICMP Destination Unreachable codes that indicate filtered ports are present, if so return filtered status
            match icmp_header.get_icmp_code() {
                DestinationUnreachableCodes::DestinationNetworkUnreachable | DestinationUnreachableCodes::DestinationHostUnreachable | DestinationUnreachableCodes::DestinationProtocolUnreachable
                | DestinationUnreachableCodes::CommunicationAdministrativelyProhibited | DestinationUnreachableCodes::HostAdministrativelyProhibited
                | DestinationUnreachableCodes::NetworkAdministrativelyProhibited => {
                    Some((interface_port, target_port, PortStatus::Filtered))
                },
                _ => None
            }
        },

        // if original packet protocol is UDP, we check for closed or filtered ports
        IpNextHeaderProtocols::Udp => {
            // create UDP header from our original IP packet and extract interface and target ports
            let udp_header: UdpPacket = UdpPacket::new(icmp_ip_header.payload())?;
            let interface_port: u16 = udp_header.get_source();
            let target_port: u16 = udp_header.get_destination();

            // check if ICMP Destination Unreachable codes that indicate filtered or closed ports are present, if so return filtered or closed status
            match icmp_header.get_icmp_code() {
                DestinationUnreachableCodes::DestinationNetworkUnreachable | DestinationUnreachableCodes::DestinationHostUnreachable | DestinationUnreachableCodes::DestinationProtocolUnreachable
                | DestinationUnreachableCodes::CommunicationAdministrativelyProhibited | DestinationUnreachableCodes::HostAdministrativelyProhibited
                | DestinationUnreachableCodes::NetworkAdministrativelyProhibited => {
                    Some((interface_port, target_port, PortStatus::Filtered))
                },
                DestinationUnreachableCodes::DestinationPortUnreachable => {
                    Some((interface_port, target_port, PortStatus::Closed))
                },
                _ => None
            }
        },

        // for other protocols, we return None
        _ => {
            None
        }
    }
}