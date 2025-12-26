use anyhow::{anyhow, Result};
use pnet::packet::ethernet::{MutableEthernetPacket, EthernetPacket, EtherTypes};
use pnet::packet::arp::{MutableArpPacket, ArpPacket, ArpHardwareTypes, ArpOperations};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;


/**
 * Function that creates a ARP request packet with the given parameters.
 * Returns packet vector that represents ARP request packet, returns error if failed creating packet.
 */
pub fn create_arp_request_packet(src_ip: Ipv4Addr, src_mac: MacAddr, dst_ip: Ipv4Addr) -> Result<Vec<u8>> {
    // create packet header sizes and buffer vector for packet
    const ETH: usize = 14;
    const ARP: usize = 28;
    let mut packet_vec = vec![0u8; ETH + ARP];

    // create ethernet header with source and destination MAC addresses
    let mut eth_header = MutableEthernetPacket::new(&mut packet_vec[..ETH])
        .ok_or_else(|| anyhow!("Failed to create Ethernet header for ARP request packet."))?;
    eth_header.set_source(src_mac);
    eth_header.set_destination(MacAddr::broadcast());
    eth_header.set_ethertype(EtherTypes::Arp);

    // create ARP request header with source and destination IP addresses
    let mut arp_header = MutableArpPacket::new(&mut packet_vec[ETH..ETH + ARP])
        .ok_or_else(|| anyhow!("Failed to create ARP header for ARP request packet."))?;
    arp_header.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_header.set_protocol_type(EtherTypes::Ipv4);
    arp_header.set_hw_addr_len(6);
    arp_header.set_proto_addr_len(4);
    arp_header.set_operation(ArpOperations::Request);
    arp_header.set_sender_proto_addr(src_ip);
    arp_header.set_sender_hw_addr(src_mac);
    arp_header.set_target_proto_addr(dst_ip);
    arp_header.set_target_hw_addr(MacAddr::zero());

    Ok(packet_vec)
}


/**
 * Function that creates a ARP response packet with the given parameters.
 * Returns packet vector that represents ARP response packet, returns error if failed creating packet.
 */
pub fn create_arp_response_packet(src_ip: Ipv4Addr, src_mac: MacAddr, dst_ip: Ipv4Addr, dst_mac: MacAddr) -> Result<Vec<u8>> {
    const ETH: usize = 14;
    const ARP: usize = 28;
    let mut packet_vec = vec![0u8; ETH + ARP];

    // create ethernet header with source and destination MAC addresses
    let mut eth_header = MutableEthernetPacket::new(&mut packet_vec[..ETH])
        .ok_or_else(|| anyhow!("Failed to create Ethernet header for ARP response packet."))?;
    eth_header.set_source(src_mac);
    eth_header.set_destination(dst_mac);
    eth_header.set_ethertype(EtherTypes::Arp);

    // create ARP response header with source and destination IP and MAC addresses
    let mut arp_header = MutableArpPacket::new(&mut packet_vec[ETH..ETH + ARP])
        .ok_or_else(|| anyhow!("Failed to create ARP header for ARP response packet."))?;
    arp_header.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_header.set_protocol_type(EtherTypes::Ipv4);
    arp_header.set_hw_addr_len(6);
    arp_header.set_proto_addr_len(4);
    arp_header.set_operation(ArpOperations::Reply);
    arp_header.set_sender_proto_addr(src_ip);
    arp_header.set_sender_hw_addr(src_mac);
    arp_header.set_target_proto_addr(dst_ip);
    arp_header.set_target_hw_addr(dst_mac);

    Ok(packet_vec)
}


/**
 * Function that extracts and validates ARP response packet.
 * Returns sender MAC address if valid ARP response, else returns None.
 */
pub fn parse_arp_response(packet: &[u8], src_ip: Ipv4Addr, src_mac: MacAddr, dst_ip: Ipv4Addr) -> Option<MacAddr> {
    // parse ethernet header and check if its ARP packet, if so continue
    let eth_header = EthernetPacket::new(packet)?;
    if eth_header.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    // parse ARP header and validate fields for are response, if matches return sender MAC address
    let arp_header = ArpPacket::new(eth_header.payload())?;
    if arp_header.get_operation() != ArpOperations::Reply || arp_header.get_sender_proto_addr() != dst_ip || 
        arp_header.get_target_proto_addr() != src_ip || arp_header.get_target_hw_addr() != src_mac {
        return None;
    }

    Some(arp_header.get_sender_hw_addr())
}