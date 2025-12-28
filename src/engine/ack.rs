use anyhow::{anyhow, Result};
use pnet::packet::tcp::TcpFlags;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use tokio::time::{self, Duration};
use rand::Rng;

use crate::engine::scanner::{ProbeMap, TxSender};
use crate::net::interface::DeviceInterface;
use crate::net::tcp_builder;
use crate::utility::scanner_enums::PortStatus;


/**
 * Function for performing TCP ACK scan on given target port.
 * Returns port status if received a response, return error if failed performing scan.
 */
pub async fn scan_ack(tx_sender: TxSender, probe_map: ProbeMap, interface_ip: Ipv4Addr, interface_mac: MacAddr, target_ip: Ipv4Addr, target_mac: MacAddr, target_port: u16, timeout: u64) -> Result<PortStatus> {
    // TODO
    Ok(PortStatus::Filtered)
}