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
 * Function for performing TCP SYN scan on given target port.
 * Returns port status if received a response, return error if failed performing scan.
 */
pub async fn scan_syn(tx_sender: TxSender, probe_map: ProbeMap, interface_ip: Ipv4Addr, interface_mac: MacAddr, target_ip: Ipv4Addr, target_mac: MacAddr, target_port: u16, timeout: u64) -> Result<PortStatus> {
    // choose a random port for sending probe from to avade detection and also create task channel for communicating with listener thread
    let rand_interface_port: u16 = rand::rng().random_range(60000..65000); //get random interface port for sending probe to target
    let (tx_probe, mut rx_probe) = DeviceInterface::create_task_channel::<PortStatus>(); //create task channel for IPC communication

    // try to acquire mutex for probe map and insert our tx probe for receiving status from listener
    if let Ok(mut probe_map) = probe_map.lock() {
        // insert our tx probe with key as tuple of our source interface port and target port
        probe_map.insert((rand_interface_port, target_port), tx_probe);
    }
    // else we failed acquiring mutex, we return error message
    else {
        return Err(anyhow!("Could not add scan probe to probe map."));
    }

    // create a TCP packet with SYN flag for performing TCP SYN scan using given tx sender channel
    let tcp_packet_vec = tcp_builder::_create_tcp_packet(interface_ip, interface_mac, rand_interface_port, target_ip, target_mac, target_port, TcpFlags::SYN)?;

    // try to acquire mutex for shared tx sender and send our probe to target on desired port
    if let Ok(mut tx_sender) = tx_sender.lock() {
        tx_sender.send_to(&tcp_packet_vec, None)
            .ok_or_else(|| anyhow!("Could not send probe to target with current socket."))??; //return error if failed sending probe
    }
    // else we failed acquiring mutex, we return error message
    else {
        return Err(anyhow!("Could not use socket for sending probe to target."));
    }

    // wait for the listener thread for sending response from target port with our rx probe channel
    let result = match time::timeout(Duration::from_millis(timeout), rx_probe.recv()).await {
        Ok(Some(status)) => status, //means we received status from port
        _ => PortStatus::Filtered //means we didn't receive response, return filtered port
    };

    // try to acquire mutex for probe map and remove our tx probe from probe map
    if let Ok(mut probe_map) = probe_map.lock() {
        // remove our tx probe using tuple of our source interface port and target port
        probe_map.remove(&(rand_interface_port, target_port));
    }

    Ok(result)
}