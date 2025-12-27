use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::io::ErrorKind::*;
use tokio::net::TcpStream;
use tokio::time::{self, Duration};

use crate::utility::scanner_enums::PortStatus;


/**
 * Function for performing TCP connect scan on given target port.
 * Returns port status if received a response, return error if failed performing scan.
 */
pub async fn scan_tcp(target_ip: Ipv4Addr, target_port: u16, timeout: u64) -> Result<PortStatus> {
    // create socket address for target IP and port
    let target_socket_address: SocketAddr = SocketAddr::new(IpAddr::V4(target_ip), target_port);

    // wait for connection to target and determine port status based on result
    match time::timeout(Duration::from_millis(timeout), TcpStream::connect(target_socket_address)).await {
        Ok(Ok(_)) => Ok(PortStatus::Open),
        Ok(Err(e)) => {
            // if error occured we check what type of error occured and return port status accordingly
            match e.kind() {
                ConnectionRefused => Ok(PortStatus::Closed),
                TimedOut | NotConnected | HostUnreachable | NetworkUnreachable => {
                    Ok(PortStatus::Filtered)
                }
                _ => Ok(PortStatus::Filtered)
            }
        },
        Err(_) => Ok(PortStatus::Filtered)
    }
}