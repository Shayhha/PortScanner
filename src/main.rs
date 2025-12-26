mod engine;
mod net;
mod utility;

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;

use crate::engine::scanner::PortScanner;
use crate::net::interface::DeviceInterface;
use crate::utility::cli::Args;


/**
 * Represents the main function for port scanner application.
 */
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let device_interface: Arc<DeviceInterface> = Arc::new(DeviceInterface::get_device_interface()?);

    println!("Using device interface: {} {:?}", device_interface.interface.name, device_interface.interface.mac);

    let scanner = PortScanner::new(device_interface, args.target, args.start_port, args.end_port, args.concurrency as usize, 5000u64, args.mode);

    scanner.start_scan().await?;

    Ok(())
}