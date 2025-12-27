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
    // parse given command line arguments
    let args = Args::parse();

    // create device interface for performing scans
    let device_interface: Arc<DeviceInterface> = Arc::new(DeviceInterface::new()?);
    device_interface.show_info()?;

    // create port scanner instance with given arguments
    let scanner = PortScanner::new(device_interface, args.target, args.start_port, args.end_port, args.concurrency as usize, args.timeout, args.mode);

    // start the port scanning process on given target
    scanner.start_scan().await?;

    Ok(())
}