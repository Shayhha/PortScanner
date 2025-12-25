mod engine;
mod net;
mod utility;

use anyhow::Result;
use clap::Parser;
use std::collections::BTreeMap;

use crate::engine::scanner::PortScanner;
use crate::utility::scanner_enums::PortStatus;
use crate::utility::cli::Args;


/**
 * Represents the main function for port scanner application.
 */
#[tokio::main]
async fn main() -> Result<()> {
    let arguments: Args = utility::cli::Args::parse();

    print!("Starting port scanner...\n");
    let interface = net::interface::get_default_interface()?;
    print!("Scan mode: {:?}\n", arguments.mode);
    println!("Using interface: {} with MAC {}", interface.name, interface.mac.map_or("None".to_string(), |m| m.to_string()));

    let mut results = BTreeMap::new();

    results.insert(22, PortStatus::Open);
    results.insert(80, PortStatus::Open);
    results.insert(443, PortStatus::Closed);
    results.insert(21, PortStatus::Filtered);
    results.insert(25, PortStatus::OpenFiltered);
    results.insert(8080, PortStatus::Closed);

    let scanner = PortScanner::new(interface, arguments.target, arguments.start_port, arguments.end_port, arguments.concurrency as usize, arguments.timeout, arguments.mode);

    scanner.print_summary(&results).await?; //test prrint summary

    Ok(())
}