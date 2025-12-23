mod net;
mod scanner;
mod utility;

use crate::utility::cli::Args;
use anyhow::Result;
use clap::Parser;


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

    Ok(())
}