mod net;
mod scanner;
mod utility;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    print!("Starting port scanner...\n");
    let interface = net::interface::get_default_interface()?;
    println!("Using interface: {} {}", interface.name, interface.mac.map_or("None".to_string(), |m| m.to_string()));
    Ok(())
}