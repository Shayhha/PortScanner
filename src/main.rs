mod net;
mod scanner;
mod utility;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    print!("Starting port scanner...\n");
    Ok(())
}