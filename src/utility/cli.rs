use crate::utility::scanner_enums::Mode;
use clap::Parser;
use std::net::Ipv4Addr;


/**
 * Command line arguments struct for port scanner application, includes flags and application info.
 */
#[derive(Parser, Debug, Clone)]
#[command(
    author = "Shay Hahiashvili",
    version = "1.0.0",
    about = "High-performance async port scanner supporting TCP, SYN, NULL, FIN and Xmas scans.",
    long_about = "High-performance asynchronous network port scanner written in Rust.\n\
                Supports TCP, SYN, NULL, FIN and Xmas scanning techniques.\n\
                Built with Tokio for scalable concurrency and low-level packet crafting\n\
                to enable fast and accurate network reconnaissance.",
    arg_required_else_help = true,
    next_line_help = true
)]
pub struct Args {
    /// Target IPv4 address
    #[arg(short = 'a', long, value_parser = clap::value_parser!(Ipv4Addr))]
    pub target: Ipv4Addr,

    /// Start port
    #[arg(short = 's', long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=65535))]
    pub start_port: u16,

    /// End port
    #[arg(short = 'e', long, default_value_t = 1024, value_parser = clap::value_parser!(u16).range(1..=65535))]
    pub end_port: u16,

    /// Max concurrent probes
    #[arg(short = 'c', long, default_value_t = 500, value_parser = clap::value_parser!(u16).range(1..=10000))]
    pub concurrency: u16,

    /// Per probe timeout in milliseconds
    #[arg(short = 't', long, default_value_t = 2500u64, value_parser = clap::value_parser!(u64).range(1..=60000))]
    pub timeout: u64,

    /// Scan mode
    #[arg(short = 'm', long, value_enum, default_value_t = Mode::Syn)]
    pub mode: Mode
}