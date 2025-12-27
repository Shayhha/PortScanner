use clap::ValueEnum;
use std::fmt;


/**
 * Mode enum that defines our supported scanning modes.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Tcp,
    Syn,
    Xmas
}


/**
 * Implement Display trait for Mode enum for printing.
 */
impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let output = match self {
            Mode::Tcp  => "\x1b[34mTCP Connect\x1b[0m",
            Mode::Syn  => "\x1b[32mSYN\x1b[0m",
            Mode::Xmas => "\x1b[31mXMAS\x1b[0m"
        };
        write!(f, "{output}")
    }
}


/**
 * PortStatus enum that defines our supported port statuses.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    OpenFiltered
}


/**
 * Implement Display trait for PortStatus enum for printing.
 */
impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let output = match self {
            PortStatus::Open => "\x1b[32mOpen\x1b[0m",
            PortStatus::Closed => "\x1b[31mClosed\x1b[0m",
            PortStatus::Filtered => "\x1b[33mFiltered\x1b[0m",
            PortStatus::OpenFiltered => "\x1b[35mOpen/Filtered\x1b[0m"
        };
        write!(f, "{output}")
    }
}