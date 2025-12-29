use clap::ValueEnum;
use std::fmt;


/**
 * Mode enum that defines our supported scanning modes.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Udp,
    Tcp,
    Syn,
    Null,
    Fin,
    Xmas,
    Ack
}


/**
 * Implement Display trait for Mode enum for printing.
 */
impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let output = match self {
            Mode::Udp  => "\x1b[96mUDP\x1b[0m",
            Mode::Tcp  => "\x1b[34mTCP Connect\x1b[0m",
            Mode::Syn  => "\x1b[32mSYN\x1b[0m",
            Mode::Null => "\x1b[35mNULL\x1b[0m",
            Mode::Fin  => "\x1b[36mFIN\x1b[0m",
            Mode::Xmas => "\x1b[31mXMAS\x1b[0m",
            Mode::Ack  => "\x1b[33mACK\x1b[0m"
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
    Unfiltered,
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
            PortStatus::Unfiltered => "\x1b[36mUnfiltered\x1b[0m",
            PortStatus::OpenFiltered => "\x1b[35mOpen/Filtered\x1b[0m"
        };
        write!(f, "{output}")
    }
}