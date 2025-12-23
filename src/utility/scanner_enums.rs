use clap::ValueEnum;


/**
 * Mode enum that defines our supported scanning modes.
 */
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Tcp,
    Syn,
    Xmas
}


/**
 * PortStatus enum that defines our supported port statuses.
 */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    OpenFiltered
}