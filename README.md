# PortScanner - High-Performance Network Port Scanner

PortScanner is a fast and efficient port scanner written in Rust. It supports multiple scan modes, including TCP Connect, UDP, SYN, FIN, Xmas, Null, and ACK scans, leveraging raw packets and OS sockets for accurate port status detection. PortScanner is designed for both reliability and performance, providing detailed scanning results for network security assessments.

## Features

- **Multiple Scan Modes:** Supports TCP Connect, UDP, SYN, FIN, Xmas, Null and ACK scans.
- **High Performance:** Uses asynchronous concurrency and raw packet crafting for fast scanning.
- **Custom Timeouts & Concurrency:** Configure maximum concurrent probes and per-probe timeout to balance speed and reliability.
- **Protocol-Specific Detection:** Accurately detects open, closed, filtered, and open|filtered ports for TCP and UDP.
- **Raw Packet Handling:** Directly crafts Ethernet, IPv4, TCP, UDP, and ICMP packets for precise control and analysis.
- **Cross-Platform:** Runs on Windows, Linux, and macOS with raw socket and datalink access.
- **Rust-Based:** Safe, efficient, and modern codebase leveraging Rust's performance and safety guarantees.

## Clone Repository

To get started, clone the repository:

```shell
git clone https://github.com/Shayhha/PortScanner
````

## Usage

1. **Build the Project:**

```shell
cargo build --release
```

2. **Run the Scanner:**

```shell
cargo run --release -- -a 192.168.1.10 -s 1 -e 1024 -m Syn -c 500 -t 2500
```

### Command Line Arguments:

* `-a, --target` : Target IPv4 address
* `-s, --start-port` : Start port
* `-e, --end-port` : End port
* `-c, --concurrency` : Max concurrent probes
* `-t, --timeout` : Timeout per probe in milliseconds
* `-m, --mode` : Scan mode (`Tcp`, `Udp`, `Syn`, `Fin`, `Xmas`, `Null`, `Ack`)

### Example:

```shell
cargo run --release -- -a 192.168.1.100 -s 20 -e 80 -m Syn -c 1000 -t 2000
```

## Scan Modes

* **TCP Connect Scan:** Uses the operating system’s TCP stack to establish full connections with target ports.
* **UDP Scan:** Sends UDP packets and determines port state based on ICMP responses.
* **SYN Scan:** Sends TCP SYN packets and analyzes responses to determine port status.
* **FIN Scan:** Sends TCP FIN packets to identify open or filtered ports.
* **XMAS Scan:** Sends TCP packets with FIN, PSH and URG flags set to analyze port behavior.
* **Null Scan:** Sends TCP packets with no flags set to identify open or filtered ports.
* **ACK Scan:** Sends TCP ACK packets to detect filtered ports by analyzing RST responses.

## Output

Scan results include each port's number, protocol, and status:

```
PORT         STATUS
----------------------
20/tcp       Closed
22/tcp       Open
53/udp       Open
80/tcp       Filtered
```

Status values:

* `Open`
* `Closed`
* `Filtered`
* `Unfiltered`
* `Open|Filtered`

## Requirements

**Rust**: Version 1.90 or higher.

**Dependencies:**
- **tokio** - Async runtime enabling high-performance concurrent tasks.
- **pnet** - Provides low-level packet crafting and network interface access.
- **clap** - Simplifies command-line argument parsing and validation.
- **anyhow** - Easy-to-use error handling with rich context.
- **rand** - Generates random values for general-purpose use in applications.
- **default_gateway** - Resolves the default gateway IP addresses by network interface.

**Important** 
- On Windows based systems [Npcap](https://npcap.com/#download) must be installed to enable packet analysis and capturing.
- On Linux and macOS you have to run the application with administrative privileges to enable packet analysis and capturing.

## Contact

For questions or feedback, please contact [shayhha@gmail.com](mailto:shayhha@gmail.com).

**Note:** This application should be used responsibly and in compliance with applicable laws and regulations. Unauthorized use is strictly prohibited.

## License

PortScanner is released under the [MIT License](LICENSE.txt).

© All rights reserved to Shayhha (Shay Hahiashvili).
