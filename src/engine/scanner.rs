use anyhow::{anyhow, Result};
use pnet::datalink::{DataLinkSender, DataLinkReceiver};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::fmt::Write;
use tokio::sync::{Semaphore, OwnedSemaphorePermit, mpsc};
use tokio::task::JoinHandle;

use crate::engine::{tcp, syn, null, fin, xmas, ack};
use crate::engine::listener::PacketListener;
use crate::net::interface::DeviceInterface;
use crate::utility::scanner_enums::{Mode, PortStatus};

// define our custom types for scanner data structures
pub type ProbeMap = Arc<Mutex<HashMap<(u16, u16), mpsc::Sender<PortStatus>>>>;
pub type ResultsMap = Arc<Mutex<BTreeMap<u16, PortStatus>>>;
pub type TxSender = Arc<Mutex<Box<dyn DataLinkSender>>>;
pub type RxReciver = Box<dyn DataLinkReceiver>;


/**
 * Represents our port scanner configuration struct.
 */
#[derive(Clone, Debug)]
pub struct PortScanner {
    pub device_interface: Arc<DeviceInterface>,
    pub target_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub start_port: u16,
    pub end_port: u16,
    pub concurrency: usize,
    pub timeout: u64,
    pub mode: Mode
}


/**
 * Implementation of port scanner struct with methods for scanning.
 */
impl PortScanner {
    /**
     * Constructor for port scanner struct.
     */
    pub fn new(device_interface: Arc<DeviceInterface>, target_ip: Ipv4Addr, start_port: u16, end_port: u16, concurrency: usize, timeout: u64, mode: Mode) -> Self {
        // resolve target MAC address, if failed use broadcast MAC address
        let target_mac = DeviceInterface::resolve_device_mac_address(&device_interface, target_ip, timeout)
            .unwrap_or(MacAddr::broadcast());
        Self { device_interface, target_ip, target_mac, start_port, end_port, concurrency, timeout, mode }
    }


    /**
     * Method for running the port scanner and creating async scan tasks for each port.
     */
    pub async fn start_scan(&self) -> Result<()> {
        // initialize our data structures for scanner tasks
        let mut scan_tasks_vec: Vec<JoinHandle<()>> = vec![]; //represents vector of scan tasks for each port
        let scan_semaphore: Arc<Semaphore> = Arc::new(Semaphore::new(self.concurrency)); //represents semaphore for limiting number of concurrent scans
        let probe_map: ProbeMap = Arc::new(Mutex::new(HashMap::new())); //represents probe map for tracking responses for each port for SYN and Xmas scans, keys are port and values are sender channel
        let results_map: ResultsMap = Arc::new(Mutex::new(BTreeMap::new())); //represents results map for storing scan result for each port, keys are port and values are port status

        // create new datalink channel socket and initialize our tx sender and rx receiver handles
        let (tx, rx) = DeviceInterface::create_datalink_channel(&self.device_interface)?;
        let tx_sender: TxSender = Arc::new(Mutex::new(tx)); //initialize tx sender handle with mutex for async scan tasks
        let rx_receiver: RxReciver = rx; //initialize rx receiver handle for listener thread

        // create our packet listener task for capturing incoming response packets
        let packet_listener: PacketListener = PacketListener::new(self.device_interface.clone(), probe_map.clone());
        packet_listener.start_listener(rx_receiver, self.target_ip, self.mode); //start packet listener in its own thread for handling incoming response packets

        // iterate over each port in given range and create async scan task for each port
        for target_port in self.start_port..=self.end_port {
            // acquire semaphore permit for our scan task
            let permit = scan_semaphore.clone().acquire_owned().await?;

            // create aysnc scan port task for port and add it to our scan tasks vector
            scan_tasks_vec.push(tokio::spawn(Self::scan_port_task(tx_sender.clone(), probe_map.clone(), results_map.clone(),
                self.device_interface.ip, self.device_interface.mac, self.target_ip, self.target_mac,target_port, self.timeout, self.mode, permit)));
        }

        // wait for all scan tasks to finish
        for task in scan_tasks_vec {
            let _ = task.await; //call await on each task
        }

        // try to acquire lock on results map and print the summary of scan results
        if let Ok(results_map) = results_map.lock() {
            let _ = self.print_scan_summary(&results_map).await?; //call print summary method
        }
        // else we failed acquiring mutex, we print error message
        else {
            return Err(anyhow!("Scan failed on target {}: Could not fetch scan results for desired target.", self.target_ip));
        }
    
        Ok(())
    }


    /**
     * Static method for performing async port scan task for given port based on selected scan mode.
     */
    async fn scan_port_task(tx: TxSender, probe_map: ProbeMap, results_map: ResultsMap, interface_ip: Ipv4Addr, interface_mac: MacAddr, target_ip: Ipv4Addr, target_mac: MacAddr, target_port: u16, timeout: u64, mode: Mode, _permit: OwnedSemaphorePermit) {
        // perform port scan on desired port based on selected scan mode
        let status = match mode {
            Mode::Tcp => tcp::scan_tcp(target_ip, target_port, timeout).await,
            Mode::Syn => syn::scan_syn(tx, probe_map, interface_ip, interface_mac, target_ip, target_mac, target_port, timeout).await,
            Mode::Null => null::scan_null(tx, probe_map, interface_ip, interface_mac, target_ip, target_mac, target_port, timeout).await,
            Mode::Fin => fin::scan_fin(tx, probe_map, interface_ip, interface_mac, target_ip, target_mac, target_port, timeout).await,
            Mode::Xmas => xmas::scan_xmas(tx, probe_map, interface_ip, interface_mac, target_ip, target_mac, target_port, timeout).await,
            Mode::Ack => ack::scan_ack(tx, probe_map, interface_ip, interface_mac, target_ip, target_mac, target_port, timeout).await
        }
        .unwrap_or_else(|e| {
            println!("Scan failed on port {}: {}", target_port, e);
            PortStatus::Filtered
        });

        // try to acquire lock on results map and insert port status result
        if let Ok(mut results_map) = results_map.lock() {
            results_map.insert(target_port, status);
        }
        // else we failed acquiring mutex, we print error message
        else {
            println!("Scan failed on port {}: Could not add port status to results map.", target_port);
        }
    }


    /**
     * Method for printing scan results summary with all scanned ports and their statuses.
     */
    async fn print_scan_summary(&self, results_map: &BTreeMap<u16, PortStatus>) -> Result<()> {
        // define output string and counters for each port status
        let mut output: String = String::new();
        let mut open: u16 = 0;
        let mut closed: u16 = 0;
        let mut filtered: u16 = 0;
        let mut open_filtered: u16 = 0;

        // write summary header with scan configuration details
        writeln!(&mut output, "\n{} Scan Summary {}", "=".repeat(30), "=".repeat(30))?;
        writeln!(&mut output, "Target IP   : {}", self.target_ip)?;
        writeln!(&mut output, "Target MAC  : {}", self.target_mac)?;
        writeln!(&mut output, "Scan mode   : {}", self.mode)?;
        writeln!(&mut output, "Port range  : {} - {}", self.start_port, self.end_port)?;
        writeln!(&mut output, "Concurrency : {}", self.concurrency)?;
        writeln!(&mut output, "{}\n", "=".repeat(74))?;

        // write table header with port results
        writeln!(&mut output, "{:<12} {}", "PORT", "STATUS")?;

        // iterate over results map and write each port result to output
        for (port, status) in results_map {
            // increment status counters based on port status
            match status {
                PortStatus::Open => {
                    open += 1;
                }
                PortStatus::Closed => {
                    closed += 1;
                }
                PortStatus::Filtered => {
                    filtered += 1;
                }
                PortStatus::OpenFiltered => {
                    open_filtered += 1;
                }
                _ => {}
            };

            // write port and its status to output
            writeln!(&mut output, "{:<12} {}", format!("{}/tcp", port), status)?;
        }
        writeln!(&mut output, "{}\n", "=".repeat(72))?;

        // write final results summary with counts for each port status
        writeln!(&mut output, "Results: Open: \x1b[32m{}\x1b[0m | Closed: \x1b[31m{}\x1b[0m | Filtered: \x1b[33m{}\x1b[0m | Open/Filtered: \x1b[35m{}\x1b[0m | Total: \x1b[36m{}\x1b[0m",
            open.to_string(), closed.to_string(), filtered.to_string(), open_filtered.to_string(), results_map.len())?;

        // print the final output to console
        println!("{}", output);

        Ok(())
    }
}