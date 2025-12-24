use anyhow::Result;
use pnet::datalink::NetworkInterface;
use std::net::Ipv4Addr;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::fmt::Write;
use tokio::sync::{Semaphore, oneshot};
use colored::*;

use crate::engine::listener::PacketListener;
use crate::utility::scanner_enums::{Mode, PortStatus};

// define our custom types for scanner data structures
pub type ScanSemaphore = Arc<Semaphore>;
pub type ScanTasksVec = Vec<tokio::task::JoinHandle<()>>;
pub type ProbeMap = Arc<Mutex<HashMap<u16, oneshot::Sender<PortStatus>>>>;
pub type ResultsMap = Arc<Mutex<BTreeMap<u16, PortStatus>>>;


/**
 * Represents our port scanner configuration struct.
 */
#[derive(Clone, Debug)]
pub struct PortScanner {
    pub interface: NetworkInterface,
    pub target: Ipv4Addr,
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
    pub fn new(interface: NetworkInterface, target: Ipv4Addr, start_port: u16, end_port: u16, concurrency: usize, timeout: u64, mode: Mode) -> Self {
        Self { interface, target, start_port, end_port, concurrency, timeout, mode }
    }


    /**
     * Method for running the port scanner and creating async scan tasks for each port.
     */
    pub async fn start_scan(&self) -> Result<()> {
        let mut scan_tasks_vec: ScanTasksVec = vec![]; //represents vector of scan tasks for each port
        let scan_semaphore: ScanSemaphore = Arc::new(Semaphore::new(self.concurrency)); //represents semaphore for limiting number of concurrent scans
        let probe_map: ProbeMap = Arc::new(Mutex::new(HashMap::new())); //represents probe map for tracking responses for each port for SYN and Xmas scans, keys are port and values are sender sockets
        let results_map: ResultsMap = Arc::new(Mutex::new(BTreeMap::new())); //represents results map for storing scan result for each port, keys are port and values are port status

        // create our packet listener task for capturing incoming response packets
        let packet_listener: PacketListener = PacketListener::new(self.interface.clone(), probe_map.clone());
        packet_listener.start_listener(); //start packet listener in its own thread for handling incoming response packets

        // iterate over each port in given range and create async scan task for each port
        for port in self.start_port..=self.end_port {
            // aquire semaphore permit and clone necessary variables for async task
            let task_permit = scan_semaphore.clone().acquire_owned().await?;
            let task_probe_map = probe_map.clone();
            let task_results_map = results_map.clone();
            let task_interface = self.interface.clone();
            let task_target = self.target;
            let task_timeout = self.timeout;
            let task_mode = self.mode;

            // create aysnc scan task for port and add it to our scan tasks vector
            scan_tasks_vec.push(tokio::spawn(async move {
                let _p = task_permit; //acquire semaphore permit

                //TODO perform port scan based on selected scan mode
                let status = match task_mode {
                    Mode::Tcp => tcp::scan_tcp(task_target, port, task_timeout).await?,
                    Mode::Syn => syn::scan_syn(&task_interface, task_probe_map, task_target, port, task_timeout).await?,
                    Mode::Xmas => xmas::scan_xmas(&task_interface, task_probe_map, task_target, port, task_timeout).await?,
                };

                // when scan is finished we store the result in our results map
                if let Ok(mut results) = task_results_map.lock() {
                    results.insert(port, status);
                }
            }));
        }

        // wait for all scan tasks to finish
        for task in scan_tasks_vec {
            let _ = task.await; //call await on each task
        }

        // after we finisghed scanning all ports we print the summary of results
        if let Ok(mut results) = results_map.lock() {
            let _ = self.print_summary(self.target, &results).await?; //call print summary method
        }
    
        Ok(())
    }


    /**
     * Method for printing scan results summary with all scanned ports and their statuses.
     */
    pub async fn print_summary(&self, target: Ipv4Addr, results_map: &BTreeMap<u16, PortStatus>) -> Result<()> {
        // define output string and counters for each port status
        let mut output: String = String::new();
        let mut open: u16 = 0;
        let mut closed: u16 = 0;
        let mut filtered: u16 = 0;
        let mut open_filtered: u16 = 0;

        // write summary header with scan configuration details
        writeln!(&mut output, "\n{} Scan Summary {}", "-".repeat(29), "-".repeat(29))?;
        writeln!(&mut output, "Target      : {}", target)?;
        writeln!(&mut output, "Scan mode   : {:?}", self.mode)?;
        writeln!(&mut output, "Port range  : {}-{}", self.start_port, self.end_port)?;
        writeln!(&mut output, "Concurrency : {}", self.concurrency)?;
        writeln!(&mut output, "{}\n", "-".repeat(72))?;

        // write table header with port results
        writeln!(&mut output, "{:<12} {}", "PORT", "STATUS")?;

        // iterate over results map and write each port result to output
        for (port, status) in results_map {
            // set label based on port status and increment counter
            let label = match status {
                PortStatus::Open => {
                    open += 1;
                    "OPEN".green()
                }
                PortStatus::Closed => {
                    closed += 1;
                    "CLOSED".red()
                }
                PortStatus::Filtered => {
                    filtered += 1;
                    "FILTERED".yellow()
                }
                PortStatus::OpenFiltered => {
                    open_filtered += 1;
                    "OPEN/FILTERED".magenta()
                }
            };

            // write port and its status to output
            writeln!(&mut output, "{:<12} {}", format!("{}/tcp", port), label)?;
        }
        writeln!(&mut output, "{}\n", "-".repeat(72))?;

        // write final results summary with counts for each port status
        writeln!(&mut output, "Results: Open: {} | Closed: {} | Filtered: {} | Open/Filtered: {} | Total: {}",
            open.to_string().green(), closed.to_string().red(), filtered.to_string().yellow(), open_filtered.to_string().magenta(), results_map.len())?;

        // print the final output to console
        println!("{}", output);

        Ok(())
    }
}