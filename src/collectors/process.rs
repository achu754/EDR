use crate::collectors::CollectorEvent;
use crate::config::Config;
use crate::database::{Database, ProcessEvent};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};
use wmi::{COMLibrary, WMIConnection};

pub struct ProcessCollector {
    config: Config,
    db: Arc<Database>,
    event_tx: broadcast::Sender<CollectorEvent>,
    known_processes: HashMap<u32, String>,
}

impl ProcessCollector {
    pub fn new(
        config: Config,
        db: Arc<Database>,
        event_tx: broadcast::Sender<CollectorEvent>,
    ) -> Self {
        Self {
            config,
            db,
            event_tx,
            known_processes: HashMap::new(),
        }
    }

    pub async fn run(&mut self, shutdown_rx: &mut broadcast::Receiver<()>) -> Result<()> {
        info!("Process collector started");

        // Initialize known processes
        if let Err(e) = self.initialize_known_processes() {
            warn!("Failed to initialize known processes: {}", e);
        }

        let poll_interval = self.config.collectors.process.poll_interval;
        let mut tick = interval(Duration::from_secs(poll_interval));

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Err(e) = self.check_for_new_processes().await {
                        error!("Error checking for new processes: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Process collector shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    fn initialize_known_processes(&mut self) -> Result<()> {
        let com_con = COMLibrary::new()?;
        let wmi_con = WMIConnection::new(com_con)?;

        let processes: Vec<HashMap<String, wmi::Variant>> =
            wmi_con.raw_query("SELECT ProcessId, Name FROM Win32_Process")?;

        for process in processes {
            if let (Some(wmi::Variant::UI4(pid)), Some(wmi::Variant::String(name))) =
                (process.get("ProcessId"), process.get("Name"))
            {
                self.known_processes.insert(*pid, name.clone());
            }
        }

        debug!("Initialized {} known processes", self.known_processes.len());
        Ok(())
    }

    async fn check_for_new_processes(&mut self) -> Result<()> {
        let com_con = COMLibrary::new()?;
        let wmi_con = WMIConnection::new(com_con)?;

        let processes: Vec<HashMap<String, wmi::Variant>> = wmi_con.raw_query(
            "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process",
        )?;

        for process in processes {
            let pid = match process.get("ProcessId") {
                Some(wmi::Variant::UI4(p)) => *p,
                _ => continue,
            };

            // Check if this is a new process
            if self.known_processes.contains_key(&pid) {
                continue;
            }

            let parent_pid = match process.get("ParentProcessId") {
                Some(wmi::Variant::UI4(p)) => *p,
                _ => 0,
            };

            let name = match process.get("Name") {
                Some(wmi::Variant::String(n)) => n.clone(),
                _ => String::from("Unknown"),
            };

            let image_path = match process.get("ExecutablePath") {
                Some(wmi::Variant::String(p)) => p.clone(),
                _ => String::from("Unknown"),
            };

            let command_line = match process.get("CommandLine") {
                Some(wmi::Variant::String(c)) => c.clone(),
                _ => String::from(""),
            };

            // Get username (simplified - in production, would use more robust method)
            let username = self
                .get_process_username(pid)
                .unwrap_or_else(|| String::from("Unknown"));

            let event = ProcessEvent {
                id: None,
                timestamp: Utc::now(),
                pid,
                parent_pid,
                image_path: image_path.clone(),
                command_line: command_line.clone(),
                username: username.clone(),
            };

            // Store in database
            match self.db.insert_process_event(&event).await {
                Ok(id) => {
                    debug!("Logged process creation: PID={}, Image={}", pid, image_path);
                    let mut event_with_id = event.clone();
                    event_with_id.id = Some(id);

                    // Broadcast event
                    let _ = self.event_tx.send(CollectorEvent::Process(event_with_id));

                    // Mark as known
                    self.known_processes.insert(pid, name);
                }
                Err(e) => {
                    error!("Failed to insert process event: {}", e);
                }
            }
        }

        Ok(())
    }

    fn get_process_username(&self, _pid: u32) -> Option<String> {
        // Simplified: In production, would use GetTokenInformation or WMI Win32_Process.GetOwner()
        // For now, return None to indicate "Unknown"
        None
    }
}
