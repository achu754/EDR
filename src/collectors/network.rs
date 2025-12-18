use crate::collectors::CollectorEvent;
use crate::config::Config;
use crate::database::{Database, NetworkEvent};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashSet;
use std::mem;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::AF_INET;

pub struct NetworkCollector {
    config: Config,
    db: Arc<Database>,
    event_tx: broadcast::Sender<CollectorEvent>,
    known_connections: HashSet<String>,
}

impl NetworkCollector {
    pub fn new(
        config: Config,
        db: Arc<Database>,
        event_tx: broadcast::Sender<CollectorEvent>,
    ) -> Self {
        Self {
            config,
            db,
            event_tx,
            known_connections: HashSet::new(),
        }
    }

    pub async fn run(&mut self, shutdown_rx: &mut broadcast::Receiver<()>) -> Result<()> {
        info!("Network collector started");

        let poll_interval = self.config.collectors.network.poll_interval;
        let mut tick = interval(Duration::from_secs(poll_interval));

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Err(e) = self.check_network_connections().await {
                        error!("Error checking network connections: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Network collector shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn check_network_connections(&mut self) -> Result<()> {
        // Check TCP connections
        self.check_tcp_connections().await?;

        // Check UDP connections
        self.check_udp_connections().await?;

        Ok(())
    }

    async fn check_tcp_connections(&mut self) -> Result<()> {
        unsafe {
            let mut size: u32 = 0;

            // Get required buffer size
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if size == 0 {
                return Ok(());
            }

            let mut buffer = vec![0u8; size as usize];

            // Get TCP table
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result != 0 {
                return Ok(()); // Silently skip on error
            }

            let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let num_entries = (*table).dwNumEntries as usize;

            for i in 0..num_entries {
                let row_ptr = (table as *const u8)
                    .add(mem::size_of::<u32>())
                    .add(i * mem::size_of::<MIB_TCPROW_OWNER_PID>())
                    as *const MIB_TCPROW_OWNER_PID;

                let row = &*row_ptr;

                let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
                let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                let remote_addr = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
                let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
                let pid = row.dwOwningPid;
                let state = tcp_state_to_string(row.dwState);

                // Create a unique key for this connection
                let key = format!(
                    "tcp:{}:{}:{}:{}:{}",
                    pid, local_addr, local_port, remote_addr, remote_port
                );

                // Only log new connections
                if !self.known_connections.contains(&key) {
                    let event = NetworkEvent {
                        id: None,
                        timestamp: Utc::now(),
                        pid,
                        local_addr: local_addr.to_string(),
                        local_port,
                        remote_addr: remote_addr.to_string(),
                        remote_port,
                        protocol: "TCP".to_string(),
                        state: state.clone(),
                    };

                    // Store in database
                    match self.db.insert_network_event(&event).await {
                        Ok(id) => {
                            debug!(
                                "Logged TCP connection: PID={}, {}:{} -> {}:{}",
                                pid, local_addr, local_port, remote_addr, remote_port
                            );

                            let mut event_with_id = event.clone();
                            event_with_id.id = Some(id);

                            // Broadcast event
                            let _ = self.event_tx.send(CollectorEvent::Network(event_with_id));

                            self.known_connections.insert(key);
                        }
                        Err(e) => {
                            error!("Failed to insert network event: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn check_udp_connections(&mut self) -> Result<()> {
        unsafe {
            let mut size: u32 = 0;

            // Get required buffer size
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if size == 0 {
                return Ok(());
            }

            let mut buffer = vec![0u8; size as usize];

            // Get UDP table
            let result = GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result != 0 {
                return Ok(()); // Silently skip on error
            }

            let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
            let num_entries = (*table).dwNumEntries as usize;

            for i in 0..num_entries {
                let row_ptr = (table as *const u8)
                    .add(mem::size_of::<u32>())
                    .add(i * mem::size_of::<MIB_UDPROW_OWNER_PID>())
                    as *const MIB_UDPROW_OWNER_PID;

                let row = &*row_ptr;

                let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
                let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                let pid = row.dwOwningPid;

                // Create a unique key for this connection
                let key = format!("udp:{}:{}:{}", pid, local_addr, local_port);

                // Only log new connections
                if !self.known_connections.contains(&key) {
                    let event = NetworkEvent {
                        id: None,
                        timestamp: Utc::now(),
                        pid,
                        local_addr: local_addr.to_string(),
                        local_port,
                        remote_addr: "0.0.0.0".to_string(),
                        remote_port: 0,
                        protocol: "UDP".to_string(),
                        state: "LISTENING".to_string(),
                    };

                    // Store in database
                    match self.db.insert_network_event(&event).await {
                        Ok(id) => {
                            debug!(
                                "Logged UDP connection: PID={}, {}:{}",
                                pid, local_addr, local_port
                            );

                            let mut event_with_id = event.clone();
                            event_with_id.id = Some(id);

                            // Broadcast event
                            let _ = self.event_tx.send(CollectorEvent::Network(event_with_id));

                            self.known_connections.insert(key);
                        }
                        Err(e) => {
                            error!("Failed to insert network event: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn tcp_state_to_string(state: u32) -> String {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
    .to_string()
}
