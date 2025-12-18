use crate::collectors::CollectorEvent;
use crate::config::Config;
use crate::database::{Database, PersistenceEvent};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};
use windows::core::HSTRING;
use windows::Win32::System::Registry::{
    RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ, REG_VALUE_TYPE,
};

pub struct PersistenceCollector {
    config: Config,
    db: Arc<Database>,
    event_tx: broadcast::Sender<CollectorEvent>,
    known_registry_values: HashMap<String, String>,
    known_startup_files: HashMap<String, String>,
}

impl PersistenceCollector {
    pub fn new(
        config: Config,
        db: Arc<Database>,
        event_tx: broadcast::Sender<CollectorEvent>,
    ) -> Self {
        Self {
            config,
            db,
            event_tx,
            known_registry_values: HashMap::new(),
            known_startup_files: HashMap::new(),
        }
    }

    pub async fn run(&mut self, shutdown_rx: &mut broadcast::Receiver<()>) -> Result<()> {
        info!("Persistence collector started");

        // Initialize known persistence mechanisms
        self.initialize_known_persistence();

        let poll_interval = self.config.collectors.persistence.poll_interval;
        let mut tick = interval(Duration::from_secs(poll_interval));

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Err(e) = self.check_persistence_mechanisms().await {
                        error!("Error checking persistence mechanisms: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Persistence collector shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    fn initialize_known_persistence(&mut self) {
        // Initialize known registry values
        for reg_path in &self.config.collectors.persistence.watch_registry {
            if let Ok(values) = self.read_registry_key(reg_path) {
                for (name, data) in values {
                    let key = format!("{}\\{}", reg_path, name);
                    self.known_registry_values.insert(key, data);
                }
            }
        }

        // Initialize known startup files
        for path in &self.config.collectors.persistence.watch_paths {
            if let Ok(files) = self.read_startup_folder(path) {
                for (file, hash) in files {
                    self.known_startup_files.insert(file, hash);
                }
            }
        }

        debug!(
            "Initialized {} known registry values and {} startup files",
            self.known_registry_values.len(),
            self.known_startup_files.len()
        );
    }

    async fn check_persistence_mechanisms(&mut self) -> Result<()> {
        // Check registry keys
        for reg_path in self.config.collectors.persistence.watch_registry.clone() {
            if let Err(e) = self.check_registry_key(&reg_path).await {
                warn!("Error checking registry key {}: {}", reg_path, e);
            }
        }

        // Check startup folders
        for path in self.config.collectors.persistence.watch_paths.clone() {
            if let Err(e) = self.check_startup_folder(&path).await {
                warn!("Error checking startup folder {}: {}", path, e);
            }
        }

        Ok(())
    }

    async fn check_registry_key(&mut self, reg_path: &str) -> Result<()> {
        let values = self.read_registry_key(reg_path)?;

        for (name, data) in values {
            let key = format!("{}\\{}", reg_path, name);

            // Check if this is a new or modified value
            if let Some(known_data) = self.known_registry_values.get(&key) {
                if known_data == &data {
                    continue; // No change
                }
            }

            let event = PersistenceEvent {
                id: None,
                timestamp: Utc::now(),
                persistence_type: "registry".to_string(),
                location: reg_path.to_string(),
                value_name: Some(name.clone()),
                value_data: data.clone(),
            };

            // Store in database
            match self.db.insert_persistence_event(&event).await {
                Ok(id) => {
                    debug!("Logged registry persistence: {}\\{}", reg_path, name);

                    let mut event_with_id = event.clone();
                    event_with_id.id = Some(id);

                    // Broadcast event
                    let _ = self
                        .event_tx
                        .send(CollectorEvent::Persistence(event_with_id));

                    self.known_registry_values.insert(key, data);
                }
                Err(e) => {
                    error!("Failed to insert persistence event: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn check_startup_folder(&mut self, folder_path: &str) -> Result<()> {
        // Handle wildcard in path
        if folder_path.contains('*') {
            return self.check_wildcard_path(folder_path).await;
        }

        let files = self.read_startup_folder(folder_path)?;

        for (file, hash) in files {
            // Check if this is a new or modified file
            if let Some(known_hash) = self.known_startup_files.get(&file) {
                if known_hash == &hash {
                    continue; // No change
                }
            }

            let event = PersistenceEvent {
                id: None,
                timestamp: Utc::now(),
                persistence_type: "filesystem".to_string(),
                location: folder_path.to_string(),
                value_name: None,
                value_data: file.clone(),
            };

            // Store in database
            match self.db.insert_persistence_event(&event).await {
                Ok(id) => {
                    debug!("Logged filesystem persistence: {}", file);

                    let mut event_with_id = event.clone();
                    event_with_id.id = Some(id);

                    // Broadcast event
                    let _ = self
                        .event_tx
                        .send(CollectorEvent::Persistence(event_with_id));

                    self.known_startup_files.insert(file, hash);
                }
                Err(e) => {
                    error!("Failed to insert persistence event: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn check_wildcard_path(&mut self, pattern: &str) -> Result<()> {
        // Simple wildcard expansion for C:\Users\*\...
        if pattern.starts_with("C:\\Users\\*\\") {
            let users_dir = Path::new("C:\\Users");
            if let Ok(entries) = fs::read_dir(users_dir) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        let expanded =
                            pattern.replace("C:\\Users\\*", entry.path().to_str().unwrap_or(""));
                        let _ = self.check_startup_folder(&expanded).await;
                    }
                }
            }
        }
        Ok(())
    }

    fn read_registry_key(&self, reg_path: &str) -> Result<HashMap<String, String>> {
        let mut values = HashMap::new();

        let (hkey, subkey) = self.parse_registry_path(reg_path)?;

        unsafe {
            let mut key: HKEY = HKEY::default();
            let subkey_hstring = HSTRING::from(subkey);

            if RegOpenKeyExW(hkey, &subkey_hstring, 0, KEY_READ, &mut key).is_err() {
                return Ok(values); // Key doesn't exist
            }

            let mut num_values: u32 = 0;
            let mut max_value_name_len: u32 = 0;
            let mut max_value_len: u32 = 0;

            if RegQueryInfoKeyW(
                key,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(&mut num_values),
                Some(&mut max_value_name_len),
                Some(&mut max_value_len),
                None,
                None,
            )
            .is_err()
            {
                return Ok(values);
            }

            for i in 0..num_values {
                let mut name_buf = vec![0u16; (max_value_name_len + 1) as usize];
                let mut name_len = name_buf.len() as u32;
                let mut data_buf = vec![0u8; max_value_len as usize];
                let mut data_len = data_buf.len() as u32;
                let mut value_type: REG_VALUE_TYPE = REG_VALUE_TYPE::default();

                if RegEnumValueW(
                    key,
                    i,
                    windows::core::PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    Some(&mut value_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                )
                .is_ok()
                {
                    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                    let data = String::from_utf8_lossy(&data_buf[..data_len as usize]).to_string();
                    values.insert(name, data);
                }
            }
        }

        Ok(values)
    }

    fn parse_registry_path(&self, reg_path: &str) -> Result<(HKEY, &str)> {
        if let Some(subkey) = reg_path.strip_prefix("HKLM\\") {
            Ok((HKEY_LOCAL_MACHINE, subkey))
        } else if let Some(subkey) = reg_path.strip_prefix("HKCU\\") {
            Ok((HKEY_CURRENT_USER, subkey))
        } else {
            anyhow::bail!("Unsupported registry hive in path: {}", reg_path)
        }
    }

    fn read_startup_folder(&self, folder_path: &str) -> Result<HashMap<String, String>> {
        let mut files = HashMap::new();

        let path = Path::new(folder_path);
        if !path.exists() {
            return Ok(files);
        }

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        let file_path = entry.path().display().to_string();
                        // Use file size as a simple "hash" for change detection
                        let hash = metadata.len().to_string();
                        files.insert(file_path, hash);
                    }
                }
            }
        }

        Ok(files)
    }
}
