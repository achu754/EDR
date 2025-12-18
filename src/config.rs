use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub log_level: String,
    pub database: DatabaseConfig,
    pub jsonl_log: JsonlLogConfig,
    pub collectors: CollectorsConfig,
    pub hunts: HuntsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonlLogConfig {
    pub enabled: bool,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorsConfig {
    pub process: ProcessCollectorConfig,
    pub network: NetworkCollectorConfig,
    pub persistence: PersistenceCollectorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCollectorConfig {
    pub enabled: bool,
    pub poll_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCollectorConfig {
    pub enabled: bool,
    pub poll_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceCollectorConfig {
    pub enabled: bool,
    pub poll_interval: u64,
    pub watch_paths: Vec<String>,
    pub watch_registry: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntsConfig {
    pub enabled: bool,
    pub auto_hunt: bool,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref()).context("Failed to read config file")?;

        let config: Config =
            serde_yaml::from_str(&content).context("Failed to parse config YAML")?;

        Ok(config)
    }
}
