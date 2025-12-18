use crate::collectors::{CollectorEvent, CollectorManager};
use crate::config::Config;
use crate::database::Database;
use crate::hunts::HuntEngine;
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand};
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "agent")]
#[command(about = "EDR-style endpoint monitoring agent", long_about = None)]
pub struct Cli {
    #[arg(short, long, default_value = "config.yaml")]
    pub config: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the monitoring agent
    Start,

    /// Show agent status
    Status,

    /// Export collected events
    Export {
        #[arg(long)]
        since: String,

        #[arg(long, default_value = "jsonl")]
        format: String,
    },

    /// Run detection hunts on collected data
    Hunt {
        #[arg(long)]
        rule: String,
    },
}

pub async fn start_agent(config: Config) -> Result<()> {
    info!("Starting EDR agent...");

    // Initialize database
    let db_url = format!("sqlite:{}", config.database.path);
    let db = Arc::new(Database::new(&db_url).await?);

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = broadcast::channel(10);

    // Start collector manager
    let (collector_manager, mut event_rx) = CollectorManager::new(config.clone(), Arc::clone(&db));

    // Start hunt engine if enabled
    let hunt_engine = if config.hunts.enabled {
        Some(Arc::new(HuntEngine::new(Arc::clone(&db))))
    } else {
        None
    };

    // Spawn event logger task
    let jsonl_log_enabled = config.jsonl_log.enabled;
    let jsonl_log_path = config.jsonl_log.path.clone();
    let auto_hunt = config.hunts.auto_hunt;
    let hunt_engine_clone = hunt_engine.clone();

    tokio::spawn(async move {
        let mut jsonl_file = if jsonl_log_enabled {
            Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&jsonl_log_path)
                    .expect("Failed to open JSONL log file"),
            )
        } else {
            None
        };

        while let Ok(event) = event_rx.recv().await {
            match event {
                CollectorEvent::Process(process_event) => {
                    // Write to JSONL log
                    if let Some(ref mut file) = jsonl_file {
                        if let Ok(json) = serde_json::to_string(&process_event) {
                            let _ = writeln!(file, "{}", json);
                        }
                    }

                    // Run auto-hunt if enabled
                    if auto_hunt {
                        if let Some(ref engine) = hunt_engine_clone {
                            if let Err(e) = engine.check_event(&process_event).await {
                                error!("Error running auto-hunt: {}", e);
                            }
                        }
                    }
                }
                CollectorEvent::Network(network_event) => {
                    if let Some(ref mut file) = jsonl_file {
                        if let Ok(json) = serde_json::to_string(&network_event) {
                            let _ = writeln!(file, "{}", json);
                        }
                    }
                }
                CollectorEvent::Persistence(persistence_event) => {
                    if let Some(ref mut file) = jsonl_file {
                        if let Ok(json) = serde_json::to_string(&persistence_event) {
                            let _ = writeln!(file, "{}", json);
                        }
                    }
                }
                CollectorEvent::Shutdown => break,
            }
        }
    });

    // Start collectors
    tokio::spawn(async move {
        if let Err(e) = collector_manager.start(shutdown_rx).await {
            error!("Collector manager error: {}", e);
        }
    });

    info!("EDR agent is running. Press Ctrl+C to stop.");

    // Wait for Ctrl+C
    signal::ctrl_c().await?;

    info!("Shutdown signal received, stopping agent...");
    let _ = shutdown_tx.send(());

    // Give collectors time to clean up
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    info!("EDR agent stopped.");
    Ok(())
}

pub async fn show_status(config: Config) -> Result<()> {
    let db_url = format!("sqlite:{}", config.database.path);
    let db = Database::new(&db_url).await?;

    let (process_count, network_count, persistence_count, hunt_count) = db.count_events().await?;

    println!("═══════════════════════════════════════");
    println!("        EDR Agent Status");
    println!("═══════════════════════════════════════");
    println!("Database: {}", config.database.path);
    println!();
    println!("Event Counts:");
    println!("  Process events:     {}", process_count);
    println!("  Network events:     {}", network_count);
    println!("  Persistence events: {}", persistence_count);
    println!("  Hunt matches:       {}", hunt_count);
    println!();
    println!("Collectors:");
    println!(
        "  Process:     {}",
        if config.collectors.process.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  Network:     {}",
        if config.collectors.network.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  Persistence: {}",
        if config.collectors.persistence.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!();
    println!("Hunts:");
    println!(
        "  Enabled:     {}",
        if config.hunts.enabled { "yes" } else { "no" }
    );
    println!(
        "  Auto-hunt:   {}",
        if config.hunts.auto_hunt { "yes" } else { "no" }
    );
    println!("═══════════════════════════════════════");

    Ok(())
}

pub async fn export_events(config: Config, since: String, format: String) -> Result<()> {
    let db_url = format!("sqlite:{}", config.database.path);
    let db = Database::new(&db_url).await?;

    let since_dt = parse_time_duration(&since)?;

    info!("Exporting events since {} in {} format", since_dt, format);

    let process_events = db.get_process_events_since(since_dt).await?;
    let network_events = db.get_network_events_since(since_dt).await?;
    let persistence_events = db.get_persistence_events_since(since_dt).await?;

    match format.as_str() {
        "jsonl" => {
            for event in process_events {
                println!("{}", serde_json::to_string(&event)?);
            }
            for event in network_events {
                println!("{}", serde_json::to_string(&event)?);
            }
            for event in persistence_events {
                println!("{}", serde_json::to_string(&event)?);
            }
        }
        "csv" => {
            // Process events
            println!("event_type,timestamp,pid,parent_pid,image_path,command_line,username");
            for event in process_events {
                println!(
                    "process,{},{},{},{},{},{}",
                    event.timestamp,
                    event.pid,
                    event.parent_pid,
                    csv_escape(&event.image_path),
                    csv_escape(&event.command_line),
                    csv_escape(&event.username)
                );
            }

            // Network events
            for event in network_events {
                println!(
                    "network,{},{},{}:{},{}:{},{}",
                    event.timestamp,
                    event.pid,
                    event.local_addr,
                    event.local_port,
                    event.remote_addr,
                    event.remote_port,
                    event.protocol
                );
            }

            // Persistence events
            for event in persistence_events {
                println!(
                    "persistence,{},{},{},{},{}",
                    event.timestamp,
                    event.persistence_type,
                    csv_escape(&event.location),
                    csv_escape(&event.value_name.unwrap_or_default()),
                    csv_escape(&event.value_data)
                );
            }
        }
        _ => {
            anyhow::bail!("Unsupported format: {}. Use 'jsonl' or 'csv'", format);
        }
    }

    Ok(())
}

pub async fn run_hunt(config: Config, rule: String) -> Result<()> {
    let db_url = format!("sqlite:{}", config.database.path);
    let db = Arc::new(Database::new(&db_url).await?);

    let hunt_engine = HuntEngine::new(db);

    println!("═══════════════════════════════════════");
    println!("     Running Hunt: {}", rule);
    println!("═══════════════════════════════════════");
    println!();

    let matches = hunt_engine.run_hunt(&rule).await?;

    if matches.is_empty() {
        println!("No matches found.");
    } else {
        println!("Found {} matches:\n", matches.len());

        for (i, hunt_match) in matches.iter().enumerate() {
            println!("Match #{}:", i + 1);
            println!("  Timestamp:   {}", hunt_match.timestamp);
            println!("  Rule:        {}", hunt_match.rule_name);
            println!("  Event Type:  {}", hunt_match.event_type);
            println!("  Event ID:    {}", hunt_match.event_id);
            println!("  Description: {}", hunt_match.description);
            println!();
        }
    }

    println!("═══════════════════════════════════════");

    Ok(())
}

fn parse_time_duration(duration_str: &str) -> Result<DateTime<Utc>> {
    let now = Utc::now();

    if duration_str.ends_with('h') {
        let hours: i64 = duration_str.trim_end_matches('h').parse()?;
        Ok(now - Duration::hours(hours))
    } else if duration_str.ends_with('d') {
        let days: i64 = duration_str.trim_end_matches('d').parse()?;
        Ok(now - Duration::days(days))
    } else if duration_str.ends_with('w') {
        let weeks: i64 = duration_str.trim_end_matches('w').parse()?;
        Ok(now - Duration::weeks(weeks))
    } else {
        anyhow::bail!("Invalid duration format. Use format like '24h', '7d', or '1w'");
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
