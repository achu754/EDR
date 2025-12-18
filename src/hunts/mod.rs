pub mod rules;

use crate::database::{Database, HuntMatch, ProcessEvent};
use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, info};

pub struct HuntEngine {
    db: Arc<Database>,
}

impl HuntEngine {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn run_hunt(&self, rule_name: &str) -> Result<Vec<HuntMatch>> {
        info!("Running hunt: {}", rule_name);

        let matches = match rule_name {
            "suspicious-powershell" => self.hunt_suspicious_powershell().await?,
            "lolbins" => self.hunt_lolbins().await?,
            "suspicious-parent-child" => self.hunt_suspicious_parent_child().await?,
            _ => {
                anyhow::bail!("Unknown hunt rule: {}", rule_name);
            }
        };

        info!("Hunt completed: {} matches found", matches.len());
        Ok(matches)
    }

    pub async fn run_all_hunts(&self) -> Result<Vec<HuntMatch>> {
        let mut all_matches = Vec::new();

        all_matches.extend(self.hunt_suspicious_powershell().await?);
        all_matches.extend(self.hunt_lolbins().await?);
        all_matches.extend(self.hunt_suspicious_parent_child().await?);

        Ok(all_matches)
    }

    pub async fn check_event(&self, event: &ProcessEvent) -> Result<Vec<HuntMatch>> {
        let mut matches = Vec::new();

        // Check suspicious PowerShell
        if let Some(hunt_match) = rules::check_suspicious_powershell(event) {
            let hunt_match_with_id = self.store_hunt_match(&hunt_match).await?;
            matches.push(hunt_match_with_id);
        }

        // Check LOLBins
        if let Some(hunt_match) = rules::check_lolbins(event) {
            let hunt_match_with_id = self.store_hunt_match(&hunt_match).await?;
            matches.push(hunt_match_with_id);
        }

        Ok(matches)
    }

    async fn hunt_suspicious_powershell(&self) -> Result<Vec<HuntMatch>> {
        let since = Utc::now() - chrono::Duration::hours(24 * 7); // Last week
        let events = self.db.get_process_events_since(since).await?;

        let mut matches = Vec::new();

        for event in events {
            if let Some(hunt_match) = rules::check_suspicious_powershell(&event) {
                let hunt_match_with_id = self.store_hunt_match(&hunt_match).await?;
                matches.push(hunt_match_with_id);
            }
        }

        Ok(matches)
    }

    async fn hunt_lolbins(&self) -> Result<Vec<HuntMatch>> {
        let since = Utc::now() - chrono::Duration::hours(24 * 7); // Last week
        let events = self.db.get_process_events_since(since).await?;

        let mut matches = Vec::new();

        for event in events {
            if let Some(hunt_match) = rules::check_lolbins(&event) {
                let hunt_match_with_id = self.store_hunt_match(&hunt_match).await?;
                matches.push(hunt_match_with_id);
            }
        }

        Ok(matches)
    }

    async fn hunt_suspicious_parent_child(&self) -> Result<Vec<HuntMatch>> {
        let since = Utc::now() - chrono::Duration::hours(24 * 7); // Last week
        let events = self.db.get_process_events_since(since).await?;

        let mut matches = Vec::new();

        for event in &events {
            // Find parent process
            if let Some(parent) = events.iter().find(|e| {
                if let Some(pid) = e.id {
                    pid as u32 == event.parent_pid
                } else {
                    false
                }
            }) {
                if let Some(hunt_match) = rules::check_suspicious_parent_child(parent, event) {
                    let hunt_match_with_id = self.store_hunt_match(&hunt_match).await?;
                    matches.push(hunt_match_with_id);
                }
            }
        }

        Ok(matches)
    }

    async fn store_hunt_match(&self, hunt_match: &HuntMatch) -> Result<HuntMatch> {
        let id = self.db.insert_hunt_match(hunt_match).await?;
        debug!("Stored hunt match: {} (ID: {})", hunt_match.rule_name, id);

        let mut match_with_id = hunt_match.clone();
        match_with_id.id = Some(id);

        Ok(match_with_id)
    }
}
