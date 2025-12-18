pub mod migrations;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub parent_pid: u32,
    pub image_path: String,
    pub command_line: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEvent {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub persistence_type: String, // "registry" or "filesystem"
    pub location: String,
    pub value_name: Option<String>,
    pub value_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntMatch {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub rule_name: String,
    pub event_type: String,
    pub event_id: i64,
    pub description: String,
}

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;
        migrations::run_migrations(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn insert_process_event(&self, event: &ProcessEvent) -> Result<i64> {
        let id = sqlx::query(
            r#"
            INSERT INTO process_events (timestamp, pid, parent_pid, image_path, command_line, username)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&event.timestamp)
        .bind(event.pid)
        .bind(event.parent_pid)
        .bind(&event.image_path)
        .bind(&event.command_line)
        .bind(&event.username)
        .execute(&self.pool)
        .await?
        .last_insert_rowid();

        Ok(id)
    }

    pub async fn insert_network_event(&self, event: &NetworkEvent) -> Result<i64> {
        let id = sqlx::query(
            r#"
            INSERT INTO network_events (timestamp, pid, local_addr, local_port, remote_addr, remote_port, protocol, state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&event.timestamp)
        .bind(event.pid)
        .bind(&event.local_addr)
        .bind(event.local_port)
        .bind(&event.remote_addr)
        .bind(event.remote_port)
        .bind(&event.protocol)
        .bind(&event.state)
        .execute(&self.pool)
        .await?
        .last_insert_rowid();

        Ok(id)
    }

    pub async fn insert_persistence_event(&self, event: &PersistenceEvent) -> Result<i64> {
        let id = sqlx::query(
            r#"
            INSERT INTO persistence_events (timestamp, persistence_type, location, value_name, value_data)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&event.timestamp)
        .bind(&event.persistence_type)
        .bind(&event.location)
        .bind(&event.value_name)
        .bind(&event.value_data)
        .execute(&self.pool)
        .await?
        .last_insert_rowid();

        Ok(id)
    }

    pub async fn insert_hunt_match(&self, hunt_match: &HuntMatch) -> Result<i64> {
        let id = sqlx::query(
            r#"
            INSERT INTO hunt_matches (timestamp, rule_name, event_type, event_id, description)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&hunt_match.timestamp)
        .bind(&hunt_match.rule_name)
        .bind(&hunt_match.event_type)
        .bind(hunt_match.event_id)
        .bind(&hunt_match.description)
        .execute(&self.pool)
        .await?
        .last_insert_rowid();

        Ok(id)
    }

    pub async fn get_process_events_since(&self, since: DateTime<Utc>) -> Result<Vec<ProcessEvent>> {
        let events = sqlx::query(
            r#"
            SELECT id, timestamp, pid, parent_pid, image_path, command_line, username
            FROM process_events
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            "#,
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| ProcessEvent {
            id: Some(row.get(0)),
            timestamp: row.get(1),
            pid: row.get::<i64, _>(2) as u32,
            parent_pid: row.get::<i64, _>(3) as u32,
            image_path: row.get(4),
            command_line: row.get(5),
            username: row.get(6),
        })
        .collect();

        Ok(events)
    }

    pub async fn get_network_events_since(&self, since: DateTime<Utc>) -> Result<Vec<NetworkEvent>> {
        let events = sqlx::query(
            r#"
            SELECT id, timestamp, pid, local_addr, local_port, remote_addr, remote_port, protocol, state
            FROM network_events
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            "#,
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| NetworkEvent {
            id: Some(row.get(0)),
            timestamp: row.get(1),
            pid: row.get::<i64, _>(2) as u32,
            local_addr: row.get(3),
            local_port: row.get::<i64, _>(4) as u16,
            remote_addr: row.get(5),
            remote_port: row.get::<i64, _>(6) as u16,
            protocol: row.get(7),
            state: row.get(8),
        })
        .collect();

        Ok(events)
    }

    pub async fn get_persistence_events_since(&self, since: DateTime<Utc>) -> Result<Vec<PersistenceEvent>> {
        let events = sqlx::query(
            r#"
            SELECT id, timestamp, persistence_type, location, value_name, value_data
            FROM persistence_events
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            "#,
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| PersistenceEvent {
            id: Some(row.get(0)),
            timestamp: row.get(1),
            persistence_type: row.get(2),
            location: row.get(3),
            value_name: row.get(4),
            value_data: row.get(5),
        })
        .collect();

        Ok(events)
    }

    pub async fn get_hunt_matches_since(&self, since: DateTime<Utc>) -> Result<Vec<HuntMatch>> {
        let matches = sqlx::query(
            r#"
            SELECT id, timestamp, rule_name, event_type, event_id, description
            FROM hunt_matches
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            "#,
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| HuntMatch {
            id: Some(row.get(0)),
            timestamp: row.get(1),
            rule_name: row.get(2),
            event_type: row.get(3),
            event_id: row.get(4),
            description: row.get(5),
        })
        .collect();

        Ok(matches)
    }

    pub async fn count_events(&self) -> Result<(i64, i64, i64, i64)> {
        let process_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM process_events")
            .fetch_one(&self.pool)
            .await?;

        let network_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM network_events")
            .fetch_one(&self.pool)
            .await?;

        let persistence_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM persistence_events")
            .fetch_one(&self.pool)
            .await?;

        let hunt_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hunt_matches")
            .fetch_one(&self.pool)
            .await?;

        Ok((process_count, network_count, persistence_count, hunt_count))
    }
}
