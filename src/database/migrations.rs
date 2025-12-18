use anyhow::Result;
use sqlx::SqlitePool;
use tracing::info;

pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    info!("Running database migrations...");

    // Create process_events table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS process_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pid INTEGER NOT NULL,
            parent_pid INTEGER NOT NULL,
            image_path TEXT NOT NULL,
            command_line TEXT NOT NULL,
            username TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create network_events table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pid INTEGER NOT NULL,
            local_addr TEXT NOT NULL,
            local_port INTEGER NOT NULL,
            remote_addr TEXT NOT NULL,
            remote_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create persistence_events table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS persistence_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            persistence_type TEXT NOT NULL,
            location TEXT NOT NULL,
            value_name TEXT,
            value_data TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create hunt_matches table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS hunt_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            event_type TEXT NOT NULL,
            event_id INTEGER NOT NULL,
            description TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indices for better query performance
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_process_timestamp ON process_events(timestamp)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_process_pid ON process_events(pid)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_events(timestamp)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_network_pid ON network_events(pid)")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_persistence_timestamp ON persistence_events(timestamp)",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunt_timestamp ON hunt_matches(timestamp)")
        .execute(pool)
        .await?;

    info!("Database migrations completed successfully");
    Ok(())
}
