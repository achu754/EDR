use anyhow::Result;
use clap::Parser;
use edr_agent::cli::{self, Cli, Commands};
use edr_agent::config;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize tracing based on config
    let config = config::Config::load(&cli.config)?;
    init_tracing(&config);

    info!("EDR Agent starting...");

    // Execute command
    match cli.command {
        Commands::Start => {
            cli::start_agent(config).await?;
        }
        Commands::Status => {
            cli::show_status(config).await?;
        }
        Commands::Export { since, format } => {
            cli::export_events(config, since, format).await?;
        }
        Commands::Hunt { rule } => {
            cli::run_hunt(config, rule).await?;
        }
    }

    Ok(())
}

fn init_tracing(config: &config::Config) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("edr_agent={}", config.log_level))
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
