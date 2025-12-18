pub mod network;
pub mod persistence;
pub mod process;

use crate::config::Config;
use crate::database::Database;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Clone)]
pub enum CollectorEvent {
    Process(crate::database::ProcessEvent),
    Network(crate::database::NetworkEvent),
    Persistence(crate::database::PersistenceEvent),
    Shutdown,
}

pub struct CollectorManager {
    config: Config,
    db: Arc<Database>,
    event_tx: broadcast::Sender<CollectorEvent>,
}

impl CollectorManager {
    pub fn new(config: Config, db: Arc<Database>) -> (Self, broadcast::Receiver<CollectorEvent>) {
        let (event_tx, event_rx) = broadcast::channel(1000);

        (
            Self {
                config,
                db,
                event_tx,
            },
            event_rx,
        )
    }

    pub async fn start(&self, shutdown_rx: tokio::sync::broadcast::Receiver<()>) -> Result<()> {
        let mut handles = vec![];

        // Start process collector
        if self.config.collectors.process.enabled {
            let handle = tokio::spawn({
                let config = self.config.clone();
                let db = Arc::clone(&self.db);
                let event_tx = self.event_tx.clone();
                let mut shutdown = shutdown_rx.resubscribe();

                async move {
                    process::ProcessCollector::new(config, db, event_tx)
                        .run(&mut shutdown)
                        .await
                }
            });
            handles.push(handle);
        }

        // Start network collector
        if self.config.collectors.network.enabled {
            let handle = tokio::spawn({
                let config = self.config.clone();
                let db = Arc::clone(&self.db);
                let event_tx = self.event_tx.clone();
                let mut shutdown = shutdown_rx.resubscribe();

                async move {
                    network::NetworkCollector::new(config, db, event_tx)
                        .run(&mut shutdown)
                        .await
                }
            });
            handles.push(handle);
        }

        // Start persistence collector
        if self.config.collectors.persistence.enabled {
            let handle = tokio::spawn({
                let config = self.config.clone();
                let db = Arc::clone(&self.db);
                let event_tx = self.event_tx.clone();
                let mut shutdown = shutdown_rx.resubscribe();

                async move {
                    persistence::PersistenceCollector::new(config, db, event_tx)
                        .run(&mut shutdown)
                        .await
                }
            });
            handles.push(handle);
        }

        // Wait for all collectors to finish
        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CollectorEvent> {
        self.event_tx.subscribe()
    }
}
