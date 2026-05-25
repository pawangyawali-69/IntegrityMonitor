//! Ingestion pipeline coordinator — lifecycle management for all pipeline components.
//!
//! The coordinator:
//! - Creates the priority queue set
//! - Creates and manages the event router
//! - Creates the replay journal for crash recovery
//! - Starts/stops the worker pool
//! - Manages source adapter registration
//! - Provides health monitoring and metrics
//! - Handles graceful shutdown with event drain

use crate::telemetry::pipeline::event::{
    CanonicalEventType, EventCategory, EventPriority, SourceId, SourceTrust, TelemetryEnvelope,
};
use crate::telemetry::pipeline::journal::ReplayJournal;
use crate::telemetry::pipeline::queues::PriorityQueueSet;
use crate::telemetry::pipeline::router::{EventRouter, RoutingDecision};
use crate::telemetry::pipeline::worker::{
    run_worker, WorkerHandle, WorkerStats, TimelineWorker, UiStreamWorker,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

// ─── Coordinator ─────────────────────────────────────────────────────────────

/// Central coordinator for the telemetry ingestion pipeline.
///
/// Manages lifecycle, health, and metrics for all pipeline components.
/// Call `start()` after construction to begin processing.
pub struct IngestionCoordinator {
    /// Priority queue set (shared with workers and router)
    pub queues: Arc<PriorityQueueSet>,
    /// Event router (stateless, shared)
    pub router: Arc<EventRouter>,
    /// Replay journal for crash recovery
    pub journal: ReplayJournal,
    /// Worker handles for lifecycle management
    workers: Vec<WorkerHandle>,
    /// Application data directory
    data_dir: PathBuf,
    /// Whether the coordinator is running
    running: Arc<AtomicBool>,
    /// Shutdown signal for internal timer tasks
    shutdown_signals: Vec<oneshot::Sender<()>>,
}

impl IngestionCoordinator {
    /// Create a new ingestion coordinator with journal at the given data directory.
    pub fn new(data_dir: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let journal_path = data_dir.join("pipeline.journal");
        let journal = ReplayJournal::open(&journal_path)?;

        // Replay any events from previous crash
        let replayed = journal.replay()?;
        if !replayed.is_empty() {
            log::info!("Pipeline: replayed {} events from crash journal", replayed.len());
        }

        let queues = Arc::new(PriorityQueueSet::new());
        let router = Arc::new(EventRouter::new(queues.clone()));

        // Re-route replayed events
        if !replayed.is_empty() {
            for event in replayed {
                router.route(event);
            }
        }

        Ok(Self {
            queues,
            router,
            journal,
            workers: Vec::new(),
            data_dir,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_signals: Vec::new(),
        })
    }

    /// Start all workers. Returns handles for lifecycle management.
    pub fn start(
        &mut self,
        app_handle: tauri::AppHandle,
        timeline: Arc<std::sync::Mutex<crate::core::timeline::TimelineEngine>>,
    ) {
        self.running.store(true, Ordering::Relaxed);
        let queues = self.queues.clone();

        // ── Timeline Worker ────────────────────────────────────────────────
        let (tl_shutdown_tx, tl_shutdown_rx) = oneshot::channel();
        let tl_stats = Arc::new(WorkerStats::default());
        let tl_complete_tx = {
            let (tx, _rx) = oneshot::channel();
            tx
        };
        let tl_worker = TimelineWorker::new(timeline);

        let queues_clone = queues.clone();
        let tl_stats_clone = tl_stats.clone();
        tokio::spawn(async move {
            run_worker(tl_worker, queues_clone, tl_shutdown_rx, tl_stats_clone, tl_complete_tx).await;
        });

        self.workers.push(WorkerHandle {
            name: "timeline",
            shutdown_tx: Some(tl_shutdown_tx),
            stats: tl_stats,
        });

        // ── UI Stream Worker ───────────────────────────────────────────────
        let (ui_shutdown_tx, ui_shutdown_rx) = oneshot::channel();
        let ui_stats = Arc::new(WorkerStats::default());
        let ui_complete_tx = {
            let (tx, _rx) = oneshot::channel();
            tx
        };
        let ui_worker = UiStreamWorker::new(app_handle);

        let queues_clone = queues.clone();
        let ui_stats_clone = ui_stats.clone();
        tokio::spawn(async move {
            run_worker(ui_worker, queues_clone, ui_shutdown_rx, ui_stats_clone, ui_complete_tx).await;
        });

        self.workers.push(WorkerHandle {
            name: "ui_stream",
            shutdown_tx: Some(ui_shutdown_tx),
            stats: ui_stats,
        });

        // ── Heartbeat Producer ─────────────────────────────────────────────
        let (hb_shutdown_tx, mut hb_shutdown_rx) = oneshot::channel();
        let hb_queues = queues.clone();
        let hb_running = self.running.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut hb_shutdown_rx => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        if !hb_running.load(Ordering::Relaxed) {
                            break;
                        }
                        let envelope = TelemetryEnvelope::new(
                            SourceId::DetectionEngine,
                            SourceTrust::Kernel,
                            EventPriority::Low,
                            EventCategory::Heartbeat,
                            CanonicalEventType::Heartbeat,
                            serde_json::json!({
                                "uptime_secs": std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            }),
                        );
                        hb_queues.dispatch(envelope);
                    }
                }
            }
            log::info!("Heartbeat producer stopped");
        });

        self.shutdown_signals.push(hb_shutdown_tx);

        log::info!("Ingestion coordinator started with {} workers", self.workers.len());
    }

    /// Emit an event into the pipeline. This is the primary entry point for all
    /// telemetry sources (ETW, kernel driver, file monitor, etc.).
    ///
    /// The event is:
    /// 1. Written to the replay journal (crash recovery)
    /// 2. Routed to the appropriate priority queue
    ///
    /// Returns the routing decision.
    pub fn emit(&self, envelope: TelemetryEnvelope) -> RoutingDecision {
        // Step 1: Journal for crash recovery (best-effort, don't block on journal error)
        if let Err(e) = self.journal.append(&envelope) {
            log::warn!("Failed to journal event: {}", e);
        }

        // Step 2: Route to priority queue
        self.router.route(envelope)
    }

    /// Emit a batch of events. More efficient than emit() in a loop.
    pub fn emit_batch(&self, events: Vec<TelemetryEnvelope>) -> RoutingStats {
        let total = events.len();
        let mut journaled = 0usize;
        let mut delivered = 0usize;
        let mut shed = 0usize;
        let mut filtered = 0usize;

        for event in events {
            if self.journal.append(&event).is_ok() {
                journaled += 1;
            }
            match self.router.route(event) {
                RoutingDecision::Delivered => delivered += 1,
                RoutingDecision::Shed => shed += 1,
                RoutingDecision::Filtered => filtered += 1,
                RoutingDecision::Rejected => filtered += 1,
            }
        }

        RoutingStats { total, journaled, delivered, shed, filtered }
    }

    /// Graceful shutdown. Drains remaining events and stops all workers.
    pub async fn shutdown(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        log::info!("Coordinator shutting down...");

        // Stop all worker tasks
        for handle in self.workers.drain(..) {
            let name = handle.name;
            if let Err(e) = tokio::time::timeout(
                Duration::from_secs(5),
                handle.shutdown(),
            ).await {
                log::warn!("Worker '{name}' did not shut down cleanly: {e:?}");
            }
        }

        // Send shutdown to internal timers
        for tx in self.shutdown_signals.drain(..) {
            let _ = tx.send(());
        }

        // Flush journal
        if let Err(e) = self.journal.checkpoint() {
            log::warn!("Journal checkpoint during shutdown failed: {}", e);
        }

        log::info!(
            "Coordinator shutdown complete. Pipeline metrics: {:?}",
            self.queues.metrics_snapshot()
        );
    }

    /// Current pipeline health summary.
    pub fn health(&self) -> PipelineHealth {
        let snapshot = self.queues.metrics_snapshot();
        PipelineHealth {
            running: self.running.load(Ordering::Relaxed),
            workers: self.workers.len(),
            total_received: snapshot.received,
            total_dropped: snapshot.dropped,
            total_backpressured: snapshot.backpressured,
            queue_depth: self.queues.total_depth() as u64,
            overloaded: self.queues.is_overloaded(),
            journal_size: self.journal.size(),
            journal_records: self.journal.record_count(),
        }
    }
}

// ─── Supporting Types ────────────────────────────────────────────────────────

/// Statistics from a batch emit operation.
#[derive(Debug, Clone, Copy)]
pub struct RoutingStats {
    pub total: usize,
    pub journaled: usize,
    pub delivered: usize,
    pub shed: usize,
    pub filtered: usize,
}

/// Snapshot of pipeline health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineHealth {
    pub running: bool,
    pub workers: usize,
    pub total_received: u64,
    pub total_dropped: u64,
    pub total_backpressured: u64,
    pub queue_depth: u64,
    pub overloaded: bool,
    pub journal_size: u64,
    pub journal_records: u64,
}

// ─── Source Adapter Trait ────────────────────────────────────────────────────

/// A source adapter converts external telemetry (ETW, kernel driver, etc.) into
/// canonical `TelemetryEnvelope` events and feeds them into the pipeline.
///
/// Each adapter runs as its own tokio task and communicates with the coordinator
/// through the shared router or a direct channel.
pub trait SourceAdapter: Send + 'static {
    /// Name of this source (for logging and metrics).
    fn name(&self) -> &'static str;

    /// Return the source ID used to tag events from this adapter.
    fn source_id(&self) -> SourceId;

    /// Return the trust level of this source.
    fn trust(&self) -> SourceTrust;

    /// Start producing events. The adapter should call `coordinator.emit()` for each event.
    /// The `shutdown_rx` signal is used to stop the adapter.
    fn run(
        self: Box<Self>,
        coordinator: Arc<IngestionCoordinator>,
        shutdown_rx: oneshot::Receiver<()>,
    );
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::pipeline::event::*;
    use std::sync::Mutex;

    #[test]
    fn test_coordinator_emit_and_route() {
        let dir = std::env::temp_dir().join(format!("im_coord_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let mut coord = IngestionCoordinator::new(dir.clone()).unwrap();

        let ev = TelemetryEnvelope::new(
            SourceId::ProcessMonitor,
            SourceTrust::Kernel,
            EventPriority::Critical,
            EventCategory::Kernel,
            CanonicalEventType::KernelEvent,
            serde_json::json!({"type": "test"}),
        );

        let decision = coord.emit(ev);
        assert_eq!(decision, RoutingDecision::Delivered);
        assert!(coord.queues.critical.len() > 0);

        // Verify journal was written
        assert!(coord.journal.size() > 8);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_coordinator_batch_emit() {
        let dir = std::env::temp_dir().join(format!("im_coord_batch_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let coord = IngestionCoordinator::new(dir.clone()).unwrap();

        let events: Vec<_> = (0..10).map(|i| {
            TelemetryEnvelope::new(
                SourceId::AntiCheatMonitor,
                SourceTrust::User,
                EventPriority::Medium,
                EventCategory::Process,
                CanonicalEventType::ProcessCreated,
                serde_json::json!({"pid": i}),
            )
        }).collect();

        let stats = coord.emit_batch(events);
        assert_eq!(stats.total, 10);
        assert_eq!(stats.journaled, 10);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_crash_replay() {
        let dir = std::env::temp_dir().join(format!("im_crash_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let journal_path = dir.join("pipeline.journal");

        // First "session": emit events then "crash" (drop without cleanup)
        {
            let journal = ReplayJournal::open(&journal_path).unwrap();
            for _ in 0..5 {
                let ev = TelemetryEnvelope::new(
                    SourceId::ProcessMonitor,
                    SourceTrust::User,
                    EventPriority::Medium,
                    EventCategory::Process,
                    CanonicalEventType::ProcessCreated,
                    serde_json::json!({"pid": 1}),
                );
                journal.append(&ev).unwrap();
            }
            // No checkpoint — simulates crash
        }

        // Second "session": coordinator replays events from journal
        {
            let coord = IngestionCoordinator::new(dir.clone()).unwrap();
            // Journal should be empty after replay
            assert_eq!(coord.journal.record_count(), 0);
            // Events should be in the queues
            assert_eq!(coord.queues.total_depth(), 5);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
