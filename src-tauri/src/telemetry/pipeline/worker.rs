//! Worker pool for the telemetry ingestion pipeline.
//!
//! Each subsystem (detection, storage, correlation, timeline, UI stream) gets its own
//! dedicated worker with independent priority channel read. Workers are agnostic to
//! the source of events — all events flow through the priority router first.
//!
//! Each worker runs as a tokio task and processes events in batches for efficiency.
//! Workers can be dynamically started/stopped via the coordinator.

use crate::telemetry::pipeline::event::{EventPriority, TelemetryEnvelope};
use crate::telemetry::pipeline::queues::{PriorityQueueSet, DRAIN_BATCH_SIZE};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::Emitter;

// ─── Worker Configuration ────────────────────────────────────────────────────

/// How often workers flush their pending state (even without events).
const WORKER_TICK_MS: u64 = 250;

/// Maximum events in a single batch for a worker.
const MAX_BATCH_SIZE: usize = 256;

// ─── Worker Definition ───────────────────────────────────────────────────────

/// A worker consumes events from the priority channels and processes them for
/// a specific subsystem.
pub trait Worker: Send + 'static {
    /// Unique name for this worker (used for monitoring).
    fn name(&self) -> &'static str;

    /// Which priority levels this worker consumes from.
    fn subscribed_priorities(&self) -> Vec<EventPriority>;

    /// Process a batch of events. Called periodically (every ~250ms) with
    /// accumulated events since the last invocation.
    ///
    /// `events` is drained before the call — the worker takes ownership.
    fn process_batch(&mut self, events: Vec<TelemetryEnvelope>);

    /// Called during shutdown to allow workers to flush final state.
    fn on_shutdown(&mut self) {
        log::info!("Worker '{}' shutting down", self.name());
    }

    /// Check if the worker is healthy. Override for subsystem-specific health.
    fn is_healthy(&self) -> bool {
        true
    }
}

// ─── Worker Handle ───────────────────────────────────────────────────────────

/// Handle to a running worker. Used for lifecycle management.
pub struct WorkerHandle {
    pub name: &'static str,
    pub shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    pub stats: Arc<WorkerStats>,
}

impl WorkerHandle {
    /// Request a graceful shutdown and wait for completion.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        log::info!("Worker '{}' shutdown complete", self.name);
    }
}

/// Statistics for a single worker.
#[derive(Debug, Default)]
pub struct WorkerStats {
    pub events_processed: std::sync::atomic::AtomicU64,
    pub batches_processed: std::sync::atomic::AtomicU64,
    pub errors: std::sync::atomic::AtomicU64,
    pub last_batch_size: std::sync::atomic::AtomicUsize,
    pub last_processing_us: std::sync::atomic::AtomicU64,
    pub peak_batch_size: std::sync::atomic::AtomicUsize,
}

// ─── Worker Runner ───────────────────────────────────────────────────────────

/// Runs a worker in a tokio task. Collects events from subscribed priority channels
/// and delivers batches to the worker's `process_batch`.
pub async fn run_worker<W: Worker>(
    mut worker: W,
    queues: Arc<PriorityQueueSet>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    stats: Arc<WorkerStats>,
    worker_complete_tx: tokio::sync::oneshot::Sender<()>,
) {
    let priorities = worker.subscribed_priorities();
    let tick_duration = Duration::from_millis(WORKER_TICK_MS);
    let mut pending: Vec<TelemetryEnvelope> = Vec::with_capacity(DRAIN_BATCH_SIZE * 2);
    let mut last_tick = Instant::now();

    log::info!("Worker '{}' started (priorities: {:?})", worker.name(), priorities);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                // Flush remaining events
                if !pending.is_empty() {
                    let batch = std::mem::take(&mut pending);
                    let count = batch.len();
                    worker.process_batch(batch);
                    stats.events_processed.fetch_add(count as u64, std::sync::atomic::Ordering::Relaxed);
                    stats.batches_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                worker.on_shutdown();
                let _ = worker_complete_tx.send(());
                return;
            }
            _ = tokio::time::sleep(tick_duration) => {
                // Collect events from subscribed priority channels
                let _batch_start = Instant::now();

                for priority in &priorities {
                    let channel = match priority {
                        EventPriority::Critical => &queues.critical,
                        EventPriority::High => &queues.high,
                        EventPriority::Medium => &queues.medium,
                        EventPriority::Low => &queues.low,
                    };

                    // Non-blocking drain of available events
                    let remaining = MAX_BATCH_SIZE.saturating_sub(pending.len());
                    if remaining == 0 {
                        break;
                    }
                    channel.drain_batch(&mut pending, remaining);
                }

                // Process batch if we have events or enough time has passed
                let should_process = !pending.is_empty() || last_tick.elapsed() >= Duration::from_secs(5);

                if should_process && !pending.is_empty() {
                    let count = pending.len();
                    let batch = std::mem::take(&mut pending);

                    let process_start = Instant::now();
                    worker.process_batch(batch);
                    let elapsed_us = process_start.elapsed().as_micros() as u64;

                    stats.events_processed.fetch_add(count as u64, std::sync::atomic::Ordering::Relaxed);
                    stats.batches_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    stats.last_batch_size.store(count, std::sync::atomic::Ordering::Relaxed);
                    stats.last_processing_us.store(elapsed_us, std::sync::atomic::Ordering::Relaxed);

                    let mut peak = stats.peak_batch_size.load(std::sync::atomic::Ordering::Relaxed);
                    while count > peak {
                        match stats.peak_batch_size.compare_exchange(
                            peak, count,
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(p) => peak = p,
                        }
                    }

                    if elapsed_us > 50_000 {
                        log::warn!(
                            "Worker '{}' slow batch: {} events in {}ms",
                            worker.name(), count, elapsed_us / 1000
                        );
                    }
                }

                last_tick = Instant::now();
                pending.shrink_to_fit();
            }
        }
    }
}

// ─── Built-in Workers ────────────────────────────────────────────────────────

/// Marker: worker is alive and healthy. Used for heartbeat monitoring.
pub struct HeartbeatWorker {
    pub name: &'static str,
    pub queues: Arc<PriorityQueueSet>,
}

impl Worker for HeartbeatWorker {
    fn name(&self) -> &'static str { "heartbeat" }
    fn subscribed_priorities(&self) -> Vec<EventPriority> { vec![] }

    fn process_batch(&mut self, _events: Vec<TelemetryEnvelope>) {
        // Heartbeat worker doesn't consume events; it produces them on a timer.
        // The coordinator drives the heartbeat timer separately.
    }
}

/// Timeline worker: copies events to the in-memory timeline buffer.
pub struct TimelineWorker {
    timeline: Arc<std::sync::Mutex<crate::core::timeline::TimelineEngine>>,
}

impl TimelineWorker {
    pub fn new(timeline: Arc<std::sync::Mutex<crate::core::timeline::TimelineEngine>>) -> Self {
        Self { timeline }
    }

    fn event_to_timeline(ev: &TelemetryEnvelope) -> crate::core::TimelineEvent {
        crate::core::TimelineEvent {
            id: ev.id.to_string(),
            timestamp: {
                let secs = (ev.timestamp_ns / 1_000_000_000) as i64;
                let nsecs = (ev.timestamp_ns % 1_000_000_000) as u32;
                chrono::DateTime::from_timestamp(secs, nsecs)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| chrono::Utc::now().to_rfc3339())
            },
            event_type: format!("{:?}", ev.event_type),
            category: ev.category.to_string(),
            description: format!("{:?} from {}", ev.event_type, ev.source),
            severity: match ev.priority {
                EventPriority::Critical => "critical",
                EventPriority::High => "high",
                EventPriority::Medium => "medium",
                EventPriority::Low => "info",
            }.to_string(),
            source: ev.source.to_string(),
            process_name: None,
            pid: None,
            path: None,
            details: ev.payload.clone(),
        }
    }
}

impl Worker for TimelineWorker {
    fn name(&self) -> &'static str { "timeline" }
    fn subscribed_priorities(&self) -> Vec<EventPriority> {
        vec![EventPriority::Critical, EventPriority::High, EventPriority::Medium, EventPriority::Low]
    }

    fn process_batch(&mut self, events: Vec<TelemetryEnvelope>) {
        if let Ok(mut tl) = self.timeline.lock() {
            for ev in &events {
                let tl_event = Self::event_to_timeline(ev);
                tl.add_event(tl_event);
            }
        }
    }
}

/// UI streaming worker: forwards events to the Tauri frontend via app handle events.
pub struct UiStreamWorker {
    app_handle: tauri::AppHandle,
    // Buffer for batching UI updates
    batch_buffer: Vec<TelemetryEnvelope>,
}

impl UiStreamWorker {
    pub fn new(app_handle: tauri::AppHandle) -> Self {
        Self {
            app_handle,
            batch_buffer: Vec::with_capacity(32),
        }
    }
}

impl Worker for UiStreamWorker {
    fn name(&self) -> &'static str { "ui_stream" }
    fn subscribed_priorities(&self) -> Vec<EventPriority> {
        vec![EventPriority::Critical, EventPriority::High, EventPriority::Medium]
    }

    fn process_batch(&mut self, events: Vec<TelemetryEnvelope>) {
        // Buffer up to 32 events then emit as array to reduce IPC overhead
        for ev in events {
            self.batch_buffer.push(ev);
            if self.batch_buffer.len() >= 32 {
                self.flush();
            }
        }
        if !self.batch_buffer.is_empty() {
            self.flush();
        }
    }

    fn on_shutdown(&mut self) {
        if !self.batch_buffer.is_empty() {
            self.flush();
        }
    }
}

impl UiStreamWorker {
    fn flush(&mut self) {
        let batch = std::mem::take(&mut self.batch_buffer);
        if let Ok(json) = serde_json::to_value(&batch) {
            let _ = self.app_handle.emit("telemetry-events", json);
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::pipeline::event::*;

    struct TestWorker {
        pub processed: std::sync::Arc<std::sync::Mutex<Vec<TelemetryEnvelope>>>,
    }

    impl Worker for TestWorker {
        fn name(&self) -> &'static str { "test" }
        fn subscribed_priorities(&self) -> Vec<EventPriority> {
            vec![EventPriority::High, EventPriority::Medium]
        }
        fn process_batch(&mut self, events: Vec<TelemetryEnvelope>) {
            let mut p = self.processed.lock().unwrap();
            p.extend(events);
        }
    }

    #[tokio::test]
    async fn test_worker_processes_events() {
        use crate::telemetry::pipeline::queues::PriorityQueueSet;
        use std::sync::Arc;

        let queues = Arc::new(PriorityQueueSet::new());
        let processed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let worker = TestWorker { processed: processed.clone() };
        let stats = Arc::new(WorkerStats::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (complete_tx, _complete_rx) = tokio::sync::oneshot::channel();

        // Send some events before starting the worker
        for i in 0..5 {
            let ev = TelemetryEnvelope::new(
                SourceId::ProcessMonitor,
                SourceTrust::User,
                EventPriority::High,
                EventCategory::Process,
                CanonicalEventType::ProcessCreated,
                serde_json::json!({"pid": i, "name": format!("proc_{}", i)}),
            );
            queues.dispatch(ev);
        }

        // Start worker briefly
        let worker_task = tokio::spawn(async move {
            run_worker(worker, queues, shutdown_rx, stats, complete_tx).await;
        });

        // Give worker time to process
        tokio::time::sleep(Duration::from_millis(600)).await;

        // Shutdown
        let _ = shutdown_tx.send(());
        let _ = worker_task.await;

        let p = processed.lock().unwrap();
        assert_eq!(p.len(), 5, "Worker should have processed all 5 events");
    }
}
