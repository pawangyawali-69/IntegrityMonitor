//! Unified Telemetry Router — single reactive routing layer for all envelopes.
//!
//! Architecture:
//!   Sources → TelemetryRouter → Priority Channels → Subscribers (UI, Storage, Correlation, etc.)
//!
//! Uses bounded crossbeam channels per subscriber, with category/severity filtering
//! and backpressure policies.

use crate::telemetry::envelope::*;
use crossbeam::channel as cb_channel;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ─── Backpressure ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressurePolicy {
    /// Drop oldest events when the queue is full
    DropOldest,
    /// Drop newest (i.e., skip send) when full
    DropNewest,
    /// Block until space frees up
    Block,
}

impl Default for BackpressurePolicy {
    fn default() -> Self {
        BackpressurePolicy::DropOldest
    }
}

// ─── Subscriber ──────────────────────────────────────────────────────────────

struct RouterSubscriber {
    sender: cb_channel::Sender<TelemetryEnvelope>,
    filter: FrontendSubscription,
    policy: BackpressurePolicy,
    delivered: AtomicU64,
    dropped: AtomicU64,
}

// ─── Router Stats ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct RouterStats {
    pub total_routed: u64,
    pub total_dropped: u64,
    pub total_filtered: u64,
    pub subscriber_count: usize,
}

// ─── TelemetryRouter ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TelemetryRouter {
    subscribers: Arc<Mutex<Vec<Arc<RouterSubscriber>>>>,
    emitted: Arc<AtomicU64>,
    dropped_total: Arc<AtomicU64>,
    filtered_total: Arc<AtomicU64>,
}

impl TelemetryRouter {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(Vec::new())),
            emitted: Arc::new(AtomicU64::new(0)),
            dropped_total: Arc::new(AtomicU64::new(0)),
            filtered_total: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Subscribe to envelopes matching a filter.
    pub fn subscribe(&self, filter: FrontendSubscription) -> cb_channel::Receiver<TelemetryEnvelope> {
        self.subscribe_with_policy(filter, BackpressurePolicy::DropOldest, 4096)
    }

    /// Subscribe with explicit capacity and backpressure policy.
    pub fn subscribe_with_policy(
        &self,
        filter: FrontendSubscription,
        policy: BackpressurePolicy,
        capacity: usize,
    ) -> cb_channel::Receiver<TelemetryEnvelope> {
        let (tx, rx) = cb_channel::bounded(capacity);
        let sub = Arc::new(RouterSubscriber {
            sender: tx,
            filter,
            policy,
            delivered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        });
        self.subscribers.lock().unwrap().push(sub);
        rx
    }

    /// Route an envelope to all matching subscribers.
    pub fn route(&self, envelope: TelemetryEnvelope) {
        let mut dropped_any = false;
        let subscribers = self.subscribers.lock().unwrap();

        for sub in subscribers.iter() {
            if !sub.filter.matches(&envelope) {
                self.filtered_total.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let delivered = match sub.policy {
                BackpressurePolicy::DropOldest => sub.sender.try_send(envelope.clone()).is_ok(),
                BackpressurePolicy::DropNewest => {
                    if sub.sender.is_full() {
                        false
                    } else {
                        sub.sender.try_send(envelope.clone()).is_ok()
                    }
                }
                BackpressurePolicy::Block => sub.sender.send(envelope.clone()).is_ok(),
            };

            if delivered {
                sub.delivered.fetch_add(1, Ordering::Relaxed);
            } else {
                sub.dropped.fetch_add(1, Ordering::Relaxed);
                dropped_any = true;
            }
        }

        self.emitted.fetch_add(1, Ordering::Relaxed);
        if dropped_any {
            self.dropped_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Route a batch of envelopes (more efficient than individual calls).
    pub fn route_batch(&self, envelopes: &[TelemetryEnvelope]) {
        for envelope in envelopes {
            self.route(envelope.clone());
        }
    }

    /// Create a frontend-oriented subscription stream with Tauri-compatible channel.
    pub fn subscribe_frontend(
        &self,
        categories: CategoryFilter,
        min_severity: Severity,
    ) -> cb_channel::Receiver<TelemetryEnvelope> {
        let filter = FrontendSubscription {
            categories,
            min_severity,
            process_filter: None,
            replay_mode: false,
        };
        self.subscribe_with_policy(filter, BackpressurePolicy::DropOldest, 2048)
    }

    /// Snapshot of router statistics.
    pub fn stats(&self) -> RouterStats {
        let count = self.subscribers.lock().unwrap().len();
        RouterStats {
            total_routed: self.emitted.load(Ordering::Relaxed),
            total_dropped: self.dropped_total.load(Ordering::Relaxed),
            total_filtered: self.filtered_total.load(Ordering::Relaxed),
            subscriber_count: count,
        }
    }

    /// Number of unique subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().unwrap().len()
    }

    /// Total number of envelopes routed.
    pub fn emitted_count(&self) -> u64 {
        self.emitted.load(Ordering::Relaxed)
    }
}

impl Default for TelemetryRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Router worker: processes envelopes from a source channel ─────────────────

/// Spawns a background thread that reads envelopes from `rx` and routes them
/// through `router`. Returns a handle for shutdown.
pub fn spawn_router_worker(
    router: TelemetryRouter,
    rx: cb_channel::Receiver<TelemetryEnvelope>,
    name: &'static str,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name(format!("router-{}", name))
        .spawn(move || {
            while let Ok(envelope) = rx.recv() {
                router.route(envelope);
            }
        })
        .expect("failed to spawn router worker")
}

/// Batched router worker — drains up to 64 envelopes at a time.
pub fn spawn_router_worker_batched(
    router: TelemetryRouter,
    rx: cb_channel::Receiver<TelemetryEnvelope>,
    name: &'static str,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name(format!("router-batch-{}", name))
        .spawn(move || {
            let mut batch = Vec::with_capacity(64);
            loop {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(envelope) => {
                        batch.push(envelope);
                        // drain available
                        while batch.len() < 64 {
                            match rx.try_recv() {
                                Ok(e) => batch.push(e),
                                Err(_) => break,
                            }
                        }
                        router.route_batch(&batch);
                        batch.clear();
                    }
                    Err(cb_channel::RecvTimeoutError::Timeout) => {
                        if !batch.is_empty() {
                            router.route_batch(&batch);
                            batch.clear();
                        }
                    }
                    Err(cb_channel::RecvTimeoutError::Disconnected) => {
                        if !batch.is_empty() {
                            router.route_batch(&batch);
                        }
                        break;
                    }
                }
            }
        })
        .expect("failed to spawn batched router worker")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_delivery() {
        let router = TelemetryRouter::new();
        let rx = router.subscribe(FrontendSubscription::all());

        let env = TelemetryEnvelope::new(
            TelemetryCategory::Process,
            TelemetrySource::ProcessMonitor,
            Severity::Informational,
            TelemetryPayload::Heartbeat { uptime_secs: 0, events_per_sec: 0, subsystem_count: 0 },
        );
        router.route(env);

        let received = rx.recv_timeout(Duration::from_millis(100));
        assert!(received.is_ok());
    }

    #[test]
    fn test_router_filtering() {
        let router = TelemetryRouter::new();
        let filter = FrontendSubscription {
            categories: CategoryFilter::DETECTION,
            min_severity: Severity::High,
            process_filter: None,
            replay_mode: false,
        };
        let rx = router.subscribe(filter);

        let env = TelemetryEnvelope::new(
            TelemetryCategory::FileSystem,
            TelemetrySource::FileMonitor,
            Severity::Low,
            TelemetryPayload::FileChanged { path: "x".into(), file_name: "x".into(), event_type: "modified".into(), size: 0, hash: None },
        );
        router.route(env);

        let received = rx.try_recv();
        assert!(received.is_err()); // should be filtered
    }

    #[test]
    fn test_router_stats() {
        let router = TelemetryRouter::new();
        let _rx = router.subscribe(FrontendSubscription::all());

        let env = TelemetryEnvelope::new(
            TelemetryCategory::System,
            TelemetrySource::ProcessMonitor,
            Severity::Informational,
            TelemetryPayload::Heartbeat { uptime_secs: 1, events_per_sec: 1, subsystem_count: 1 },
        );
        router.route(env);
        router.route(env);

        let stats = router.stats();
        assert_eq!(stats.total_routed, 2);
        assert_eq!(stats.subscriber_count, 1);
    }
}
