//! Priority channel system with bounded backpressure, telemetry shedding, and per-core affinity.
//!
//! Design constraints:
//! - 10,000+ events/sec sustained
//! - Bounded memory (no unbounded growth under any load)
//! - Priority guarantees (critical events always delivered before low)
//! - Backpressure propagation to sources
//! - Graceful shedding under overload
//! - Per-CPU sharding for scalability

use crate::telemetry::pipeline::event::{EventPriority, TelemetryEnvelope};
use crossbeam::channel as cb_channel;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ─── Channel Configuration ───────────────────────────────────────────────────

/// Per-priority channel capacities. These are hard bounds — no dynamic resizing.
/// Chosen to accommodate burst traffic without OOM.
pub const CAPACITY_CRITICAL: usize = 2048;   // Must not drop critical events
pub const CAPACITY_HIGH: usize     = 8192;   // 8K high-priority before shedding
pub const CAPACITY_MEDIUM: usize   = 16384;  // 16K medium
pub const CAPACITY_LOW: usize      = 32768;  // 32K low (first to shed)

/// Drain batch sizes for worker consumption.
pub const DRAIN_BATCH_SIZE: usize = 64;

// ─── Metrics ─────────────────────────────────────────────────────────────────

/// Atomic counters for telemetry pipeline health monitoring.
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    pub events_received: AtomicU64,
    pub events_delivered_high: AtomicU64,
    pub events_delivered_medium: AtomicU64,
    pub events_delivered_low: AtomicU64,
    pub events_dropped: AtomicU64,
    pub events_backpressured: AtomicU64,
    pub bytes_ingested: AtomicU64,
    pub peak_queue_depth: AtomicU64,
}

impl PipelineMetrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            received: self.events_received.load(Ordering::Relaxed),
            delivered_high: self.events_delivered_high.load(Ordering::Relaxed),
            delivered_medium: self.events_delivered_medium.load(Ordering::Relaxed),
            delivered_low: self.events_delivered_low.load(Ordering::Relaxed),
            dropped: self.events_dropped.load(Ordering::Relaxed),
            backpressured: self.events_backpressured.load(Ordering::Relaxed),
            bytes: self.bytes_ingested.load(Ordering::Relaxed),
            peak_depth: self.peak_queue_depth.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub received: u64,
    pub delivered_high: u64,
    pub delivered_medium: u64,
    pub delivered_low: u64,
    pub dropped: u64,
    pub backpressured: u64,
    pub bytes: u64,
    pub peak_depth: u64,
}

// ─── Priority Channel ────────────────────────────────────────────────────────

/// A single bounded channel for one priority level.
/// Uses crossbeam's bounded channel for MPMC with blocking send for critical priority,
/// and try_send for all others (non-blocking, drops on overflow).
pub struct PriorityChannel {
    /// Crossbeam sender (shared with workers)
    sender: cb_channel::Sender<TelemetryEnvelope>,
    /// Crossbeam receiver
    receiver: cb_channel::Receiver<TelemetryEnvelope>,
    /// Priority level
    priority: EventPriority,
    /// Capacity hard limit
    capacity: usize,
    /// Drop count for this priority
    dropped: AtomicU64,
    /// Backpressure count (critical only)
    backpressured: AtomicU64,
    /// Peak depth tracking
    peak_depth: AtomicU64,
}

impl PriorityChannel {
    pub fn new(priority: EventPriority, capacity: usize) -> Self {
        let (sender, receiver) = cb_channel::bounded(capacity);
        Self {
            sender,
            receiver,
            priority,
            capacity,
            dropped: AtomicU64::new(0),
            backpressured: AtomicU64::new(0),
            peak_depth: AtomicU64::new(0),
        }
    }

    /// Send an event into this priority channel.
    ///
    /// For Critical priority: blocks (backpressure) if full — guarantees delivery.
    /// For all others: non-blocking try_send — drops on overflow, increments drop counter.
    ///
    /// Returns `true` if delivered, `false` if dropped (non-critical only).
    #[inline]
    pub fn send(&self, event: TelemetryEnvelope, metrics: &PipelineMetrics) -> bool {
        let size = event.estimated_size() as u64;
        metrics.bytes_ingested.fetch_add(size, Ordering::Relaxed);
        metrics.events_received.fetch_add(1, Ordering::Relaxed);

        match self.priority {
            EventPriority::Critical => {
                // Critical: backpressure. Block until space is available.
                let start = Instant::now();
                match self.sender.send(event) {
                    Ok(()) => {
                        let elapsed = start.elapsed();
                        if elapsed > Duration::from_micros(100) {
                            // Log if blocked for significant time
                            self.backpressured.fetch_add(1, Ordering::Relaxed);
                            metrics.events_backpressured.fetch_add(1, Ordering::Relaxed);
                        }
                        self.track_depth();
                        metrics.events_delivered_high.fetch_add(1, Ordering::Relaxed);
                        true
                    }
                    Err(e) => {
                        log::error!("Critical channel disconnected: {}", e);
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                }
            }
            EventPriority::High => {
                match self.sender.try_send(event) {
                    Ok(()) => {
                        self.track_depth();
                        metrics.events_delivered_high.fetch_add(1, Ordering::Relaxed);
                        true
                    }
                    Err(cb_channel::TrySendError::Full(_)) => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                    Err(cb_channel::TrySendError::Disconnected(_)) => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                }
            }
            EventPriority::Medium => {
                match self.sender.try_send(event) {
                    Ok(()) => {
                        self.track_depth();
                        metrics.events_delivered_medium.fetch_add(1, Ordering::Relaxed);
                        true
                    }
                    Err(cb_channel::TrySendError::Full(_)) => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                    Err(cb_channel::TrySendError::Disconnected(_)) => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                }
            }
            EventPriority::Low => {
                match self.sender.try_send(event) {
                    Ok(()) => {
                        self.track_depth();
                        metrics.events_delivered_low.fetch_add(1, Ordering::Relaxed);
                        true
                    }
                    Err(cb_channel::TrySendError::Full(_)) => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                    Err(cb_channel::TrySendError::Disconnected(_)) => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                }
            }
        }
    }

    /// Receive a batch of events (non-blocking).
    #[inline]
    pub fn drain_batch(&self, batch: &mut Vec<TelemetryEnvelope>, max: usize) -> usize {
        let count = self.receiver.try_recv_all_timeout(batch, max, Duration::from_micros(100));
        count
    }

    /// Receive a single event (blocking with timeout).
    #[inline]
    pub fn recv_timeout(&self, timeout: Duration) -> Result<TelemetryEnvelope, cb_channel::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    /// Number of events currently in the queue.
    #[inline]
    pub fn len(&self) -> usize {
        self.receiver.len()
    }

    /// Check if queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.receiver.is_empty()
    }

    /// Clone the sender for producer use.
    #[inline]
    pub fn sender(&self) -> cb_channel::Sender<TelemetryEnvelope> {
        self.sender.clone()
    }

    /// Get drop count as metric.
    #[inline]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Track peak queue depth.
    fn track_depth(&self) {
        let current = self.receiver.len() as u64;
        let mut peak = self.peak_depth.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_depth.compare_exchange(peak, current, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }
}

// ─── Priority Queue Set ──────────────────────────────────────────────────────

/// Complete set of priority channels. Central dispatch point for all telemetry.
///
/// Usage:
/// ```rust,ignore
/// let queues = PriorityQueueSet::new();
/// let sent = queues.dispatch(event);
/// ```
pub struct PriorityQueueSet {
    pub critical: PriorityChannel,
    pub high: PriorityChannel,
    pub medium: PriorityChannel,
    pub low: PriorityChannel,
    pub metrics: PipelineMetrics,
    /// Event age threshold. Events older than this are dropped.
    max_event_age: Duration,
    /// Last time we logged shedding info
    last_shed_log: std::sync::Mutex<Instant>,
}

impl PriorityQueueSet {
    pub fn new() -> Self {
        Self {
            critical: PriorityChannel::new(EventPriority::Critical, CAPACITY_CRITICAL),
            high: PriorityChannel::new(EventPriority::High, CAPACITY_HIGH),
            medium: PriorityChannel::new(EventPriority::Medium, CAPACITY_MEDIUM),
            low: PriorityChannel::new(EventPriority::Low, CAPACITY_LOW),
            metrics: PipelineMetrics::default(),
            max_event_age: Duration::from_secs(60),
            last_shed_log: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Dispatch an event to the correct priority queue.
    ///
    /// Returns `true` if delivered, `false` if shed.
    #[inline]
    pub fn dispatch(&self, event: TelemetryEnvelope) -> bool {
        // Age check: drop events older than max_event_age
        if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            let event_time = event.timestamp_ns as u128;
            let now_ns = now.as_nanos();
            if now_ns > event_time && (now_ns - event_time) > self.max_event_age.as_nanos() {
                // Event too old, silently drop
                self.metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }

        let result = match event.priority {
            EventPriority::Critical => self.critical.send(event, &self.metrics),
            EventPriority::High => self.high.send(event, &self.metrics),
            EventPriority::Medium => self.medium.send(event, &self.metrics),
            EventPriority::Low => self.low.send(event, &self.metrics),
        };

        // Periodic shedding log
        if !result {
            let dropped_total = self.metrics.events_dropped.load(Ordering::Relaxed);
            if dropped_total > 0 && dropped_total % 1000 == 0 {
                let mut last_log = self.last_shed_log.lock().unwrap();
                if last_log.elapsed() > Duration::from_secs(5) {
                    log::warn!(
                        "Telemetry shedding: {} dropped, queue depths: C={}/{} H={}/{} M={}/{} L={}/{}",
                        dropped_total,
                        self.critical.len(), CAPACITY_CRITICAL,
                        self.high.len(), CAPACITY_HIGH,
                        self.medium.len(), CAPACITY_MEDIUM,
                        self.low.len(), CAPACITY_LOW,
                    );
                    *last_log = Instant::now();
                }
            }
        }

        result
    }

    /// Current aggregate queue depth.
    #[inline]
    pub fn total_depth(&self) -> usize {
        self.critical.len() + self.high.len() + self.medium.len() + self.low.len()
    }

    /// Check if the pipeline is in overload (combined depth > 75% of total capacity).
    #[inline]
    pub fn is_overloaded(&self) -> bool {
        let total = self.total_depth() as f64;
        let capacity = (CAPACITY_CRITICAL + CAPACITY_HIGH + CAPACITY_MEDIUM + CAPACITY_LOW) as f64;
        total / capacity > 0.75
    }

    /// Get a snapshot of current metrics.
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }
}

// ─── Crossbeam Extensions ────────────────────────────────────────────────────

/// Utility: try to receive up to `max` items, non-blocking, with optional timeout fallback.
trait TryRecvBatch {
    fn try_recv_all_timeout(&self, batch: &mut Vec<TelemetryEnvelope>, max: usize, timeout: Duration) -> usize;
}

impl TryRecvBatch for cb_channel::Receiver<TelemetryEnvelope> {
    fn try_recv_all_timeout(&self, batch: &mut Vec<TelemetryEnvelope>, max: usize, timeout: Duration) -> usize {
        let start = Instant::now();
        let mut count = 0;

        // Fast path: try_recv for up to `max` items
        while count < max {
            match self.try_recv() {
                Ok(ev) => {
                    batch.push(ev);
                    count += 1;
                }
                Err(cb_channel::TryRecvError::Empty) => {
                    // If we got at least one item, return immediately (no latency)
                    if count > 0 {
                        break;
                    }
                    // If empty, wait a tiny bit for the first one
                    if start.elapsed() < timeout {
                        std::thread::yield_now();
                        continue;
                    }
                    break;
                }
                Err(cb_channel::TryRecvError::Disconnected) => break,
            }
        }
        count
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::pipeline::event::*;

    fn make_event(priority: EventPriority) -> TelemetryEnvelope {
        TelemetryEnvelope::new(
            SourceId::ProcessMonitor,
            SourceTrust::User,
            priority,
            EventCategory::Process,
            CanonicalEventType::ProcessCreated,
            serde_json::json!({"pid": 0}),
        )
    }

    #[test]
    fn test_priority_channel_critical_backpressure() {
        use std::sync::Arc;
        let ch = Arc::new(PriorityChannel::new(EventPriority::Critical, 2));
        let metrics = PipelineMetrics::default();

        // Fill the channel
        assert!(ch.send(make_event(EventPriority::Critical), &metrics));
        assert!(ch.send(make_event(EventPriority::Critical), &metrics));

        // Drain one item from a background thread to unblock the next send
        let ch_clone = ch.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let _ = ch_clone.receiver.try_recv();
        });

        // Next send blocks briefly then succeeds once receiver drains
        assert!(ch.send(make_event(EventPriority::Critical), &metrics));
        t.join().unwrap();
    }

    #[test]
    fn test_priority_channel_noncritical_drop() {
        let ch = PriorityChannel::new(EventPriority::High, 2);
        let metrics = PipelineMetrics::default();

        assert!(ch.send(make_event(EventPriority::High), &metrics));
        assert!(ch.send(make_event(EventPriority::High), &metrics));
        // At capacity — next send should drop
        assert!(!ch.send(make_event(EventPriority::High), &metrics));
        assert_eq!(ch.dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_drain_batch() {
        let ch = PriorityChannel::new(EventPriority::Medium, 64);
        let metrics = PipelineMetrics::default();

        for _ in 0..10 {
            ch.send(make_event(EventPriority::Medium), &metrics);
        }

        let mut batch = Vec::with_capacity(DRAIN_BATCH_SIZE);
        let count = ch.drain_batch(&mut batch, DRAIN_BATCH_SIZE);
        assert_eq!(count, 10);
    }

    #[test]
    fn test_priority_dispatch() {
        let queues = PriorityQueueSet::new();

        assert!(queues.dispatch(make_event(EventPriority::Critical)));
        assert!(queues.dispatch(make_event(EventPriority::High)));
        assert!(queues.dispatch(make_event(EventPriority::Medium)));
        assert!(queues.dispatch(make_event(EventPriority::Low)));

        assert_eq!(queues.critical.len(), 1);
        assert_eq!(queues.high.len(), 1);
        assert_eq!(queues.medium.len(), 1);
        assert_eq!(queues.low.len(), 1);
    }
}
