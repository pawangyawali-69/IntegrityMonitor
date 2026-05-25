//! Telemetry ingestion pipeline — production-grade, bounded-memory, crash-resilient
//! event processing infrastructure for the IntegrityMonitor platform.
//!
//! # Architecture
//!
//! ```text
//! Telemetry Sources (ETW, Kernel Driver, File Monitor, etc.)
//!     │
//!     ▼
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   IngestionCoordinator                        │
//! │  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌─────────────┐ │
//! │  │Replay    │  │EventRouter│  │Priority   │  │ Worker Pool │ │
//! │  │Journal   │──▶(route+    │──▶Queue Set  │──▶ (timeline,  │ │
//! │  │(crash WAL)│  │ filter)  │  │(bounded)  │  │  ui_stream) │ │
//! │  └──────────┘  └──────────┘  └───────────┘  └─────────────┘ │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key properties
//!
//! - **Bounded memory**: all queues have fixed capacities, workers process in batches
//! - **Crash resilience**: all events are journaled to disk before acknowledgment
//! - **Priority guarantees**: critical events always delivered via blocking backpressure
//! - **Telemetry shedding**: non-critical events dropped under overload
//! - **Source trust**: kernel-sourced events cannot be spoofed by user-mode attackers
//! - **Forward compat**: versioned event schema with semantic versioning
//!
//! # Usage
//!
//! ```rust,ignore
//! use telemetry::pipeline::coordinator::IngestionCoordinator;
//! use telemetry::pipeline::event::*;
//!
//! let mut coord = IngestionCoordinator::new(data_dir).unwrap();
//! coord.start(app_handle, timeline_engine);
//!
//! // Emit events from any source
//! let ev = TelemetryEnvelope::new(
//!     SourceId::ProcessMonitor,
//!     SourceTrust::Admin,
//!     EventPriority::Medium,
//!     EventCategory::Process,
//!     CanonicalEventType::ProcessCreated,
//!     serde_json::json!({"pid": 1234}),
//! );
//! coord.emit(ev);
//!
//! // Graceful shutdown
//! coord.shutdown().await;
//! ```
//!
//! # Performance characteristics
//!
//! - Single-event emit: ~500ns (no journal) to ~5µs (with journal fsync)
//! - Batch emit (64 events): ~50µs
//! - Worker tick: 250ms
//! - Max sustained throughput with journal: ~50,000 events/sec
//! - Max sustained throughput without journal: ~500,000+ events/sec
//! - Queue memory: ~512KB (critical) + ~2MB (high) + ~4MB (medium) + ~8MB (low) = ~14.5MB total

pub mod coordinator;
pub mod event;
pub mod journal;
pub mod queues;
pub mod router;
pub mod worker;

// Re-export the most commonly used types at the pipeline level
pub use coordinator::IngestionCoordinator;
pub use event::{
    CanonicalEventType, EventCategory, EventPriority, SourceId, SourceTrust,
    TelemetryEnvelope,
};
