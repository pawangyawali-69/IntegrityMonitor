//! Telemetry streaming — bridges TelemetryRouter → Tauri frontend via chunked IPC.

use crate::telemetry::envelope::*;
use crate::telemetry::router::TelemetryRouter;
use crossbeam::channel as cb_channel;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};

const BATCH_MAX: usize = 32;
const FLUSH_INTERVAL: Duration = Duration::from_millis(50);

/// Spawns a background thread that reads envelopes from the router and emits
/// them to the frontend as Tauri events. Returns a handle for shutdown.
pub fn spawn_frontend_streamer(
    router: TelemetryRouter,
    app_handle: AppHandle,
) -> FrontendStreamHandle {
    let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = shutdown_flag.clone();

    let rx = router.subscribe_frontend(CategoryFilter::ALL, Severity::Informational);

    std::thread::Builder::new()
        .name("telemetry-streamer".into())
        .spawn(move || {
            let mut batch: Vec<TelemetryEnvelope> = Vec::with_capacity(BATCH_MAX);
            let mut last_flush = std::time::Instant::now();

            loop {
                if flag.load(Ordering::Relaxed) {
                    // flush remaining
                    if !batch.is_empty() {
                        let _ = app_handle.emit("telemetry-batch", &batch);
                        batch.clear();
                    }
                    break;
                }

                match rx.recv_timeout(FLUSH_INTERVAL) {
                    Ok(envelope) => {
                        batch.push(envelope);
                        if batch.len() >= BATCH_MAX || last_flush.elapsed() >= Duration::from_secs(1) {
                            let _ = app_handle.emit("telemetry-batch", &batch);
                            batch.clear();
                            last_flush = std::time::Instant::now();
                        }
                    }
                    Err(cb_channel::RecvTimeoutError::Timeout) => {
                        if !batch.is_empty() && last_flush.elapsed() >= FLUSH_INTERVAL {
                            let _ = app_handle.emit("telemetry-batch", &batch);
                            batch.clear();
                            last_flush = std::time::Instant::now();
                        }
                    }
                    Err(cb_channel::RecvTimeoutError::Disconnected) => {
                        if !batch.is_empty() {
                            let _ = app_handle.emit("telemetry-batch", &batch);
                        }
                        break;
                    }
                }
            }
        })
        .expect("failed to spawn telemetry streamer");

    FrontendStreamHandle { shutdown: shutdown_flag }
}

/// Spawns a per-subscription stream worker that emits filtered envelopes
/// as `telemetry-events` Tauri events.
pub fn spawn_filtered_stream(
    router: TelemetryRouter,
    app_handle: AppHandle,
    subscription: FrontendSubscription,
    event_name: &'static str,
) -> FrontendStreamHandle {
    let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = shutdown_flag.clone();
    let rx = router.subscribe(subscription);

    std::thread::Builder::new()
        .name(format!("stream-{}", event_name))
        .spawn(move || {
            let mut batch: Vec<TelemetryEnvelope> = Vec::with_capacity(BATCH_MAX);
            loop {
                if flag.load(Ordering::Relaxed) {
                    if !batch.is_empty() {
                        let _ = app_handle.emit(event_name, &batch);
                    }
                    break;
                }
                match rx.recv_timeout(FLUSH_INTERVAL) {
                    Ok(env) => {
                        batch.push(env);
                        if batch.len() >= BATCH_MAX {
                            let _ = app_handle.emit(event_name, &batch);
                            batch.clear();
                        }
                    }
                    Err(cb_channel::RecvTimeoutError::Timeout) => {
                        if !batch.is_empty() {
                            let _ = app_handle.emit(event_name, &batch);
                            batch.clear();
                        }
                    }
                    Err(cb_channel::RecvTimeoutError::Disconnected) => {
                        if !batch.is_empty() {
                            let _ = app_handle.emit(event_name, &batch);
                        }
                        break;
                    }
                }
            }
        })
        .expect("failed to spawn filtered stream");

    FrontendStreamHandle { shutdown: shutdown_flag }
}

/// Handle to a frontend stream — can be used to shut it down.
pub struct FrontendStreamHandle {
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl FrontendStreamHandle {
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// Metrics snapshot for a streaming session.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamMetrics {
    pub envelopes_sent: u64,
    pub batches_sent: u64,
}

impl Default for StreamMetrics {
    fn default() -> Self {
        Self { envelopes_sent: 0, batches_sent: 0 }
    }
}
