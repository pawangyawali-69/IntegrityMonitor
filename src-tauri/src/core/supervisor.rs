use crate::telemetry::{EventBus, journal};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Shared health state accessible from all subsystems.
pub struct SystemHealth {
    pub started_at: Instant,
    pub etw_alive: AtomicBool,
    pub journal_alive: AtomicBool,
    pub trust_worker_alive: AtomicBool,
    pub storage_alive: AtomicBool,
    pub correlation_alive: AtomicBool,
    pub last_health_event: AtomicU64,
}

impl SystemHealth {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            etw_alive: AtomicBool::new(true),
            journal_alive: AtomicBool::new(true),
            trust_worker_alive: AtomicBool::new(true),
            storage_alive: AtomicBool::new(true),
            correlation_alive: AtomicBool::new(true),
            last_health_event: AtomicU64::new(0),
        }
    }

}

/// Runtime supervision subsystem: monitors liveness of all background subsystems,
/// reports health to the UI, and attempts auto-restart of dead subsystems.
pub struct SystemSupervisor {
    health: Arc<SystemHealth>,
    event_bus: EventBus,
    proc_table: crate::telemetry::ProcessTable,
}

impl SystemSupervisor {
    pub fn new(
        event_bus: EventBus,
        proc_table: crate::telemetry::ProcessTable,
    ) -> Self {
        Self {
            health: Arc::new(SystemHealth::new()),
            event_bus,
            proc_table,
        }
    }

    pub fn health(&self) -> Arc<SystemHealth> {
        self.health.clone()
    }

    /// Start the supervisor loop in a background thread.
    /// Checks subsystem health every 15 seconds and emits health events to the UI.
    pub fn run(&self) {
        let health = self.health.clone();
        let bus = self.event_bus.clone();
        let _proc_table = self.proc_table.clone();

        std::thread::spawn(move || {
            log::info!("System supervisor started (health check interval: 15s)");

            loop {
                std::thread::sleep(Duration::from_secs(15));

                let uptime = health.started_at.elapsed();
                let etw = crate::telemetry::etw::etw_event_count();
                let corr = crate::telemetry::correlation::corr_events_processed();
                let trust = crate::telemetry::etw::trust_events_processed();

                let journal_count = journal::get_journal_path()
                    .to_string_lossy()
                    .to_string();
                let _ = &journal_count; // used for log context

                // Read journal size
                let journal_events = {
                    // Open a temporary connection to check journal size
                    let jpath = journal::get_journal_path();
                    if jpath.exists() {
                        match journal::EventJournal::open(jpath) {
                            Ok(j) => j.count().unwrap_or(-1),
                            Err(_) => -1,
                        }
                    } else {
                        -1
                    }
                };

                let total_emitted = bus.emit_count();

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Calculate events per second since last check
                let prev_total = health.last_health_event.swap(total_emitted, Ordering::Relaxed);
                let eps = if prev_total > 0 {
                    (total_emitted - prev_total) / 15
                } else {
                    0
                };

                // Determine subsystem health
                let etw_stalled = uptime.as_secs() > 60 && etw == 0;
                let corr_stalled = uptime.as_secs() > 60 && corr == 0;
                let trust_stalled = uptime.as_secs() > 60 && trust == 0;
                let journal_stalled = journal_events < 0;

                if etw_stalled {
                    log::warn!("Supervisor: ETW subsystem appears stalled (0 events in {}s)", uptime.as_secs());
                    health.etw_alive.store(false, Ordering::Relaxed);
                } else {
                    health.etw_alive.store(true, Ordering::Relaxed);
                }

                if corr_stalled {
                    log::warn!("Supervisor: Correlation subsystem appears stalled (0 events in {}s)", uptime.as_secs());
                    health.correlation_alive.store(false, Ordering::Relaxed);
                } else {
                    health.correlation_alive.store(true, Ordering::Relaxed);
                }

                if trust_stalled {
                    log::warn!("Supervisor: Trust worker appears stalled (0 verifications in {}s)", uptime.as_secs());
                    health.trust_worker_alive.store(false, Ordering::Relaxed);
                } else {
                    health.trust_worker_alive.store(true, Ordering::Relaxed);
                }

                if journal_stalled {
                    log::warn!("Supervisor: Journal subsystem is not responding");
                    health.journal_alive.store(false, Ordering::Relaxed);
                } else {
                    health.journal_alive.store(true, Ordering::Relaxed);
                }

                log::info!(
                    "SystemHealth [uptime={}s] etw={} corr={} trust={} journal={} total={} eps={}",
                    uptime.as_secs(), etw, corr, trust, journal_events, total_emitted, eps
                );

                // Emit health event (broadcast = no journaling for internal events)
                bus.broadcast(crate::telemetry::TelemetryEvent::SystemHealth {
                    uptime_secs: uptime.as_secs(),
                    etw_events_processed: etw,
                    corr_events_processed: corr,
                    journal_events_written: journal_events.max(0) as u64,
                    trust_events_processed: trust,
                    total_events_emitted: total_emitted,
                    total_events_dropped: 0,
                    seconds_since_last_event: 0,
                    events_per_sec: eps,
                    subsystem_count: 5,
                });

                // Restart logic for stalled subsystems
                if etw_stalled {
                    log::warn!("Supervisor: ETW restart not yet implemented (requires trace restart)");
                }
                if corr_stalled {
                    log::warn!("Supervisor: Correlation restart not yet implemented");
                }
            }
        });
    }
}
