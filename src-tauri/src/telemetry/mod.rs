pub mod etw;
pub mod trust;
pub mod pe;
pub mod storage;
pub mod journal;
pub mod correlation;
pub mod memory;
pub mod network;
pub mod anti_cheat;
pub mod yara;
pub mod envelope;
pub mod normalize;
pub mod router;
pub mod stream;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use dashmap::DashMap;

enum BackpressurePolicy {
    DropOldest,
    DropNewest,
    Block,
}

struct Subscriber {
    sender: crossbeam::channel::Sender<TelemetryEvent>,
    policy: BackpressurePolicy,
}

#[derive(Clone)]
pub struct EventBus {
    subscribers: Arc<Mutex<Vec<Subscriber>>>,
    journal_tx: Option<crossbeam::channel::Sender<TelemetryEvent>>,
    emit_count: Arc<AtomicU64>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(Vec::new())),
            journal_tx: None,
            emit_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_journal(&mut self, tx: crossbeam::channel::Sender<TelemetryEvent>) {
        self.journal_tx = Some(tx);
    }

    pub fn emit(&self, event: TelemetryEvent) {
        self.emit_count.fetch_add(1, Ordering::Relaxed);
        if let Some(ref jtx) = self.journal_tx {
            let _ = jtx.try_send(event.clone());
        }
        let subs = self.subscribers.lock().unwrap();
        for sub in subs.iter() {
            match sub.policy {
                BackpressurePolicy::DropOldest => {
                    let _ = sub.sender.try_send(event.clone());
                }
                BackpressurePolicy::DropNewest => {
                    if sub.sender.is_full() {
                        // skip — drop newest
                    } else {
                        let _ = sub.sender.try_send(event.clone());
                    }
                }
                BackpressurePolicy::Block => {
                    let _ = sub.sender.send(event.clone());
                }
            }
        }
    }

    /// Emit without journaling (used for replay and internal system events)
    pub fn broadcast(&self, event: TelemetryEvent) {
        self.emit_count.fetch_add(1, Ordering::Relaxed);
        let subs = self.subscribers.lock().unwrap();
        for sub in subs.iter() {
            let _ = sub.sender.try_send(event.clone());
        }
    }

    pub fn subscribe(&self) -> crossbeam::channel::Receiver<TelemetryEvent> {
        self.subscribe_with_capacity(4096)
    }

    pub fn subscribe_with_capacity(&self, capacity: usize) -> crossbeam::channel::Receiver<TelemetryEvent> {
        let (tx, rx) = crossbeam::channel::bounded(capacity);
        self.subscribers.lock().unwrap().push(Subscriber {
            sender: tx,
            policy: BackpressurePolicy::DropOldest,
        });
        rx
    }

    pub fn emit_count(&self) -> u64 {
        self.emit_count.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum TelemetryEvent {
    ProcessCreated {
        pid: u32,
        parent_pid: u32,
        name: String,
        path: String,
        command_line: String,
        session_id: u32,
        timestamp: String,
        user_sid: Option<String>,
        trust_info: Option<trust::TrustInfo>,
    },
    ProcessTerminated {
        pid: u32,
        exit_code: u32,
        timestamp: String,
    },
    ThreadCreated {
        pid: u32,
        tid: u32,
        start_address: Option<u64>,
        timestamp: String,
    },
    ImageLoaded {
        pid: u32,
        process_name: String,
        image_path: String,
        image_base: u64,
        image_size: u64,
        timestamp: String,
        trust_info: Option<trust::TrustInfo>,
        pe_anomalies: Vec<String>,
    },
    FileChanged {
        path: String,
        file_name: String,
        event_type: String,
        timestamp: String,
        size: u64,
        pid: Option<u32>,
        process_name: Option<String>,
        hash: Option<String>,
    },
    NetworkConnection {
        pid: u32,
        process_name: String,
        local_addr: String,
        local_port: u16,
        remote_addr: String,
        remote_port: u16,
        protocol: String,
        timestamp: String,
    },
    RegistryModified {
        key_path: String,
        value_name: Option<String>,
        event_type: String,
        pid: u32,
        process_name: String,
        timestamp: String,
    },
    SuspiciousActivity {
        rule_name: String,
        severity: String,
        description: String,
        pid: u32,
        process_name: String,
        evidence: Vec<String>,
        timestamp: String,
    },
    IntegrityAlert {
        pid: u32,
        process_name: String,
        alert_type: String,
        details: String,
        timestamp: String,
    },
    MemoryChanged {
        pid: u32,
        process_name: String,
        base_address: u64,
        size: usize,
        old_protect: String,
        new_protect: String,
        change_type: String,
        timestamp: String,
    },
    SystemHealth {
        uptime_secs: u64,
        etw_events_processed: u64,
        corr_events_processed: u64,
        journal_events_written: u64,
        trust_events_processed: u64,
        total_events_emitted: u64,
        total_events_dropped: u64,
        seconds_since_last_event: u64,
        events_per_sec: u64,
        subsystem_count: u32,
    },
}

pub type ProcessTable = Arc<DashMap<u32, ProcessState>>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessState {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub session_id: u32,
    pub user_sid: Option<String>,
    pub start_time: String,
    pub exit_time: Option<String>,
    pub exit_code: Option<u32>,
    pub is_alive: bool,
    pub trust_info: Option<trust::TrustInfo>,
    pub modules: Vec<ModuleState>,
    pub threads: Vec<ThreadState>,
    pub integrity_flags: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleState {
    pub base: u64,
    pub size: u64,
    pub path: String,
    pub name: String,
    pub trust_info: Option<trust::TrustInfo>,
    pub hash: String,
    pub is_suspicious: bool,
    pub anomalies: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreadState {
    pub tid: u32,
    pub start_address: Option<u64>,
    pub is_alive: bool,
    pub integrity_flags: Vec<String>,
}

pub fn initialize_platform() -> (EventBus, ProcessTable) {
    let (jtx, jrx) = crossbeam::channel::unbounded();
    let mut bus = EventBus::new();
    bus.set_journal(jtx);
    let proc_table: ProcessTable = Arc::new(DashMap::new());

    // Start journal worker (persists all events to SQLite)
    let journal_path = journal::get_journal_path();
    journal::start_journal_worker(jrx, journal_path);

    // Start trust verification worker (offloads Authenticode from ETW thread)
    let trust_rx = etw::init_trust_worker();
    let trust_bus = bus.clone();
    std::thread::spawn(move || {
        etw::run_trust_worker(trust_rx, trust_bus);
    });

    let bus_clone = bus.clone();
    let proc_clone = proc_table.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create ETW runtime");
        rt.block_on(etw::run_etw_consumer(bus_clone, proc_clone));
    });

    let bus_clone = bus.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create storage runtime");
        rt.block_on(async move {
            let mut actor = storage::StorageActor::new(bus_clone);
            actor.run().await;
        });
    });

    let bus_clone = bus.clone();
    let proc_clone = proc_table.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create correlation runtime");
        rt.block_on(async move {
            let mut actor = correlation::CorrelationActor::new(bus_clone, proc_clone);
            actor.run().await;
        });
    });

    (bus, proc_table)
}


