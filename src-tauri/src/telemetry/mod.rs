pub mod etw;
pub mod trust;
pub mod pe;
pub mod storage;
pub mod correlation;
pub mod memory;
pub mod network;
pub mod anti_cheat;
pub mod yara;


use tokio::sync::broadcast;
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<TelemetryEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn emit(&self, event: TelemetryEvent) {
        if self.tx.receiver_count() == 0 {
            return;
        }
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TelemetryEvent> {
        self.tx.subscribe()
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
    let bus = EventBus::new(4096);
    let proc_table: ProcessTable = Arc::new(DashMap::new());

    let bus_clone = bus.clone();
    let proc_clone = proc_table.clone();
    tokio::spawn(async move {
        etw::run_etw_consumer(bus_clone, proc_clone).await;
    });

    let bus_clone = bus.clone();
    tokio::spawn(async move {
        let mut actor = storage::StorageActor::new(bus_clone);
        actor.run().await;
    });

    let bus_clone = bus.clone();
    let proc_clone = proc_table.clone();
    tokio::spawn(async move {
        let mut actor = correlation::CorrelationActor::new(bus_clone, proc_clone);
        actor.run().await;
    });

    (bus, proc_table)
}


