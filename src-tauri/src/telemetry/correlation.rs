use crate::telemetry::{EventBus, TelemetryEvent, ProcessTable};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct CorrelationActor {
    event_rx: crossbeam::channel::Receiver<TelemetryEvent>,
    event_bus: EventBus,
    proc_table: ProcessTable,

    process_window: VecDeque<(Instant, TelemetryEvent)>,
    image_window: VecDeque<(Instant, TelemetryEvent)>,
    file_window: VecDeque<(Instant, TelemetryEvent)>,
    net_window: VecDeque<(Instant, TelemetryEvent)>,

    graph_store: Option<GraphStore>,
    last_node_for_pid: HashMap<u32, i64>,
}

impl CorrelationActor {
    pub fn new(bus: EventBus, proc_table: ProcessTable) -> Self {
        let event_rx = bus.subscribe();
        let graph_store = {
            let base = std::env::var("LOCALAPPDATA")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("C:\\Temp"));
            let path = base.join("IntegrityMonitor").join("correlation_graph.db");
            match GraphStore::open(path) {
                Ok(g) => { log::info!("GraphStore opened successfully"); Some(g) }
                Err(e) => { log::warn!("GraphStore failed to open: {}", e); None }
            }
        };
        Self {
            event_rx,
            event_bus: bus,
            proc_table,
            process_window: VecDeque::with_capacity(500),
            image_window: VecDeque::with_capacity(500),
            file_window: VecDeque::with_capacity(500),
            net_window: VecDeque::with_capacity(200),
            graph_store,
            last_node_for_pid: HashMap::new(),
        }
    }

    pub async fn run(&mut self) {
        loop {
            match self.event_rx.recv_timeout(Duration::from_secs(60)) {
                Ok(event) => {
                    self.ingest_event(event);
                }
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {
                    prune_window(&mut self.process_window, Duration::from_secs(300));
                    prune_window(&mut self.image_window, Duration::from_secs(300));
                    prune_window(&mut self.file_window, Duration::from_secs(300));
                    prune_window(&mut self.net_window, Duration::from_secs(300));
                }
                Err(crossbeam::channel::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn ingest_event(&mut self, event: TelemetryEvent) {
        CORR_EVENTS_PROCESSED.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();

        match &event {
            TelemetryEvent::ProcessCreated { .. }
            | TelemetryEvent::ImageLoaded { .. }
            | TelemetryEvent::FileChanged { .. }
            | TelemetryEvent::NetworkConnection { .. }
            | TelemetryEvent::SuspiciousActivity { .. }
            | TelemetryEvent::IntegrityAlert { .. }
            | TelemetryEvent::SystemHealth { .. } => {}
            _ => return,
        }

        match &event {
            TelemetryEvent::ProcessCreated { .. } => {
                self.process_window.push_back((now, event.clone()));
                prune_window(&mut self.process_window, Duration::from_secs(300));
                self.check_process_anomalies();
            }
            TelemetryEvent::ImageLoaded { .. } => {
                self.image_window.push_back((now, event.clone()));
                prune_window(&mut self.image_window, Duration::from_secs(300));
                self.check_image_anomalies();
            }
            TelemetryEvent::FileChanged { .. } => {
                self.file_window.push_back((now, event.clone()));
                prune_window(&mut self.file_window, Duration::from_secs(300));
                self.check_file_anomalies();
            }
            TelemetryEvent::NetworkConnection { .. } => {
                self.net_window.push_back((now, event.clone()));
                prune_window(&mut self.net_window, Duration::from_secs(300));
                self.check_network_anomalies();
            }
            _ => {}
        }

        // Persist event to graph store and create temporal edges
        if let Some(ref store) = self.graph_store {
            let pid = extract_pid(&event);
            match store.insert_node(&event) {
                Ok(node_id) => {
                    // Link to previous event for same PID
                    if let Some(prev_id) = self.last_node_for_pid.get(&pid) {
                        let _ = store.link_events(*prev_id, node_id, "temporal", 1.0);
                    }
                    // For process create, link to parent process if known
                    if let TelemetryEvent::ProcessCreated { parent_pid, .. } = &event {
                        if *parent_pid > 0 {
                            if let Some(parent_node) = self.last_node_for_pid.get(parent_pid) {
                                let _ = store.link_events(*parent_node, node_id, "parent_child", 1.5);
                            }
                        }
                    }
                    self.last_node_for_pid.insert(pid, node_id);
                }
                Err(e) => log::error!("GraphStore insert failed: {}", e),
            }
        }
    }

    pub fn get_chains(&self) -> Vec<crate::core::CorrelationEvent> {
        self.graph_store.as_ref()
            .map(|g| g.get_chains(100))
            .unwrap_or_default()
    }

    // ── Correlation Rules ──

    fn check_process_anomalies(&self) {
        let _now = Instant::now();

        let recent_procs: Vec<&TelemetryEvent> = self.process_window.iter()
            .filter(|(t, _)| t.elapsed() < Duration::from_secs(60))
            .map(|(_, e)| e)
            .collect();

        if recent_procs.len() >= 3 {
            let office_procs = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"];
            let has_office = recent_procs.iter().any(|e| {
                if let TelemetryEvent::ProcessCreated { name, .. } = e {
                    office_procs.iter().any(|o| name.to_lowercase().contains(o))
                } else { false }
            });
            let has_powershell = recent_procs.iter().any(|e| {
                if let TelemetryEvent::ProcessCreated { name, .. } = e {
                    name.to_lowercase().contains("powershell") || name.to_lowercase().contains("pwsh")
                } else { false }
            });
            let has_network = !self.net_window.is_empty() && self.net_window.back()
                .map(|(t, _)| t.elapsed() < Duration::from_secs(30))
                .unwrap_or(false);

            if has_office && has_powershell && has_network {
                log::warn!("Correlation: Office -> PowerShell -> Network (possible macro execution)");
                self.emit_detection(
                    "office_macro_execution",
                    "high",
                    "Office application launched PowerShell followed by network connection",
                    0,
                    "".to_string(),
                    vec!["office_detected".into(), "powershell_detected".into(), "network_detected".into()],
                );
            }
        }

        if let Some((_, latest)) = self.process_window.back() {
            if let TelemetryEvent::ProcessCreated { pid, name, parent_pid, .. } = latest {
                let suspicious = match name.to_lowercase().as_str() {
                    "rundll32.exe" | "regsvr32.exe" | "mshta.exe" | "cscript.exe" | "wscript.exe" => {
                        self.proc_table.get(parent_pid).map(|p| {
                            let parent_name = p.name.to_lowercase();
                            parent_name.contains("explorer") || parent_name.contains("outlook")
                                || parent_name.contains("winword") || parent_name.contains("excel")
                        }).unwrap_or(false)
                    }
                    _ => false,
                };

                if suspicious {
                    log::warn!("Correlation: Suspicious LOLBin spawned by parent PID {}", parent_pid);
                    self.emit_detection(
                        "lolbin_execution",
                        "medium",
                        &format!("Suspicious LOLBin execution: {}", name),
                        *pid,
                        name.to_string(),
                        vec![format!("parent_pid: {}", parent_pid)],
                    );
                }
            }
        }
    }

    fn check_image_anomalies(&self) {
        if let Some((_, latest)) = self.image_window.back() {
            if let TelemetryEvent::ImageLoaded { pid, image_path, pe_anomalies, .. } = latest {
                let lower = image_path.to_lowercase();

                if lower.contains("\\temp\\") || lower.contains("\\appdata\\local\\temp\\") {
                    if let Some(proc) = self.proc_table.get(pid) {
                        let proc_name = proc.name.clone();
                        if !lower.contains(&proc_name.to_lowercase()) {
                            log::warn!("Correlation: DLL loaded from temp into PID {}", pid);
                            self.emit_detection(
                                "temp_dll_injection",
                                "high",
                                &format!("DLL loaded from temporary directory into process {}", proc_name),
                                *pid,
                                proc_name,
                                vec![format!("dll_path: {}", image_path)],
                            );
                        }
                    }
                }

                if !pe_anomalies.is_empty() {
                    let proc_name = self.proc_table.get(pid)
                        .map(|p| p.name.clone())
                        .unwrap_or_default();
                    self.emit_detection(
                        "pe_anomaly",
                        "high",
                        &format!("PE structure anomalies in module loaded by {}", proc_name),
                        *pid,
                        proc_name,
                        pe_anomalies.clone(),
                    );
                }
            }
        }
    }

    fn check_file_anomalies(&self) {
        let recent_files: Vec<&TelemetryEvent> = self.file_window.iter()
            .filter(|(t, _)| t.elapsed() < Duration::from_secs(120))
            .map(|(_, e)| e)
            .collect();

        let recent_procs: Vec<&TelemetryEvent> = self.process_window.iter()
            .filter(|(t, _)| t.elapsed() < Duration::from_secs(120))
            .map(|(_, e)| e)
            .collect();

        for file_ev in &recent_files {
            if let TelemetryEvent::FileChanged { file_name, event_type, .. } = file_ev {
                if event_type != "created" && event_type != "modified" { continue; }
                if !file_name.ends_with(".exe") && !file_name.ends_with(".dll")
                    && !file_name.ends_with(".ps1") { continue; }

                for proc_ev in &recent_procs {
                    if let TelemetryEvent::ProcessCreated { name, .. } = proc_ev {
                        let fn_lower = file_name.to_lowercase().replace(".exe", "").replace(".ps1", "");
                        let pn_lower = name.to_lowercase().replace(".exe", "");
                        if fn_lower == pn_lower {
                            log::warn!("Correlation: File creation followed by matching process execution");
                            self.emit_detection(
                                "file_execution_correlation",
                                "medium",
                                &format!("File '{}' created then '{}' executed within 2 min", file_name, name),
                                0,
                                name.clone(),
                                vec![format!("file: {}", file_name)],
                            );
                            return;
                        }
                    }
                }
            }
        }
    }

    fn check_network_anomalies(&self) {
        if let Some((_, latest)) = self.net_window.back() {
            if let TelemetryEvent::NetworkConnection { pid, remote_addr, remote_port, .. } = latest {
                let suspicious_ports = [4444, 1337, 31337, 5555, 6666, 7777, 8888, 9001, 12345, 54321];
                if suspicious_ports.contains(remote_port) {
                    let proc_name = self.proc_table.get(pid)
                        .map(|p| p.name.clone())
                        .unwrap_or_default();
                    self.emit_detection(
                        "suspicious_port",
                        "medium",
                        &format!("Connection on suspicious port {} from {}", remote_port, proc_name),
                        *pid,
                        proc_name,
                        vec![format!("remote: {}:{}", remote_addr, remote_port)],
                    );
                }

                if *remote_port == 443 || *remote_port == 8080 {
                    let count = self.net_window.iter()
                        .filter(|(t, e)| {
                            if t.elapsed() > Duration::from_secs(300) { return false; }
                            matches!(e, TelemetryEvent::NetworkConnection { remote_addr: ra, .. } if ra == remote_addr)
                        })
                        .count();
                    if count > 10 {
                        let proc_name = self.proc_table.get(pid)
                            .map(|p| p.name.clone())
                            .unwrap_or_default();
                        self.emit_detection(
                            "potential_beaconing",
                            "high",
                            &format!("High connection count ({}) to {} from {} (possible beaconing)", count, remote_addr, proc_name),
                            *pid,
                            proc_name,
                            vec![format!("connections: {}", count)],
                        );
                    }
                }
            }
        }
    }

    fn emit_detection(&self, rule_name: &str, severity: &str, description: &str, pid: u32, process_name: String, evidence: Vec<String>) {
        self.event_bus.emit(TelemetryEvent::SuspiciousActivity {
            rule_name: rule_name.into(),
            severity: severity.into(),
            description: description.into(),
            pid,
            process_name,
            evidence,
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }
}

/// Graph-based attack chain store using SQLite adjacency list.
/// Reconstructs temporal attack chains from correlated events.
pub struct GraphStore {
    conn: Mutex<rusqlite::Connection>,
}

impl GraphStore {
    pub fn open(db_path: std::path::PathBuf) -> Result<Self, String> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let conn = rusqlite::Connection::open(&db_path).map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA journal_mode=WAL;").map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;").map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA busy_timeout=5000;").map_err(|e| e.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS graph_nodes (
                node_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                pid INTEGER NOT NULL DEFAULT 0,
                parent_pid INTEGER NOT NULL DEFAULT 0,
                process_name TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '{}',
                timestamp TEXT NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS graph_edges (
                edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_node INTEGER NOT NULL REFERENCES graph_nodes(node_id),
                dst_node INTEGER NOT NULL REFERENCES graph_nodes(node_id),
                relation TEXT NOT NULL,
                weight REAL NOT NULL DEFAULT 1.0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_pid ON graph_nodes(pid);
            CREATE INDEX IF NOT EXISTS idx_nodes_timestamp ON graph_nodes(timestamp);
            CREATE INDEX IF NOT EXISTS idx_edges_src ON graph_edges(src_node);
            CREATE INDEX IF NOT EXISTS idx_edges_dst ON graph_edges(dst_node);"
        ).map_err(|e| e.to_string())?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn insert_node(&self, event: &TelemetryEvent) -> Result<i64, String> {
        let (event_type, pid, parent_pid, process_name, description, details, ts) = classify_event(event);
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO graph_nodes (event_type, pid, parent_pid, process_name, description, details, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![event_type, pid, parent_pid, process_name, description, details, ts],
        ).map_err(|e| e.to_string())?;
        Ok(c.last_insert_rowid())
    }

    /// Create edges between related events based on PID/temporal proximity.
    pub fn link_events(&self, src: i64, dst: i64, relation: &str, weight: f64) -> Result<(), String> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO graph_edges (src_node, dst_node, relation, weight) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![src, dst, relation, weight],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Reconstruct attack chains using temporal BFS from the given node.
    /// Returns chains of correlated events describing an attack path.
    pub fn get_chains(&self, limit: usize) -> Vec<crate::core::CorrelationEvent> {
        let c = self.conn.lock().unwrap();
        let mut chains = Vec::new();

        // Find root nodes (process creates with no parent context, or flagged events)
        let mut stmt = match c.prepare(
            "SELECT node_id, event_type, pid, process_name, description, details, timestamp
             FROM graph_nodes ORDER BY timestamp DESC LIMIT ?1"
        ) {
            Ok(s) => s,
            Err(_) => return chains,
        };

        let roots: std::result::Result<Vec<(i64, String, u32, String, String, String, String)>, _> = stmt.query_map(
            rusqlite::params![limit.min(100) as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            }
        ).map(|rows| rows.filter_map(|r| r.ok()).collect());

        let roots = match roots {
            Ok(r) => r,
            Err(_) => return chains,
        };

        for (node_id, event_type, _pid, ref process_name, _description, _details, _ts) in roots {
            let mut visited = std::collections::HashSet::new();
            let mut chain_nodes = Vec::new();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(node_id);

            while let Some(current) = queue.pop_front() {
                if !visited.insert(current) {
                    continue;
                }

                let node_info = {
                    let mut s = match c.prepare(
                        "SELECT n.event_type, n.pid, n.process_name, n.description, n.details, n.timestamp
                         FROM graph_nodes n WHERE n.node_id = ?1"
                    ) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let info: std::result::Result<(String, u32, String, String, String, String), _> = s.query_row(
                        rusqlite::params![current], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, u32>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                        ))
                    });
                    info.ok()
                };

                if let Some((ev_type, ev_pid, ev_name, ev_desc, ev_details, ev_ts)) = node_info {
                    chain_nodes.push(crate::core::TimelineEvent {
                        id: format!("n{}", current),
                        timestamp: ev_ts,
                        event_type: ev_type,
                        category: "correlation".into(),
                        description: ev_desc,
                        severity: "medium".into(),
                        source: "graph_store".into(),
                        process_name: Some(ev_name),
                        pid: Some(ev_pid),
                        path: None,
                        details: serde_json::from_str(&ev_details).unwrap_or_default(),
                    });
                }

                let mut edge_stmt = match c.prepare(
                    "SELECT e.dst_node FROM graph_edges e WHERE e.src_node = ?1 ORDER BY e.weight DESC LIMIT 20"
                ) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let edge_rows: std::result::Result<Vec<i64>, _> = edge_stmt.query_map(
                    rusqlite::params![current], |row| {
                    row.get::<_, i64>(0)
                }).map(|rows| rows.filter_map(|r| r.ok()).collect());

                if let Ok(next_ids) = edge_rows {
                    for next in next_ids {
                        queue.push_back(next);
                    }
                }
            }

            if chain_nodes.len() >= 2 {
                let first_ts = chain_nodes[0].timestamp.clone();
                let last_ts = chain_nodes[chain_nodes.len() - 1].timestamp.clone();
                let desc = format!("Attack chain: {} spawned by {} ({} events)", event_type, process_name, chains.len() + 1);
                chains.push(crate::core::CorrelationEvent {
                    id: format!("chain-n{}", node_id),
                    events: chain_nodes,
                    relationship_type: "temporal_bfs".into(),
                    confidence: (chains.len() as f64 * 0.15).min(0.95),
                    description: desc,
                    timestamp_start: first_ts,
                    timestamp_end: last_ts,
                });
            }
        }
        chains
    }

    pub fn count(&self) -> Result<i64, String> {
        let c = self.conn.lock().unwrap();
        c.query_row("SELECT COUNT(*) FROM graph_nodes", [], |row| row.get::<_, i64>(0))
            .map_err(|e| e.to_string())
    }
}

fn extract_pid(event: &TelemetryEvent) -> u32 {
    match event {
        TelemetryEvent::ProcessCreated { pid, .. } => *pid,
        TelemetryEvent::ProcessTerminated { pid, .. } => *pid,
        TelemetryEvent::ThreadCreated { pid, .. } => *pid,
        TelemetryEvent::ImageLoaded { pid, .. } => *pid,
        TelemetryEvent::FileChanged { pid, .. } => pid.unwrap_or(0),
        TelemetryEvent::NetworkConnection { pid, .. } => *pid,
        TelemetryEvent::RegistryModified { pid, .. } => *pid,
        TelemetryEvent::SuspiciousActivity { pid, .. } => *pid,
        TelemetryEvent::IntegrityAlert { pid, .. } => *pid,
        TelemetryEvent::MemoryChanged { pid, .. } => *pid,
        TelemetryEvent::SystemHealth { .. } => 0,
    }
}

/// Extract classification fields from a TelemetryEvent for graph storage.
fn classify_event(event: &TelemetryEvent) -> (String, u32, u32, String, String, String, String) {
    let ts = chrono::Utc::now().to_rfc3339();
    match event {
        TelemetryEvent::ProcessCreated { pid, parent_pid, name, path, .. } => {
            ("process_create".into(), *pid, *parent_pid, name.clone(),
             format!("Process created: {} (PID {})", name, pid),
             serde_json::json!({"path": path}).to_string(), ts)
        }
        TelemetryEvent::ImageLoaded { pid, process_name, image_path, .. } => {
            ("image_load".into(), *pid, 0, process_name.clone(),
             format!("Image loaded: {}", image_path),
             serde_json::json!({"image_path": image_path}).to_string(), ts)
        }
        TelemetryEvent::SuspiciousActivity { pid, process_name, rule_name, description, .. } => {
            ("suspicious_activity".into(), *pid, 0, process_name.clone(),
             format!("{}: {}", rule_name, description),
             serde_json::json!({"rule": rule_name}).to_string(), ts)
        }
        TelemetryEvent::IntegrityAlert { pid, process_name, alert_type, .. } => {
            ("integrity_alert".into(), *pid, 0, process_name.clone(),
             format!("Integrity alert: {}", alert_type),
             serde_json::json!({"alert_type": alert_type}).to_string(), ts)
        }
        TelemetryEvent::NetworkConnection { pid, process_name, remote_addr, remote_port, .. } => {
            ("network_connection".into(), *pid, 0, process_name.clone(),
             format!("Connection to {}:{}", remote_addr, remote_port),
                 serde_json::json!({"remote_addr": remote_addr, "remote_port": remote_port}).to_string(), ts)
        }
        TelemetryEvent::ThreadCreated { pid, tid, .. } => {
            ("thread_create".into(), *pid, 0, String::new(),
             format!("Thread created: TID {}", tid),
             serde_json::json!({"tid": tid}).to_string(), ts)
        }
        TelemetryEvent::FileChanged { pid, process_name, file_name, event_type, .. } => {
            ("file_change".into(), pid.unwrap_or(0), 0, process_name.clone().unwrap_or_default(),
             format!("File {}: {}", event_type, file_name),
             serde_json::json!({"file_name": file_name, "event_type": event_type}).to_string(), ts)
        }
        TelemetryEvent::MemoryChanged { pid, process_name, base_address, change_type, .. } => {
            ("memory_change".into(), *pid, 0, process_name.clone(),
             format!("Memory {} at 0x{:X}", change_type, base_address),
             serde_json::json!({"base_address": base_address, "change_type": change_type}).to_string(), ts)
        }
        _ => ("other".into(), 0, 0, String::new(), String::new(), "{}".into(), ts),
    }
}

fn prune_window(window: &mut VecDeque<(Instant, TelemetryEvent)>, max_age: Duration) {
    while let Some(front) = window.front() {
        if front.0.elapsed() > max_age {
            window.pop_front();
        } else {
            break;
        }
    }
}

use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static CORR_EVENTS_PROCESSED: AtomicU64 = AtomicU64::new(0);

/// Incremented on every event ingested. Used by SystemSupervisor for liveness.
pub fn corr_events_processed() -> u64 {
    CORR_EVENTS_PROCESSED.load(Ordering::Relaxed)
}
