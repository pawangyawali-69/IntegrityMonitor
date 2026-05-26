use crate::telemetry::{EventBus, TelemetryEvent};
use crate::telemetry::trust::TrustInfo;
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub struct StorageActor {
    db: Arc<Mutex<rusqlite::Connection>>,
    event_rx: crossbeam::channel::Receiver<TelemetryEvent>,
    batch: Vec<TelemetryEvent>,
}

impl StorageActor {
    pub fn new(bus: EventBus) -> Self {
        let db_path = Self::db_path();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let conn = rusqlite::Connection::open(&db_path)
            .expect("Failed to open database");

        conn.execute_batch("PRAGMA journal_mode=WAL;").ok();
        conn.execute_batch("PRAGMA synchronous=NORMAL;").ok();
        conn.execute_batch("PRAGMA busy_timeout=5000;").ok();

        let conn = Arc::new(Mutex::new(conn));
        Self::create_schema(&conn);

        let event_rx = bus.subscribe();

        log::info!("Storage actor initialized at {:?}", db_path);

        Self {
            db: conn,
            event_rx,
            batch: Vec::with_capacity(100),
        }
    }

    fn db_path() -> PathBuf {
        get_db_path()
    }

    fn create_schema(conn: &Arc<Mutex<rusqlite::Connection>>) {
        let c = conn.lock();
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS processes (
                pid INTEGER NOT NULL,
                parent_pid INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                path TEXT NOT NULL DEFAULT '',
                command_line TEXT NOT NULL DEFAULT '',
                session_id INTEGER NOT NULL DEFAULT 0,
                user_sid TEXT,
                start_time TEXT NOT NULL,
                exit_time TEXT,
                exit_code INTEGER,
                is_alive INTEGER NOT NULL DEFAULT 1,
                signer TEXT,
                is_signed INTEGER NOT NULL DEFAULT 0,
                is_microsoft INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (pid, start_time)
            );

            CREATE TABLE IF NOT EXISTS image_loads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL DEFAULT '',
                image_path TEXT NOT NULL,
                image_base INTEGER NOT NULL,
                image_size INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                signer TEXT,
                is_signed INTEGER NOT NULL DEFAULT 0,
                is_microsoft INTEGER NOT NULL DEFAULT 0,
                anomalies TEXT NOT NULL DEFAULT '[]',
                hash TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                size INTEGER NOT NULL DEFAULT 0,
                pid INTEGER,
                process_name TEXT,
                hash TEXT
            );

            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL DEFAULT '',
                local_addr TEXT NOT NULL DEFAULT '',
                local_port INTEGER NOT NULL DEFAULT 0,
                remote_addr TEXT NOT NULL DEFAULT '',
                remote_port INTEGER NOT NULL DEFAULT 0,
                protocol TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS registry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_path TEXT NOT NULL,
                value_name TEXT,
                event_type TEXT NOT NULL,
                pid INTEGER NOT NULL DEFAULT 0,
                process_name TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                pid INTEGER NOT NULL DEFAULT 0,
                process_name TEXT NOT NULL DEFAULT '',
                evidence TEXT NOT NULL DEFAULT '[]',
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS integrity_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL DEFAULT '',
                alert_type TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
            CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(name);
            CREATE INDEX IF NOT EXISTS idx_processes_time ON processes(start_time);
            CREATE INDEX IF NOT EXISTS idx_image_loads_pid ON image_loads(pid);
            CREATE INDEX IF NOT EXISTS idx_file_events_time ON file_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(timestamp);
            CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);"
        ).expect("Failed to create database schema");
    }

    pub async fn run(&mut self) {
        loop {
            match self.event_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(event) => {
                    self.batch.push(event);
                    if self.batch.len() >= 50 {
                        self.flush_batch();
                    }
                }
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {
                    if !self.batch.is_empty() {
                        self.flush_batch();
                    }
                }
                Err(crossbeam::channel::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn flush_batch(&mut self) {
        let batch = std::mem::replace(&mut self.batch, Vec::with_capacity(100));
        let count = batch.len();
        if count == 0 {
            return;
        }

        let c = self.db.lock();
        let tx = match c.unchecked_transaction() {
            Ok(t) => t,
            Err(e) => {
                log::warn!("Failed to start transaction for batch of {} events: {}", count, e);
                return;
            }
        };
        for event in &batch {
            if let Err(e) = insert_event(&tx, event) {
                log::warn!("Failed to insert event: {}", e);
            }
        }
        if let Err(e) = tx.commit() {
            log::warn!("Failed to commit batch of {} events: {}", count, e);
        }

        log::debug!("Stored {} events in single transaction", count);
    }
}

fn insert_event(conn: &rusqlite::Transaction, event: &TelemetryEvent) -> Result<(), rusqlite::Error> {
    match event {
        TelemetryEvent::ProcessCreated { pid, parent_pid, name, path, command_line, session_id, timestamp, user_sid, trust_info } => {
            let (is_signed, is_microsoft, signer) = trust_info_to_fields(trust_info);
            conn.execute(
                "INSERT OR REPLACE INTO processes (pid, parent_pid, name, path, command_line, session_id, user_sid, start_time, is_alive, signer, is_signed, is_microsoft)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11)",
                rusqlite::params![pid, parent_pid, name, path, command_line, session_id, user_sid, timestamp, signer, is_signed, is_microsoft],
            )?;
        }
        TelemetryEvent::ProcessTerminated { pid, exit_code, timestamp } => {
            conn.execute(
                "UPDATE processes SET exit_time=?1, exit_code=?2, is_alive=0 WHERE pid=?3 AND is_alive=1",
                rusqlite::params![timestamp, exit_code, pid],
            )?;
        }
        TelemetryEvent::ImageLoaded { pid, process_name, image_path, image_base, image_size, timestamp, trust_info, pe_anomalies } => {
            let (is_signed, is_microsoft, signer) = trust_info_to_fields(trust_info);
            let anomalies_json = serde_json::to_string(pe_anomalies).unwrap_or_default();
            conn.execute(
                "INSERT INTO image_loads (pid, process_name, image_path, image_base, image_size, timestamp, signer, is_signed, is_microsoft, anomalies)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![pid, process_name, image_path, image_base, image_size, timestamp, signer, is_signed, is_microsoft, anomalies_json],
            )?;
        }
        TelemetryEvent::SuspiciousActivity { rule_name, severity, description, pid, process_name, evidence, timestamp } => {
            let evidence_json = serde_json::to_string(evidence).unwrap_or_default();
            conn.execute(
                "INSERT INTO detections (rule_name, severity, description, pid, process_name, evidence, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![rule_name, severity, description, pid, process_name, evidence_json, timestamp],
            )?;
        }
        TelemetryEvent::IntegrityAlert { pid, process_name, alert_type, details, timestamp } => {
            conn.execute(
                "INSERT INTO integrity_alerts (pid, process_name, alert_type, details, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![pid, process_name, alert_type, details, timestamp],
            )?;
        }
        TelemetryEvent::MemoryChanged { .. } => {
            // Memory delta events are transient — not persisted to storage
        }
        _ => {}
    }
    Ok(())
}

fn trust_info_to_fields(info: &Option<TrustInfo>) -> (i32, i32, Option<String>) {
    match info {
        Some(ti) => (ti.is_signed as i32, ti.is_microsoft as i32, ti.signer.clone()),
        None => (0, 0, None),
    }
}

pub fn get_db_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Temp"));
    base.join("IntegrityMonitor").join("integrity_monitor.db")
}

pub struct DatabaseReader {
    conn: Mutex<rusqlite::Connection>,
}

impl DatabaseReader {
    pub fn new(path: &PathBuf) -> Self {
        let conn = rusqlite::Connection::open(path)
            .expect("Failed to open database for reader");
        conn.execute_batch("PRAGMA journal_mode=WAL;").ok();
        conn.execute_batch("PRAGMA synchronous=NORMAL;").ok();
        Self { conn: Mutex::new(conn) }
    }

    pub fn get_detections(&self, severity: Option<&str>, limit: usize) -> Vec<serde_json::Value> {
        let c = self.conn.lock();
        let mut results = Vec::new();
        if let Some(sev) = severity {
            if let Ok(mut stmt) = c.prepare(
                "SELECT rule_name, severity, description, pid, process_name, evidence, timestamp FROM detections WHERE severity=?1 ORDER BY timestamp DESC LIMIT ?2"
            ) {
                if let Ok(rows) = stmt.query_map(rusqlite::params![sev, limit], |row| {
                    Ok(serde_json::json!({
                        "ruleName": row.get::<_, String>(0)?,
                        "severity": row.get::<_, String>(1)?,
                        "description": row.get::<_, String>(2)?,
                        "pid": row.get::<_, i32>(3)?,
                        "processName": row.get::<_, String>(4)?,
                        "evidence": row.get::<_, String>(5)?,
                        "timestamp": row.get::<_, String>(6)?,
                    }))
                }) {
                    for row in rows.flatten() { results.push(row); }
                }
            }
        } else {
            if let Ok(mut stmt) = c.prepare(
                "SELECT rule_name, severity, description, pid, process_name, evidence, timestamp FROM detections ORDER BY timestamp DESC LIMIT ?1"
            ) {
                if let Ok(rows) = stmt.query_map(rusqlite::params![limit], |row| {
                    Ok(serde_json::json!({
                        "ruleName": row.get::<_, String>(0)?,
                        "severity": row.get::<_, String>(1)?,
                        "description": row.get::<_, String>(2)?,
                        "pid": row.get::<_, i32>(3)?,
                        "processName": row.get::<_, String>(4)?,
                        "evidence": row.get::<_, String>(5)?,
                        "timestamp": row.get::<_, String>(6)?,
                    }))
                }) {
                    for row in rows.flatten() { results.push(row); }
                }
            }
        }
        results
    }

    pub fn get_process_history(&self, limit: usize) -> Vec<serde_json::Value> {
        let c = self.conn.lock();
        let mut results = Vec::new();
        if let Ok(mut stmt) = c.prepare(
            "SELECT pid, parent_pid, name, path, command_line, start_time, exit_time, is_alive, signer, is_signed FROM processes ORDER BY start_time DESC LIMIT ?1"
        ) {
            if let Ok(rows) = stmt.query_map(rusqlite::params![limit], |row| {
                Ok(serde_json::json!({
                    "pid": row.get::<_, i32>(0)?,
                    "parentPid": row.get::<_, i32>(1)?,
                    "name": row.get::<_, String>(2)?,
                    "path": row.get::<_, String>(3)?,
                    "commandLine": row.get::<_, String>(4)?,
                    "startTime": row.get::<_, String>(5)?,
                    "exitTime": row.get::<_, Option<String>>(6)?,
                    "isAlive": row.get::<_, i32>(7)? == 1,
                    "signer": row.get::<_, Option<String>>(8)?,
                    "isSigned": row.get::<_, i32>(9)? == 1,
                }))
            }) {
                for row in rows.flatten() { results.push(row); }
            }
        }
        results
    }

    pub fn get_image_loads(&self, pid: Option<u32>, limit: usize) -> Vec<serde_json::Value> {
        let c = self.conn.lock();
        let mut results = Vec::new();
        if let Some(p) = pid {
            if let Ok(mut stmt) = c.prepare(
                "SELECT image_path, image_base, image_size, timestamp, signer, is_signed, anomalies, hash FROM image_loads WHERE pid=?1 ORDER BY timestamp DESC LIMIT ?2"
            ) {
                if let Ok(rows) = stmt.query_map(rusqlite::params![p, limit], |row| {
                    Ok(serde_json::json!({
                        "imagePath": row.get::<_, String>(0)?,
                        "imageBase": row.get::<_, i64>(1)?,
                        "imageSize": row.get::<_, i64>(2)?,
                        "timestamp": row.get::<_, String>(3)?,
                        "signer": row.get::<_, Option<String>>(4)?,
                        "isSigned": row.get::<_, i32>(5)? == 1,
                        "anomalies": row.get::<_, String>(6)?,
                        "hash": row.get::<_, String>(7)?,
                    }))
                }) {
                    for row in rows.flatten() { results.push(row); }
                }
            }
        } else {
            if let Ok(mut stmt) = c.prepare(
                "SELECT image_path, image_base, image_size, timestamp, signer, is_signed, anomalies, hash FROM image_loads ORDER BY timestamp DESC LIMIT ?1"
            ) {
                if let Ok(rows) = stmt.query_map(rusqlite::params![limit], |row| {
                    Ok(serde_json::json!({
                        "imagePath": row.get::<_, String>(0)?,
                        "imageBase": row.get::<_, i64>(1)?,
                        "imageSize": row.get::<_, i64>(2)?,
                        "timestamp": row.get::<_, String>(3)?,
                        "signer": row.get::<_, Option<String>>(4)?,
                        "isSigned": row.get::<_, i32>(5)? == 1,
                        "anomalies": row.get::<_, String>(6)?,
                        "hash": row.get::<_, String>(7)?,
                    }))
                }) {
                    for row in rows.flatten() { results.push(row); }
                }
            }
        }
        results
    }

    pub fn search(&self, query: &str, limit: usize) -> Vec<serde_json::Value> {
        let c = self.conn.lock();
        let mut results = Vec::new();
        let pattern = format!("%{}%", query);
        if let Ok(mut stmt) = c.prepare(
            "SELECT pid, name, path, command_line, start_time, signer, is_signed FROM processes WHERE name LIKE ?1 OR path LIKE ?1 OR command_line LIKE ?1 ORDER BY start_time DESC LIMIT ?2"
        ) {
            if let Ok(rows) = stmt.query_map(rusqlite::params![pattern, limit], |row| {
                Ok(serde_json::json!({
                    "type": "process",
                    "pid": row.get::<_, i32>(0)?,
                    "name": row.get::<_, String>(1)?,
                    "path": row.get::<_, String>(2)?,
                    "commandLine": row.get::<_, String>(3)?,
                    "timestamp": row.get::<_, String>(4)?,
                    "signer": row.get::<_, Option<String>>(5)?,
                    "isSigned": row.get::<_, i32>(6)? == 1,
                }))
            }) {
                for row in rows.flatten() { results.push(row); }
            }
        }
        if let Ok(mut stmt) = c.prepare(
            "SELECT image_path, pid, timestamp, signer, is_signed FROM image_loads WHERE image_path LIKE ?1 ORDER BY timestamp DESC LIMIT ?2"
        ) {
            if let Ok(rows) = stmt.query_map(rusqlite::params![pattern, limit], |row| {
                Ok(serde_json::json!({
                    "type": "image",
                    "path": row.get::<_, String>(0)?,
                    "pid": row.get::<_, i32>(1)?,
                    "timestamp": row.get::<_, String>(2)?,
                    "signer": row.get::<_, Option<String>>(3)?,
                    "isSigned": row.get::<_, i32>(4)? == 1,
                }))
            }) {
                for row in rows.flatten() { results.push(row); }
            }
        }
        results
    }
}
