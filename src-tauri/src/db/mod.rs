pub mod schema;

use std::path::PathBuf;
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<rusqlite::Connection>,
}

impl Database {
    pub fn new() -> Result<Self, rusqlite::Error> {
        let db_path = Self::db_path();
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = rusqlite::Connection::open(&db_path)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn initialize_schema(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        conn.execute_batch(schema::CREATE_PROCESSES_TABLE).map_err(|e| e.to_string())?;
        conn.execute_batch(schema::CREATE_FILE_EVENTS_TABLE).map_err(|e| e.to_string())?;
        conn.execute_batch(schema::CREATE_TIMELINE_TABLE).map_err(|e| e.to_string())?;
        conn.execute_batch(schema::CREATE_CORRELATIONS_TABLE).map_err(|e| e.to_string())?;
        conn.execute_batch(schema::CREATE_MODULES_TABLE).map_err(|e| e.to_string())?;
        conn.execute_batch(schema::CREATE_EMULATOR_TABLE).map_err(|e| e.to_string())?;
        conn.execute_batch(schema::CREATE_SUSPICION_SCORES_TABLE).map_err(|e| e.to_string())?;
        conn.execute_batch(schema::CREATE_ARTIFACTS_TABLE).map_err(|e| e.to_string())?;
        conn.execute_batch(schema::CREATE_NETWORK_EVENTS_TABLE).map_err(|e| e.to_string())?;
        conn.execute_batch(schema::CREATE_ALERTS_TABLE).map_err(|e| e.to_string())?;
        conn.execute_batch(schema::CREATE_INDEXES).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn enable_wal(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;")
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn insert_process(
        &self,
        pid: u32,
        parent_pid: u32,
        name: &str,
        path: &str,
        command_line: &str,
        timestamp: &str,
        session_id: u32,
    ) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO processes (pid, parent_pid, name, path, command_line, start_time, session_id, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))",
            rusqlite::params![pid, parent_pid, name, path, command_line, timestamp, session_id],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn update_process_termination(&self, pid: u32, exit_code: u32, timestamp: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "UPDATE processes SET exit_code = ?1, last_seen = ?2 WHERE pid = ?3",
            rusqlite::params![exit_code, timestamp, pid],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn insert_file_event(
        &self,
        path: &str,
        file_name: &str,
        event_type: &str,
        timestamp: &str,
        size: u64,
        pid: Option<u32>,
        process_name: Option<&str>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO file_events (path, file_name, event_type, timestamp, size, process_pid, process_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![path, file_name, event_type, timestamp, size, pid, process_name],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn insert_network_event(
        &self,
        pid: u32,
        process_name: &str,
        local_addr: &str,
        local_port: u16,
        remote_addr: &str,
        remote_port: u16,
        protocol: &str,
        timestamp: &str,
    ) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO network_events (pid, process_name, local_addr, local_port, remote_addr, remote_port, protocol, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![pid, process_name, local_addr, local_port, remote_addr, remote_port, protocol, timestamp],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn insert_alert(
        &self,
        rule_name: &str,
        severity: &str,
        description: &str,
        pid: u32,
        process_name: &str,
        evidence: &[String],
        timestamp: &str,
    ) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let evidence_json = serde_json::to_string(evidence).unwrap_or_default();
        conn.execute(
            "INSERT INTO alerts (rule_name, severity, description, pid, process_name, evidence, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![rule_name, severity, description, pid, process_name, evidence_json, timestamp],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn begin_transaction(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        conn.execute_batch("BEGIN IMMEDIATE").map_err(|e| e.to_string())
    }

    pub fn commit_transaction(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        conn.execute_batch("COMMIT").map_err(|e| e.to_string())
    }

    #[allow(dead_code)]
    pub fn query_timeline(&self, limit: usize, offset: usize) -> Result<Vec<serde_json::Value>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event_type, category, description, severity, source,
                    process_name, pid, path, details
             FROM timeline_events ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2"
        ).map_err(|e| e.to_string())?;

        let rows = stmt.query_map(rusqlite::params![limit as i64, offset as i64], |row| {
            let details_str: String = row.get(10).unwrap_or_default();
            let details: serde_json::Value = serde_json::from_str(&details_str).unwrap_or(serde_json::Value::Null);
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0).unwrap_or_default(),
                "timestamp": row.get::<_, String>(1).unwrap_or_default(),
                "eventType": row.get::<_, String>(2).unwrap_or_default(),
                "category": row.get::<_, String>(3).unwrap_or_default(),
                "description": row.get::<_, String>(4).unwrap_or_default(),
                "severity": row.get::<_, String>(5).unwrap_or_default(),
                "source": row.get::<_, String>(6).unwrap_or_default(),
                "processName": row.get::<_, Option<String>>(7).unwrap_or(None),
                "pid": row.get::<_, Option<i64>>(8).unwrap_or(None),
                "path": row.get::<_, Option<String>>(9).unwrap_or(None),
                "details": details,
            }))
        }).map_err(|e| e.to_string())?;

        let mut results = Vec::new();
        for row in rows {
            if let Ok(val) = row {
                results.push(val);
            }
        }
        Ok(results)
    }

    fn db_path() -> PathBuf {
        let base = std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        base.join("IntegrityMonitor").join("integrity_monitor.db")
    }
}
