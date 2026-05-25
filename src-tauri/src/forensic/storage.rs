use crate::forensic::*;
use crate::forensic::timeline::AttackChain;
use crate::forensic::correlation::CorrelationChain;
use crate::forensic::anti_forensic::AntiForensicFinding;
use std::path::PathBuf;
use parking_lot::Mutex;
use std::sync::Arc;

/// Persistent storage for forensic artifacts.
/// Uses SQLite with WAL mode for concurrent reads and partition-aware tables.
pub struct ForensicStorage {
    conn: Arc<Mutex<rusqlite::Connection>>,
    db_path: PathBuf,
}

impl ForensicStorage {
    pub fn open(db_path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let conn = rusqlite::Connection::open(&db_path).map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA journal_mode=WAL;").map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;").map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA busy_timeout=5000;").map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA cache_size=-65536;").map_err(|e| e.to_string())?; // 64MB cache

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path,
        };
        storage.create_schema()?;
        Ok(storage)
    }

    fn create_schema(&self) -> Result<(), String> {
        let c = self.conn.lock();
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS forensic_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_raw INTEGER NOT NULL,
                volume_id INTEGER NOT NULL,
                file_reference TEXT NOT NULL,
                parent_reference TEXT NOT NULL,
                usn INTEGER NOT NULL,
                usn_reason INTEGER NOT NULL,
                source_info INTEGER NOT NULL DEFAULT 0,
                sequence_number INTEGER NOT NULL DEFAULT 0,
                filename TEXT NOT NULL,
                parent_path TEXT,
                process_pid INTEGER,
                process_name TEXT,
                forensic_hash BLOB,
                partition_hour INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS forensic_chains (
                id TEXT PRIMARY KEY,
                rule_name TEXT NOT NULL,
                pattern TEXT NOT NULL,
                description TEXT NOT NULL,
                confidence REAL NOT NULL,
                timestamp_start_raw INTEGER NOT NULL,
                timestamp_end_raw INTEGER NOT NULL,
                mitre_technique TEXT,
                evidence TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS anti_forensic_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                confidence REAL NOT NULL,
                affected_artifacts TEXT NOT NULL DEFAULT '[]',
                timestamp_raw INTEGER NOT NULL,
                mitre_technique TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS file_lifecycles (
                file_reference TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                created_raw INTEGER,
                deleted_raw INTEGER,
                rename_count INTEGER NOT NULL DEFAULT 0,
                modification_count INTEGER NOT NULL DEFAULT 0,
                associated_pids TEXT NOT NULL DEFAULT '[]',
                forensic_flags TEXT NOT NULL DEFAULT '[]',
                last_updated INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS forensic_watermarks (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_fevents_timestamp ON forensic_events(timestamp_raw);
            CREATE INDEX IF NOT EXISTS idx_fevents_frn ON forensic_events(file_reference);
            CREATE INDEX IF NOT EXISTS idx_fevents_partition ON forensic_events(partition_hour);
            CREATE INDEX IF NOT EXISTS idx_fevents_usn ON forensic_events(usn);
            CREATE INDEX IF NOT EXISTS idx_chains_confidence ON forensic_chains(confidence DESC);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON anti_forensic_findings(severity);"
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn store_events(&self, events: &[FilesystemEvent]) -> Result<usize, String> {
        let c = self.conn.lock();

        // Use transaction for batch insert
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        let mut count = 0;

        for event in events {
            let partition_hour = event.timestamp.raw / 3_600_000_0000; // 1 hour in 100ns ticks
            let hash_bytes: Option<Vec<u8>> = Some(event.forensic_hash.to_vec());

            tx.execute(
                "INSERT INTO forensic_events (timestamp_raw, volume_id, file_reference, parent_reference,
                 usn, usn_reason, source_info, sequence_number, filename, parent_path,
                 process_pid, process_name, forensic_hash, partition_hour)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                rusqlite::params![
                    event.timestamp.raw,
                    event.volume,
                    format!("{:016x}", event.file_reference),
                    format!("{:016x}", event.parent_reference),
                    event.usn,
                    event.usn_reason,
                    event.source_info,
                    event.sequence_number,
                    event.filename,
                    event.parent_path,
                    event.process_pid,
                    event.process_name,
                    hash_bytes,
                    partition_hour,
                ],
            ).map_err(|e| e.to_string())?;
            count += 1;
        }

        tx.commit().map_err(|e| e.to_string())?;
        Ok(count)
    }

    pub fn store_chains(&self, chains: &[CorrelationChain]) -> Result<usize, String> {
        let c = self.conn.lock();
        let mut count = 0;

        for chain in chains {
            let evidence_json = serde_json::to_string(&chain.evidence).unwrap_or_default();
            c.execute(
                "INSERT OR REPLACE INTO forensic_chains (id, rule_name, pattern, description,
                 confidence, timestamp_start_raw, timestamp_end_raw, mitre_technique, evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    chain.id,
                    chain.rule_name,
                    chain.pattern,
                    chain.description,
                    chain.confidence,
                    chain.timestamp_start.raw,
                    chain.timestamp_end.raw,
                    chain.mitre_technique,
                    evidence_json,
                ],
            ).map_err(|e| e.to_string())?;
            count += 1;
        }

        Ok(count)
    }

    pub fn store_findings(&self, findings: &[AntiForensicFinding]) -> Result<usize, String> {
        let c = self.conn.lock();
        let mut count = 0;

        for f in findings {
            let artifacts_json = serde_json::to_string(&f.affected_artifacts).unwrap_or_default();
            c.execute(
                "INSERT INTO anti_forensic_findings (finding_type, severity, description,
                 confidence, affected_artifacts, timestamp_raw, mitre_technique)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    format!("{:?}", f.finding_type),
                    format!("{:?}", f.severity),
                    f.description,
                    f.confidence,
                    artifacts_json,
                    f.timestamp.raw,
                    f.mitre_technique,
                ],
            ).map_err(|e| e.to_string())?;
            count += 1;
        }

        Ok(count)
    }

    pub fn get_watermark(&self, key: &str) -> Option<i64> {
        let c = self.conn.lock();
        c.query_row(
            "SELECT value FROM forensic_watermarks WHERE key = ?1",
            rusqlite::params![key],
            |row| row.get(0),
        ).ok()
    }

    pub fn set_watermark(&self, key: &str, value: i64) -> Result<(), String> {
        let c = self.conn.lock();
        c.execute(
            "INSERT OR REPLACE INTO forensic_watermarks (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn query_events_by_frn(&self, frn: FileReference, limit: usize) -> Result<Vec<FilesystemEvent>, String> {
        let c = self.conn.lock();
        let frn_str = format!("{:016x}", frn);
        let mut stmt = c.prepare(
            "SELECT timestamp_raw, volume_id, file_reference, parent_reference, usn, usn_reason,
             source_info, sequence_number, filename, parent_path, process_pid, process_name
             FROM forensic_events WHERE file_reference = ?1 ORDER BY timestamp_raw DESC LIMIT ?2"
        ).map_err(|e| e.to_string())?;

        let rows = stmt.query_map(rusqlite::params![frn_str, limit], |row| {
            Ok(FilesystemEvent {
                timestamp: Timestamp { raw: row.get(0)? },
                volume: row.get(1)?,
                file_reference: u64::from_str_radix(&row.get::<_, String>(2)?, 16).unwrap_or(0),
                parent_reference: u64::from_str_radix(&row.get::<_, String>(3)?, 16).unwrap_or(0),
                usn: row.get(4)?,
                usn_reason: row.get(5)?,
                source_info: row.get(6)?,
                sequence_number: row.get(7)?,
                mft_timestamps: None,
                filename: row.get(8)?,
                parent_path: row.get(9)?,
                process_pid: row.get(10)?,
                process_name: row.get(11)?,
                forensic_hash: [0u8; 32],
                corruption_flags: Vec::new(),
            })
        }).map_err(|e| e.to_string())?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(|e| e.to_string())?);
        }
        Ok(events)
    }

    pub fn query_events_by_time_range(&self, start_raw: i64, end_raw: i64, limit: usize) -> Result<Vec<FilesystemEvent>, String> {
        let c = self.conn.lock();
        let mut stmt = c.prepare(
            "SELECT timestamp_raw, volume_id, file_reference, parent_reference, usn, usn_reason,
             source_info, sequence_number, filename, parent_path, process_pid, process_name
             FROM forensic_events WHERE timestamp_raw >= ?1 AND timestamp_raw <= ?2
             ORDER BY timestamp_raw ASC LIMIT ?3"
        ).map_err(|e| e.to_string())?;

        let rows = stmt.query_map(rusqlite::params![start_raw, end_raw, limit], |row| {
            Ok(FilesystemEvent {
                timestamp: Timestamp { raw: row.get(0)? },
                volume: row.get(1)?,
                file_reference: u64::from_str_radix(&row.get::<_, String>(2)?, 16).unwrap_or(0),
                parent_reference: u64::from_str_radix(&row.get::<_, String>(3)?, 16).unwrap_or(0),
                usn: row.get(4)?,
                usn_reason: row.get(5)?,
                source_info: row.get(6)?,
                sequence_number: row.get(7)?,
                mft_timestamps: None,
                filename: row.get(8)?,
                parent_path: row.get(9)?,
                process_pid: row.get(10)?,
                process_name: row.get(11)?,
                forensic_hash: [0u8; 32],
                corruption_flags: Vec::new(),
            })
        }).map_err(|e| e.to_string())?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(|e| e.to_string())?);
        }
        Ok(events)
    }

    pub fn query_chains(&self, limit: usize, min_confidence: f64) -> Result<Vec<CorrelationChain>, String> {
        let c = self.conn.lock();
        let mut stmt = c.prepare(
            "SELECT id, rule_name, pattern, description, confidence,
             timestamp_start_raw, timestamp_end_raw, mitre_technique, evidence
             FROM forensic_chains WHERE confidence >= ?1 ORDER BY confidence DESC LIMIT ?2"
        ).map_err(|e| e.to_string())?;

        let rows = stmt.query_map(rusqlite::params![min_confidence, limit], |row| {
            Ok(CorrelationChain {
                id: row.get(0)?,
                rule_name: row.get(1)?,
                pattern: row.get(2)?,
                description: row.get(3)?,
                confidence: row.get(4)?,
                timestamp_start: Timestamp { raw: row.get(5)? },
                timestamp_end: Timestamp { raw: row.get(6)? },
                mitre_technique: row.get(7)?,
                evidence: serde_json::from_str(&row.get::<_, String>(8)?).unwrap_or_default(),
                events: Vec::new(),
                process_events: Vec::new(),
            })
        }).map_err(|e| e.to_string())?;

        let mut chains = Vec::new();
        for row in rows {
            chains.push(row.map_err(|e| e.to_string())?);
        }
        Ok(chains)
    }

    pub fn prune_hourly_partitions(&self, retention_hours: i64) -> Result<usize, String> {
        let cutoff = Timestamp::now().raw - retention_hours * 3_600_000_0000;
        let c = self.conn.lock();
        let count = c.execute(
            "DELETE FROM forensic_events WHERE partition_hour < ?1",
            rusqlite::params![cutoff / 3_600_000_0000],
        ).map_err(|e| e.to_string())?;
        Ok(count)
    }

    pub fn event_count(&self) -> Result<i64, String> {
        let c = self.conn.lock();
        c.query_row("SELECT COUNT(*) FROM forensic_events", [], |row| row.get(0))
            .map_err(|e| e.to_string())
    }

    pub fn chain_count(&self) -> Result<i64, String> {
        let c = self.conn.lock();
        c.query_row("SELECT COUNT(*) FROM forensic_chains", [], |row| row.get(0))
            .map_err(|e| e.to_string())
    }
}

pub fn get_forensic_db_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Temp"));
    base.join("IntegrityMonitor").join("forensic_engine.db")
}
