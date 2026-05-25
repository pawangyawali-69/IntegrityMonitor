use crate::telemetry::TelemetryEvent;
use parking_lot::Mutex;
use rusqlite::Connection;
use std::path::PathBuf;

/// Append-only SQLite event journal with watermark-based replay.
/// Every event emitted through EventBus is persisted here before broadcast.
/// On startup, unprocessed events are replayed to rebuild correlation state.
pub struct EventJournal {
    conn: Mutex<Connection>,
    _db_path: PathBuf,
}

impl EventJournal {
    pub fn open(db_path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA journal_mode=WAL;").map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;").map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA busy_timeout=5000;").map_err(|e| e.to_string())?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS event_journal (
                seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS journal_watermark (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_replayed_seq INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO journal_watermark (id, last_replayed_seq) VALUES (1, 0);"
        ).map_err(|e| e.to_string())?;

        Ok(Self { conn: Mutex::new(conn), _db_path: db_path })
    }

    pub fn append_batch(&self, events: &[TelemetryEvent]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let c = self.conn.lock();
        let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
        for event in events {
            let event_json = serde_json::to_string(event).map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO event_journal (event_json) VALUES (?1)",
                rusqlite::params![event_json],
            ).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_watermark(&self) -> i64 {
        let c = self.conn.lock();
        c.query_row(
            "SELECT last_replayed_seq FROM journal_watermark WHERE id = 1",
            [],
            |row| row.get(0),
        ).unwrap_or(0)
    }

    pub fn set_watermark(&self, seq: i64) -> Result<(), String> {
        let c = self.conn.lock();
        c.execute(
            "UPDATE journal_watermark SET last_replayed_seq = ?1 WHERE id = 1",
            rusqlite::params![seq],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn replay_from(&self, seq: i64) -> Result<Vec<(i64, TelemetryEvent)>, String> {
        let c = self.conn.lock();
        let mut stmt = c.prepare(
            "SELECT seq_id, event_json FROM event_journal WHERE seq_id > ?1 ORDER BY seq_id ASC"
        ).map_err(|e| e.to_string())?;
        let rows = stmt.query_map(rusqlite::params![seq], |row| {
            let seq_id: i64 = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((seq_id, json))
        }).map_err(|e| e.to_string())?;

        let mut result = Vec::new();
        for row in rows {
            let (seq_id, json) = row.map_err(|e| e.to_string())?;
            match serde_json::from_str::<TelemetryEvent>(&json) {
                Ok(event) => result.push((seq_id, event)),
                Err(e) => log::warn!("Journal replay: skipping deserialization error at seq {}: {}", seq_id, e),
            }
        }
        Ok(result)
    }

    pub fn prune_before(&self, seq: i64) -> Result<(), String> {
        let c = self.conn.lock();
        c.execute("DELETE FROM event_journal WHERE seq_id <= ?1", rusqlite::params![seq])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn count(&self) -> Result<i64, String> {
        let c = self.conn.lock();
        c.query_row("SELECT COUNT(*) FROM event_journal", [], |row| row.get(0))
            .map_err(|e| e.to_string())
    }
}

pub fn get_journal_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Temp"));
    base.join("IntegrityMonitor").join("event_journal.db")
}

/// Start the background journal worker thread.
/// Receives events from the crossbeam channel and writes them to SQLite in batches.
pub fn start_journal_worker(rx: crossbeam::channel::Receiver<TelemetryEvent>, db_path: PathBuf) {
    std::thread::spawn(move || {
        let journal = match EventJournal::open(db_path) {
            Ok(j) => j,
            Err(e) => {
                log::error!("Journal worker: failed to open: {}", e);
                return;
            }
        };

        let mut batch: Vec<TelemetryEvent> = Vec::with_capacity(100);

        loop {
            match rx.recv() {
                Ok(event) => batch.push(event),
                Err(crossbeam::channel::RecvError) => {
                    log::warn!("Journal worker: channel disconnected");
                    return;
                }
            }

            while batch.len() < 100 {
                match rx.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(crossbeam::channel::TryRecvError::Empty) => break,
                    Err(crossbeam::channel::TryRecvError::Disconnected) => {
                        log::warn!("Journal worker: channel disconnected during drain");
                        break;
                    }
                }
            }

            if let Err(e) = journal.append_batch(&batch) {
                log::error!("Journal worker: write failed: {}", e);
            }

            batch.clear();
        }
    });
}

/// Replay unprocessed events from the journal into the event bus.
/// Uses watermark to determine which events have already been replayed.
pub fn replay_journal(event_bus: &crate::telemetry::EventBus) {
    let db_path = get_journal_path();
    let journal = match EventJournal::open(db_path) {
        Ok(j) => j,
        Err(e) => {
            log::error!("Journal replay: failed to open: {}", e);
            return;
        }
    };

    let watermark = journal.get_watermark();
    let events = match journal.replay_from(watermark) {
        Ok(e) => e,
        Err(e) => {
            log::error!("Journal replay: read failed: {}", e);
            return;
        }
    };

    if events.is_empty() {
        log::info!("Journal replay: no unprocessed events (watermark={})", watermark);
        return;
    }

    log::info!("Journal replay: replaying {} events from seq {}", events.len(), watermark);

    let mut max_seq = watermark;
    for (seq_id, event) in &events {
        event_bus.broadcast(event.clone());
        if *seq_id > max_seq {
            max_seq = *seq_id;
        }
    }

    if let Err(e) = journal.set_watermark(max_seq) {
        log::error!("Journal replay: watermark update failed: {}", e);
    }

    log::info!("Journal replay: completed, watermark set to {}", max_seq);
}
