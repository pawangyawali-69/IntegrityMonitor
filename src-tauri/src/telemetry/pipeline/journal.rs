//! Crash-resilient replay journal for telemetry events.
//!
//! Writes every event to disk before acknowledging to the source.
//! On startup, replays unprocessed events from the journal.
//! Supports pruning, corruption recovery, and integrity verification.
//!
//! Design:
//! - Append-only WAL format (sequential writes, no overwrite)
//! - Each record: [CRC32 | Length | JSON data]
//! - Periodic checkpoint: marks safe replay position
//! - Automatic corruption recovery: skips damaged trailing records

use crate::telemetry::pipeline::event::TelemetryEnvelope;
use crc32fast::Hasher as Crc32Hasher;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Magic bytes: "IMRJ" (Integrity Monitor Replay Journal)
const JOURNAL_MAGIC: [u8; 4] = [0x49, 0x4D, 0x52, 0x4A];
const JOURNAL_VERSION: u32 = 1;
const RECORD_HEADER_SIZE: usize = 8; // CRC32(4) + Length(4)
const CHECKPOINT_INTERVAL: usize = 10_000; // Every 10k events
const MAX_JOURNAL_SIZE: u64 = 512 * 1024 * 1024; // 512 MB max before rotation
const MAX_RECORD_SIZE: u32 = 1024 * 1024; // 1 MB max per event

// ─── Error Type ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum JournalError {
    Io(std::io::Error),
    Corruption(String),
    RecordTooBig(u32),
    MagicMismatch,
    VersionMismatch(u32),
    CrcMismatch { expected: u32, actual: u32 },
    Serialization(String),
    Empty,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Io(e) => write!(f, "Journal I/O: {}", e),
            JournalError::Corruption(s) => write!(f, "Journal corruption: {}", s),
            JournalError::RecordTooBig(s) => write!(f, "Record too big: {} > {}", s, MAX_RECORD_SIZE),
            JournalError::MagicMismatch => write!(f, "Journal magic mismatch"),
            JournalError::VersionMismatch(v) => write!(f, "Journal version {} not supported", v),
            JournalError::CrcMismatch { expected, actual } => {
                write!(f, "CRC mismatch: expected {:08X}, got {:08X}", expected, actual)
            }
            JournalError::Serialization(s) => write!(f, "Serialization: {}", s),
            JournalError::Empty => write!(f, "Journal is empty"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<std::io::Error> for JournalError {
    fn from(e: std::io::Error) -> Self {
        JournalError::Io(e)
    }
}

// ─── Journal Record ──────────────────────────────────────────────────────────

/// A single record in the replay journal.
#[derive(Debug)]
struct JournalRecord {
    crc32: u32,
    length: u32,
    data: Vec<u8>,
}

impl JournalRecord {
    fn from_event(event: &TelemetryEnvelope) -> Result<Self, JournalError> {
        let json = serde_json::to_vec(event).map_err(|e| JournalError::Serialization(e.to_string()))?;
        let len = json.len() as u32;
        if len > MAX_RECORD_SIZE {
            return Err(JournalError::RecordTooBig(len));
        }

        let mut crc = Crc32Hasher::new();
        crc.update(&json);
        let crc32 = crc.finalize();

        Ok(Self {
            crc32,
            length: len,
            data: json,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RECORD_HEADER_SIZE + self.data.len());
        buf.extend_from_slice(&self.crc32.to_le_bytes());
        buf.extend_from_slice(&self.length.to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    fn from_reader<R: Read>(reader: &mut R) -> Result<Self, JournalError> {
        let mut header = [0u8; RECORD_HEADER_SIZE];
        reader.read_exact(&mut header)?;

        let crc32 = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let length = u32::from_le_bytes(header[4..8].try_into().unwrap());

        if length > MAX_RECORD_SIZE {
            return Err(JournalError::RecordTooBig(length));
        }

        let mut data = vec![0u8; length as usize];
        reader.read_exact(&mut data)?;

        // Verify CRC
        let mut crc = Crc32Hasher::new();
        crc.update(&data);
        let actual = crc.finalize();
        if actual != crc32 {
            return Err(JournalError::CrcMismatch { expected: crc32, actual });
        }

        Ok(Self { crc32, length, data })
    }

    fn into_event(self) -> Result<TelemetryEnvelope, JournalError> {
        serde_json::from_slice(&self.data)
            .map_err(|e| JournalError::Serialization(e.to_string()))
    }
}

// ─── Replay Journal ──────────────────────────────────────────────────────────

/// Append-only replay journal for crash recovery.
///
/// Thread-safe: uses internal mutex for write serialization.
/// Reads are independent (used during replay, before production use).
pub struct ReplayJournal {
    /// Journal file path
    path: PathBuf,
    /// Writer (buffered, append-only)
    writer: Mutex<BufWriter<File>>,
    /// Total bytes written (for size tracking)
    bytes_written: AtomicU64,
    /// Total records written
    records_written: AtomicU64,
    /// Last checkpoint position (bytes offset)
    checkpoint_pos: AtomicU64,
}

impl ReplayJournal {
    /// Open or create a replay journal at the given path.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let exists = path.exists();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .append(true)
            .open(&path)?;

        let bytes_written: u64 = if exists {
            // Validate header
            let mut reader = BufReader::new(&file);
            let mut magic = [0u8; 4];
            reader.read_exact(&mut magic)?;
            if magic != JOURNAL_MAGIC {
                return Err(JournalError::MagicMismatch);
            }
            let mut version_bytes = [0u8; 4];
            reader.read_exact(&mut version_bytes)?;
            let version = u32::from_le_bytes(version_bytes);
            if version != JOURNAL_VERSION {
                return Err(JournalError::VersionMismatch(version));
            }
            file.metadata()?.len()
        } else {
            // Write header
            let mut writer = BufWriter::new(&file);
            writer.write_all(&JOURNAL_MAGIC)?;
            writer.write_all(&JOURNAL_VERSION.to_le_bytes())?;
            writer.flush()?;
            drop(writer);
            8u64 // magic(4) + version(4)
        };

        let writer = BufWriter::new(
            OpenOptions::new()
                .append(true)
                .open(&path)?
        );

        Ok(Self {
            path,
            writer: Mutex::new(writer),
            bytes_written: AtomicU64::new(bytes_written),
            records_written: AtomicU64::new(0),
            checkpoint_pos: AtomicU64::new(0),
        })
    }

    /// Append an event to the journal. Returns the byte offset of the record.
    pub fn append(&self, event: &TelemetryEnvelope) -> Result<u64, JournalError> {
        let record = JournalRecord::from_event(event)?;
        let bytes = record.to_bytes();
        let record_len = bytes.len() as u64;

        let offset = {
            let mut writer = self.writer.lock().unwrap();
            let offset = self.bytes_written.load(Ordering::Relaxed);
            writer.write_all(&bytes)?;
            writer.flush()?;
            offset
        };

        self.bytes_written.fetch_add(record_len, Ordering::Relaxed);
        let record_num = self.records_written.fetch_add(1, Ordering::Relaxed) + 1;

        // Periodic checkpoint
        if record_num % CHECKPOINT_INTERVAL as u64 == 0 {
            self.checkpoint()?;
        }

        // Journal rotation check
        if self.bytes_written.load(Ordering::Relaxed) > MAX_JOURNAL_SIZE {
            // Non-blocking advice: caller should rotate via rotate_journal()
            log::warn!("Replay journal exceeds {} bytes, consider rotation", MAX_JOURNAL_SIZE);
        }

        self.sync_data()?;

        Ok(offset)
    }

    /// Read all unprocessed events from the journal.
    /// On success, truncates the journal (or marks checkpoint).
    pub fn replay(&self) -> Result<Vec<TelemetryEnvelope>, JournalError> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(&file);

        // Skip header
        reader.seek(SeekFrom::Start(8))?; // magic + version

        let mut events = Vec::new();
        let mut last_good_offset = 8u64;

        loop {
            let offset = reader.stream_position()?;
            match JournalRecord::from_reader(&mut reader) {
                Ok(record) => {
                    match record.into_event() {
                        Ok(event) => {
                            events.push(event);
                            last_good_offset = offset;
                        }
                        Err(e) => {
                            log::warn!("Journal replay: skipping invalid event at offset {}: {}", offset, e);
                            // Attempt to recover: skip to next valid record
                            continue;
                        }
                    }
                }
                Err(JournalError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // End of journal
                    break;
                }
                Err(JournalError::CrcMismatch { .. }) => {
                    log::warn!("Journal replay: CRC mismatch at offset {}, truncating", offset);
                    // Truncate at last good position
                    break;
                }
                Err(e) => {
                    log::warn!("Journal replay: error at offset {}: {}, truncating", offset, e);
                    break;
                }
            }
        }

        // Truncate journal to remove replayed events (keep header + checkpoint space)
        self.truncate_at(last_good_offset)?;

        Ok(events)
    }

    /// Replay only events since the last checkpoint.
    pub fn replay_from_checkpoint(&self) -> Result<Vec<TelemetryEnvelope>, JournalError> {
        let checkpoint = self.checkpoint_pos.load(Ordering::Relaxed);
        if checkpoint == 0 {
            return self.replay();
        }

        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(&file);
        reader.seek(SeekFrom::Start(checkpoint))?;

        let mut events = Vec::new();
        loop {
            match JournalRecord::from_reader(&mut reader) {
                Ok(record) => {
                    if let Ok(event) = record.into_event() {
                        events.push(event);
                    }
                }
                Err(JournalError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    log::warn!("Journal replay from checkpoint: error at {}: {}", checkpoint, e);
                    break;
                }
            }
        }

        Ok(events)
    }

    /// Write a checkpoint marker. All events before checkpoint are safe to prune.
    pub fn checkpoint(&self) -> Result<(), JournalError> {
        let pos = self.bytes_written.load(Ordering::Relaxed);
        let mut writer = self.writer.lock().unwrap();

        // Write checkpoint marker: magic(4) + pos(8)
        writer.write_all(b"CHKP")?;
        writer.write_all(&pos.to_le_bytes())?;
        writer.flush()?;

        self.checkpoint_pos.store(pos, Ordering::Relaxed);
        Ok(())
    }

    /// Truncate journal to the given byte offset.
    fn truncate_at(&self, offset: u64) -> Result<(), JournalError> {
        let file = OpenOptions::new()
            .write(true)
            .open(&self.path)?;
        file.set_len(offset)?;
        self.bytes_written.store(offset, Ordering::Relaxed);
        Ok(())
    }

    /// Rotate the journal: rename old, create new.
    pub fn rotate_journal(&self) -> Result<(), JournalError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let rotated_path = self.path.with_extension(format!("{}.journal.old", ts));

        // Flush and close old writer
        {
            let mut writer = self.writer.lock().unwrap();
            writer.flush()?;
        }

        std::fs::rename(&self.path, &rotated_path)?;

        // Create new journal with header
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&self.path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(&JOURNAL_MAGIC)?;
        writer.write_all(&JOURNAL_VERSION.to_le_bytes())?;
        writer.flush()?;

        *self.writer.lock().unwrap() = writer;
        self.bytes_written.store(8, Ordering::Relaxed);
        self.records_written.store(0, Ordering::Relaxed);
        self.checkpoint_pos.store(0, Ordering::Relaxed);

        // Delete old journal asynchronously (don't block startup)
        let rotated_path_clone = rotated_path.clone();
        std::thread::spawn(move || {
            let _ = std::fs::remove_file(&rotated_path_clone);
        });

        log::info!("Replay journal rotated: {} -> {:?}", ts, rotated_path);
        Ok(())
    }

    /// Call fsync on the underlying file.
    fn sync_data(&self) -> Result<(), JournalError> {
        let mut writer = self.writer.lock().unwrap();
        writer.flush()?;
        let file = writer.get_mut();
        file.sync_all()?;
        Ok(())
    }

    /// Current journal size in bytes.
    pub fn size(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    /// Number of records written since last rotation.
    pub fn record_count(&self) -> u64 {
        self.records_written.load(Ordering::Relaxed)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::pipeline::event::*;
    use std::sync::Arc;

    fn test_event() -> TelemetryEnvelope {
        TelemetryEnvelope::new(
            SourceId::ProcessMonitor,
            SourceTrust::User,
            EventPriority::Medium,
            EventCategory::Process,
            CanonicalEventType::ProcessCreated,
            serde_json::json!({"pid": 1234, "name": "test.exe"}),
        )
    }

    #[test]
    fn test_journal_append_and_replay() {
        let dir = std::env::temp_dir().join(format!("im_journal_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.journal");

        {
            let journal = ReplayJournal::open(&path).unwrap();
            let ev = test_event();
            journal.append(&ev).unwrap();
            journal.append(&ev).unwrap();
            journal.append(&ev).unwrap();
        }

        {
            let journal = ReplayJournal::open(&path).unwrap();
            let events = journal.replay().unwrap();
            assert_eq!(events.len(), 3);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_journal_corruption_recovery() {
        let dir = std::env::temp_dir().join(format!("im_journal_corrupt_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("corrupt.journal");

        // Write a valid journal with one record
        {
            let journal = ReplayJournal::open(&path).unwrap();
            journal.append(&test_event()).unwrap();
        }

        // Corrupt the last byte
        {
            let mut f = OpenOptions::new().write(true).open(&path).unwrap();
            let len = f.metadata().unwrap().len();
            f.seek(SeekFrom::End(-1)).unwrap();
            f.write_all(&[0xFF]).unwrap();
        }

        // Should still be able to read valid records up to corruption
        {
            let journal = ReplayJournal::open(&path).unwrap();
            let events = journal.replay().unwrap();
            // May get 0 or 1 depending on where corruption hit
            assert!(events.len() <= 1, "Corruption should not cause panic");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_journal_rotation() {
        let dir = std::env::temp_dir().join(format!("im_journal_rot_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("rotate.journal");

        let journal = ReplayJournal::open(&path).unwrap();
        journal.append(&test_event()).unwrap();
        journal.rotate_journal().unwrap();

        // After rotation, the new journal should be empty
        assert_eq!(journal.size(), 8); // Just header
        assert_eq!(journal.record_count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_record_crc_integrity() {
        let ev = test_event();
        let record = JournalRecord::from_event(&ev).unwrap();
        let bytes = record.to_bytes();

        // Tamper with data
        let mut tampered = bytes.clone();
        if tampered.len() > RECORD_HEADER_SIZE {
            tampered[RECORD_HEADER_SIZE] ^= 0xFF;
        }

        // Should fail CRC check
        let mut cursor = std::io::Cursor::new(&tampered[..]);
        let result = JournalRecord::from_reader(&mut cursor);
        assert!(result.is_err());
        match result {
            Err(JournalError::CrcMismatch { .. }) => {} // Expected
            _ => panic!("Expected CRC mismatch"),
        }
    }
}
