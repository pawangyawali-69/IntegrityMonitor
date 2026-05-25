use std::path::Path;
use std::fs::File;
use std::io::{Read, Seek};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use bitflags::bitflags;

// ─── USN Record Structures ──────────────────────────────────────────

pub const USN_RECORD_V2_MIN: usize = 60;
pub const USN_RECORD_V3_MIN: usize = 68;
pub const USN_RECORD_V4_MIN: usize = 80;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct UsnReason: u32 {
        const DATA_OVERWRITE        = 0x0000_0001;
        const DATA_EXTEND           = 0x0000_0002;
        const DATA_TRUNCATION       = 0x0000_0004;
        const NAMED_DATA_OVERWRITE  = 0x0000_0010;
        const NAMED_DATA_EXTEND     = 0x0000_0020;
        const NAMED_DATA_TRUNCATION = 0x0000_0040;
        const FILE_CREATE           = 0x0000_0100;
        const FILE_DELETE           = 0x0000_0200;
        const PROPERTY_CHANGE       = 0x0000_0400;
        const SECURITY_CHANGE      = 0x0000_0800;
        const RENAME_OLD_NAME       = 0x0000_1000;
        const RENAME_NEW_NAME       = 0x0000_2000;
        const INDEXABLE_CHANGE      = 0x0000_4000;
        const BASIC_INFO_CHANGE     = 0x0000_8000;
        const HARD_LINK_CHANGE      = 0x0001_0000;
        const COMPRESSION_CHANGE    = 0x0002_0000;
        const ENCRYPTION_CHANGE     = 0x0004_0000;
        const OBJECT_ID_CHANGE      = 0x0008_0000;
        const REPARSE_POINT_CHANGE  = 0x0010_0000;
        const STREAM_CHANGE         = 0x0020_0000;
        const TRANSACTED_CHANGE     = 0x0040_0000;
        const DIRECTORY_RENAME_OLD  = 0x0100_0000;
        const DIRECTORY_RENAME_NEW  = 0x0200_0000;
        const CLOSE                 = 0x8000_0000;
    }
}

impl UsnReason {
    pub fn display_flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.contains(Self::DATA_OVERWRITE) { flags.push("DATA_OVERWRITE"); }
        if self.contains(Self::DATA_EXTEND) { flags.push("DATA_EXTEND"); }
        if self.contains(Self::DATA_TRUNCATION) { flags.push("DATA_TRUNCATION"); }
        if self.contains(Self::NAMED_DATA_OVERWRITE) { flags.push("NAMED_DATA_OVERWRITE"); }
        if self.contains(Self::NAMED_DATA_EXTEND) { flags.push("NAMED_DATA_EXTEND"); }
        if self.contains(Self::NAMED_DATA_TRUNCATION) { flags.push("NAMED_DATA_TRUNCATION"); }
        if self.contains(Self::FILE_CREATE) { flags.push("FILE_CREATE"); }
        if self.contains(Self::FILE_DELETE) { flags.push("FILE_DELETE"); }
        if self.contains(Self::PROPERTY_CHANGE) { flags.push("PROPERTY_CHANGE"); }
        if self.contains(Self::SECURITY_CHANGE) { flags.push("SECURITY_CHANGE"); }
        if self.contains(Self::RENAME_OLD_NAME) { flags.push("RENAME_OLD_NAME"); }
        if self.contains(Self::RENAME_NEW_NAME) { flags.push("RENAME_NEW_NAME"); }
        if self.contains(Self::INDEXABLE_CHANGE) { flags.push("INDEXABLE_CHANGE"); }
        if self.contains(Self::BASIC_INFO_CHANGE) { flags.push("BASIC_INFO_CHANGE"); }
        if self.contains(Self::HARD_LINK_CHANGE) { flags.push("HARD_LINK_CHANGE"); }
        if self.contains(Self::COMPRESSION_CHANGE) { flags.push("COMPRESSION_CHANGE"); }
        if self.contains(Self::ENCRYPTION_CHANGE) { flags.push("ENCRYPTION_CHANGE"); }
        if self.contains(Self::OBJECT_ID_CHANGE) { flags.push("OBJECT_ID_CHANGE"); }
        if self.contains(Self::REPARSE_POINT_CHANGE) { flags.push("REPARSE_POINT_CHANGE"); }
        if self.contains(Self::STREAM_CHANGE) { flags.push("STREAM_CHANGE"); }
        if self.contains(Self::TRANSACTED_CHANGE) { flags.push("TRANSACTED_CHANGE"); }
        if self.contains(Self::DIRECTORY_RENAME_OLD) { flags.push("DIRECTORY_RENAME_OLD"); }
        if self.contains(Self::DIRECTORY_RENAME_NEW) { flags.push("DIRECTORY_RENAME_NEW"); }
        if self.contains(Self::CLOSE) { flags.push("CLOSE"); }
        flags
    }

    /// Returns true if this reason indicates a rename operation.
    pub fn is_rename(&self) -> bool {
        self.contains(Self::RENAME_OLD_NAME)
            || self.contains(Self::RENAME_NEW_NAME)
            || self.contains(Self::DIRECTORY_RENAME_OLD)
            || self.contains(Self::DIRECTORY_RENAME_NEW)
    }

    /// Human-readable summary of the reason flags.
    pub fn to_human_readable(&self) -> String {
        let parts = self.display_flags();
        if parts.is_empty() {
            "UNKNOWN".into()
        } else {
            parts.join(" | ")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileRef {
    Ntfs(u64),
    Refs(u128),
}

impl FileRef {
    pub fn entry_number(&self) -> u64 {
        match self {
            FileRef::Ntfs(v) => v & 0x0000_FFFF_FFFF_FFFF,
            FileRef::Refs(v) => *v as u64,
        }
    }

    pub fn sequence_number(&self) -> u16 {
        match self {
            FileRef::Ntfs(v) => (v >> 48) as u16,
            FileRef::Refs(v) => (*v >> 64) as u16,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedUsnRecord {
    pub record_length: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_reference: FileRef,
    pub parent_reference: FileRef,
    pub usn: u64,
    pub timestamp: DateTime<Utc>,
    pub reason: UsnReason,
    pub source_info: u32,
    pub file_attributes: u32,
    pub file_name: String,
    pub raw_reason: u32,
    pub source: RecordSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordSource {
    Allocated,     // from $UsnJrnl:$J
    Ghost,         // from $LogFile but not in $J
    Carved,        // from unallocated space
}

// ─── Type Aliases for Pre-existing API compatibility ─────────────────

pub type UsnJournalReader = StreamingJournalReader;
pub type UsnRecord = ParsedUsnRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VolumeId(pub u64);

impl std::fmt::Display for VolumeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Volume({:x})", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub id: VolumeId,
    pub usn_journal_id: u64,
    pub next_usn: i64,
    pub first_usn: i64,
    pub max_usn: i64,
    pub maximum_size: u64,
    pub allocation_delta: u64,
    pub major_version: u16,
    pub minor_version: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp {
    pub raw: i64,
}

impl Timestamp {
    pub fn now() -> Self {
        Self { raw: chrono::Utc::now().timestamp_nanos() }
    }

    pub fn from_filetime(ft: i64) -> Self {
        Self { raw: ft }
    }

    pub fn to_filetime(&self) -> i64 {
        self.raw
    }

    pub fn to_datetime(&self) -> chrono::DateTime<chrono::Utc> {
        if self.raw <= 0 {
            return chrono::DateTime::from_timestamp(0, 0).unwrap();
        }
        let unix_secs = self.raw / 10_000_000 - 11644473600;
        let nanos = (self.raw % 10_000_000).unsigned_abs() as u32 * 100;
        chrono::DateTime::from_timestamp(unix_secs, nanos).unwrap()
    }

    pub fn to_rfc3339(&self) -> String {
        self.to_datetime().to_rfc3339()
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_rfc3339())
    }
}

/// MFT timestamps container — combines SI and FN timestamp sets
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MftTimestamps {
    pub si_created: Timestamp,
    pub si_modified: Timestamp,
    pub si_mft_modified: Timestamp,
    pub si_accessed: Timestamp,
    pub fn_created: Option<Timestamp>,
    pub fn_modified: Option<Timestamp>,
    pub fn_mft_modified: Option<Timestamp>,
    pub fn_accessed: Option<Timestamp>,
}

impl MftTimestamps {
    pub fn created_datetime(&self) -> chrono::DateTime<chrono::Utc> {
        self.si_created.to_datetime()
    }

    pub fn fn_created_datetime(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.fn_created.map(|t| t.to_datetime())
    }
}

// ─── Streaming Reader ────────────────────────────────────────────────

enum ReadBacking {
    File(File),
    Cursor(std::io::Cursor<Vec<u8>>),
}

pub struct StreamingJournalReader {
    backing: ReadBacking,
    position: u64,
    end_position: u64,
    buffer: Vec<u8>,
    overlap_size: usize,
    pub stats: JournalReadStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalReadStats {
    pub total_records: u64,
    pub total_bytes: u64,
    pub corrupt_records: u64,
    pub version_v2: u64,
    pub version_v3: u64,
    pub version_v4: u64,
    pub skipped_gaps: u64,
    pub max_usn: u64,
    pub min_timestamp: i64,
    pub max_timestamp: i64,
}

impl Default for JournalReadStats {
    fn default() -> Self {
        Self {
            total_records: 0,
            total_bytes: 0,
            corrupt_records: 0,
            version_v2: 0,
            version_v3: 0,
            version_v4: 0,
            skipped_gaps: 0,
            max_usn: 0,
            min_timestamp: 0,
            max_timestamp: 0,
        }
    }
}

impl StreamingJournalReader {
    /// Returns volume info (for compatibility with anti_forensic API)
    pub fn volume(&self) -> &VolumeInfo {
        // Static fallback — real impl would query FSCTL_QUERY_USN_JOURNAL
        static DEFAULT_VOLUME: std::sync::LazyLock<VolumeInfo> = std::sync::LazyLock::new(|| {
            VolumeInfo {
                id: VolumeId(0),
                usn_journal_id: 0,
                next_usn: 0,
                first_usn: 0,
                max_usn: 0,
                maximum_size: 0,
                allocation_delta: 0,
                major_version: 2,
                minor_version: 0,
            }
        });
        &DEFAULT_VOLUME
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let file = File::open(path.as_ref())?;
        let end_position = file.metadata()?.len();
        Ok(Self {
            backing: ReadBacking::File(file),
            position: 0,
            end_position,
            buffer: Vec::with_capacity(65536),
            overlap_size: 256,
            stats: JournalReadStats::default(),
        })
    }

    /// Create a reader from an in-memory buffer (no file backing).
    /// Used for carved records and offline analysis.
    pub fn from_buffer(data: &[u8]) -> Self {
        let len = data.len() as u64;
        Self {
            backing: ReadBacking::Cursor(std::io::Cursor::new(data.to_vec())),
            position: 0,
            end_position: len,
            buffer: Vec::with_capacity(65536),
            overlap_size: 256,
            stats: JournalReadStats::default(),
        }
    }

    fn fill_buffer(&mut self) -> Result<usize, JournalError> {
        let read_size = self.buffer.capacity() - self.overlap_size;
        let mut temp = vec![0u8; read_size];
        let overlap_start = self.buffer.len().saturating_sub(self.overlap_size);
        let overlap_data = self.buffer[overlap_start..].to_vec();

        let bytes_read = match &mut self.backing {
            ReadBacking::File(f) => f.read(&mut temp)?,
            ReadBacking::Cursor(c) => c.read(&mut temp)?,
        };

        if bytes_read == 0 {
            return Ok(0);
        }
        self.buffer.clear();
        self.buffer.extend_from_slice(&overlap_data);
        self.buffer.extend_from_slice(&temp[..bytes_read]);
        self.position += bytes_read as u64;
        Ok(bytes_read + overlap_data.len())
    }

    pub fn read_all(&mut self) -> Result<Vec<ParsedUsnRecord>, JournalError> {
        let mut records = Vec::new();
        while let Some(record) = self.next_record()? {
            records.push(record);
        }
        Ok(records)
    }

    pub fn next_record(&mut self) -> Result<Option<ParsedUsnRecord>, JournalError> {
        loop {
            if self.buffer.len() < 64 && self.position < self.end_position {
                if self.fill_buffer()? == 0 {
                    return Ok(None);
                }
            }
            if self.buffer.len() < 64 {
                return Ok(None);
            }

            let mut found = false;
            let mut record_offset = 0;

            for offset in (0..self.buffer.len().saturating_sub(60)).step_by(8) {
                if self.try_valid_at(offset) {
                    found = true;
                    record_offset = offset;
                    break;
                }
            }

            if !found {
                let advance = self.buffer.len().saturating_sub(self.overlap_size);
                self.buffer.drain(..advance);
                self.stats.skipped_gaps += 1;
                continue;
            }

            let record_length = u32::from_le_bytes(
                self.buffer[record_offset..record_offset + 4].try_into().unwrap()
            ) as usize;

            if record_offset + record_length > self.buffer.len() {
                if self.position >= self.end_position {
                    return Err(JournalError::TruncatedRecord);
                }
                if self.fill_buffer()? == 0 {
                    return Err(JournalError::TruncatedRecord);
                }
                continue;
            }

            let parsed = self.parse_at(record_offset)?;
            self.buffer.drain(..record_offset + record_length);
            return Ok(Some(parsed));
        }
    }

    fn try_valid_at(&self, offset: usize) -> bool {
        if offset + 6 > self.buffer.len() {
            return false;
        }
        let record_length = u32::from_le_bytes(
            self.buffer[offset..offset + 4].try_into().unwrap()
        ) as usize;

        if record_length < USN_RECORD_V2_MIN || record_length > 65536 {
            return false;
        }
        if offset + record_length > self.buffer.len() {
            return false;
        }

        let major = u16::from_le_bytes(
            self.buffer[offset + 4..offset + 6].try_into().unwrap()
        );

        matches!(major, 2 | 3 | 4)
    }

    fn parse_at(&mut self, offset: usize) -> Result<ParsedUsnRecord, JournalError> {
        let data = &self.buffer[offset..];
        let record_length = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let major_version = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let minor_version = u16::from_le_bytes(data[6..8].try_into().unwrap());

        let (file_ref, parent_ref) = match major_version {
            2 | 3 => {
                let fr = u64::from_le_bytes(data[8..16].try_into().unwrap());
                let pr = u64::from_le_bytes(data[16..24].try_into().unwrap());
                (FileRef::Ntfs(fr), FileRef::Ntfs(pr))
            }
            4 => {
                let fr = u128::from_le_bytes(data[8..24].try_into().unwrap());
                let pr = u128::from_le_bytes(data[24..40].try_into().unwrap());
                (FileRef::Refs(fr), FileRef::Refs(pr))
            }
            _ => return Err(JournalError::UnsupportedVersion(major_version)),
        };

        let usn_offset = if major_version == 4 { 40 } else { 24 };
        let ts_offset = if major_version == 4 { 48 } else { 32 };

        let usn = u64::from_le_bytes(data[usn_offset..usn_offset + 8].try_into().unwrap());
        let timestamp_raw = i64::from_le_bytes(data[ts_offset..ts_offset + 8].try_into().unwrap());
        let reason = u32::from_le_bytes(data[ts_offset + 8..ts_offset + 12].try_into().unwrap());

        let (name_offset, name_length) = if major_version == 4 {
            let off = u16::from_le_bytes(data[ts_offset + 24..ts_offset + 26].try_into().unwrap());
            let len = u16::from_le_bytes(data[ts_offset + 22..ts_offset + 24].try_into().unwrap());
            (off, len)
        } else {
            let off = u16::from_le_bytes(data[0x3A..0x3C].try_into().unwrap());
            let len = u16::from_le_bytes(data[0x38..0x3A].try_into().unwrap());
            (off, len)
        };
        let source_info = u32::from_le_bytes(data[ts_offset + 12..ts_offset + 16].try_into().unwrap());
        let file_attributes = u32::from_le_bytes(data[ts_offset + 16..ts_offset + 20].try_into().unwrap());

        let name_start = name_offset as usize;
        let name_chars = name_length as usize / 2;
        let file_name = if name_start + name_chars * 2 <= data.len() {
            let name_utf16: Vec<u16> = data[name_start..name_start + name_chars * 2]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&name_utf16)
                .trim_end_matches('\0')
                .to_string()
        } else {
            String::new()
        };

        self.stats.total_records += 1;
        self.stats.total_bytes += record_length as u64;
        if usn > self.stats.max_usn { self.stats.max_usn = usn; }
        if timestamp_raw > self.stats.max_timestamp { self.stats.max_timestamp = timestamp_raw; }
        match major_version {
            2 => self.stats.version_v2 += 1,
            3 => self.stats.version_v3 += 1,
            4 => self.stats.version_v4 += 1,
            _ => {}
        }

        Ok(ParsedUsnRecord {
            record_length,
            major_version,
            minor_version,
            file_reference: file_ref,
            parent_reference: parent_ref,
            usn,
            timestamp: filetime_to_datetime(timestamp_raw),
            reason: UsnReason::from_bits_truncate(reason),
            source_info,
            file_attributes,
            file_name,
            raw_reason: reason,
            source: RecordSource::Allocated,
        })
    }
}

// ─── Live Journal Monitor ────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod live {
    use super::*;
    use std::ffi::c_void;
    use std::sync::atomic::Ordering;

    // ---------------------------------------------------------------------------
    // Windows FFI — thin wrappers so we don't depend on windows crate 0.54 layout
    // ---------------------------------------------------------------------------
    type HANDLE = isize;

    const INVALID_HANDLE_VALUE: HANDLE = -1;
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const ERROR_HANDLE_EOF: u32 = 38;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const ERROR_MORE_DATA: u32 = 234;

    const METHOD_BUFFERED: u32 = 0;
    const FILE_ANY_ACCESS: u32 = 0;
    const FILE_DEVICE_FILE_SYSTEM: u32 = 0x0009;

    const fn ctl_code(dev: u32, func: u32, method: u32, access: u32) -> u32 {
        (dev << 16) | (access << 14) | (func << 2) | method
    }

    const FSCTL_QUERY_USN_JOURNAL: u32 =
        ctl_code(FILE_DEVICE_FILE_SYSTEM, 0x0094, METHOD_BUFFERED, FILE_ANY_ACCESS);
    const FSCTL_READ_USN_JOURNAL: u32 =
        ctl_code(FILE_DEVICE_FILE_SYSTEM, 0x009b, METHOD_BUFFERED, FILE_ANY_ACCESS);

    #[repr(C)]
    struct UsnJournalDataV2 {
        usn_journal_id: u64,
        first_usn: i64,
        next_usn: i64,
        lowest_valid_usn: i64,
        max_usn: i64,
        maximum_size: u64,
        allocation_delta: u64,
        supported_min_major_version: u16,
        supported_max_major_version: u16,
    }

    #[repr(C)]
    struct ReadUsnJournalDataV2 {
        start_usn: i64,
        reason_mask: u32,
        return_only_on_close: u32,
        timeout: u64,
        bytes_to_wait_for: u64,
        usn_journal_id: u64,
        min_major_version: u16,
        max_major_version: u16,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *const c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: HANDLE,
        ) -> HANDLE;

        fn GetLastError() -> u32;

        fn CloseHandle(hObject: HANDLE) -> u32;

        fn DeviceIoControl(
            hDevice: HANDLE,
            dwIoControlCode: u32,
            lpInBuffer: *const c_void,
            nInBufferSize: u32,
            lpOutBuffer: *mut c_void,
            nOutBufferSize: u32,
            lpBytesReturned: *mut u32,
            lpOverlapped: *const c_void,
        ) -> u32;
    }

    // ---------------------------------------------------------------------------
    // Public monitor
    // ---------------------------------------------------------------------------
    pub struct LiveJournalMonitor {
        volume_handle: HANDLE,
        watermark: AtomicU64,
        journal_id: u64,
    }

    unsafe impl Send for LiveJournalMonitor {}
    unsafe impl Sync for LiveJournalMonitor {}

    impl LiveJournalMonitor {
        pub fn open(volume_path: &str) -> Result<Self, JournalError> {
            let wide: Vec<u16> = volume_path.encode_utf16().chain(std::iter::once(0)).collect();
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | FILE_FLAG_BACKUP_SEMANTICS,
                    0,
                )
            };

            if handle == INVALID_HANDLE_VALUE {
                return Err(JournalError::Platform(format!(
                    "CreateFileW failed: 0x{:X}",
                    unsafe { GetLastError() }
                )));
            }

            let mut journal_data: UsnJournalDataV2 = unsafe { std::mem::zeroed() };
            let mut returned: u32 = 0;

            // FSCTL_QUERY_USN_JOURNAL takes a dummy input buffer
            let success = unsafe {
                DeviceIoControl(
                    handle,
                    FSCTL_QUERY_USN_JOURNAL,
                    std::ptr::null(),
                    0,
                    &mut journal_data as *mut _ as *mut c_void,
                    std::mem::size_of::<UsnJournalDataV2>() as u32,
                    &mut returned,
                    std::ptr::null(),
                )
            };

            if success == 0 {
                let _ = unsafe { CloseHandle(handle) };
                return Err(JournalError::Platform(format!(
                    "FSCTL_QUERY_USN_JOURNAL failed: 0x{:X}",
                    unsafe { GetLastError() }
                )));
            }

            Ok(Self {
                volume_handle: handle,
                watermark: AtomicU64::new(journal_data.next_usn as u64),
                journal_id: journal_data.usn_journal_id,
            })
        }

        pub fn read_new_records(&self) -> Result<Vec<ParsedUsnRecord>, JournalError> {
            let start_usn = self.watermark.load(Ordering::Acquire);

            let input = ReadUsnJournalDataV2 {
                start_usn: start_usn as i64,
                reason_mask: 0xFFFFFFFF,
                return_only_on_close: 0,
                timeout: 0,
                bytes_to_wait_for: 0,
                usn_journal_id: self.journal_id,
                min_major_version: 2,
                max_major_version: 4,
            };

            let mut buffer = vec![0u8; 1_048_576];
            let mut returned: u32 = 0;

            let success = unsafe {
                DeviceIoControl(
                    self.volume_handle,
                    FSCTL_READ_USN_JOURNAL,
                    &input as *const _ as *const c_void,
                    std::mem::size_of::<ReadUsnJournalDataV2>() as u32,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len() as u32,
                    &mut returned,
                    std::ptr::null(),
                )
            };

            if success == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_HANDLE_EOF || err == ERROR_MORE_DATA {
                    return Ok(Vec::new());
                }
                return Err(JournalError::Platform(format!(
                    "FSCTL_READ_USN_JOURNAL: 0x{:X}",
                    err
                )));
            }

            let data = &buffer[..returned as usize];
            let mut reader = StreamingJournalReader::from_buffer(data);
            let mut records = Vec::new();
            while let Some(record) = reader.next_record()? {
                self.watermark.store(record.usn, Ordering::Release);
                records.push(record);
            }

            Ok(records)
        }
    }

    impl Drop for LiveJournalMonitor {
        fn drop(&mut self) {
            if self.volume_handle != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.volume_handle);
                }
            }
        }
    }
}

// ─── Utility ─────────────────────────────────────────────────────────

pub fn filetime_to_datetime(filetime: i64) -> DateTime<Utc> {
    if filetime <= 0 {
        return DateTime::from_timestamp(0, 0).unwrap();
    }
    let unix_secs = filetime / 10_000_000 - 11644473600;
    let nanos = (filetime % 10_000_000).unsigned_abs() as u32 * 100;
    DateTime::from_timestamp(unix_secs, nanos).unwrap_or_default()
}

pub fn datetime_to_filetime(dt: &DateTime<Utc>) -> i64 {
    (dt.timestamp() + 11644473600) * 10_000_000 + dt.timestamp_subsec_nanos() as i64 / 100
}

// ─── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unsupported USN version: {0}")]
    UnsupportedVersion(u16),
    #[error("Truncated record")]
    TruncatedRecord,
    #[error("Platform error: {0}")]
    Platform(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_v2_record(filename: &str, reason: u32) -> Vec<u8> {
        let filename_utf16: Vec<u16> = filename.encode_utf16().collect();
        let name_bytes: Vec<u8> = filename_utf16.iter()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let total_len = USN_RECORD_V2_MIN + name_bytes.len();
        let mut buf = vec![0u8; total_len];
        // Record length
        buf[0..4].copy_from_slice(&(total_len as u32).to_le_bytes());
        // Version 2.0
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        // File reference
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        // Parent reference
        buf[16..24].copy_from_slice(&5u64.to_le_bytes()); // root
        // USN
        buf[24..32].copy_from_slice(&100u64.to_le_bytes());
        // Timestamp (FILETIME)
        let ft = 132000000000000000i64; // approx 2019
        buf[32..40].copy_from_slice(&ft.to_le_bytes());
        // Reason
        buf[40..44].copy_from_slice(&reason.to_le_bytes());
        // Source info
        buf[44..48].copy_from_slice(&0u32.to_le_bytes());
        // Security ID
        buf[48..52].copy_from_slice(&0u32.to_le_bytes());
        // File attributes
        buf[52..56].copy_from_slice(&0u32.to_le_bytes());
        // File name length (bytes)
        buf[56..58].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        // File name offset
        let name_off = USN_RECORD_V2_MIN as u16;
        buf[58..60].copy_from_slice(&name_off.to_le_bytes());
        // File name
        buf[name_off as usize..name_off as usize + name_bytes.len()].copy_from_slice(&name_bytes);
        buf
    }

    #[test]
    fn test_parse_v2_record() {
        let data = make_v2_record("test.txt", 0x100); // FILE_CREATE
        let mut reader = StreamingJournalReader::from_buffer(&data);
        let record = reader.next_record().unwrap().unwrap();
        assert_eq!(record.major_version, 2);
        assert_eq!(record.file_name, "test.txt");
        assert!(record.reason.contains(UsnReason::FILE_CREATE));
        assert_eq!(record.stats.total_records, 1);
    }

    #[test]
    fn test_parse_multiple_records() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_v2_record("file1.txt", 0x100));
        data.extend_from_slice(&make_v2_record("file2.txt", 0x200));
        data.extend_from_slice(&make_v2_record("file3.txt", 0x800));
        let mut reader = StreamingJournalReader::from_buffer(&data);
        let records = reader.read_all().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].file_name, "file1.txt");
        assert_eq!(records[1].file_name, "file2.txt");
        assert!(records[2].reason.contains(UsnReason::SECURITY_CHANGE));
    }

    #[test]
    fn test_filetime_conversion_roundtrip() {
        let now = Utc::now();
        let ft = datetime_to_filetime(&now);
        let back = filetime_to_datetime(ft);
        let diff = (now - back).num_milliseconds().abs();
        assert!(diff < 2, "Roundtrip diff: {}ms", diff);
    }

    #[test]
    fn test_file_ref_extraction() {
        let ref_ntfs = FileRef::Ntfs(0x0004_0000_0000_0001);
        assert_eq!(ref_ntfs.entry_number(), 1);
        assert_eq!(ref_ntfs.sequence_number(), 4);
    }
}
