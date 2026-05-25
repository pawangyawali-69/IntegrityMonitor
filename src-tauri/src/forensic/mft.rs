use crate::forensic::*;
use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use windows::Win32::System::IO::OVERLAPPED;

/// MFT (Master File Table) reader and correlation engine.
/// Reads $MFT via raw volume access and extracts file records
/// for cross-correlation with USN journal entries.
pub struct MftReader {
    volume_handle: std::os::windows::io::OwnedHandle,
    volume_id: VolumeId,
    mft_size: u64,
    record_size: u32,
}

#[repr(C, packed)]
struct MftRecordHeader {
    signature: [u8; 4],       // "FILE"
    fixup_offset: u16,
    fixup_count: u16,
    log_sequence_number: u64,
    sequence_number: u16,
    hard_link_count: u16,
    first_attribute_offset: u16,
    flags: u16,               // 0x00=in use, 0x01=in use+alloc, 0x02=directory, 0x04=deleted
    used_size: u32,
    allocated_size: u32,
    file_reference: u64,
    next_attribute_id: u16,
    _padding: u16,
    record_number: u32,
}

const MFT_RECORD_SIGNATURE: [u8; 4] = [b'F', b'I', b'L', b'E'];
const MFT_BAAD_SIGNATURE: [u8; 4] = [b'B', b'A', b'A', b'D'];

#[repr(C, packed)]
struct AttrHeader {
    type_code: u32,           // $STANDARD_INFORMATION=0x10, $ATTRIBUTE_LIST=0x20, $FILE_NAME=0x30, $DATA=0x80
    length: u32,
    non_resident: u8,
    name_length: u8,
    name_offset: u16,
    flags: u16,               // 0x0001=compressed, 0x0002=encrypted, 0x0004=sparse
    attribute_id: u16,
}

#[repr(C, packed)]
struct ResidentAttr {
    header: AttrHeader,
    value_length: u32,
    value_offset: u16,
    _reserved: u16,           // indexed flag
}

#[repr(C, packed)]
struct NonResidentAttr {
    header: AttrHeader,
    lowest_vcn: u64,
    highest_vcn: u64,
    run_offset: u16,
    compression_unit: u16,
    _padding: [u8; 4],
    allocated_size: u64,
    data_size: u64,
    initialized_size: u64,
    compressed_size: u64,
}

#[derive(Debug, Clone)]
pub struct MftRecord {
    pub record_number: u32,
    pub sequence_number: u16,
    pub flags: u16,
    pub hard_link_count: u16,
    pub is_deleted: bool,
    pub is_directory: bool,
    pub is_in_use: bool,
    pub attributes: Vec<MftAttribute>,
    pub timestamps: Option<MftTimestamps>,
    pub filename: Option<String>,
    pub dos_filename: Option<String>,
    pub parent_frn: Option<u64>,
    pub data_size: u64,
    pub resident_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum MftAttribute {
    StandardInformation(MftTimestamps),
    FileName {
        parent_frn: u64,
        filename: String,
        namespace: u8,
        timestamps: MftTimestamps,
    },
    Data {
        resident: bool,
        size: u64,
        content: Option<Vec<u8>>,
    },
    AttributeList,
    ObjectId,
    ReparsePoint {
        tag: u32,
        data: Vec<u8>,
    },
    IndexRoot,
    IndexAllocation,
    Bitmap,
    LoggedUtilityStream,
    Unknown {
        type_code: u32,
        size: u64,
    },
}

impl MftReader {
    pub fn open(volume_path: &str, volume_id: VolumeId) -> Result<Self, String> {
        use std::os::windows::io::FromRawHandle;
        use windows::Win32::Storage::FileSystem::*;
        use windows::Win32::Foundation::*;

        let wide: Vec<u16> = std::ffi::OsStr::new(volume_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        }.map_err(|e| format!("Failed to open volume for MFT: error={}", e))?;

        let owned = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle.0 as *mut _) };

        // Determine MFT size and record size via NTFS boot sector
        let (mft_size, record_size) = Self::read_mft_metadata(&owned)?;

        Ok(Self {
            volume_handle: owned,
            volume_id,
            mft_size,
            record_size,
        })
    }

    fn read_mft_metadata(handle: &std::os::windows::io::OwnedHandle) -> Result<(u64, u32), String> {
        use windows::Win32::Storage::FileSystem::*;
        use windows::Win32::Foundation::*;

        let mut boot_sector = [0u8; 512];
        let mut bytes_read: u32 = 0;

        unsafe {
            ReadFile(
                HANDLE(handle.as_raw_handle() as isize),
                Some(&mut boot_sector as &mut [u8]),
                Some(&mut bytes_read),
                None,
            )
        }.map_err(|e| format!("Failed to read boot sector: error={}", e))?;

        if &boot_sector[3..7] != b"NTFS" {
            return Err("Not an NTFS volume".into());
        }

        let bytes_per_cluster = boot_sector[13] as u32;
        let bytes_per_sector = u16::from_le_bytes([boot_sector[11], boot_sector[12]]) as u32;
        let clusters_per_mft_record = boot_sector[0x40] as i8;

        let record_size = if clusters_per_mft_record < 0 {
            1u32 << (-clusters_per_mft_record as u32)
        } else {
            bytes_per_cluster * clusters_per_mft_record as u32
        };

        let mft_cluster = u64::from_le_bytes([
            boot_sector[0x30], boot_sector[0x31], boot_sector[0x32], boot_sector[0x33],
            boot_sector[0x34], boot_sector[0x35], boot_sector[0x36], boot_sector[0x37],
        ]);

        let mft_byte_offset = mft_cluster * bytes_per_cluster as u64;

        Ok((mft_byte_offset, record_size))
    }

    pub fn record_size(&self) -> u32 {
        self.record_size
    }

    pub fn total_records(&self) -> u64 {
        if self.record_size == 0 { return 0; }
        self.mft_size / self.record_size as u64
    }

    pub fn read_record(&self, record_number: u32) -> Result<Option<MftRecord>, String> {
        use windows::Win32::Storage::FileSystem::*;
        use windows::Win32::Foundation::*;

        let offset = self.mft_size + record_number as u64 * self.record_size as u64;

        let mut buffer = vec![0u8; self.record_size as usize];
        let mut bytes_read: u32 = 0;

        unsafe {
            let mut overlapped = ManuallyDrop::new(std::mem::zeroed::<OVERLAPPED>());
            overlapped.Anonymous.Anonymous.Offset = offset as u32;
            overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;

            match ReadFile(
                HANDLE(self.volume_handle.as_raw_handle() as isize),
                Some(buffer.as_mut_slice()),
                Some(&mut bytes_read),
                Some(&mut *overlapped),
            ) {
                Ok(()) => {
                    if bytes_read == 0 {
                        return Ok(None);
                    }
                }
                Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_IO_PENDING.0) => {
                    // I/O pending — unchanged behavior from original
                }
                Err(e) if e.code() == windows::core::HRESULT::from_win32(38) => {
                    return Ok(None);
                }
                Err(e) => {
                    return Err(format!("MFT read error at record {}: error={}", record_number, e));
                }
            }
        }

        let header = buffer.as_ptr() as *const MftRecordHeader;
        let signature = unsafe { std::slice::from_raw_parts((*header).signature.as_ptr(), 4) };

        if signature != MFT_RECORD_SIGNATURE {
            if signature == MFT_BAAD_SIGNATURE {
                log::warn!("MFT record {} is BAAD (corrupt)", record_number);
                return Ok(None);
            }
            return Ok(None);
        }

        let flags = unsafe { (*header).flags };
        let seq = unsafe { (*header).sequence_number };
        let attr_offset = unsafe { (*header).first_attribute_offset as usize };
        let hardlinks = unsafe { (*header).hard_link_count };

        let mut record = MftRecord {
            record_number,
            sequence_number: seq,
            flags,
            hard_link_count: hardlinks,
            is_deleted: (flags >> 3) & 1 == 1,
            is_directory: flags & 0x02 == 0x02,
            is_in_use: flags & 0x01 == 0x01,
            attributes: Vec::new(),
            timestamps: None,
            filename: None,
            dos_filename: None,
            parent_frn: None,
            data_size: 0,
            resident_data: None,
        };

        // Parse attributes
        let mut pos = attr_offset;
        while pos + 4 <= buffer.len() {
            let attr_header = buffer[pos..].as_ptr() as *const AttrHeader;
            let type_code = unsafe { (*attr_header).type_code };
            let attr_length = unsafe { (*attr_header).length as usize };

            if type_code == 0xFFFFFFFF || attr_length < 24 || pos + attr_length > buffer.len() {
                break; // end of attributes
            }

            self.parse_attribute(&buffer[pos..pos + attr_length], &mut record);

            pos += attr_length;
        }

        Ok(Some(record))
    }

    fn parse_attribute(&self, data: &[u8], record: &mut MftRecord) {
        let header = data.as_ptr() as *const AttrHeader;
        let type_code = unsafe { (*header).type_code };
        let non_resident = unsafe { (*header).non_resident } != 0;

        match type_code {
            0x10 => { // $STANDARD_INFORMATION
                if !non_resident {
                    if let Some(ts) = self.parse_standard_info(data) {
                        record.timestamps = Some(ts);
                        record.attributes.push(MftAttribute::StandardInformation(ts));
                    }
                }
            }
            0x30 => { // $FILE_NAME
                if let Some((parent, name, ns, ts)) = self.parse_filename(data) {
                    if ns < 2 {
                        record.filename.get_or_insert(name.clone());
                        record.parent_frn = Some(parent);
                        record.timestamps.get_or_insert(ts);
                    } else {
                        record.dos_filename = Some(name.clone());
                    }
                    record.attributes.push(MftAttribute::FileName {
                        parent_frn: parent,
                        filename: name,
                        namespace: ns,
                        timestamps: ts,
                    });
                }
            }
            0x80 => { // $DATA
                if non_resident {
                    let size = unsafe {
                        let nr = data.as_ptr() as *const NonResidentAttr;
                        (*nr).data_size
                    };
                    record.data_size = size;
                    record.attributes.push(MftAttribute::Data {
                        resident: false,
                        size,
                        content: None,
                    });
                } else {
                    let (size, content) = self.parse_resident_data(data);
                    record.data_size = size;
                    record.attributes.push(MftAttribute::Data {
                        resident: true,
                        size,
                        content: content.clone(),
                    });
                    if content.as_ref().map_or(false, |c| c.len() <= 1024) {
                        record.resident_data = content;
                    }
                }
            }
            0x20 => {
                record.attributes.push(MftAttribute::AttributeList);
            }
            0x40 => {
                record.attributes.push(MftAttribute::ObjectId);
            }
            0x50 => { // $REPARSE_POINT
                if !non_resident {
                    let value_offset = unsafe {
                        let r = data.as_ptr() as *const ResidentAttr;
                        (*r).value_offset as usize + std::mem::size_of::<ResidentAttr>() - std::mem::size_of::<AttrHeader>()
                    };
                    // Recalculate relative to data start
                    let value_offset_rel = unsafe { (*(data.as_ptr() as *const ResidentAttr)).value_offset as usize };
                    let value_length = unsafe { (*(data.as_ptr() as *const ResidentAttr)).value_length as usize };

                    let abs_offset = std::mem::size_of::<AttrHeader>() + value_offset_rel;
                    if abs_offset + 4 <= data.len() {
                        let tag = u32::from_le_bytes([
                            data[abs_offset], data[abs_offset + 1],
                            data[abs_offset + 2], data[abs_offset + 3],
                        ]);
                        let reparse_data = data[abs_offset..abs_offset + value_length.min(data.len() - abs_offset)].to_vec();
                        record.attributes.push(MftAttribute::ReparsePoint {
                            tag,
                            data: reparse_data,
                        });
                    }
                }
            }
            0x90 => { record.attributes.push(MftAttribute::IndexRoot); }
            0xA0 => { record.attributes.push(MftAttribute::IndexAllocation); }
            0xB0 => { record.attributes.push(MftAttribute::Bitmap); }
            0xC0 => { record.attributes.push(MftAttribute::LoggedUtilityStream); }
            _ => {
                record.attributes.push(MftAttribute::Unknown {
                    type_code,
                    size: if non_resident {
                        unsafe { (*(data.as_ptr() as *const NonResidentAttr)).data_size }
                    } else {
                        unsafe { (*(data.as_ptr() as *const ResidentAttr)).value_length as u64 }
                    },
                });
            }
        }
    }

    fn parse_standard_info(&self, data: &[u8]) -> Option<MftTimestamps> {
        let res = data.as_ptr() as *const ResidentAttr;
        let value_offset = unsafe { (*res).value_offset as usize };
        let value_length = unsafe { (*res).value_length as usize };

        let abs_offset = std::mem::size_of::<AttrHeader>() + value_offset;
        if abs_offset + 32 > data.len() || value_length < 48 {
            return None;
        }

        let ts_base = &data[abs_offset..];
        if ts_base.len() < 32 { return None; }

        Some(MftTimestamps {
            si_created: Timestamp::from_filetime(i64::from_le_bytes(ts_base[0..8].try_into().ok()?)),
            si_modified: Timestamp::from_filetime(i64::from_le_bytes(ts_base[8..16].try_into().ok()?)),
            si_mft_modified: Timestamp::from_filetime(i64::from_le_bytes(ts_base[16..24].try_into().ok()?)),
            si_accessed: Timestamp::from_filetime(i64::from_le_bytes(ts_base[24..32].try_into().ok()?)),
            fn_created: None,
            fn_modified: None,
            fn_mft_modified: None,
            fn_accessed: None,
        })
    }

    fn parse_filename(&self, data: &[u8]) -> Option<(u64, String, u8, MftTimestamps)> {
        let res = data.as_ptr() as *const ResidentAttr;
        let value_offset = unsafe { (*res).value_offset as usize };
        let value_length = unsafe { (*res).value_length as usize };

        let abs_offset = std::mem::size_of::<AttrHeader>() + value_offset;
        if abs_offset + 68 > data.len() || value_length < 68 {
            return None;
        }

        let fn_data = &data[abs_offset..abs_offset + 68];

        let parent_frn = u64::from_le_bytes(fn_data[0..8].try_into().ok()?);
        // fn_data[8..12] = creation time (FILETIME)
        // fn_data[12..16] = modification time
        // fn_data[16..20] = mft modification time
        // fn_data[20..24] = access time
        // fn_data[24..28] = allocated size
        // fn_data[28..32] = real size
        // fn_data[32..36] = file flags
        // fn_data[36..40] = extended attributes
        // fn_data[40] = filename length (in chars)
        // fn_data[41] = filename namespace (0=POSIX, 1=Win32, 2=DOS, 3=DOS+Win32)

        let fn_len = fn_data[40] as usize;
        let namespace = fn_data[41];

        let ts = MftTimestamps {
            si_created: Timestamp::from_filetime(0),
            si_modified: Timestamp::from_filetime(0),
            si_mft_modified: Timestamp::from_filetime(0),
            si_accessed: Timestamp::from_filetime(0),
            fn_created: Some(Timestamp::from_filetime(i64::from_le_bytes(fn_data[8..16].try_into().ok()?))),
            fn_modified: Some(Timestamp::from_filetime(i64::from_le_bytes(fn_data[16..24].try_into().ok()?))),
            fn_mft_modified: Some(Timestamp::from_filetime(i64::from_le_bytes(fn_data[24..32].try_into().ok()?))),
            fn_accessed: Some(Timestamp::from_filetime(i64::from_le_bytes(fn_data[32..40].try_into().ok()?))),
        };

        if fn_len == 0 || 68 + fn_len * 2 > value_length {
            return None;
        }

        let name_start = abs_offset + 68;
        let name_bytes = &data[name_start..name_start + fn_len * 2];
        let name_utf16: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let filename = String::from_utf16_lossy(&name_utf16);

        Some((parent_frn, filename, namespace, ts))
    }

    fn parse_resident_data(&self, data: &[u8]) -> (u64, Option<Vec<u8>>) {
        let res = data.as_ptr() as *const ResidentAttr;
        let value_offset = unsafe { (*res).value_offset as usize };
        let value_length = unsafe { (*res).value_length as usize };

        let abs_offset = std::mem::size_of::<AttrHeader>() + value_offset;
        if abs_offset + value_length > data.len() {
            return (value_length as u64, None);
        }

        Some(data[abs_offset..abs_offset + value_length].to_vec());
        (value_length as u64, Some(data[abs_offset..abs_offset + value_length].to_vec()))
    }

    /// Read all MFT records and return as a batch
    pub fn read_all(&self) -> Vec<MftRecord> {
        let total = self.total_records();
        let mut records = Vec::with_capacity(total as usize / 100);

        log::info!("Reading MFT: {} estimated records", total);

        for i in 0..total {
            match self.read_record(i as u32) {
                Ok(Some(record)) => records.push(record),
                Ok(None) => {}
                Err(e) => log::warn!("MFT read error at record {}: {}", i, e),
            }

            if records.len() % 10000 == 0 && records.len() > 0 {
                log::info!("MFT progress: {}/{} records", i, total);
            }
        }

        log::info!("MFT read complete: {} records", records.len());
        records
    }

    /// Correlate MFT records with USN journal entries.
    /// Returns orphan entries (present in USN but not in MFT)
    /// and new entries (present in MFT but no matching USN).
    pub fn correlate_with_usn(
        &self,
        usn_events: &[FilesystemEvent],
    ) -> MftCorrelationResult {
        let mut result = MftCorrelationResult {
            matched: Vec::new(),
            orphan_usn_entries: Vec::new(),
            orphan_mft_records: Vec::new(),
            timestamp_anomalies: Vec::new(),
            sequence_anomalies: Vec::new(),
            deleted_entries: Vec::new(),
        };

        let mft_frns: std::collections::HashSet<u64> = self.read_all()
            .iter()
            .map(|r| {
                let seq = r.sequence_number;
                ((r.record_number as u64) | (seq as u64) << 48)
            })
            .collect();

        for event in usn_events {
            if !mft_frns.contains(&event.file_reference) {
                result.orphan_usn_entries.push(event.clone());
            }

            if let Some(mft) = self.read_record(event.file_reference as u32).ok().flatten() {
                // Check sequence number mismatch
                let expected_seq = (event.file_reference >> 48) as u16;
                if mft.sequence_number != expected_seq {
                    result.sequence_anomalies.push(SequenceAnomaly {
                        file_reference: event.file_reference,
                        expected_sequence: expected_seq,
                        actual_sequence: mft.sequence_number,
                        usn: event.usn,
                        timestamp: event.timestamp.clone(),
                    });
                }

                // Check timestamps
                if let Some(mft_ts) = &mft.timestamps {
                    let usn_time = event.timestamp.raw;
                    let mft_time = mft_ts.si_modified.raw;
                    if (usn_time - mft_time).abs() > 10_000_000 { // 1 second
                        result.timestamp_anomalies.push(TimestampAnomaly {
                            file_reference: event.file_reference,
                            usn_timestamp: event.timestamp.clone(),
                            mft_timestamp: mft_ts.clone(),
                            usn: event.usn,
                            filename: event.filename.clone(),
                        });
                    }
                }

                if mft.is_deleted {
                    result.deleted_entries.push(DeletedFileEntry {
                        record_number: mft.record_number,
                        sequence_number: mft.sequence_number,
                        filename: mft.filename.clone().unwrap_or_default(),
                        last_usn_event: event.usn,
                        last_timestamp: event.timestamp.clone(),
                    });
                }
            }
        }

        result
    }
}

#[derive(Debug, Clone, Default)]
pub struct MftCorrelationResult {
    pub matched: Vec<(FilesystemEvent, MftRecord)>,
    pub orphan_usn_entries: Vec<FilesystemEvent>,
    pub orphan_mft_records: Vec<MftRecord>,
    pub timestamp_anomalies: Vec<TimestampAnomaly>,
    pub sequence_anomalies: Vec<SequenceAnomaly>,
    pub deleted_entries: Vec<DeletedFileEntry>,
}

#[derive(Debug, Clone)]
pub struct TimestampAnomaly {
    pub file_reference: FileReference,
    pub usn_timestamp: Timestamp,
    pub mft_timestamp: MftTimestamps,
    pub usn: UsnValue,
    pub filename: String,
}

#[derive(Debug, Clone)]
pub struct SequenceAnomaly {
    pub file_reference: FileReference,
    pub expected_sequence: u16,
    pub actual_sequence: u16,
    pub usn: UsnValue,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone)]
pub struct DeletedFileEntry {
    pub record_number: u32,
    pub sequence_number: u16,
    pub filename: String,
    pub last_usn_event: UsnValue,
    pub last_timestamp: Timestamp,
}

impl MftCorrelationResult {
    pub fn has_anomalies(&self) -> bool {
        !self.timestamp_anomalies.is_empty()
            || !self.sequence_anomalies.is_empty()
            || !self.orphan_usn_entries.is_empty()
    }

    pub fn forensic_flags(&self) -> Vec<IntegrityFlag> {
        let mut flags = Vec::new();
        for _ in &self.orphan_usn_entries {
            flags.push(IntegrityFlag {
                flag_type: IntegrityFlagType::OrphanEntry,
                severity: IntegritySeverity::Warning,
                description: "USN entry references file not found in MFT".into(),
                evidence: Vec::new(),
            });
        }
        for _ in &self.sequence_anomalies {
            flags.push(IntegrityFlag {
                flag_type: IntegrityFlagType::SequenceAnomaly,
                severity: IntegritySeverity::Suspicious,
                description: "MFT sequence number mismatch — possible file reference reuse or manipulation".into(),
                evidence: Vec::new(),
            });
        }
        for a in &self.timestamp_anomalies {
            flags.push(IntegrityFlag {
                flag_type: IntegrityFlagType::TimestampAnomaly,
                severity: IntegritySeverity::Suspicious,
                description: format!("Timestamp mismatch for {}: USN={} vs MFT={}", a.filename, a.usn_timestamp.raw, a.mft_timestamp.si_modified.raw),
                evidence: Vec::new(),
            });
        }
        flags
    }
}
