use crate::forensic::usn::{ParsedUsnRecord, RecordSource, StreamingJournalReader, filetime_to_datetime, UsnReason, JournalError};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ─── $LogFile Parser ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostRecord {
    pub file_name: String,
    pub usn: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub reason: u32,
    pub file_reference: u64,
    pub parent_reference: u64,
    pub source: GhostSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GhostSource {
    LogFileRcrd,
    LogFileSlack,
    Unallocated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFileParseResult {
    pub total_pages: u64,
    pub rcrd_pages: u64,
    pub rstr_pages: u64,
    pub usn_records_extracted: u64,
    pub ghost_records_found: u64,
    pub ghost_records: Vec<GhostRecord>,
    pub errors: Vec<String>,
}

/// Parse $LogFile to extract embedded USN records and identify ghost records
pub struct LogFileParser {
    data: Vec<u8>,
    allocated_usns: HashSet<u64>,
    result: LogFileParseResult,
}

impl LogFileParser {
    pub fn new(logfile_data: Vec<u8>, allocated_usns: HashSet<u64>) -> Self {
        Self {
            data: logfile_data,
            allocated_usns,
            result: LogFileParseResult {
                total_pages: 0,
                rcrd_pages: 0,
                rstr_pages: 0,
                usn_records_extracted: 0,
                ghost_records_found: 0,
                ghost_records: Vec::new(),
                errors: Vec::new(),
            },
        }
    }

    pub fn parse(&mut self) -> &LogFileParseResult {
        if self.data.len() < 4096 {
            self.result.errors.push("LogFile too small".into());
            return &self.result;
        }

        self.result.total_pages = (self.data.len() / 4096) as u64;

        // Scan for RSTR (restart) pages
        for page in 0..self.result.total_pages as usize {
            let offset = page * 4096;
            if offset + 4 > self.data.len() {
                break;
            }

            let sig = &self.data[offset..offset + 4];
            match sig {
                b"RSTR" => {
                    self.result.rstr_pages += 1;
                    self.process_rstr_page(offset);
                }
                b"RCRD" => {
                    self.result.rcrd_pages += 1;
                    self.process_rcrd_page(offset);
                }
                _ => {}
            }
        }

        &self.result
    }

    fn process_rstr_page(&mut self, offset: usize) {
        // RSTR page header (simplified):
        // 0x00: "RSTR"
        // 0x0C: 8-byte sequence number (last LSN for this restart area)
        // 0x20+: RCRD page reference array
        // Each reference: 8 bytes LSN + 8 bytes offset into file

        if offset + 32 > self.data.len() {
            return;
        }

        // Extract RCRD page references from the restart area
        // The restart page contains an array of RCRD page offsets
        let mut ref_offset = offset + 32;
        let end = (offset + 4096).min(self.data.len());

        while ref_offset + 16 <= end {
            let _lsn = u64::from_le_bytes(
                self.data[ref_offset..ref_offset + 8].try_into().unwrap_or([0; 8])
            );
            let page_offset = u64::from_le_bytes(
                self.data[ref_offset + 8..ref_offset + 16].try_into().unwrap_or([0; 8])
            ) as usize;

            if page_offset == 0 {
                break;
            }

            if page_offset + 4 <= self.data.len() && &self.data[page_offset..page_offset + 4] == b"RCRD" {
                self.process_rcrd_page(page_offset);
            }

            ref_offset += 16;
        }
    }

    fn process_rcrd_page(&mut self, offset: usize) {
        // RCRD page: 4096 bytes
        // 0x00: "RCRD" (4 bytes)
        // 0x04: update sequence number (2 bytes)
        // 0x06: fixup count (2 bytes)
        // 0x08: last LSN (8 bytes)
        // 0x10: flags (4 bytes)
        // 0x20+: redo/undo records

        let page_end = (offset + 4096).min(self.data.len());
        let mut pos = offset + 32; // skip header

        while pos + 8 <= page_end {
            let rec_len = u16::from_le_bytes(
                self.data[pos..pos + 2].try_into().unwrap_or([0, 0])
            ) as usize;

            if rec_len == 0 {
                pos += 2;
                continue;
            }

            if rec_len < 8 || pos + rec_len > page_end {
                break;
            }

            // Check record type
            let rec_type = u16::from_le_bytes(
                self.data[pos + 2..pos + 4].try_into().unwrap_or([0, 0])
            );

            // Type 0x0E = CLFS_USN_RECORD (USN journal record in redo data)
            if rec_type == 0x0E {
                let rec_data = self.data[pos + 8..pos + rec_len].to_vec();
                self.extract_usn_from_redo(&rec_data);
            }

            pos += rec_len;
        }

        // Also check page slack (unused space at end of page)
        // Ghost records found here were likely intentionally destroyed
        let slack_pos = (pos / 8) * 8; // align to 8 bytes
        if slack_pos + 64 <= page_end {
            let slack_data = self.data[slack_pos..page_end].to_vec();
            self.extract_usn_from_slack(&slack_data);
        }
    }

    fn extract_usn_from_redo(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos + 64 <= data.len() {
            // Look for USN record signature: valid length + version 2/3
            let major = u16::from_le_bytes(
                data[pos + 4..pos + 6].try_into().unwrap_or([0, 0])
            );
            let minor = u16::from_le_bytes(
                data[pos + 6..pos + 8].try_into().unwrap_or([0, 0])
            );

            if (major == 2 || major == 3) && minor == 0 {
                let rl = u32::from_le_bytes(
                    data[pos..pos + 4].try_into().unwrap_or([0; 4])
                ) as usize;

                if rl >= 60 && rl <= 65536 && pos + rl <= data.len() {
                    let usn_offset = u64::from_le_bytes(
                        data[pos + 24..pos + 32].try_into().unwrap_or([0; 8])
                    );

                    self.result.usn_records_extracted += 1;

                    // Check if this USN exists in the allocated journal
                    if !self.allocated_usns.contains(&usn_offset) {
                        let name_len = u16::from_le_bytes(
                            data[pos + 0x38..pos + 0x3A].try_into().unwrap_or([0, 0])
                        ) as usize;
                        let name_off = u16::from_le_bytes(
                            data[pos + 0x3A..pos + 0x3C].try_into().unwrap_or([0, 0])
                        ) as usize;

                        let file_name = if name_off + name_len * 2 <= data.len() && name_len > 0 {
                            let name_utf16: Vec<u16> = data[pos + name_off..pos + name_off + name_len * 2]
                                .chunks(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            String::from_utf16_lossy(&name_utf16)
                                .trim_end_matches('\0')
                                .to_string()
                        } else {
                            String::new()
                        };

                        let timestamp = i64::from_le_bytes(
                            data[pos + 32..pos + 40].try_into().unwrap_or([0; 8])
                        );
                        let reason = u32::from_le_bytes(
                            data[pos + 40..pos + 44].try_into().unwrap_or([0; 4])
                        );
                        let file_ref = u64::from_le_bytes(
                            data[pos + 8..pos + 16].try_into().unwrap_or([0; 8])
                        );
                        let parent_ref = u64::from_le_bytes(
                            data[pos + 16..pos + 24].try_into().unwrap_or([0; 8])
                        );

                        self.result.ghost_records.push(GhostRecord {
                            file_name,
                            usn: usn_offset,
                            timestamp: filetime_to_datetime(timestamp),
                            reason,
                            file_reference: file_ref,
                            parent_reference: parent_ref,
                            source: GhostSource::LogFileRcrd,
                        });
                        self.result.ghost_records_found += 1;
                    }

                    pos += rl;
                    continue;
                }
            }

            // Try next alignment
            let next_align = ((pos / 8) + 1) * 8;
            if next_align > pos + 2 {
                pos = next_align;
            } else {
                pos += 8;
            }
        }
    }

    fn extract_usn_from_slack(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos + 64 <= data.len() {
            let major = u16::from_le_bytes(
                data[pos + 4..pos + 6].try_into().unwrap_or([0, 0])
            );
            if major >= 2 && major <= 4 {
                let rl = u32::from_le_bytes(
                    data[pos..pos + 4].try_into().unwrap_or([0; 4])
                ) as usize;
                if rl >= 60 && rl <= 65536 && pos + rl <= data.len() {
                    let usn_offset = u64::from_le_bytes(
                        data[pos + 24..pos + 32].try_into().unwrap_or([0; 8])
                    );
                    if !self.allocated_usns.contains(&usn_offset) {
                        let name_len = u16::from_le_bytes(
                            data[pos + 0x38..pos + 0x3A].try_into().unwrap_or([0, 0])
                        ) as usize;
                        let name_off = u16::from_le_bytes(
                            data[pos + 0x3A..pos + 0x3C].try_into().unwrap_or([0, 0])
                        ) as usize;
                        let file_name = if name_off + name_len * 2 <= data.len() && name_len > 0 {
                            let name_utf16: Vec<u16> = data[pos + name_off..pos + name_off + name_len * 2]
                                .chunks(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            String::from_utf16_lossy(&name_utf16)
                                .trim_end_matches('\0')
                                .to_string()
                        } else {
                            String::new()
                        };

                        self.result.ghost_records.push(GhostRecord {
                            file_name,
                            usn: usn_offset,
                            timestamp: chrono::Utc::now(),
                            reason: 0,
                            file_reference: 0,
                            parent_reference: 0,
                            source: GhostSource::LogFileSlack,
                        });
                        self.result.ghost_records_found += 1;
                    }
                    pos += rl;
                    continue;
                }
            }
            pos += 8;
        }
    }

    pub fn into_records(self) -> Vec<ParsedUsnRecord> {
        self.result.ghost_records.into_iter().map(|g| ParsedUsnRecord {
            record_length: 0,
            major_version: 2,
            minor_version: 0,
            file_reference: crate::forensic::usn::FileRef::Ntfs(g.file_reference),
            parent_reference: crate::forensic::usn::FileRef::Ntfs(g.parent_reference),
            usn: g.usn,
            timestamp: g.timestamp,
            reason: UsnReason::from_bits_truncate(g.reason),
            source_info: 0,
            file_attributes: 0,
            file_name: g.file_name,
            raw_reason: g.reason,
            source: RecordSource::Ghost,
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghost_record_count_empty() {
        let allocated = HashSet::new();
        let data = vec![0u8; 8192];
        let mut parser = LogFileParser::new(data, allocated);
        parser.parse();
        assert_eq!(parser.result.ghost_records_found, 0);
        assert_eq!(parser.result.total_pages, 2);
    }
}
