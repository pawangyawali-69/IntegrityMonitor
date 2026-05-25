use crate::forensic::*;
use crate::forensic::usn::UsnJournalReader;
use crate::forensic::mft::MftReader;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// Anti-forensic detection engine.
/// Detects tampering with:
/// - USN Journal (wiping, truncation, manipulation)
/// - MFT records (deleted entry hiding, timestomping)
/// - Timestamps (NtfsDisableLastAccessUpdate bypass)
/// - File system artifacts (ADS, reparse points, TxF)
/// - Journal continuity analysis
pub struct AntiForensicDetector {
    // Baseline state for comparison
    snapshots: HashMap<String, VolumeSnapshot>,
}

#[derive(Debug, Clone)]
pub struct VolumeSnapshot {
    pub volume_id: VolumeId,
    pub timestamp: Timestamp,
    pub usn_journal_id: u64,
    pub first_usn: i64,
    pub next_usn: i64,
    pub max_usn: i64,
    pub maximum_size: u64,
    pub allocation_delta: u64,
    pub total_records: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AntiForensicFinding {
    pub finding_type: AntiForensicType,
    pub severity: IntegritySeverity,
    pub description: String,
    pub evidence: Vec<String>,
    pub confidence: f64,
    pub affected_artifacts: Vec<String>,
    pub timestamp: Timestamp,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum AntiForensicType {
    JournalWiped,
    JournalTruncated,
    JournalContinuityBreak,
    JournalRecreated,
    JournalMaxSizeChanged,
    JournalAllocationDeltaChanged,
    MftRecordManipulated,
    MftSequenceSkew,
    MftOrphanRecords,
    TimestampSkew,
    Timestomping,
    NtfsTimestomping,
    AdsAbuse,
    ReparsePointAbuse,
    TransactedFile,
    HiddenExecutable,
    SlackSpaceArtifact,
    FileSystemRollback,
}

impl AntiForensicDetector {
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
        }
    }

    /// Analyze journal state for anti-forensic indicators
    pub fn analyze_journal(
        &mut self,
        reader: &UsnJournalReader,
    ) -> Vec<AntiForensicFinding> {
        let mut findings = Vec::new();
        let volume = reader.volume();
        let volume_key = format!("{}", volume.id);

        // Check for journal recreation (USN Journal ID changed)
        if let Some(prev) = self.snapshots.get(&volume_key) {
            if prev.usn_journal_id != volume.usn_journal_id {
                findings.push(AntiForensicFinding {
                    finding_type: AntiForensicType::JournalRecreated,
                    severity: IntegritySeverity::Critical,
                    description: "USN Journal was recreated — possible forensic countermeasure".into(),
                    evidence: vec![
                        format!("Previous journal ID: {:x}", prev.usn_journal_id),
                        format!("Current journal ID: {:x}", volume.usn_journal_id),
                        format!("Previous next USN: {}", prev.next_usn),
                        format!("Current next USN: {}", volume.next_usn),
                    ],
                    confidence: 0.95,
                    affected_artifacts: vec!["USN Journal".into()],
                    timestamp: Timestamp::now(),
                    mitre_technique: Some("T1070.004".into()),
                });
            }

            // Check for journal truncation (next_usn went backwards)
            if volume.next_usn < prev.next_usn {
                findings.push(AntiForensicFinding {
                    finding_type: AntiForensicType::JournalTruncated,
                    severity: IntegritySeverity::Critical,
                    description: "USN Journal was truncated — records after last watermark removed".into(),
                    evidence: vec![
                        format!("Previous next USN: {}", prev.next_usn),
                        format!("Current next USN: {}", volume.next_usn),
                        format!("Records removed: {}", prev.next_usn - volume.next_usn),
                    ],
                    confidence: 0.9,
                    affected_artifacts: vec!["USN Journal".into()],
                    timestamp: Timestamp::now(),
                    mitre_technique: Some("T1070.004".into()),
                });
            }

            // Check for maximum size reduction
            if volume.maximum_size < prev.maximum_size {
                findings.push(AntiForensicFinding {
                    finding_type: AntiForensicType::JournalMaxSizeChanged,
                    severity: IntegritySeverity::Warning,
                    description: "USN Journal maximum size decreased — possible journal size manipulation".into(),
                    evidence: vec![
                        format!("Previous max size: {} bytes", prev.maximum_size),
                        format!("Current max size: {} bytes", volume.maximum_size),
                    ],
                    confidence: 0.6,
                    affected_artifacts: vec!["USN Journal".into()],
                    timestamp: Timestamp::now(),
                    mitre_technique: Some("T1070.004".into()),
                });
            }
        }

        // Check for zero or near-zero records (journal wipe)
        if volume.next_usn - volume.first_usn < 100 {
            findings.push(AntiForensicFinding {
                finding_type: AntiForensicType::JournalWiped,
                severity: IntegritySeverity::Critical,
                description: "USN Journal contains very few records — possible journal wipe".into(),
                evidence: vec![
                    format!("First USN: {}", volume.first_usn),
                    format!("Next USN: {}", volume.next_usn),
                    format!("Record count: {}", volume.next_usn - volume.first_usn),
                ],
                confidence: 0.85,
                affected_artifacts: vec!["USN Journal".into()],
                timestamp: Timestamp::now(),
                mitre_technique: Some("T1070.004".into()),
            });
        }

        // Update snapshot
        self.snapshots.insert(volume_key.clone(), VolumeSnapshot {
            volume_id: volume.id,
            timestamp: Timestamp::now(),
            usn_journal_id: volume.usn_journal_id,
            first_usn: volume.first_usn,
            next_usn: volume.next_usn,
            max_usn: 0,
            maximum_size: volume.maximum_size,
            allocation_delta: volume.allocation_delta,
            total_records: 0,
        });

        findings
    }

    /// Detect timestomping by comparing MFT timestamps across attributes
    pub fn detect_timestomping(&self, events: &[FilesystemEvent]) -> Vec<AntiForensicFinding> {
        let mut findings = Vec::new();

        for event in events {
            if let Some(ref mft_ts) = event.mft_timestamps {
                // Check $SI vs $FN timestamp inconsistency (timestomping indicator)
                if let Some(ref fn_modified) = mft_ts.fn_modified {
                    let diff = (mft_ts.si_modified.raw - fn_modified.raw).abs();
                    // More than 1 hour difference between SI and FN modification times
                    if diff > 3_600_000_0000 {
                        findings.push(AntiForensicFinding {
                            finding_type: AntiForensicType::Timestomping,
                            severity: IntegritySeverity::Suspicious,
                            description: format!("$SI/$FN modified timestamp mismatch for FRN {:016x} — timestomping indicator", event.file_reference),
                            evidence: vec![
                                format!("$SI modified: {}", mft_ts.si_modified.to_rfc3339()),
                                format!("$FN modified: {}", fn_modified.to_rfc3339()),
                                format!("Difference: {} seconds", diff / 10_000_000),
                            ],
                            confidence: 0.7,
                            affected_artifacts: vec![format!("MFT record {}", event.file_reference & 0xFFFF)],
                            timestamp: event.timestamp.clone(),
                            mitre_technique: Some("T1070.006".into()),
                        });
                    }
                }

                // Check for timestamps set in the future
                let now = Timestamp::now();
                if mft_ts.si_created.raw > now.raw {
                    findings.push(AntiForensicFinding {
                        finding_type: AntiForensicType::TimestampSkew,
                        severity: IntegritySeverity::Critical,
                        description: format!("File {:016x} has creation timestamp in the future", event.file_reference),
                        evidence: vec![
                            format!("SI Created: {}", mft_ts.si_created.to_rfc3339()),
                            format!("Current time: {}", now.to_rfc3339()),
                        ],
                        confidence: 0.95,
                        affected_artifacts: vec![format!("MFT record {}", event.file_reference & 0xFFFF)],
                        timestamp: event.timestamp.clone(),
                        mitre_technique: Some("T1070.006".into()),
                    });
                }
            }
        }

        findings
    }

    /// Detect ADS (Alternate Data Stream) abuse by analyzing stream events
    pub fn detect_ads_abuse(&self, events: &[FilesystemEvent]) -> Vec<AntiForensicFinding> {
        let mut findings = Vec::new();
        let mut stream_events: HashMap<FileReference, Vec<&FilesystemEvent>> = HashMap::new();

        for ev in events {
            let reason = UsnReason::from_bits_truncate(ev.usn_reason);
            if reason.contains(UsnReason::STREAM_CHANGE) || reason.contains(UsnReason::NAMED_DATA_OVERWRITE) {
                stream_events.entry(ev.file_reference).or_default().push(ev);
            }
        }

        for (frn, evts) in &stream_events {
            if evts.len() >= 3 {
                let last = evts.last().unwrap();
                findings.push(AntiForensicFinding {
                    finding_type: AntiForensicType::AdsAbuse,
                    severity: IntegritySeverity::Suspicious,
                    description: format!("Frequent stream changes on FRN {:016x} — possible ADS payload", frn),
                    evidence: vec![
                        format!("Stream change count: {}", evts.len()),
                        format!("Last change: {}", last.timestamp.to_rfc3339()),
                    ],
                    confidence: 0.6,
                    affected_artifacts: vec![format!("FRN {:016x}", frn)],
                    timestamp: last.timestamp.clone(),
                    mitre_technique: Some("T1564.004".into()),
                });
            }
        }

        findings
    }

    /// Detect reparse point abuse (symlinks, mount points, IO reparse)
    pub fn detect_reparse_point_abuse(&self, events: &[FilesystemEvent]) -> Vec<AntiForensicFinding> {
        let mut findings = Vec::new();

        for ev in events {
            let reason = UsnReason::from_bits_truncate(ev.usn_reason);
            if reason.contains(UsnReason::REPARSE_POINT_CHANGE) {
                findings.push(AntiForensicFinding {
                    finding_type: AntiForensicType::ReparsePointAbuse,
                    severity: IntegritySeverity::Warning,
                    description: format!("Reparse point changed on FRN {:016x} — possible redirection", ev.file_reference),
                    evidence: vec![
                        format!("File: {}", ev.filename),
                        format!("Timestamp: {}", ev.timestamp.to_rfc3339()),
                    ],
                    confidence: 0.5,
                    affected_artifacts: vec![format!("FRN {:016x}", ev.file_reference)],
                    timestamp: ev.timestamp.clone(),
                    mitre_technique: Some("T1574.002".into()),
                });
            }
        }

        findings
    }

    /// Detect executable hidden in user-writable paths (bypassed execution)
    pub fn detect_hidden_executables(&self, events: &[FilesystemEvent]) -> Vec<AntiForensicFinding> {
        let mut findings = Vec::new();
        let suspicious_paths = ["\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\"];

        for ev in events {
            let path_lower = ev.filename.to_lowercase();
            let is_suspicious_path = suspicious_paths.iter().any(|p| path_lower.contains(p));

            if !is_suspicious_path { continue; }

            let reason = UsnReason::from_bits_truncate(ev.usn_reason);
            if reason.contains(UsnReason::FILE_CREATE) && path_lower.ends_with(".exe") {
                findings.push(AntiForensicFinding {
                    finding_type: AntiForensicType::HiddenExecutable,
                    severity: IntegritySeverity::Suspicious,
                    description: format!("Executable created in suspicious path: {}", ev.filename),
                    evidence: vec![
                        format!("Path: {}", ev.filename),
                        format!("FRN: {:016x}", ev.file_reference),
                    ],
                    confidence: 0.75,
                    affected_artifacts: vec![format!("FRN {:016x}", ev.file_reference)],
                    timestamp: ev.timestamp.clone(),
                    mitre_technique: Some("T1036.005".into()),
                });
            }
        }

        findings
    }

    /// Journal continuity analysis — detect gaps in the journal sequence
    pub fn analyze_journal_continuity(
        &self,
        events: &[FilesystemEvent],
    ) -> Vec<AntiForensicFinding> {
        let mut findings = Vec::new();

        if events.len() < 2 {
            return findings;
        }

        let mut prev_usn = events[0].usn;
        let mut gap_count = 0;
        let mut total_gap_entries = 0u64;

        for ev in &events[1..] {
            let gap = ev.usn - prev_usn;
            if gap > 1 {
                gap_count += 1;
                total_gap_entries += (gap - 1) as u64;
            }
            prev_usn = ev.usn;
        }

        if gap_count > 0 {
            let avg_gap = if gap_count > 0 { total_gap_entries as f64 / gap_count as f64 } else { 0.0 };
            let severity = if avg_gap > 100.0 {
                IntegritySeverity::Critical
            } else if avg_gap > 10.0 {
                IntegritySeverity::Suspicious
            } else {
                IntegritySeverity::Warning
            };

            findings.push(AntiForensicFinding {
                finding_type: AntiForensicType::JournalContinuityBreak,
                severity,
                description: format!("Found {} gaps in USN journal sequence ({} missing entries)", gap_count, total_gap_entries),
                evidence: vec![
                    format!("Gap count: {}", gap_count),
                    format!("Missing entries: {}", total_gap_entries),
                    format!("Average gap size: {:.1}", avg_gap),
                    format!("Events analyzed: {}", events.len()),
                ],
                confidence: if avg_gap > 100.0 { 0.9 } else { 0.6 },
                affected_artifacts: vec!["USN Journal".into()],
                timestamp: Timestamp::now(),
                mitre_technique: Some("T1070.004".into()),
            });
        }

        findings
    }

    /// MFT slack-space detection: check for records with data but marked deleted
    pub fn detect_mft_slack_artifacts(&self, mft_reader: &MftReader) -> Vec<AntiForensicFinding> {
        let mut findings = Vec::new();
        let total = mft_reader.total_records();

        // Sample MFT for deleted records with non-zero data sizes
        let sample_size = total.min(100_000);
        let mut deleted_with_data = 0u64;
        let mut total_deleted = 0u64;

        for i in 0..sample_size {
            if let Ok(Some(record)) = mft_reader.read_record(i as u32) {
                if record.is_deleted {
                    total_deleted += 1;
                    if record.data_size > 0 {
                        deleted_with_data += 1;
                    }
                }
            }
        }

        if total_deleted > 0 && deleted_with_data > 0 {
            let ratio = deleted_with_data as f64 / total_deleted as f64;
            if ratio > 0.1 {
                findings.push(AntiForensicFinding {
                    finding_type: AntiForensicType::SlackSpaceArtifact,
                    severity: IntegritySeverity::Warning,
                    description: format!("Found {}/{} ({}%) deleted MFT records with residual data — slack-space recovery possible", deleted_with_data, total_deleted, (ratio * 100.0) as u32),
                    evidence: vec![
                        format!("Deleted records sampled: {}", total_deleted),
                        format!("With residual data: {}", deleted_with_data),
                        format!("Ratio: {:.1}%", ratio * 100.0),
                    ],
                    confidence: 0.8,
                    affected_artifacts: vec!["MFT".into()],
                    timestamp: Timestamp::now(),
                    mitre_technique: Some("T1552.004".into()),
                });
            }
        }

        findings
    }

    /// Run all anti-forensic checks and return consolidated findings
    pub fn analyze_all(
        &mut self,
        usn_reader: &UsnJournalReader,
        mft_reader: &MftReader,
        events: &[FilesystemEvent],
    ) -> Vec<AntiForensicFinding> {
        let mut all = Vec::new();
        all.extend(self.analyze_journal(usn_reader));
        all.extend(self.detect_timestomping(events));
        all.extend(self.detect_ads_abuse(events));
        all.extend(self.detect_reparse_point_abuse(events));
        all.extend(self.detect_hidden_executables(events));
        all.extend(self.analyze_journal_continuity(events));
        all.extend(self.detect_mft_slack_artifacts(mft_reader));

        // Sort by severity
        all.sort_by(|a, b| {
            let severity_order = |s: &IntegritySeverity| -> u8 {
                match s {
                    IntegritySeverity::Critical => 0,
                    IntegritySeverity::Suspicious => 1,
                    IntegritySeverity::Warning => 2,
                    IntegritySeverity::Info => 3,
                }
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        all
    }
}
