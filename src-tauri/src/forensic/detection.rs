use crate::forensic::usn::{ParsedUsnRecord, UsnReason, FileRef};
use crate::forensic::logfile::GhostRecord;
use crate::forensic::MftTimestamps;
use chrono::{DateTime, Utc, TimeDelta};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ─── Detection Types ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub rule_name: String,
    pub technique: String,
    pub confidence: f64,
    pub severity: Severity,
    pub evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub pid: Option<u32>,
    pub file_path: Option<String>,
    pub bypass_risk: f64,
}

impl DetectionResult {
    pub fn critical(technique: &str, evidence: impl Into<String>) -> Self {
        Self {
            rule_name: technique.into(),
            technique: technique.into(),
            confidence: 0.9,
            severity: Severity::Critical,
            evidence: vec![evidence.into()],
            timestamp: Utc::now(),
            pid: None,
            file_path: None,
            bypass_risk: 0.3,
        }
    }

    pub fn high(technique: &str, evidence: impl Into<String>) -> Self {
        Self {
            rule_name: technique.into(),
            technique: technique.into(),
            confidence: 0.75,
            severity: Severity::High,
            evidence: vec![evidence.into()],
            timestamp: Utc::now(),
            pid: None,
            file_path: None,
            bypass_risk: 0.4,
        }
    }

    pub fn medium(technique: &str, evidence: impl Into<String>) -> Self {
        Self {
            rule_name: technique.into(),
            technique: technique.into(),
            confidence: 0.5,
            severity: Severity::Medium,
            evidence: vec![evidence.into()],
            timestamp: Utc::now(),
            pid: None,
            file_path: None,
            bypass_risk: 0.5,
        }
    }

    pub fn low(technique: &str, evidence: impl Into<String>) -> Self {
        Self {
            rule_name: technique.into(),
            technique: technique.into(),
            confidence: 0.25,
            severity: Severity::Low,
            evidence: vec![evidence.into()],
            timestamp: Utc::now(),
            pid: None,
            file_path: None,
            bypass_risk: 0.6,
        }
    }

    pub fn none() -> Self {
        Self {
            rule_name: String::new(),
            technique: String::new(),
            confidence: 0.0,
            severity: Severity::None,
            evidence: Vec::new(),
            timestamp: Utc::now(),
            pid: None,
            file_path: None,
            bypass_risk: 0.0,
        }
    }

    pub fn score(&self) -> f64 {
        let sw = match self.severity {
            Severity::Critical => 0.95,
            Severity::High => 0.75,
            Severity::Medium => 0.5,
            Severity::Low => 0.25,
            Severity::None => 0.0,
        };
        sw * self.confidence * (1.0 - self.bypass_risk)
    }

    pub fn is_detected(&self) -> bool {
        self.severity != Severity::None && self.confidence > 0.3
    }
}

// ─── Rule Context ────────────────────────────────────────────────────

pub struct RuleContext {
    pub usn_records: Vec<ParsedUsnRecord>,
    pub ghost_records: Vec<GhostRecord>,
    pub mft_entries: Vec<crate::forensic::mft::MftRecord>,
    pub logfile_data: Vec<u8>,
    pub mftmirr_data: Option<Vec<u8>>,
    pub window_seconds: i64,
}

// ─── Rule Trait ──────────────────────────────────────────────────────

pub trait ForensicsRule: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult>;
}

// ─── 1. Journal Clear Detection ──────────────────────────────────────

pub struct JournalClearRule;

impl ForensicsRule for JournalClearRule {
    fn name(&self) -> &'static str { "Journal Clear Detection" }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        if ctx.ghost_records.is_empty() {
            return results;
        }

        let ghost_count = ctx.ghost_records.len();
        let allocated_count = ctx.usn_records.len();

        if ghost_count > allocated_count {
            results.push(DetectionResult::high("T1070.004",
                format!("Ghost records ({}) exceed allocated USN records ({}). Possible fsutil usn deletejournal",
                    ghost_count, allocated_count)));
        } else if ghost_count as f64 > allocated_count as f64 * 0.1 {
            results.push(DetectionResult::medium("T1070.004",
                format!("Ghost records ({}) > 10% of allocated ({}). Possible journal clearing or wrap",
                    ghost_count, allocated_count)));
        }

        // Check: ghost records older than oldest allocated USN
        if let (Some(oldest_ghost), Some(oldest_alloc)) = (
            ctx.ghost_records.iter().map(|g| g.timestamp).min(),
            ctx.usn_records.iter().map(|r| r.timestamp).min(),
        ) {
            if oldest_ghost < oldest_alloc {
                let gap_hours = (oldest_alloc - oldest_ghost).num_hours();
                results.push(DetectionResult::high("T1070.004",
                    format!("Ghost records predate oldest allocated USN by {} hours. Journal was cleared.", gap_hours)));
            }
        }

        results
    }
}

// ─── 2. Timestomping Detection ───────────────────────────────────────

pub struct TimestompRule;

impl ForensicsRule for TimestompRule {
    fn name(&self) -> &'static str { "Timestomping Detection" }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        for mft_entry in &ctx.mft_entries {
            let si = match &mft_entry.timestamps {
                Some(ts) => ts,
                None => continue,
            };

            // Find FN timestamp from attributes
            let fn_ts = mft_entry.attributes.iter().find_map(|attr| {
                if let crate::forensic::mft::MftAttribute::FileName { timestamps, .. } = attr {
                    Some(timestamps)
                } else {
                    None
                }
            });

            // Check SI vs FN timestamp mismatch
            if let Some(fn_ts) = fn_ts {
                let si_created_ft = si.si_created.to_filetime();
                let fn_created_ft = fn_ts.si_created.to_filetime();
                let diff_secs = (si_created_ft - fn_created_ft).abs() / 10_000_000;
                if diff_secs > 2 {
                    results.push(DetectionResult::medium("T1070.006",
                        format!("MFT entry {}: SI_Created vs FN_Created mismatch by {}s. Possible timestomping.",
                            mft_entry.record_number, diff_secs)));
                }
            }

            // Check earliest USN record vs SI_Created
            let entry_records: Vec<_> = ctx.usn_records.iter()
                .filter(|r| r.file_reference.entry_number() == mft_entry.record_number as u64)
                .collect();

            if let Some(earliest_usn) = entry_records.iter().map(|r| r.timestamp).min() {
                let si_create_dt = si.created_datetime();
                if si_create_dt > earliest_usn {
                    let diff_secs = (si_create_dt - earliest_usn).num_seconds().abs();
                    if diff_secs > 5 {
                        results.push(DetectionResult::high("T1070.006",
                            format!("MFT entry {}: SI_Created ({}) is after earliest USN record ({}). Timestamp backdated by {}s.",
                                mft_entry.record_number, si_create_dt, earliest_usn, diff_secs)));
                    }
                }
            }
        }

        results
    }
}

// ─── 3. Secure Deletion Detection ────────────────────────────────────

pub struct SecureDeleteRule;

impl ForensicsRule for SecureDeleteRule {
    fn name(&self) -> &'static str { "Secure Deletion Detection" }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        let mut by_ref: HashMap<u64, Vec<&ParsedUsnRecord>> = HashMap::new();
        for rec in &ctx.usn_records {
            if rec.reason.intersects(UsnReason::FILE_DELETE | UsnReason::RENAME_OLD_NAME | UsnReason::RENAME_NEW_NAME) {
                by_ref.entry(rec.file_reference.entry_number()).or_default().push(rec);
            }
        }

        for (ref_num, recs) in &by_ref {
            let names: Vec<&str> = recs.iter().map(|r| r.file_name.as_str()).collect();

            // SDelete: AAAA, BBBB, CCCC, ..., ZZZZ -> delete
            let repeating_alpha = names.iter()
                .filter(|n| n.len() >= 2 && n.chars().all(|c| n.chars().next() == Some(c)))
                .count();

            if repeating_alpha >= 2 {
                results.push(DetectionResult::high("T1070.004",
                    format!("SDelete pattern on ref {}: {} renames with repeating characters before deletion", ref_num, names.len())));
            }

            // CCleaner: .tmp bulk delete
            let tmp_count = names.iter().filter(|n| n.to_lowercase().ends_with(".tmp")).count();
            if tmp_count as f64 > names.len() as f64 * 0.5 && names.len() >= 5 {
                results.push(DetectionResult::medium("T1070.004",
                    format!("CCleaner-like pattern: {} of {} names are .tmp files", tmp_count, names.len())));
            }
        }

        results
    }
}

// ─── 4. Ransomware Pattern Detection ─────────────────────────────────

pub struct RansomwareRule;

impl ForensicsRule for RansomwareRule {
    fn name(&self) -> &'static str { "Ransomware Pattern Detection" }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        let ransomware_exts: HashSet<&str> = [
            ".encrypted", ".locked", ".crypto", ".zepto", ".cerber",
            ".cry", ".crypt", ".locky", ".wallet", ".onion",
            ".aaa", ".micro", ".better_call_saul", ".harry",
        ].iter().cloned().collect();

        // Group by parent directory (approximated via parent ref)
        let mut by_parent: HashMap<u64, Vec<&ParsedUsnRecord>> = HashMap::new();
        for rec in &ctx.usn_records {
            if rec.reason.intersects(UsnReason::RENAME_NEW_NAME | UsnReason::DATA_EXTEND | UsnReason::DATA_OVERWRITE) {
                let parent = rec.parent_reference.entry_number();
                by_parent.entry(parent).or_default().push(rec);
            }
        }

        for (parent, recs) in &by_parent {
            if recs.len() < 50 {
                continue; // threshold
            }

            let rename_count = recs.iter().filter(|r| r.reason.contains(UsnReason::RENAME_NEW_NAME)).count();
            let data_write_count = recs.iter().filter(|r| {
                r.reason.contains(UsnReason::DATA_EXTEND) || r.reason.contains(UsnReason::DATA_OVERWRITE)
            }).count();

            if rename_count < 10 || data_write_count < 20 {
                continue;
            }

            // Check for ransomware extensions
            let ext_match = recs.iter().any(|r| {
                ransomware_exts.iter().any(|ext| r.file_name.to_lowercase().ends_with(ext))
            });

            if ext_match {
                results.push(DetectionResult::critical("T1486",
                    format!("Ransomware pattern: parent ref {} - {} renames + {} writes with known ransomware extensions",
                        parent, rename_count, data_write_count)));
            } else {
                // Mass rename without known extensions is still suspicious
                let time_window = recs.last().map(|r| r.timestamp)
                    .zip(recs.first().map(|r| r.timestamp));
                if let Some((last, first)) = time_window {
                    if (last - first).num_seconds() < 60 && rename_count > 20 {
                        results.push(DetectionResult::high("T1486",
                            format!("Possible ransomware: {} files renamed within {}s", rename_count, (last - first).num_seconds())));
                    }
                }
            }
        }

        results
    }
}

// ─── 5. Dropper Staging Detection ────────────────────────────────────

pub struct DropperStagingRule;

impl ForensicsRule for DropperStagingRule {
    fn name(&self) -> &'static str { "Dropper Staging Detection" }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        let mut by_parent: HashMap<u64, Vec<&ParsedUsnRecord>> = HashMap::new();
        for rec in &ctx.usn_records {
            if rec.reason.contains(UsnReason::FILE_CREATE) {
                by_parent.entry(rec.parent_reference.entry_number()).or_default().push(rec);
            }
        }

        for (parent, creates) in &by_parent {
            let temp_creates = creates.iter()
                .filter(|r| {
                    let lower = r.file_name.to_lowercase();
                    lower.contains("temp") || lower.contains("appdata") || lower.contains("download")
                }).count();

            if temp_creates > 0 {
                let system_creates = creates.iter()
                    .filter(|r| {
                        let lower = r.file_name.to_lowercase();
                        lower.contains("system32") || lower.contains("syswow64")
                    }).count();

                if temp_creates >= 1 && system_creates >= 1 {
                    results.push(DetectionResult::high("T1072",
                        format!("Dropper staging: parent ref {} — {} temp creates + {} System32 creates",
                            parent, temp_creates, system_creates)));
                }
            }
        }

        results
    }
}

// ─── 6. ADS (Alternate Data Stream) Detection ────────────────────────

pub struct AdsAbuseRule;

impl ForensicsRule for AdsAbuseRule {
    fn name(&self) -> &'static str { "ADS Abuse Detection" }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        ctx.usn_records.iter()
            .filter(|r| r.reason.intersects(
                UsnReason::NAMED_DATA_OVERWRITE
                | UsnReason::NAMED_DATA_EXTEND
                | UsnReason::NAMED_DATA_TRUNCATION
            ))
            .map(|r| {
                DetectionResult::medium("T1564.004",
                    format!("ADS operation on '{}' (ref {}): {:?}",
                        r.file_name, r.file_reference.entry_number(), r.reason))
            })
            .collect()
    }
}

// ─── 7. Process Doppelgänging Detection ──────────────────────────────

pub struct TransactedFileRule;

impl ForensicsRule for TransactedFileRule {
    fn name(&self) -> &'static str { "Transacted NTFS Abuse" }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        // TRANSACTED_CHANGE reason flag set indicates TxF operation
        for rec in &ctx.usn_records {
            if rec.reason.contains(UsnReason::TRANSACTED_CHANGE) {
                // Look for suspicious pattern: FILE_CREATE + TRANSACTED_CHANGE + FILE_DELETE
                let entry = rec.file_reference.entry_number();
                let related: Vec<_> = ctx.usn_records.iter()
                    .filter(|r| r.file_reference.entry_number() == entry)
                    .collect();

                let has_create = related.iter().any(|r| r.reason.contains(UsnReason::FILE_CREATE));
                let has_delete = related.iter().any(|r| r.reason.contains(UsnReason::FILE_DELETE));

                if has_create && has_delete {
                    results.push(DetectionResult::critical("T1055.015",
                        format!("Transacted file ref {}: {} — possible Process Doppelgänging",
                            entry, rec.file_name)));
                }
            }
        }

        results
    }
}

// ─── 8. Reparse Point Abuse ──────────────────────────────────────────

pub struct ReparsePointRule;

impl ForensicsRule for ReparsePointRule {
    fn name(&self) -> &'static str { "Reparse Point Abuse" }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        ctx.usn_records.iter()
            .filter(|r| r.reason.contains(UsnReason::REPARSE_POINT_CHANGE))
            .map(|r| {
                DetectionResult::medium("T1543.001",
                    format!("Reparse point change on '{}' — possible mount point or symlink abuse", r.file_name))
            })
            .collect()
    }
}

// ─── 9. File Timestamp Anomaly ───────────────────────────────────────

pub struct FileTimestampAnomalyRule;

impl ForensicsRule for FileTimestampAnomalyRule {
    fn name(&self) -> &'static str { "File Timestamp Anomaly" }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        let now = Utc::now();

        for rec in &ctx.usn_records {
            if rec.timestamp > now + TimeDelta::hours(1) {
                results.push(DetectionResult::high("T1070.006",
                    format!("USN record '{}' has future timestamp: {}", rec.file_name, rec.timestamp)));
            }
            if rec.timestamp.format("%Y").to_string().parse::<i32>().unwrap_or(9999) < 2000 {
                results.push(DetectionResult::high("T1070.006",
                    format!("USN record '{}' has invalid timestamp: {}", rec.file_name, rec.timestamp)));
            }
        }

        results
    }
}

// ─── 10. Persistence via DLL Creation ────────────────────────────────

pub struct PersistenceDllRule;

impl ForensicsRule for PersistenceDllRule {
    fn name(&self) -> &'static str { "Persistence DLL Detection" }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        for rec in &ctx.usn_records {
            let lower = rec.file_name.to_lowercase();
            if !lower.ends_with(".dll") {
                continue;
            }
            if !rec.reason.contains(UsnReason::FILE_CREATE) {
                continue;
            }

            let in_system = lower.contains("system32") || lower.contains("syswow64");
            let in_temp = lower.contains("\\temp\\") || lower.contains("\\appdata");
            let in_startup = lower.contains("startup") || lower.contains("\\roaming\\microsoft\\windows\\start menu");

            if in_startup {
                results.push(DetectionResult::high("T1547.001",
                    format!("DLL created in Startup folder: {}", rec.file_name)));
            }
            if in_system && in_temp {
                results.push(DetectionResult::high("T1074",
                    format!("DLL staged in Temp then deployed to System32: {}", rec.file_name)));
            }
        }

        results
    }
}

// ─── Rule Set ────────────────────────────────────────────────────────

pub struct AntiForensicRuleSet {
    rules: Vec<Box<dyn ForensicsRule>>,
}

impl AntiForensicRuleSet {
    pub fn new() -> Self {
        Self {
            rules: vec![
                Box::new(JournalClearRule),
                Box::new(TimestompRule),
                Box::new(SecureDeleteRule),
                Box::new(RansomwareRule),
                Box::new(DropperStagingRule),
                Box::new(AdsAbuseRule),
                Box::new(TransactedFileRule),
                Box::new(ReparsePointRule),
                Box::new(FileTimestampAnomalyRule),
                Box::new(PersistenceDllRule),
            ],
        }
    }

    pub fn evaluate_all(&self, ctx: &RuleContext) -> Vec<DetectionResult> {
        let mut all = Vec::new();
        for rule in &self.rules {
            let results = rule.evaluate(ctx);
            for r in results {
                if r.is_detected() {
                    all.push(r);
                }
            }
        }
        // Sort by score descending
        all.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap_or(std::cmp::Ordering::Equal));
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensic::usn::{ParsedUsnRecord, FileRef, UsnReason};
    use chrono::Utc;

    fn make_usn_record(ref_num: u64, name: &str, reason: UsnReason, timestamp: DateTime<Utc>) -> ParsedUsnRecord {
        ParsedUsnRecord {
            record_length: 60,
            major_version: 2,
            minor_version: 0,
            file_reference: FileRef::Ntfs(ref_num),
            parent_reference: FileRef::Ntfs(5),
            usn: ref_num * 100,
            timestamp,
            reason,
            source_info: 0,
            file_attributes: 0,
            file_name: name.to_string(),
            raw_reason: reason.bits(),
            source: crate::forensic::usn::RecordSource::Allocated,
        }
    }

    #[test]
    fn test_ransomware_rule_no_false_positive() {
        let ctx = RuleContext {
            usn_records: vec![
                make_usn_record(1, "document.txt", UsnReason::FILE_CREATE, Utc::now()),
                make_usn_record(1, "document.txt", UsnReason::DATA_EXTEND, Utc::now()),
            ],
            ghost_records: Vec::new(),
            mft_entries: Vec::new(),
            logfile_data: Vec::new(),
            mftmirr_data: None,
            window_seconds: 60,
        };

        let rule = RansomwareRule;
        let results = rule.evaluate(&ctx);
        assert!(results.is_empty(), "Should not trigger on 2 records");
    }

    #[test]
    fn test_timestomp_empty_mft_no_error() {
        let ctx = RuleContext {
            usn_records: Vec::new(),
            ghost_records: Vec::new(),
            mft_entries: Vec::new(),
            logfile_data: Vec::new(),
            mftmirr_data: None,
            window_seconds: 60,
        };

        let rule = TimestompRule;
        let results = rule.evaluate(&ctx);
        assert!(results.is_empty());
    }
}
