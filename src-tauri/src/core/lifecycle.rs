//! Process Lifecycle State — tracks every process from birth through death to archival.
//!
//! Maintains a dead process cache so terminated processes remain visible for
//! forensic replay, ancestry reconstruction, and attack-chain tracing.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

// ─── Lifecycle States ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProcessLifecycleState {
    /// Process is actively running
    Live = 0,
    /// Process is suspended (e.g., WER, debugger break)
    Suspended = 1,
    /// Process is a zombie (child reaped but entry not cleaned)
    Zombie = 2,
    /// Process has exited but is retained for forensic replay
    Terminated = 3,
    /// Process entry is historical (archived for long-term analysis)
    Historical = 4,
}

impl ProcessLifecycleState {
    pub fn is_active(&self) -> bool {
        matches!(self, ProcessLifecycleState::Live | ProcessLifecycleState::Suspended)
    }

    pub fn is_visible(&self) -> bool {
        !matches!(self, ProcessLifecycleState::Historical)
    }

    pub fn label(&self) -> &'static str {
        match self {
            ProcessLifecycleState::Live => "live",
            ProcessLifecycleState::Suspended => "suspended",
            ProcessLifecycleState::Zombie => "zombie",
            ProcessLifecycleState::Terminated => "terminated",
            ProcessLifecycleState::Historical => "historical",
        }
    }
}

// ─── Process Lifecycle Entry ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProcessLifecycle {
    pub pid: u32,
    pub state: ProcessLifecycleState,
    pub name: String,
    pub path: String,
    pub parent_pid: u32,
    pub start_time: String,
    pub exit_time: Option<String>,
    pub exit_code: Option<u32>,
    pub last_seen: Instant,
}

impl ProcessLifecycle {
    pub fn new(pid: u32, name: String, path: String, parent_pid: u32, start_time: String) -> Self {
        Self {
            pid,
            state: ProcessLifecycleState::Live,
            name,
            path,
            parent_pid,
            start_time,
            exit_time: None,
            exit_code: None,
            last_seen: Instant::now(),
        }
    }

    /// Time since this process was last refreshed (periodic monitor tick).
    pub fn age(&self) -> Duration {
        self.last_seen.elapsed()
    }

    pub fn mark_terminated(&mut self, exit_code: u32) {
        self.state = ProcessLifecycleState::Terminated;
        self.exit_code = Some(exit_code);
        self.exit_time = Some(chrono::Utc::now().to_rfc3339());
        self.last_seen = Instant::now();
    }

    pub fn mark_historical(&mut self) {
        self.state = ProcessLifecycleState::Historical;
    }

    pub fn refresh(&mut self) {
        self.last_seen = Instant::now();
    }
}

// ─── Dead Process Cache ──────────────────────────────────────────────────────

/// Holds terminated/historical process entries for forensic replay.
pub struct DeadProcessCache {
    /// Maximum number of dead processes to retain.
    max_entries: usize,
    /// Retention time for terminated processes before they become historical.
    terminate_ttl: Duration,
    /// Retention time for historical processes before eviction.
    historical_ttl: Duration,
}

impl DeadProcessCache {
    pub fn new() -> Self {
        Self {
            max_entries: 10_000,
            terminate_ttl: Duration::from_secs(3600),
            historical_ttl: Duration::from_secs(86400),
        }
    }

    pub fn with_limits(max_entries: usize, terminate_ttl: Duration, historical_ttl: Duration) -> Self {
        Self { max_entries, terminate_ttl, historical_ttl }
    }

    /// Returns true if the entry should be evicted.
    pub fn should_evict(&self, entry: &ProcessLifecycle) -> bool {
        match entry.state {
            ProcessLifecycleState::Terminated => entry.age() > self.terminate_ttl,
            ProcessLifecycleState::Historical => entry.age() > self.historical_ttl,
            _ => false,
        }
    }

    /// Prune expired entries from the cache. Returns the number removed.
    pub fn prune(&self, cache: &DashMap<u32, ProcessLifecycle>) -> usize {
        let mut removed = 0;
        cache.retain(|_pid, entry| {
            if self.should_evict(entry) {
                removed += 1;
                false
            } else {
                true
            }
        });
        if cache.len() > self.max_entries {
            // oldest-first eviction
            let mut entries: Vec<(u32, Instant)> = cache.iter()
                .map(|r| (*r.key(), r.value().last_seen))
                .collect();
            entries.sort_by_key(|&(_, ts)| ts);
            let excess = cache.len() - self.max_entries;
            for entry in entries.into_iter().take(excess) {
                cache.remove(&entry.0);
                removed += 1;
            }
        }
        removed
    }
}

impl Default for DeadProcessCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Processes a heartbeat tick: transitions Terminated → Historical after TTL,
/// evicts Historical entries past retention.
pub fn tick_lifecycle(cache: &DashMap<u32, ProcessLifecycle>, opts: &DeadProcessCache) {
    let now = Instant::now();
    let terminate_ttl = opts.terminate_ttl;
    let historical_ttl = opts.historical_ttl;

    cache.retain(|_pid, entry| {
        match entry.state {
            ProcessLifecycleState::Terminated if now.duration_since(entry.last_seen) > terminate_ttl => {
                entry.state = ProcessLifecycleState::Historical;
                entry.last_seen = now;
                true
            }
            ProcessLifecycleState::Historical if now.duration_since(entry.last_seen) > historical_ttl => {
                false
            }
            _ => true,
        }
    });
}

/// Reconstruct the ancestry chain for a PID from the process table + dead cache.
pub fn build_ancestry_chain(
    pid: u32,
    live_table: &DashMap<u32, ProcessLifecycle>,
    dead_cache: &DashMap<u32, ProcessLifecycle>,
) -> Vec<ProcessLifecycle> {
    let mut chain = Vec::new();
    let mut current = pid;

    loop {
        let found = live_table
            .get(&current)
            .map(|r| r.clone())
            .or_else(|| dead_cache.get(&current).map(|r| r.clone()));

        match found {
            Some(entry) => {
                let parent = entry.parent_pid;
                chain.push(entry);
                if parent == 0 || parent == current {
                    break;
                }
                current = parent;
            }
            None => break,
        }
    }

    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_transitions() {
        let mut p = ProcessLifecycle::new(100, "test.exe".into(), "C:\\test.exe".into(), 0, "now".into());
        assert_eq!(p.state, ProcessLifecycleState::Live);
        p.mark_terminated(0);
        assert_eq!(p.state, ProcessLifecycleState::Terminated);
        assert!(p.exit_code.is_some());
    }

    #[test]
    fn test_dead_cache_prune() {
        let cache = DashMap::new();
        let opts = DeadProcessCache::with_limits(
            100,
            Duration::from_secs(0), // immediate prune
            Duration::from_secs(0),
        );
        cache.insert(1, ProcessLifecycle::new(1, "a.exe".into(), "".into(), 0, "".into()));
        assert_eq!(cache.len(), 1);
        opts.prune(&cache);
        // all entries have age 0 which is >= 0, so they get pruned
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_ancestry_chain() {
        let live = DashMap::new();
        let dead = DashMap::new();

        live.insert(1, ProcessLifecycle::new(1, "init.exe".into(), "".into(), 0, "".into()));
        live.insert(2, ProcessLifecycle::new(2, "child.exe".into(), "".into(), 1, "".into()));
        live.insert(3, ProcessLifecycle::new(3, "grandchild.exe".into(), "".into(), 2, "".into()));

        let chain = build_ancestry_chain(3, &live, &dead);
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].pid, 3);
        assert_eq!(chain[2].pid, 1);
    }
}
