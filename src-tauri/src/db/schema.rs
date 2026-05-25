pub const CREATE_PROCESSES_TABLE: &str = "
CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    parent_pid INTEGER,
    name TEXT NOT NULL,
    path TEXT,
    command_line TEXT,
    cpu_usage REAL DEFAULT 0,
    memory_usage INTEGER DEFAULT 0,
    thread_count INTEGER DEFAULT 0,
    handle_count INTEGER DEFAULT 0,
    session_id INTEGER DEFAULT 0,
    start_time TEXT,
    exit_code INTEGER,
    is_suspicious INTEGER DEFAULT 0,
    suspicion_score REAL DEFAULT 0,
    suspicion_reasons TEXT,
    integrity_level TEXT,
    is_emulator_related INTEGER DEFAULT 0,
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now'))
);";

pub const CREATE_MODULES_TABLE: &str = "
CREATE TABLE IF NOT EXISTS process_modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    base_address TEXT,
    size INTEGER DEFAULT 0,
    path TEXT,
    name TEXT,
    is_signed INTEGER DEFAULT 0,
    signer TEXT,
    hash TEXT,
    is_suspicious INTEGER DEFAULT 0,
    suspicion_reasons TEXT,
    first_seen TEXT DEFAULT (datetime('now'))
);";

pub const CREATE_FILE_EVENTS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS file_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    file_name TEXT,
    event_type TEXT NOT NULL,
    timestamp TEXT DEFAULT (datetime('now')),
    size INTEGER DEFAULT 0,
    hash TEXT,
    process_pid INTEGER,
    process_name TEXT,
    is_suspicious INTEGER DEFAULT 0
);";

pub const CREATE_TIMELINE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS timeline_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    severity TEXT DEFAULT 'info',
    source TEXT,
    process_name TEXT,
    pid INTEGER,
    path TEXT,
    details TEXT
);";

pub const CREATE_CORRELATIONS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS correlations (
    id TEXT PRIMARY KEY,
    relationship_type TEXT NOT NULL,
    confidence REAL DEFAULT 0,
    description TEXT,
    timestamp_start TEXT,
    timestamp_end TEXT,
    events TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);";

pub const CREATE_EMULATOR_TABLE: &str = "
CREATE TABLE IF NOT EXISTS emulator_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    process_name TEXT,
    pid INTEGER,
    running INTEGER DEFAULT 0,
    integrity_score REAL DEFAULT 100,
    injected_dlls TEXT,
    suspicious_children TEXT,
    overlays_detected TEXT,
    file_modifications TEXT,
    last_checked TEXT
);";

pub const CREATE_SUSPICION_SCORES_TABLE: &str = "
CREATE TABLE IF NOT EXISTS suspicion_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,
    target_id TEXT,
    overall_score REAL DEFAULT 0,
    categories TEXT,
    flags TEXT,
    risk_level TEXT,
    calculated_at TEXT DEFAULT (datetime('now'))
);";

pub const CREATE_ARTIFACTS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parser_name TEXT NOT NULL,
    entry_type TEXT,
    data TEXT,
    hash TEXT,
    is_suspicious INTEGER DEFAULT 0,
    discovered_at TEXT DEFAULT (datetime('now'))
);";

pub const CREATE_NETWORK_EVENTS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    process_name TEXT,
    local_addr TEXT,
    local_port INTEGER,
    remote_addr TEXT,
    remote_port INTEGER,
    protocol TEXT,
    timestamp TEXT DEFAULT (datetime('now'))
);";

pub const CREATE_ALERTS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    pid INTEGER,
    process_name TEXT,
    evidence TEXT,
    timestamp TEXT DEFAULT (datetime('now'))
);";

pub const CREATE_INDEXES: &str = "
CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_timeline_category ON timeline_events(category);
CREATE INDEX IF NOT EXISTS idx_file_events_timestamp ON file_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_network_events_pid ON network_events(pid);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
";
