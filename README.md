# IntegrityMonitor

A production-grade Windows security monitoring, anti-cheat, forensic analysis, and telemetry platform. Built with Rust + Tauri.

> **Admin requirement:** Full data collection (module enumeration, memory scanning, kernel driver operations) requires running as Administrator. Without elevation, the system operates in limited mode — process list and basic file/network telemetry still function.

---

## Detection Engine — 26 Techniques

The detection engine evaluates 26 techniques across all running processes every 3 seconds, producing per-technique confidence scores (0.0–1.0), severity ratings, evidence, telemetry-gap documentation, and bypass-risk estimates.

| # | Technique | Targets | Severity | Bypass Risk |
|---|-----------|---------|----------|-------------|
| 1 | **Process Hollowing** | Processes whose signed-module ratio is 0 out of many — indicates replaced .text section | CRITICAL | 0.6 |
| 2 | **Manual Mapping** | MEM_PRIVATE \| PAGE_EXECUTE_READWRITE regions with no file mapping (unlinked DLLs) | MEDIUM | 0.7 |
| 3 | **Reflective DLL Injection** | Executable private memory containing PE header (MZ) not in loaded module list; thread start addresses landing in private memory | HIGH | 0.6 |
| 4 | **APC Injection** | QueueUserAPC to remote processes; threads returning from alertable waits with unexpected RIP | HIGH | 0.8 |
| 5 | **CreateRemoteThread** | OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread chain | HIGH | 0.5 |
| 6 | **Process Doppelganging** | NTFS transacted I/O — process with no backing file on disk; TxF handles | CRITICAL | 0.9 |
| 7 | **Transacted Hollowing** | TxF replacement of existing executable contents | CRITICAL | 0.9 |
| 8 | **RWX Shellcode** | Modules loaded from temp directories as shellcode staging indicator | CRITICAL | 0.3 |
| 9 | **PowerShell Abuse** | Command-line pattern matching: `-EncodedCommand`, `-Exec Bypass`, `Invoke-Expression`, `DownloadString`, `FromBase64String`, etc. | HIGH | 0.4 |
| 10 | **AMSI Bypass** | amsi.dll .text section hash mismatch; WriteProcessMemory targeting amsi.dll | CRITICAL | 0.7 |
| 11 | **ETW Bypass** | ntdll!EtwEventWrite function bytes modified; provider registration tampering | CRITICAL | 0.8 |
| 12 | **DLL Unlinking** | PEB InLoadOrderModuleList vs. VAD enumeration discrepancy; FLINK/BLINK integrity | HIGH | 0.5 |
| 13 | **PEB Tampering** | BeingDebugged / NtGlobalFlag / ImageBaseAddress mismatch | MEDIUM | 0.4 |
| 14 | **Handle Hijacking** | OpenProcess to LSASS/winlogon with PROCESS_ALL_ACCESS; ObCallback logging | HIGH | 0.6 |
| 15 | **LSASS Dumping** | MiniDumpWriteDump to PID 4 (LSASS); handles with PROCESS_VM_READ; .dmp file creation | CRITICAL | 0.6 |
| 16 | **Kernel Callback Tampering** | Registered callback list vs. known-good baseline; unexpected or missing callbacks | CRITICAL | 0.9 |
| 17 | **Cheat Engine** | Process name signatures; VEH debugging hooks | MEDIUM | 0.3 |
| 18 | **Speedhack** | QPC ticks vs. wall-clock ratio deviating from expected range | CRITICAL | 0.4 |
| 19 | **Overlay Injection** | WS_EX_LAYERED/TOOLWINDOW windows; d3d11.dll in non-game processes | LOW | 0.2 |
| 20 | **Unsigned Driver** | EnumDeviceDrivers + WinVerifyTrust; known-vulnerable drivers (BYOVD) | CRITICAL | 0.6 |
| 21 | **Thread Context Hijack** | SetThreadContext redirecting RIP; unexpected CONTEXT_EXTENDED registers | HIGH | 0.7 |
| 22 | **Token Privilege Escalation** | SeDebugPrivilege / SeTcbPrivilege / SeLoadDriverPrivilege via AdjustTokenPrivileges | HIGH | 0.5 |
| 23 | **Image Hijacking** | DLLs loaded from AppData/Temp/Downloads; unsigned DLLs from non-system paths | HIGH | 0.3 |
| 24 | **WMI Persistence** | __FilterToConsumerBinding, __EventFilter, __CommandLineEventConsumer instances | HIGH | 0.5 |
| 25 | **Scheduled Task Abuse** | schtasks.exe with suspicious params; tasks executing from user-writable locations | HIGH | 0.5 |
| 26 | **NTDLL Unhooking** | In-memory ntdll .text section hash vs. on-disk; syscall stubs (Hell's Gate / Halo's Gate) | HIGH | 0.7 |

### Detection Infrastructure

- **`AnomalyTracker`** — sliding-window anomaly detection over overall risk scores. Uses Welford's online algorithm for mean/std; 3-sigma z-score threshold; 10-sample baseline warmup; full adaptation at 100 samples; 3600-second window
- **`DetectionSummary`** — aggregates all 26 results; produces scoring indicators (`detect:*` prefixed flags, `high_detection_risk`, `multiple_techniques_detected`, `high_bypass_risk`)
- Per-technique telemetry-gap documentation and bypass-risk estimates for honest operational posture assessment

---

## Process & Module Analysis

### Process Monitor
- Polls all running processes every 3 seconds via `sysinfo::System`
- Captures: PID, parent PID, name, path, command line, CPU usage, memory usage, start time
- **Module enumeration** (`CreateToolhelp32Snapshot`): enumerates all loaded DLLs per process
- Module-level analysis:
  - **Authenticode verification** via `WinVerifyTrust` + `CryptQueryObject` + `CertFindCertificateInStore`
  - **Partial SHA-256 hashing**: first 4KB + last 4KB + filename + file size (for files ≥ 4KB); full hash for smaller files
  - **Suspicion heuristics**: temp-directory path, unsigned + non-system path, non-standard drive
- **Hash/trust cache** (`TRUST_CACHE`): 10,000-entry LRU with 300-second TTL

### File Monitor
- **Real-time directory change notification** via `ReadDirectoryChangesW` (overlapped I/O)
- Watches: `%TEMP%`, `C:\Windows\Temp`, `%LOCALAPPDATA%`
- Tracks 11 extensions: `exe`, `dll`, `sys`, `bat`, `ps1`, `vbs`, `js`, `jar`, `scr`, `com`, `tmp`
- Events: created, deleted, modified, renamed
- Ring buffer capped at 10,000 events

### Memory Scanner
- **VirtualQueryEx** enumeration per process: base address, size, state (committed/reserved/free), protection (NOACCESS/RO/RW/WC/EX/EX_RO/EX_RW/EX_WC), type (image/mapped/private)
- Flags suspicious: RWX regions (`PAGE_EXECUTE_READWRITE`) and executable + private memory combinations

### DLL Analyzer
- Suspicious module characteristics: unsigned from non-system path, temp-directory loading, name pattern matching (inject, hook, loader, cheat), null base address, `\Device\` paths

---

## Network Telemetry

### TCP Connection Tracking
- Enumerates all TCP connections via `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_ALL`)
- Per-connection: state, local/remote address:port, owning PID
- State classification: closed, listening, syn_sent, established, fin_wait, close_wait, time_wait, etc.

### Beaconing Detection
- Records connection timestamps per (PID, remote addr, port) tuple
- Computes interval statistics: mean, standard deviation, coefficient of variation
- Flags regular beaconing when CV < 0.3 (confidence 0.8) or CV < 0.5 (confidence 0.5)
- Requires minimum 3 samples; intervals < 600s; 1-hour sliding retention

---

## Emulator Detection

Detects running Android emulators by process-name pattern matching and install-path presence:

| Emulator | Process Patterns | Install Paths | Integrity Score |
|----------|-----------------|---------------|-----------------|
| BlueStacks | HD-Player.exe, BlueStacks.exe, HD-Adb.exe, BstkSVC.exe | `C:\Program Files\BlueStacks` | 0–100 |
| LDPlayer | dnplayer.exe, LdBoxHeadless.exe, LdConsole.exe | `C:\Program Files\LDPlayer` | 0–100 |
| GameLoop | aow_exe*.exe, GameLoop.exe, TxGameAssistant.exe | `C:\Program Files\GameLoop` | 0–100 |
| MSI App Player | MSIAppPlayer.exe | `C:\Program Files\MSI App Player` | 0–100 |

Scoring: 95 (running + correct path), 70 (running + no path), 100 (not running + path exists), 0 (not present).

---

## Anti-Cheat Monitor

| Detection | Method | Confidence |
|-----------|--------|------------|
| Known cheat processes | 18 name patterns (CheatEngine, x64dbg, ProcessHacker, injector, etc.) | 0.85 |
| Overlays | 4 patterns (discord, steam, overwolf, razer) | 0.30 |
| Speedhack | QPC ratio vs wall-clock; flags <0.5 or >1.5; requires 30s uptime | 0.65 |
| Known cheat drivers | `C:\Windows\System32\drivers\*.sys` scanning; 4 name patterns | 0.90 |

---

## YARA Scanning

- Loads `.yar` / `.yara` rule files from `C:\ProgramData\IntegrityMonitor\yara` and `C:\Users\Public\Documents\IntegrityMonitor\yara`
- Hex pattern and ASCII string matching against file contents or memory buffers
- Tag-based severity extraction: `malware`/`critical` → CRITICAL, `suspicious`/`high` → HIGH

---

## Correlation Engine

### Real-time Correlation Actor (EventBus-based)
3-second-window event chaining over the telemetry stream:

| Chain Type | Trigger | Confidence | Description |
|------------|---------|------------|-------------|
| `process_network_suspicious` | ProcessCreated + NetworkConnection + SuspiciousActivity | 0.85 | Possible C2 beacon |
| `suspicious_process_behavior` | ProcessCreated + SuspiciousActivity | 0.70 | Suspicious new process |
| `integrity_violation` | IntegrityAlert | 0.90 | Process integrity violation |

### Static Correlation Rules (Timeline-based)

| Rule | Chain | Window | Confidence | Description |
|------|-------|--------|------------|-------------|
| `executable_download_execute_delete` | file_create → process_create → file_delete | 300s | 0.85 | Staged executable cleanup |
| `dll_injection_chain` | process_create → module_load → file_delete | 120s | 0.90 | Injected DLL cleanup |
| `powershell_cleanup` | process_create → file_delete | 60s | 0.75 | PowerShell script cleanup |
| `emulator_tampering` | module_load → process_create | 30s | 0.80 | Suspicious module in emulator |
| `usb_usage_chain` | usb_insert → process_create | 600s | 0.60 | USB autorun execution |
| `cleanup_script` | process_create → file_modify → file_delete | 120s | 0.70 | Script cleanup |

---

## Forensic Artifact Parsers (8 Parsers)

| Parser | Data Source | Analysis |
|--------|-------------|----------|
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | Full binary parse: SCCA signature, version, volume info (serial, creation, path), file metrics (run count, last run), strings; LZNT1/XPRESS/XPRESS_HUFF decompression; flags 14 suspicious name patterns |
| **PowerShell History** | `%APPDATA%\...\PSReadLine\ConsoleHost_history.txt` | Reads up to 500 lines; flags 28 sensitive commands (Invoke-Mimikatz, DownloadString, -EncodedCommand, etc.) |
| **Browser History** | Chrome/Edge `History` SQLite | Queries `urls` table (url, title, visit_count, last_visit); flags 16 suspicious patterns (pastebin, exploit, cheat, etc.); 200-entry limit |
| **Amcache** | `C:\Windows\AppCompat\Programs\Amcache.hve` | File existence and size metadata |
| **BAM** | Registry: `SYSTEM\...\bam\State\UserSettings` | Background Activity Moderator entry enumeration |
| **USB History** | Registry: `SYSTEM\...\Enum\USBSTOR` and `\USB` | USB device class and serial device enumeration |
| **USN Journal** | `C:\$Extend\$UsnJrnl\$J` | Change journal metadata (entry count, size) |
| **MFT** | `C:\$MFT` | Master File Table metadata (record count, size) |

---

## Scoring Engine

Weighted multi-category scoring with **6 categories** and **14 indicators**:

| Category | Weight | Indicators |
|----------|--------|------------|
| unsigned_modules | 25% | unsigned_dll (0.4), unsigned_driver (0.6) |
| process_behavior | 20% | hidden_process (0.8), suspicious_parent (0.3), remote_thread (0.7) |
| file_activity | 20% | deleted_executable (0.5), cleanup_script (0.6), timestamp_anomaly (0.3) |
| emulator_integrity | 20% | injected_dll (0.7), suspicious_overlay (0.6), modified_emulator_file (0.5) |
| memory_integrity | 15% | suspicious_memory (0.5), injected_code (0.8) |
| detection_engine | 25% | high_detection_risk (0.9), multiple_techniques (0.7), high_bypass_risk (0.3) |

Risk levels: **low** (<0.2), **medium** (<0.5), **high** (<0.8), **critical** (≥0.8).

---

## Search Engine

Full-text search via **Tantivy** (Rust Lucene):
- Indexes process names, paths, command lines; file events; detection results; timeline events
- 7 fields: id, title, description, category, timestamp, path, content
- 50MB writer buffer; auto-commit every 100 docs or 30 seconds
- Index location: `%LOCALAPPDATA%\IntegrityMonitor\search_index`
- Fallback linear scan when Tantivy returns no results

---

## Database Schema (10 Tables)

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `processes` | Process history with suspicion metadata | pid, parent_pid, name, path, cmdline, cpu/mem usage, session, integrity, is_suspicious, score |
| `process_modules` | Per-process loaded modules | pid, base_address, size, path, is_signed, signer, hash |
| `file_events` | File system change log | path, event_type, timestamp, size, hash, process_pid |
| `timeline_events` | Central event log (JSON details) | id, timestamp, event_type, category, severity, source, details |
| `correlations` | Related event chains | relationship_type, confidence, events (JSON), time window |
| `emulator_entries` | Emulator detection results | name, pid, running, integrity_score, file_modifications |
| `suspicion_scores` | Scoring snapshots | overall_score, categories, flags, risk_level |
| `artifacts` | Forensic parser results | parser_name, entry_type, data, is_suspicious |
| `network_events` | Connection history | pid, local/remote addr:port, protocol |
| `alerts` | Detection alerts | rule_name, severity, description, evidence |

7 indexes on timestamp, category, pid, severity columns. WAL mode with 5s busy timeout.

---

## Storage

- **Batched SQLite writer** via `StorageActor`: subscribes to EventBus, queues events, flushes in single transactions (50 events or 1000ms)
- 6 batch operation types: InsertProcess, UpdateTermination, InsertFileEvent, InsertNetwork, InsertAlert
- Database location: `%LOCALAPPDATA%\IntegrityMonitor\integrity_monitor.db`

---

## Event Bus

- **Actor model** with `tokio::sync::broadcast` channel (capacity 4,096)
- 10 telemetry event types: ProcessCreated, ProcessTerminated, ThreadCreated, ImageLoaded, FileChanged, NetworkConnection, RegistryModified, SuspiciousActivity, IntegrityAlert
- 3 background actors spawned at startup: ETW consumer, StorageActor, CorrelationActor
- Process table: `Arc<DashMap<u32, ProcessState>>` for lock-free concurrent access

---

## Tauri API (24 Commands)

| Command | Returns | Description |
|---------|---------|-------------|
| `get_processes` | `ProcessInfo[]` | Full process list refresh with modules |
| `get_process_modules` | `ModuleInfo[]` | Modules for a given PID |
| `get_process_tree` | `ProcessInfo[]` | Cached snapshot |
| `get_file_activity` | `FileEvent[]` | Recent file changes |
| `get_timeline_events` | `TimelineEvent[]` | Filtered timeline (category, limit) |
| `get_correlated_events` | `CorrelationEvent[]` | All correlation chains |
| `get_emulator_status` | `EmulatorInfo[]` | Emulator detection results |
| `get_suspicion_scores` | `SuspicionScore` | Running scoring engine |
| `search_all` | `SearchResult[]` | Full-text search |
| `get_artifact_summary` | `ArtifactSummary[]` | All forensic parsers |
| `get_system_overview` | `DashboardMetrics` | Summary metrics |
| `scan_file_with_yara` | `string[]` | YARA file scan |
| `get_integrity_report` | `string` (JSON) | Serialized integrity report |
| `export_timeline` | `string` (JSON) | Full timeline export |
| `get_kernel_driver_status` | `bool` | Driver running |
| `install_kernel_driver` | `bool` | Install SCM service (admin) |
| `start_kernel_driver` | `bool` | Start driver (admin) |
| `start_monitoring` | `()` | Begin 3s polling loop |
| `stop_monitoring` | `()` | Halt monitoring |
| `get_dashboard_metrics` | `DashboardMetrics` | Dashboard summary |
| `get_network_connections` | `TcpConnection[]` | TCP table snapshot |
| `get_memory_regions` | `MemoryRegion[]` | Per-PID memory map (admin) |
| `verify_file_trust` | `TrustInfo` | WinVerifyTrust for a file |
| `get_detection_status` | `DetectionSummary` | 26-technique evaluation |

---

## Kernel Driver Management

- Windows Service Control Manager (SCM) operations via `OpenSCManagerW` / `CreateServiceW` / `StartServiceW` / `ControlService` / `DeleteService`
- Binary path: `\SystemRoot\System32\drivers\IntegrityMonitor.sys`
- Operations: install, start, stop, uninstall, status query
- Service type: `SERVICE_KERNEL_DRIVER`, start type: demand start
- Requires Administrator privileges for all operations

---

## Windows APIs Used (38 Distinct)

| API | Module | Purpose |
|-----|--------|---------|
| `CreateToolhelp32Snapshot` / `Module32FirstW` / `Module32NextW` | process_monitor | DLL enumeration |
| `ReadDirectoryChangesW` / `CreateFileW` | file_monitor | Real-time file change detection |
| `CreateEventW` / `WaitForSingleObject` / `GetOverlappedResult` | file_monitor | Overlapped I/O completion |
| `CancelIoEx` | file_monitor | Async operation cancellation |
| `WinVerifyTrust` | trust | Authenticode signature verification |
| `CryptQueryObject` / `CertFindCertificateInStore` / `CertGetNameStringW` | trust | Certificate chain extraction |
| `OpenProcess` / `VirtualQueryEx` | memory | Process memory enumeration |
| `GetExtendedTcpTable` | network | TCP connection table |
| `QueryPerformanceFrequency` / `QueryPerformanceCounter` | anti_cheat | High-resolution timing |
| `OpenSCManagerW` / `CreateServiceW` / `StartServiceW` / `ControlService` / `DeleteService` | kernel | Driver lifecycle |
| `GetModuleHandleW` / `GetProcAddress` | artifact_parsers, ntapi | Dynamic API resolution |
| `RtlDecompressBuffer` (indirect) | artifact_parsers | Prefetch decompression |
| `NtQuerySystemInformation` (indirect) | ntapi | System process info |
| `OpenProcessToken` / `GetTokenInformation` / `GetCurrentProcess` | admin | Elevation check |
| `GetProcessTimes` | win32 | Process creation time |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         Tauri Frontend                       │
│             (React + TypeScript + Recharts)                  │
└──────────────────────┬──────────────────────────────────────┘
                       │ 24 IPC Commands + Event Streams
┌──────────────────────▼──────────────────────────────────────┐
│                      CoreState (RwLock)                      │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐   │
│  │ Process  │  File    │Detection │ Timeline │  Search  │   │
│  │ Monitor  │  Monitor │ Engine   │ Engine   │  Engine  │   │
│  ├──────────┼──────────┼──────────┼──────────┼──────────┤   │
│  │Emulator  │Correlat.│ Scoring  │ Artifact │  Kernel  │   │
│  │ Monitor  │ Engine   │ Engine   │ Parsers  │  Driver  │   │
│  ├──────────┼──────────┼──────────┼──────────┼──────────┤   │
│  │ Anti-    │   DLL   │ Anomaly  │   YARA   │ Network  │   │
│  │ Cheat    │Analyzer  │ Tracker  │ Scanner  │  Table   │   │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                    EventBus (broadcast)                       │
│   ETW Consumer  │  Storage Actor  │  Correlation Actor       │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                    SQLite Database (10 tables)                │
│   WAL mode  │  Batched writes  │  7 indexes                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Build

```bash
cargo tauri build
```

Requires Rust 1.75+ and Node.js 18+. The Tauri webview renders the React frontend for real-time dashboard, timeline, detection alerts, artifact reports, and system overview.
