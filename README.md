# IntegrityMonitor

A production-grade Windows security monitoring, anti-cheat, forensic, and telemetry platform.

## Architecture

- **EventBus** actor model (broadcast::channel, capacity 4096)
- **DashMap** process table for lock-free concurrent access
- **Kernel driver** with process/image/thread/object callbacks
- **SQLite** persistence with WAL mode, 10 tables
- **Tauri** frontend with real-time event streaming

## Capabilities

- Process creation/module load telemetry
- Authenticode signature verification (WinVerifyTrust)
- PE parsing with entropy/anomaly analysis
- Memory region enumeration (VirtualQueryEx)
- TCP connection tracking (GetExtendedTcpTable)
- Beaconing detection (CV-based interval analysis)
- Anti-cheat: process scanning, overlay detection, speedhack detection
- Prefetch parsing with correct compression mapping
- Artifact parsing: PowerShell, Chrome/Edge history, USB, USN journal
- Correlation engine with 300s temporal sliding window
- YARA-based memory scanning
