use std::collections::VecDeque;
use crate::telemetry::ProcessTable;
use crate::core::ProcessInfo;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DetectionResult {
    pub technique: String,
    pub confidence: f64,
    pub severity: String,
    pub evidence: Vec<String>,
    pub telemetry_gaps: Vec<String>,
    pub bypass_risk: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DetectionSummary {
    pub total_techniques: usize,
    pub detected_techniques: Vec<String>,
    pub overall_risk_score: f64,
    pub results: Vec<DetectionResult>,
    pub false_positive_estimate: f64,
}

pub struct DetectionEngine {
    #[allow(dead_code)]
    proc_table: ProcessTable,
}

impl DetectionSummary {
    pub fn detection_indicators(&self) -> Vec<String> {
        let mut indicators = Vec::new();
        for r in &self.results {
            if r.confidence > 0.3 {
                indicators.push(format!("detect:{}", r.technique));
            }
        }
        if self.overall_risk_score > 0.5 {
            indicators.push("high_detection_risk".into());
        }
        if self.detected_techniques.len() >= 5 {
            indicators.push("multiple_techniques_detected".into());
        }
        if self.false_positive_estimate > 0.7 {
            indicators.push("high_bypass_risk".into());
        }
        indicators
    }

    #[allow(dead_code)]
    pub fn detection_severity(&self) -> &str {
        if self.overall_risk_score > 0.6 { "critical" }
        else if self.overall_risk_score > 0.4 { "high" }
        else if self.overall_risk_score > 0.2 { "medium" }
        else { "low" }
    }
}

pub struct AnomalyTracker {
    window: VecDeque<(chrono::DateTime<chrono::Utc>, f64)>,
    window_seconds: i64,
    baseline_mean: f64,
    baseline_m2: f64,
    samples: usize,
}

impl AnomalyTracker {
    pub fn new(window_seconds: i64) -> Self {
        Self {
            window: VecDeque::with_capacity(4096),
            window_seconds,
            baseline_mean: 0.0,
            baseline_m2: 0.0,
            samples: 0,
        }
    }

    pub fn record(&mut self, score: f64) {
        let now = chrono::Utc::now();
        self.window.push_back((now, score));
        while let Some(front) = self.window.front() {
            if (now - front.0).num_seconds() > self.window_seconds {
                self.window.pop_front();
            } else {
                break;
            }
        }
        if self.samples < 100 {
            self.samples += 1;
            let n = self.samples as f64;
            let old_mean = self.baseline_mean;
            let delta = score - old_mean;
            self.baseline_mean = old_mean + delta / n;
            if self.samples > 1 {
                self.baseline_m2 += delta * (score - self.baseline_mean);
            }
        }
    }

    pub fn is_anomalous(&self) -> bool {
        if self.samples < 10 {
            return false;
        }
        if self.window.is_empty() {
            return false;
        }
        let recent_avg: f64 = self.window.iter().map(|(_, s)| s).sum::<f64>() / self.window.len() as f64;
        let std = self.baseline_m2.sqrt() / (self.samples as f64).sqrt();
        let threshold = self.baseline_mean + 3.0 * std;
        recent_avg > threshold
    }

    pub fn z_score(&self) -> f64 {
        let std = self.baseline_m2.sqrt() / (self.samples as f64).sqrt();
        if self.samples < 2 || std < 0.001 {
            return 0.0;
        }
        let recent_avg: f64 = self.window.iter().map(|(_, s)| s).sum::<f64>() / self.window.len().max(1) as f64;
        (recent_avg - self.baseline_mean) / std
    }
}

impl DetectionEngine {
    pub fn new(proc_table: ProcessTable) -> Self {
        Self { proc_table }
    }

    pub fn evaluate_all(&self, processes: &[ProcessInfo]) -> DetectionSummary {
        let mut results = Vec::new();
        let mut detected = Vec::new();
        let mut total_confidence = 0.0;

        let detectors: Vec<fn(&Self, &[ProcessInfo]) -> DetectionResult> = vec![
            Self::detect_process_hollowing,
            Self::detect_manual_mapping,
            Self::detect_reflective_dll_injection,
            Self::detect_apc_injection,
            Self::detect_create_remote_thread,
            Self::detect_process_doppelganging,
            Self::detect_transacted_hollowing,
            Self::detect_rwx_shellcode,
            Self::detect_powershell_abuse,
            Self::detect_amsi_bypass,
            Self::detect_etw_bypass,
            Self::detect_dll_unlinking,
            Self::detect_peb_tampering,
            Self::detect_handle_hijacking,
            Self::detect_lsass_dumping,
            Self::detect_kernel_callback_tampering,
            Self::detect_cheat_engine,
            Self::detect_speedhack,
            Self::detect_overlay_injection,
            Self::detect_unsigned_driver,
            Self::detect_thread_context_hijack,
            Self::detect_token_privilege_escalation,
            Self::detect_image_hijacking,
            Self::detect_wmi_persistence,
            Self::detect_scheduled_task_abuse,
            Self::detect_ntdll_unhooking,
        ];

        for detector in detectors {
            let result = detector(self, processes);
            if result.confidence > 0.3 {
                detected.push(result.technique.clone());
                total_confidence += result.confidence;
            }
            results.push(result);
        }

        let fp_est = results.iter()
            .map(|r| r.bypass_risk)
            .sum::<f64>() / results.len() as f64;

        DetectionSummary {
            total_techniques: results.len(),
            detected_techniques: detected,
            overall_risk_score: total_confidence / results.len() as f64,
            results,
            false_positive_estimate: fp_est,
        }
    }

    /// 1. Process Hollowing
    /// Detection theory: Hollowed processes have a mismatch between their original image
    /// and running state — the .text section is replaced with new code. Detectable by
    /// comparing original entry point (from the PE header on disk) with the actual
    /// section contents at runtime via VirtualQueryEx. Also detectable when the process
    /// image path points to a signed binary but the memory contains RWX sections with
    /// high entropy that don't match the original on-disk sections.
    /// Telemetry gap: Need on-disk PE caching for comparison; if original image is
    /// deleted after hollowing, telemetry is lost.
    /// Bypass: Mapping a fresh copy of the original PE into memory preserves hashes.
    fn detect_process_hollowing(&self, processes: &[ProcessInfo]) -> DetectionResult {
        let mut evidence = Vec::new();
        for p in processes {
            let total = p.modules.len();
            if total == 0 { continue; }
            let sig_count = p.modules.iter().filter(|m| m.is_signed).count();
            if total > 0 && sig_count == 0 && !p.path.is_empty() {
                evidence.push(format!("PID {}: {} has 0 signed modules out of {}", p.pid, p.name, total));
            }
        }
        let confidence = if evidence.len() > 2 { 0.75 } else if evidence.len() > 0 { 0.35 } else { 0.0 };
        DetectionResult {
            technique: "process_hollowing".into(),
            confidence,
            severity: if confidence > 0.5 { "CRITICAL".into() } else { "MEDIUM".into() },
            evidence,
            telemetry_gaps: vec!["No on-disk PE image cache for section comparison".into()],
            bypass_risk: 0.6,
        }
    }

    /// 2. Manual Mapping
    /// Detection theory: Manually-mapped DLLs don't appear in the PEB's InLoadOrderModuleList.
    /// They are not found by CreateToolhelp32Snapshot. Detectable by scanning for
    /// executable private memory regions that aren't backed by any known module.
    /// The memory scanner (VirtualQueryEx) identifies MEM_PRIVATE | PAGE_EXECUTE_READWRITE
    /// regions with no corresponding file mapping.
    /// Telemetry gap: Kernel-mode manual mapping (via driver) can hide regions from user-mode VAD.
    /// Bypass: Mapping as MEM_IMAGE and spoofing the VAD entry can bypass user-mode detection.
    fn detect_manual_mapping(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "manual_mapping".into(),
            confidence: 0.0,
            severity: "MEDIUM".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Need per-process VAD scan or kernel callback for MEM_PRIVATE detection".into(),
                "Kernel driver support required for complete coverage".into(),
            ],
            bypass_risk: 0.7,
        }
    }

    /// 3. Reflective DLL Injection
    /// Detection theory: Similar to manual mapping but self-maps from memory without
    /// LoadLibrary. The injected code calls its own loader. Detectable by finding
    /// executable private memory that contains a PE header (MZ magic) but is not
    /// listed as a loaded module. Also detectable if the start address of any thread
    /// points into such a region rather than into a known module.
    /// Telemetry gap: Thread start address is available from kernel thread notify
    /// but not currently traced in user mode.
    /// Bypass: Erasing the PE header after loading defeats MZ-magic scans.
    fn detect_reflective_dll_injection(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "reflective_dll_injection".into(),
            confidence: 0.0,
            severity: "HIGH".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Thread start-address telemetry not collected from kernel".into(),
                "Memory region PE header scan not implemented in hot path".into(),
            ],
            bypass_risk: 0.6,
        }
    }

    /// 4. APC Injection
    /// Detection theory: APC injection queues an APC to a target thread with a pointer
    /// to shellcode. Detectable by: (1) QueueUserAPC calls to remote processes via
    /// kernel ObCallbacks, (2) threads returning from Alertable waits with unexpected
    /// RIP values, (3) memory regions containing APC-resident shellcode.
    /// The kernel driver's ObCallbacks should log handle operations for THREAD_SET_CONTEXT.
    /// Telemetry gap: Current ObCallbacks are stubs — no handle-operation logging.
    /// Bypass: Using NtQueueApcThread (syscall) bypasses user-mode hooking.
    fn detect_apc_injection(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "apc_injection".into(),
            confidence: 0.0,
            severity: "HIGH".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Kernel ObCallbacks for thread handle operations not implemented".into(),
                "APC queue monitoring requires kernel ETW (ThreadAPC_Start) or driver".into(),
            ],
            bypass_risk: 0.8,
        }
    }

    /// 5. CreateRemoteThread
    /// Detection theory: The classic injection — OpenProcess + VirtualAllocEx + WriteProcessMemory +
    /// CreateRemoteThread. Detectable via: kernel-process handle operations with
    /// PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION access flagged, cross-process
    /// thread creation events, thread start addresses that fall in MEM_PRIVATE regions.
    /// The correlation engine can chain: handle-open + memory-write + thread-create.
    /// Telemetry gap: No handle-operation logging from kernel driver.
    /// Bypass: Using NtCreateThreadEx with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER.
    fn detect_create_remote_thread(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "create_remote_thread".into(),
            confidence: 0.0,
            severity: "HIGH".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Cross-process thread creation not tracked via kernel".into(),
                "No handle-access bitmask logging for PROCESS_CREATE_THREAD".into(),
            ],
            bypass_risk: 0.5,
        }
    }

    /// 6. Process Doppelgänging
    /// Detection theory: Uses NTFS transacted I/O — create a transaction, write a
    /// malicious PE, create a process from the transacted file, then rollback.
    /// The running process has no backing file on disk. Detectable by: (1) processes
    /// whose image file no longer exists at the claimed path, (2) processes with
    /// TxF transaction handles open, (3) SE_CREATE_GLOBAL privileges in unusual contexts.
    /// Telemetry gap: TxF is deprecated but still functional — no transaction monitoring.
    /// Bypass: Using NtCreateProcess with section handle from transacted file.
    fn detect_process_doppelganging(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "process_doppelganging".into(),
            confidence: 0.0,
            severity: "CRITICAL".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "TxF transaction creation not monitored".into(),
                "Process-image file-existence check not implemented".into(),
                "No kernel callback for transacted-file section creation".into(),
            ],
            bypass_risk: 0.9,
        }
    }

    /// 7. Transacted Hollowing
    /// Detection theory: Similar to doppelgänging but uses TxF to replace the
    /// contents of an existing executable within a transaction. Detectable by
    /// the same techniques as doppelgänging plus monitoring for TxF transactions
    /// on executable files in sensitive directories.
    /// Telemetry gap: Same as doppelgänging.
    /// Bypass: Same as doppelgänging.
    fn detect_transacted_hollowing(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "transacted_hollowing".into(),
            confidence: 0.0,
            severity: "CRITICAL".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "TxF monitoring not implemented — requires minifilter driver".into(),
                "Windows 10 20H1+ deprecated TxF APIs; legacy systems still vulnerable".into(),
            ],
            bypass_risk: 0.9,
        }
    }

    /// 8. RWX Shellcode Allocation
    /// Detection theory: Shellcode is written to memory allocated with
    /// PAGE_EXECUTE_READWRITE (0x40) protection. Detectable by VirtualQueryEx
    /// enumeration: any MEM_PRIVATE | PAGE_EXECUTE_READWRITE region is highly
    /// suspicious, especially when the region size is small (< 1MB) and the
    /// owning process is not a JIT compiler (e.g., browser, .NET runtime).
    /// This is currently the most reliable user-mode detection.
    /// Telemetry gap: No per-process JIT-allowed whitelist; browsers generate RWX.
    /// Bypass: Allocating as RW → write shellcode → change to RX (VirtualProtect).
    fn detect_rwx_shellcode(&self, processes: &[ProcessInfo]) -> DetectionResult {
        let mut evidence = Vec::new();
        for p in processes {
            let temp_mods = p.modules.iter().filter(|m| m.suspicion_reasons.iter().any(|r| r.contains("temp"))).count();
            if temp_mods > 0 {
                evidence.push(format!("PID {}: {} modules loaded from temp — possible shellcode staging", p.pid, temp_mods));
            }
        }
        let confidence = if evidence.len() > 2 { 0.85 } else if evidence.len() > 0 { 0.45 } else { 0.0 };
        DetectionResult {
            technique: "rwx_shellcode".into(),
            confidence,
            severity: "CRITICAL".into(),
            evidence,
            telemetry_gaps: vec![
                "RW→RX transition (VirtualProtect) not detected — needs VAD-change callback".into(),
                "Browser JIT regions generate false positives".into(),
            ],
            bypass_risk: 0.3,
        }
    }

    /// 9. PowerShell Abuse
    /// Detection theory: PowerShell used with encoded commands, download cradle,
    /// or suspicious parameter combinations ( -EncodedCommand, -Exec Bypass,
    /// hidden window). Detectable by analyzing PowerShell process command lines
    /// and examining the PowerShell history artifact files.
    /// Telemetry gap: Encoded commands are opaque without decoding; PowerShell
    /// script block logging (ETW event 4104) is not consumed.
    /// Bypass: Splitting commands across multiple invocations, using reflection.
    fn detect_powershell_abuse(&self, processes: &[ProcessInfo]) -> DetectionResult {
        let mut evidence = Vec::new();
        let suspicious_patterns = [
            "-EncodedCommand", "-Exec Bypass", "-WindowStyle Hidden",
            "-NoProfile", "IEX", "Invoke-Expression", "Invoke-Mimikatz",
            "DownloadString", "DownloadFile", "FromBase64String",
            "Start-Process -WindowStyle Hidden", "-Command \"$",
        ];
        for p in processes {
            if p.name.to_lowercase().contains("powershell") || p.name.to_lowercase().contains("pwsh") {
                let cmd = p.command_line.to_lowercase();
                for pat in &suspicious_patterns {
                    if cmd.contains(&pat.to_lowercase()) {
                        evidence.push(format!("PID {}: PowerShell with '{}'", p.pid, pat));
                    }
                }
            }
        }
        let confidence = (evidence.len() as f64).min(3.0) * 0.25;
        DetectionResult {
            technique: "powershell_abuse".into(),
            confidence: confidence.min(0.9),
            severity: if confidence > 0.5 { "HIGH".into() } else { "MEDIUM".into() },
            evidence,
            telemetry_gaps: vec![
                "ETW event 4104 (ScriptBlockLogging) not consumed".into(),
                "Decoded command content not analyzed".into(),
            ],
            bypass_risk: 0.4,
        }
    }

    /// 10. AMSI Bypass
    /// Detection theory: AMSI patching modifies the AmsiScanBuffer or AmsiOpenSession
    /// functions in amsi.dll. Detectable by: (1) checking amsi.dll's .text section
    /// hash against known-good (runtime integrity check), (2) monitoring for
    /// WriteProcessMemory calls targeting amsi.dll, (3) checking if AmsiInitialize
    /// returns unexpected HRESULTs.
    /// Telemetry gap: No runtime integrity checking of amsi.dll implemented.
    /// Bypass: Hardware breakpoint-based bypass avoids code modification entirely.
    fn detect_amsi_bypass(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "amsi_bypass".into(),
            confidence: 0.0,
            severity: "CRITICAL".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "amsi.dll runtime integrity check not implemented — requires ReadProcessMemory + on-disk comparison".into(),
                "ETW Microsoft-Windows-AMSI event stream not consumed".into(),
            ],
            bypass_risk: 0.7,
        }
    }

    /// 11. ETW Bypass
    /// Detection theory: ETW patching modifies ntdll!EtwEventWrite or the
    /// EventRegister functions. Detectable by: (1) checking ntdll's EtwEventWrite
    /// function bytes against known-good, (2) monitoring for memory writes to the
    /// ntdll .text section, (3) checking if provider registration responses are empty.
    /// Telemetry gap: User-mode ETW patching is hard to detect without kernel support.
    /// Bypass: Kernel-mode ETW bypass (e.g., hiding from the ETW logger list) is
    /// invisible from user mode.
    fn detect_etw_bypass(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "etw_bypass".into(),
            confidence: 0.0,
            severity: "CRITICAL".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "ntdll EtwEventWrite integrity check not implemented".into(),
                "Kernel-mode ETW provider-hiding not detectable from user mode".into(),
            ],
            bypass_risk: 0.8,
        }
    }

    /// 12. DLL Unlinking
    /// Detection theory: Malware removes itself from the PEB InLoadOrderModuleList
    /// to hide from CreateToolhelp32Snapshot and similar APIs. Detectable by:
    /// (1) comparing results from CreateToolhelp32Snapshot with VAD-based enumeration,
    /// (2) walking the PEB lists via NtQueryInformationProcess and checking for
    /// inconsistencies, (3) detecting FLINK/BLINK pointers that don't point to
    /// valid LIST_ENTRY structures.
    /// Telemetry gap: VAD-based module enumeration not implemented.
    /// Bypass: Replacing the IN_USE flag in the VAD entry rather than unlinking.
    fn detect_dll_unlinking(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "dll_unlinking".into(),
            confidence: 0.0,
            severity: "HIGH".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "VAD-based module walk not implemented — needs NtQueryVirtualMemory".into(),
                "PEB list integrity check not performed".into(),
            ],
            bypass_risk: 0.5,
        }
    }

    /// 13. PEB Tampering
    /// Detection theory: Modifying the PEB's BeingDebugged, NtGlobalFlag, or
    /// ProcessParameters to evade debugger detection. Detectable by comparing
    /// PEB fields against expected values for the current process. Also detectable
    /// by scanning for processes where the PEB's ImageBaseAddress doesn't match
    /// the actual base address from VirtualQueryEx.
    /// Telemetry gap: Cross-process PEB reading requires PROCESS_VM_READ access.
    /// Bypass: Direct kernel-mode PEB modification via EPROCESS trickery.
    fn detect_peb_tampering(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "peb_tampering".into(),
            confidence: 0.0,
            severity: "MEDIUM".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Cross-process PEB read via ReadProcessMemory not performed".into(),
                "BeingDebugged flag is trivially bypassed with NtSetInformationProcess".into(),
            ],
            bypass_risk: 0.4,
        }
    }

    /// 14. Handle Hijacking
    /// Detection theory: Opening a handle to a privileged process (e.g., LSASS,
    /// winlogon) with suspicious access rights (PROCESS_ALL_ACCESS, PROCESS_VM_*,
    /// PROCESS_CREATE_THREAD). Detectable via kernel ObCallbacks that log handle
    /// operations with their requested access masks. Also detectable by checking
    /// which processes have handles open to LSASS using NtQuerySystemInformation.
    /// Telemetry gap: ObCallbacks currently return OB_PREOP_SUCCESS without logging.
    /// Bypass: Duplicating an already-open handle avoids creating a new one.
    fn detect_handle_hijacking(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "handle_hijacking".into(),
            confidence: 0.0,
            severity: "HIGH".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Kernel ObCallbacks for handle-creation logging not wired".into(),
                "Handle-duplication events not monitored".into(),
                "Sensitive-process handle enumeration not implemented".into(),
            ],
            bypass_risk: 0.6,
        }
    }

    /// 15. LSASS Dumping
    /// Detection theory: Dumping LSASS memory for credential extraction. Detectable
    /// by: (1) MiniDumpWriteDump calls targeting PID 4 (LSASS), (2) processes with
    /// handles to LSASS with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION access,
    /// (3) creation of .dmp files by non-backup processes, (4) lsass.dll being read
    /// by suspicious callers. The most common tool (Mimikatz) uses techniques that
    /// are signatured: specific handle patterns, specific memory reads.
    /// Telemetry gap: No dump-file monitoring; no LSASS handle access logging.
    /// Bypass: Using PPL (Protected Process Light) bypass + raw disk reads.
    fn detect_lsass_dumping(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "lsass_dumping".into(),
            confidence: 0.0,
            severity: "CRITICAL".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "MiniDumpWriteDump call monitoring not implemented via ETW (ThreatIntelligence API)".into(),
                "LSASS handle-access not logged from kernel driver".into(),
                "PPL bypass detection not implemented".into(),
            ],
            bypass_risk: 0.6,
        }
    }

    /// 16. Kernel Callback Tampering
    /// Detection theory: Rootkits unregister or modify kernel callbacks (process,
    /// thread, image load, registry) to hide their activities. Detectable by
    /// comparing the current list of registered callbacks against a known-good
    /// baseline at boot time. The kernel driver should periodically verify that
    /// its own callbacks are still registered and that no unexpected callbacks
    /// have been added by competitors or malware.
    /// Telemetry gap: No callback integrity check implemented.
    /// Bypass: Direct kernel object manipulation bypasses callback API checks.
    fn detect_kernel_callback_tampering(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "kernel_callback_tampering".into(),
            confidence: 0.0,
            severity: "CRITICAL".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Kernel callback integrity verification not implemented in driver".into(),
                "Requires kernel-mode code to enumerate and verify registered callbacks".into(),
            ],
            bypass_risk: 0.9,
        }
    }

    /// 17. Cheat Engine Memory Editing
    /// Detection theory: Cheat Engine (and similar tools) use WriteProcessMemory
    /// or VirtualProtectEx to modify game memory. Detectable by: (1) process name
    /// signature (CheatEngine, CE.exe, etc.), (2) RWX memory regions in the game
    /// process that don't correspond to any module, (3) speedhack via performance
    /// counter manipulation, (4) VEH (Vectored Exception Handler) debugging hooks.
    /// Telemetry gap: Cross-process memory write tracking requires ETW or kernel
    /// driver.
    /// Bypass: Kernel-mode cheat drivers bypass all user-mode memory protections.
    fn detect_cheat_engine(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "cheat_engine".into(),
            confidence: 0.0,
            severity: "MEDIUM".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Cross-process memory write (e.g., WriteProcessMemory) not tracked".into(),
                "VEH debugging hooks not detectable from memory scan".into(),
            ],
            bypass_risk: 0.3,
        }
    }

    /// 18. Speedhack Detection
    /// Detection theory: Speedhacks manipulate the system timer or QPC
    /// (QueryPerformanceCounter) to alter game speed. Detectable by comparing
    /// QueryPerformanceCounter ticks against wall-clock time — if the ratio
    /// deviates significantly from 1.0, a speedhack is active. This is already
    /// implemented in anti_cheat.rs with a threshold of 0.5-1.5 ratio.
    /// Telemetry gap: Only sampled on-demand, not continuously monitored.
    /// Bypass: Using a hardware QPC source or kernel-mode timer manipulation.
    fn detect_speedhack(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "speedhack".into(),
            confidence: 0.0,
            severity: "CRITICAL".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Continuous QPC monitoring not implemented — only sampled on detection cycle".into(),
                "Hardware QPC source bypass (HPET vs TSC) not distinguished".into(),
            ],
            bypass_risk: 0.4,
        }
    }

    /// 19. Overlay Injection
    /// Detection theory: Game overlays (Discord, Steam, Overwolf) use CreateWindowEx
    /// with WS_EX_LAYERED or WS_EX_TRANSPARENT to draw on top of the game window.
    /// Detectable by enumerating top-level windows that have the TOOLWINDOW style,
    /// are layered, and whose process has loaded d3d11.dll/dxgi.dll without being
    /// the primary game process. This is already partially implemented.
    /// Telemetry gap: Window enumeration is polling-based, not event-driven.
    /// Bypass: Drawing directly to the game's own window surface via injected DLL.
    fn detect_overlay_injection(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "overlay_injection".into(),
            confidence: 0.0,
            severity: "LOW".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Window enumeration not implemented — overlays detected by process name only".into(),
                "Direct surface injection not detectable without kernel display driver".into(),
            ],
            bypass_risk: 0.2,
        }
    }

    /// 20. Unsigned Driver Loading
    /// Detection theory: Windows 10+ blocks unsigned kernel drivers by default
    /// (no test signing). Attackers use signed but malicious drivers (Bring Your
    /// Own Vulnerable Driver — BYOVD) or exploit kernel vulnerabilities to load
    /// unsigned code. Detectable by enumerating loaded kernel modules via
    /// EnumDeviceDrivers and checking their digital signatures with WinVerifyTrust.
    /// The known-cheat-drivers list (EIO, kprocesshacker, dbk64) provides
    /// signature-based detection.
    /// Telemetry gap: Driver enumeration is polling — new drivers between polls missed.
    /// Bypass: Using a leaked WHQL-signed certificate defeats signature checks.
    fn detect_unsigned_driver(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "unsigned_driver".into(),
            confidence: 0.0,
            severity: "CRITICAL".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "EnumDeviceDrivers + WinVerifyTrust not implemented in monitoring loop".into(),
                "BYOVD detection requires known-vulnerable-driver database".into(),
                "Driver load events from kernel not consumed by user mode".into(),
            ],
            bypass_risk: 0.6,
        }
    }

    /// 21. Thread Context Hijacking
    /// Detection theory: SetThreadContext modifies a thread's register state to
    /// redirect execution to shellcode. Detectable by kernel ObCallbacks for
    /// THREAD_SET_CONTEXT handle access, or by scanning threads for CONTEXT_EXTENDED
    /// registers that contain unexpected RIP values. Also detectable if a thread's
    /// start address (from ThreadNotifyRoutine) is overwritten by a later
    /// SetThreadContext or NtSetContextThread call.
    /// Telemetry gap: No thread-context change monitoring.
    /// Bypass: NtSetContextThread is the syscall-level equivalent — same detection.
    fn detect_thread_context_hijack(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "thread_context_hijack".into(),
            confidence: 0.0,
            severity: "HIGH".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "SetThreadContext / NtSetContextThread not monitored via kernel callback".into(),
                "Thread register-state baseline not established".into(),
            ],
            bypass_risk: 0.7,
        }
    }

    /// 22. Token Privilege Escalation
    /// Detection theory: Enabling sensitive privileges (SeDebugPrivilege,
    /// SeTcbPrivilege, SeLoadDriverPrivilege) via AdjustTokenPrivileges.
    /// Detectable by: (1) processes enabling privileges that were not enabled at
    /// startup, (2) known escalation tools (whoami /priv, EnableAllPrivileges),
    /// (3) processes with SeDebugPrivilege that are not debugging tools.
    /// Telemetry gap: No privilege audit log consumption.
    /// Bypass: Token-stealing via kernel driver (direct EPROCESS token replacement).
    fn detect_token_privilege_escalation(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "token_privilege_escalation".into(),
            confidence: 0.0,
            severity: "HIGH".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "SeDebugPrivilege enumeration not performed via NtQueryInformationToken".into(),
                "Privilege audit events (Event ID 4672, 4673) not consumed".into(),
            ],
            bypass_risk: 0.5,
        }
    }

    /// 23. Image Hijacking (DLL Search Order Hijacking)
    /// Detection theory: Dropping a malicious DLL into a directory searched before
    /// the legitimate system directory. Detectable by: (1) DLLs loaded from
    /// user-writable directories (AppData, Temp, Downloads), (2) DLLs loaded by
    /// system processes from non-system paths, (3) unsigned DLLs in the search
    /// path that shadow legitimate system DLLs.
    /// Telemetry gap: Module-load paths are analyzed post-hoc, not in real-time.
    /// Bypass: Planting a DLL with the same name as a known system DLL in AppData.
    fn detect_image_hijacking(&self, processes: &[ProcessInfo]) -> DetectionResult {
        let mut evidence = Vec::new();
        let suspicious_paths = ["\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\users\\"];
        for p in processes {
            for m in &p.modules {
                let lower = m.path.to_lowercase();
                for sp in &suspicious_paths {
                    if lower.contains(sp) && !lower.starts_with("c:\\windows\\") {
                        evidence.push(format!("PID {}: DLL in suspicious path: {}", p.pid, m.path));
                    }
                }
                if !m.is_signed && !m.path.starts_with("C:\\Windows\\") {
                    evidence.push(format!("PID {}: unsigned DLL from non-system path: {}", p.pid, m.name));
                }
            }
        }
        let confidence = (evidence.len() as f64).min(5.0) * 0.12;
        DetectionResult {
            technique: "image_hijacking".into(),
            confidence: confidence.min(0.7),
            severity: if confidence > 0.3 { "HIGH".into() } else { "MEDIUM".into() },
            evidence,
            telemetry_gaps: vec![
                "DLL load paths analyzed post-hoc, not in real-time via kernel".into(),
                "Known-dlls not checked against system baseline".into(),
            ],
            bypass_risk: 0.3,
        }
    }

    /// 24. WMI Persistence
    /// Detection theory: WMI event subscriptions can execute arbitrary scripts or
    /// binaries on system events (startup, user logon, timer). Detectable by
    /// enumerating __FilterToConsumerBinding, __EventFilter, and
    /// __CommandLineEventConsumer instances. Tools like WMIPersist and SharpVPNS
    /// create these subscriptions. The registry parser can detect these in
    /// SOFTWARE\\Microsoft\\Wbem\\. The artifact parsers can detect remaining
    /// WMI traces.
    /// Telemetry gap: WMI enumeration is polling-based and may miss transient subs.
    /// Bypass: Using active WMI event consumers that self-delete.
    fn detect_wmi_persistence(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "wmi_persistence".into(),
            confidence: 0.0,
            severity: "HIGH".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "WMI repository enumeration not performed — needs Wbem COM or wmic invocation".into(),
                "Active vs. persistent WMI subscriptions not distinguished".into(),
            ],
            bypass_risk: 0.5,
        }
    }

    /// 25. Scheduled Task Abuse
    /// Detection theory: Malware creates scheduled tasks for persistence via
    /// schtasks.exe or ITaskScheduler COM. Detectable by: (1) schtasks.exe
    /// creating tasks with suspicious parameters (run as SYSTEM, hidden, on
    /// startup), (2) tasks executing from user-writable locations, (3) tasks
    /// with obfuscated command lines, (4) tasks referencing script interpreters.
    /// Telemetry gap: Task creation event (Event ID 4698) not consumed.
    /// Bypass: Using WMI to create tasks bypasses schtasks.exe monitoring.
    fn detect_scheduled_task_abuse(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "scheduled_task_abuse".into(),
            confidence: 0.0,
            severity: "HIGH".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "Task scheduler audit events (4698, 4699) not consumed from Event Log".into(),
                "schtasks.exe command-line analysis not performed".into(),
            ],
            bypass_risk: 0.5,
        }
    }

    /// 26. NTDLL Unhooking
    /// Detection theory: EDR products hook ntdll.dll functions to monitor syscalls.
    /// Malware can unhook by loading a fresh copy of ntdll from disk and replacing
    /// the .text section. Detectable by: (1) comparing the in-memory ntdll .text
    /// section hash against the on-disk version, (2) checking for RWX regions in
    /// the ntdll module range, (3) checking for INT 2Eh or syscall instructions
    /// in unexpected locations (indicating direct syscall stubs).
    /// Telemetry gap: ntdll integrity check not performed — requires process access.
    /// Bypass: Mapping a fresh ntdll at a different base and redirecting all calls
    /// avoids .text modification entirely (Hell's Gate / Halo's Gate technique).
    fn detect_ntdll_unhooking(&self, _processes: &[ProcessInfo]) -> DetectionResult {
        DetectionResult {
            technique: "ntdll_unhooking".into(),
            confidence: 0.0,
            severity: "HIGH".into(),
            evidence: Vec::new(),
            telemetry_gaps: vec![
                "ntdll.dll .text section integrity check not implemented".into(),
                "Syscall stub detection (Hell's Gate / Halo's Gate) not implemented".into(),
                "Requires ReadProcessMemory access to target process".into(),
            ],
            bypass_risk: 0.7,
        }
    }
}