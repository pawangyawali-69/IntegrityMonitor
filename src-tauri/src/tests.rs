use crate::telemetry::trust::verify_authenticode;
use crate::telemetry::pe::parse_pe_file;

#[test]
fn test_authenticode_debug_output() {
    let paths = [
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Windows\\System32\\notepad.exe",
    ];
    for path in &paths {
        let result = verify_authenticode(path);
        eprintln!(
            "DEBUG {}: is_signed={}, chain_status={}, microsoft={}, signer={:?}, thumbprint={:?}",
            path, result.is_signed, result.chain_status, result.is_microsoft, result.signer, result.thumbprint
        );
    }
}

#[test]
fn test_authenticode_signed_system_file() {
    let result = verify_authenticode("C:\\Windows\\System32\\kernel32.dll");
    assert!(
        result.is_signed,
        "kernel32.dll should be verified signed. chain_status: {}",
        result.chain_status,
    );
    assert!(result.is_microsoft, "kernel32.dll should be Microsoft-signed");
    assert!(result.thumbprint.is_some(), "should have a thumbprint");
}

#[test]
fn test_authenticode_nonexistent_file() {
    let result = verify_authenticode("C:\\does_not_exist.exe");
    assert!(!result.is_signed, "nonexistent file should not verify");
}

#[test]
fn test_parse_pe_valid_exe() {
    let info = parse_pe_file("C:\\Windows\\System32\\kernel32.dll")
        .expect("kernel32.dll should parse as valid PE");
    assert!(
        info.sections.iter().any(|s| s.name.trim_end_matches('\0') == ".text"),
        "kernel32.dll should have a .text section"
    );
}

#[test]
fn test_parse_pe_valid_dll() {
    let info = parse_pe_file("C:\\Windows\\System32\\kernel32.dll")
        .expect("kernel32.dll should parse as valid PE");
    assert!(
        info.sections.iter().any(|s| s.name.trim_end_matches('\0') == ".text"),
        "kernel32 should have a .text section"
    );
}

#[test]
fn test_parse_pe_invalid_file() {
    let result = parse_pe_file("C:\\Windows\\System32\\kernel32.dll.nonexistent");
    assert!(result.is_none(), "nonexistent file should return None");
}

#[test]
fn test_parse_pe_has_reasonable_entropy() {
    let info = parse_pe_file("C:\\Windows\\System32\\kernel32.dll")
        .expect("kernel32.dll should parse");
    for section in &info.sections {
        assert!(
            section.entropy >= 0.0 && section.entropy <= 8.0,
            "entropy {} for section {} should be in [0, 8]",
            section.entropy,
            section.name
        );
    }
}

#[test]
fn test_parse_pe_no_security_anomalies() {
    let info = parse_pe_file("C:\\Windows\\System32\\kernel32.dll")
        .expect("kernel32.dll should parse");
    let severe: Vec<&str> = info.anomalies.iter()
        .filter(|a| a.contains("RWX") || a.contains("packed") || a.contains("High-entropy"))
        .map(|a| a.as_str())
        .collect();
    assert!(
        severe.is_empty(),
        "kernel32 should have no severe anomalies: {:?}",
        severe
    );
}

#[test]
fn test_parse_pe_is_a_dll() {
    let info = parse_pe_file("C:\\Windows\\System32\\kernel32.dll")
        .expect("kernel32.dll should parse");
    assert!(info.is_dll, "kernel32.dll should be flagged as DLL");
}
