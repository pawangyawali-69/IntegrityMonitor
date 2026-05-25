use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::WinTrust::*;
use windows::Win32::Foundation::HWND;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustInfo {
    pub is_signed: bool,
    pub is_microsoft: bool,
    pub signer: Option<String>,
    pub issuer: Option<String>,
    pub thumbprint: Option<String>,
    pub chain_status: String,
    pub timestamp: Option<String>,
    pub revocation_status: String,
}

pub fn verify_authenticode(path: &str) -> TrustInfo {
    match verify_trust(path) {
        Ok(info) => info,
        Err(e) => TrustInfo {
            is_signed: false,
            is_microsoft: false,
            signer: None,
            issuer: None,
            thumbprint: None,
            chain_status: format!("verification_error: {}", e),
            timestamp: None,
            revocation_status: "unchecked".into(),
        },
    }
}

fn verify_trust(path: &str) -> std::result::Result<TrustInfo, String> {
    unsafe {
        let wide_path: Vec<u16> = std::path::Path::new(path)
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = windows::core::PCWSTR(wide_path.as_ptr());

        let mut wtd: WINTRUST_DATA = std::mem::zeroed();
        wtd.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        wtd.dwUnionChoice = WINTRUST_DATA_UNION_CHOICE(1); // WTD_CHOICE_FILE
        wtd.Anonymous.pFile = &mut file_info as *mut WINTRUST_FILE_INFO;
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwStateAction = WTD_STATEACTION_IGNORE;
        wtd.dwProvFlags = WTD_SAFER_FLAG
            | WTD_CACHE_ONLY_URL_RETRIEVAL;

        let mut guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(
            HWND::default(),
            &mut guid,
            &mut wtd as *mut WINTRUST_DATA as *mut std::ffi::c_void,
        );

        if status == 0 {
            Ok(extract_cert_info(path))
        } else {
            let code = status as u32;
            let error_desc = match code {
                0x800B0100 => "TRUST_E_NOSIGNATURE",
                0x800B0101 => "CERT_E_EXPIRED",
                0x800B0109 => "CERT_E_UNTRUSTEDROOT",
                0x800B010F => "CERT_E_CHAINING",
                0x80096010 => "TRUST_E_BAD_DIGEST",
                0x80092026 => "CRYPT_E_NO_MATCH",
                _ => "unknown_error",
            };
            Err(format!("WinVerifyTrust: {} (0x{:08X})", error_desc, code))
        }
    }
}

fn extract_cert_info(path: &str) -> TrustInfo {
    unsafe {
        let wide_path: Vec<u16> = std::path::Path::new(path)
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut encoding: CERT_QUERY_ENCODING_TYPE = CERT_QUERY_ENCODING_TYPE(0);
        let mut content_type: CERT_QUERY_CONTENT_TYPE = CERT_QUERY_CONTENT_TYPE(0);
        let mut format_type: CERT_QUERY_FORMAT_TYPE = CERT_QUERY_FORMAT_TYPE(0);
        let mut h_store: HCERTSTORE = HCERTSTORE(std::ptr::null_mut());
        let mut h_msg: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut h_context: *mut std::ffi::c_void = std::ptr::null_mut();

        let status = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const std::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_ALL,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            Some(&mut encoding as *mut CERT_QUERY_ENCODING_TYPE),
            Some(&mut content_type as *mut CERT_QUERY_CONTENT_TYPE),
            Some(&mut format_type as *mut CERT_QUERY_FORMAT_TYPE),
            Some(&mut h_store as *mut HCERTSTORE),
            Some(&mut h_msg),
            Some(&mut h_context),
        );

        if status.is_err() || h_context.is_null() || h_store.0.is_null() {
            return TrustInfo {
                is_signed: true,
                is_microsoft: false,
                signer: None,
                issuer: None,
                thumbprint: None,
                chain_status: "signature_valid_no_chain".into(),
                timestamp: None,
                revocation_status: "unchecked".into(),
            };
        }

        let cert_ctx = CertFindCertificateInStore(
            h_store,
            encoding,
            0,
            CERT_FIND_ANY,
            Some(std::ptr::null()),
            None,
        );

        let (signer, issuer, thumbprint, is_microsoft) = if !cert_ctx.is_null() {
            let subj = get_name_str(&*cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE);
            let iss = get_name_str(&*cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE);
            let tp = get_thumbprint(&*cert_ctx);
            let ms = is_microsoft_signed(&*cert_ctx);
            (subj, iss, tp, ms)
        } else {
            (None, None, None, false)
        };

        let _ = CertCloseStore(h_store, CERT_CLOSE_STORE_FORCE_FLAG);

        TrustInfo {
            is_signed: true,
            is_microsoft,
            signer,
            issuer,
            thumbprint,
            chain_status: "verified".into(),
            timestamp: None,
            revocation_status: "unchecked".into(),
        }
    }
}

unsafe fn get_name_str(cert: &CERT_CONTEXT, name_type: u32) -> Option<String> {
    let needed = CertGetNameStringW(
        cert as *const CERT_CONTEXT,
        name_type,
        0,
        None,
        None,
    );
    if needed <= 1 { return None; }

    let mut buf = vec![0u16; needed as usize];
    let _written = CertGetNameStringW(
        cert as *const CERT_CONTEXT,
        name_type,
        0,
        None,
        Some(&mut buf),
    );
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..end]);
    if s.is_empty() { None } else { Some(s) }
}

unsafe fn get_thumbprint(cert: &CERT_CONTEXT) -> Option<String> {
    let mut count: u32 = 0;
    let ret = CertGetCertificateContextProperty(
        cert as *const CERT_CONTEXT as *mut CERT_CONTEXT,
        CERT_SHA1_HASH_PROP_ID,
        None,
        &mut count,
    );
    if ret.is_err() || count == 0 { return None; }
    let mut buf = vec![0u8; count as usize];
    let _ = CertGetCertificateContextProperty(
        cert as *const CERT_CONTEXT as *mut CERT_CONTEXT,
        CERT_SHA1_HASH_PROP_ID,
        Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
        &mut count,
    );
    Some(hex::encode(&buf))
}

unsafe fn is_microsoft_signed(cert: &CERT_CONTEXT) -> bool {
    if let Some(name) = get_name_str(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE) {
        let lower = name.to_lowercase();
        lower.contains("microsoft") || lower.contains("windows")
    } else {
        false
    }
}
