use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

const DRIVER_NAME: &str = "IntegrityMonitor";
const DRIVER_SERVICE_NAME: &str = "IntegrityMonitor";
const DRIVER_BIN_PATH: &str = r"\SystemRoot\System32\drivers\IntegrityMonitor.sys";

#[allow(non_camel_case_types)]
type SC_HANDLE = *mut std::ffi::c_void;

#[allow(dead_code)]
extern "system" {
    fn OpenSCManagerW(
        machine_name: *const u16,
        database_name: *const u16,
        desired_access: u32,
    ) -> SC_HANDLE;

    fn OpenServiceW(
        hsc_manager: SC_HANDLE,
        service_name: *const u16,
        desired_access: u32,
    ) -> SC_HANDLE;

    fn CloseServiceHandle(hsc_object: SC_HANDLE) -> i32;

    fn QueryServiceStatusEx(
        hservice: SC_HANDLE,
        info_level: u32,
        buffer: *mut u8,
        buf_size: u32,
        bytes_needed: *mut u32,
    ) -> i32;

    fn CreateServiceW(
        hsc_manager: SC_HANDLE,
        service_name: *const u16,
        display_name: *const u16,
        desired_access: u32,
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path: *const u16,
        load_order_group: *const u16,
        tag_id: *mut u32,
        dependencies: *const u16,
        service_start_name: *const u16,
        password: *const u16,
    ) -> SC_HANDLE;

    fn StartServiceW(
        hservice: SC_HANDLE,
        argc: u32,
        argv: *const *const u16,
    ) -> i32;

    fn ControlService(
        hservice: SC_HANDLE,
        control: u32,
        service_status: *mut SERVICE_STATUS,
    ) -> i32;

    fn DeleteService(hservice: SC_HANDLE) -> i32;
}

#[allow(dead_code, non_camel_case_types)]
#[repr(C)]
struct SERVICE_STATUS {
    dw_service_type: u32,
    dw_current_state: u32,
    dw_controls_accepted: u32,
    dw_win32_exit_code: u32,
    dw_service_specific_exit_code: u32,
    dw_check_point: u32,
    dw_wait_hint: u32,
}

#[repr(C)]
struct SERVICE_STATUS_PROCESS {
    dw_service_type: u32,
    dw_current_state: u32,
    dw_controls_accepted: u32,
    dw_win32_exit_code: u32,
    dw_service_specific_exit_code: u32,
    dw_check_point: u32,
    dw_wait_hint: u32,
    dw_process_id: u32,
    dw_service_flags: u32,
}

const SC_MANAGER_CONNECT: u32 = 0x0001;
const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_ALL_ACCESS: u32 = 0x000F_01FF;
const SERVICE_START: u32 = 0x0010;
#[allow(dead_code)]
const SERVICE_STOP: u32 = 0x0020;
#[allow(dead_code)]
const DELETE: u32 = 0x0001_0000;
const SERVICE_KERNEL_DRIVER: u32 = 0x0000_0001;
const SERVICE_DEMAND_START: u32 = 0x0000_0003;
const SERVICE_ERROR_NORMAL: u32 = 0x0000_0001;
const SERVICE_RUNNING: u32 = 0x0004;
const SC_STATUS_PROCESS_INFO: u32 = 0;
#[allow(dead_code)]
const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_error() -> String {
    unsafe {
        let err = windows::Win32::Foundation::GetLastError();
        format!("Win32 error code: {}", err.0)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KernelDriver {
    pub installed: bool,
    pub running: bool,
    pub version: String,
}

impl KernelDriver {
    pub fn new() -> Self {
        let mut kd = Self::default();
        kd.refresh();
        kd
    }

    fn try_query_scm() -> (bool, bool) {
        unsafe {
            let wide_name = to_wide(DRIVER_SERVICE_NAME);
            let scm = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return (false, false);
            }

            let service = OpenServiceW(scm, wide_name.as_ptr(), SERVICE_QUERY_STATUS);
            if service.is_null() {
                CloseServiceHandle(scm);
                return (false, false);
            }

            let mut status = SERVICE_STATUS_PROCESS {
                dw_service_type: 0,
                dw_current_state: 0,
                dw_controls_accepted: 0,
                dw_win32_exit_code: 0,
                dw_service_specific_exit_code: 0,
                dw_check_point: 0,
                dw_wait_hint: 0,
                dw_process_id: 0,
                dw_service_flags: 0,
            };
            let mut needed = 0u32;

            let result = QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                &mut status as *mut _ as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            );

            let installed = result != 0;
            let running = installed && status.dw_current_state == SERVICE_RUNNING;

            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            (installed, running)
        }
    }

    pub fn refresh(&mut self) {
        let (installed, running) = Self::try_query_scm();
        self.installed = installed;
        self.running = running;
    }

    pub fn install(&mut self) -> Result<(), String> {
        unsafe {
            let scm = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CREATE_SERVICE);
            if scm.is_null() {
                return Err(format!("Cannot open SCM: {}", last_error()));
            }

            let wide_service = to_wide(DRIVER_SERVICE_NAME);
            let wide_display = to_wide("IntegrityMonitor Kernel Driver");
            let wide_path = to_wide(DRIVER_BIN_PATH);

            let service = CreateServiceW(
                scm,
                wide_service.as_ptr(),
                wide_display.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                wide_path.as_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            );

            if service.is_null() {
                let err = last_error();
                CloseServiceHandle(scm);
                return Err(format!("Failed to create service: {}", err));
            }

            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            self.installed = true;
            log::info!("Kernel driver '{}' installed successfully", DRIVER_NAME);
            Ok(())
        }
    }

    pub fn start(&mut self) -> Result<(), String> {
        unsafe {
            let scm = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return Err(format!("Cannot open SCM: {}", last_error()));
            }

            let wide_name = to_wide(DRIVER_SERVICE_NAME);
            let service = OpenServiceW(scm, wide_name.as_ptr(), SERVICE_START);

            if service.is_null() {
                CloseServiceHandle(scm);
                return Err(format!("Service '{}' not found. Install it first.", DRIVER_SERVICE_NAME));
            }

            let result = StartServiceW(service, 0, null_mut());
            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if result == 0 {
                return Err(format!("Failed to start driver: {}", last_error()));
            }

            self.running = true;
            log::info!("Kernel driver '{}' started successfully", DRIVER_NAME);
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn stop(&mut self) -> Result<(), String> {
        unsafe {
            let scm = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return Err(format!("Cannot open SCM: {}", last_error()));
            }

            let wide_name = to_wide(DRIVER_SERVICE_NAME);
            let service = OpenServiceW(scm, wide_name.as_ptr(), SERVICE_STOP);

            if service.is_null() {
                CloseServiceHandle(scm);
                return Err(format!("Service '{}' not found.", DRIVER_SERVICE_NAME));
            }

            let mut status = SERVICE_STATUS {
                dw_service_type: 0,
                dw_current_state: 0,
                dw_controls_accepted: 0,
                dw_win32_exit_code: 0,
                dw_service_specific_exit_code: 0,
                dw_check_point: 0,
                dw_wait_hint: 0,
            };
            let result = ControlService(service, SERVICE_CONTROL_STOP, &mut status);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if result == 0 {
                return Err(format!("Failed to stop driver: {}", last_error()));
            }

            self.running = false;
            log::info!("Kernel driver '{}' stopped", DRIVER_NAME);
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn uninstall(&mut self) -> Result<(), String> {
        unsafe {
            let scm = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return Err(format!("Cannot open SCM: {}", last_error()));
            }

            let wide_name = to_wide(DRIVER_SERVICE_NAME);
            let service = OpenServiceW(scm, wide_name.as_ptr(), DELETE);

            if service.is_null() {
                CloseServiceHandle(scm);
                return Err(format!("Service '{}' not found.", DRIVER_SERVICE_NAME));
            }

            let result = DeleteService(service);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if result == 0 {
                return Err(format!("Failed to delete service: {}", last_error()));
            }

            self.installed = false;
            self.running = false;
            log::info!("Kernel driver '{}' uninstalled", DRIVER_NAME);
            Ok(())
        }
    }
}

impl Default for KernelDriver {
    fn default() -> Self {
        Self {
            installed: false,
            running: false,
            version: "1.0.0".into(),
        }
    }
}