use std::collections::HashMap;
use std::sync::Arc;
use dashmap::DashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TcpConnection {
    pub pid: u32,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub process_name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct BeaconingIndicator {
    pub pid: u32,
    pub process_name: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub interval_mean_secs: f64,
    pub interval_std_secs: f64,
    pub confidence: f64,
}

pub type NetworkTable = Arc<DashMap<(u32, String, u16), TcpConnection>>;

pub fn get_tcp_connections() -> Vec<TcpConnection> {
    let mut connections = Vec::new();
    unsafe {
        let mut buf_size: u32 = 0;
        let af_inet = 2u32;

        let _ = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut buf_size,
            0,
            af_inet,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        let mut buf = vec![0u8; buf_size as usize];
        let result = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            &mut buf_size,
            0,
            af_inet,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if result == 0 {
            if buf.len() < 4 {
                return connections;
            }
            let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();

            for i in 0..num_entries as usize {
                let start = 4 + i * row_size;
                if start + row_size > buf.len() {
                    break;
                }
                let entry = &*(buf.as_ptr().add(start) as *const MIB_TCPROW_OWNER_PID);
                let local_ip = u32::from_be(entry.dwLocalAddr);
                let remote_ip = u32::from_be(entry.dwRemoteAddr);

                connections.push(TcpConnection {
                    pid: entry.dwOwningPid,
                    local_addr: ip_to_string(local_ip),
                    local_port: u16::from_be(entry.dwLocalPort as u16),
                    remote_addr: ip_to_string(remote_ip),
                    remote_port: u16::from_be(entry.dwRemotePort as u16),
                    state: tcp_state_to_string(entry.dwState),
                    process_name: String::new(),
                });
            }
        }
    }
    connections
}

fn ip_to_string(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

fn tcp_state_to_string(state: u32) -> String {
    match state {
        1 => "closed",
        2 => "listening",
        3 => "syn_sent",
        4 => "syn_recv",
        5 => "established",
        6 => "fin_wait1",
        7 => "fin_wait2",
        8 => "close_wait",
        9 => "closing",
        10 => "last_ack",
        11 => "time_wait",
        12 => "delete_tcb",
        _ => "unknown",
    }.to_string()
}

#[allow(dead_code)]
type MibTcpRowOwnerPid = MIB_TCPROW_OWNER_PID;

#[repr(C)]
struct MIB_TCPROW_OWNER_PID {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
}

const TCP_TABLE_OWNER_PID_ALL: u32 = 5;

extern "system" {
    fn GetExtendedTcpTable(
        pTcpTable: *mut std::ffi::c_void,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
}

fn _result_check() {
    // Static assertion: MIB_TCPROW_OWNER_PID should be 24 bytes (6 * u32)
    const _: () = assert!(std::mem::size_of::<MIB_TCPROW_OWNER_PID>() == 24);
}

#[allow(dead_code)]
pub struct BeaconingDetector {
    connections: HashMap<(u32, String, u16), Vec<i64>>,
}

#[allow(dead_code)]
impl BeaconingDetector {
    pub fn new() -> Self {
        Self { connections: HashMap::new() }
    }

    pub fn record_connection(&mut self, pid: u32, remote_addr: &str, remote_port: u16) {
        let key = (pid, remote_addr.to_string(), remote_port);
        let now = chrono::Utc::now().timestamp();
        self.connections.entry(key).or_default().push(now);

        if self.connections.len() > 1000 {
            self.connections.retain(|_, times| {
                if let Some(last) = times.last() {
                    now - last < 3600
                } else {
                    false
                }
            });
        }
    }

    pub fn detect_beaconing(&self) -> Vec<BeaconingIndicator> {
        let mut results = Vec::new();
        for ((pid, addr, port), times) in &self.connections {
            if times.len() < 3 {
                continue;
            }

            let intervals: Vec<i64> = times.windows(2)
                .map(|w| w[1] - w[0])
                .filter(|&i| i > 0 && i < 600)
                .collect();

            if intervals.len() < 2 {
                continue;
            }

            let mean = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
            let variance = intervals.iter()
                .map(|i| (*i as f64 - mean).powi(2))
                .sum::<f64>() / intervals.len() as f64;
            let std = variance.sqrt();

            let cv = if mean > 0.0 { std / mean } else { 1.0 };
            let confidence = if cv < 0.3 {
                0.8
            } else if cv < 0.5 {
                0.5
            } else {
                0.2
            };

            if confidence > 0.3 {
                results.push(BeaconingIndicator {
                    pid: *pid,
                    process_name: String::new(),
                    remote_addr: addr.clone(),
                    remote_port: *port,
                    interval_mean_secs: mean,
                    interval_std_secs: std,
                    confidence,
                });
            }
        }
        results
    }
}
