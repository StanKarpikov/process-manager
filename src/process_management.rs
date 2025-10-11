use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::thread;
use std::time::Duration;
use std::sync::Mutex;
use std::collections::HashMap;
use log::{error, warn};
use ansi_term::Style;

use crate::{log_process_error, log_process_warn, PROCESS_COLORS};

const TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn stop_process(pid: Option<i32>, name: String) -> Result<(), String> {
    // First try to stop by PID if provided
    if let Some(pid_val) = pid {
        if let Err(e) = stop_process_by_pid(pid_val, name) {
            return Err(format!("Failed to stop process by PID {}: {}", pid_val, e));
        }
        return Ok(());
    }

    // If no PID or PID method failed, try by environment variable
    stop_process_by_env_var(&name)
}

fn stop_process_by_pid(pid: i32, name: String) -> Result<(), String> {
    let pid = Pid::from_raw(pid);
    
    // Send SIGTERM
    if let Err(e) = signal::kill(pid, Signal::SIGTERM) {
        return Err(format!("Failed to send SIGTERM: {}", e));
    }

    // Wait for 5 seconds to see if process terminates
    thread::sleep(TERMINATE_TIMEOUT);

    // Check if process still exists
    if signal::kill(pid, None).is_ok() {
        log_process_warn!(name.clone(), "Process still runs after SIGTERM");
        // Process still running, send SIGKILL
        if let Err(e) = signal::kill(pid, Signal::SIGKILL) {
            return Err(format!("Failed to send SIGKILL: {}", e));
        }

        // Wait 1 second after SIGKILL
        thread::sleep(Duration::from_secs(1));
    }

    if signal::kill(pid, None).is_ok() {
        log_process_error!(name, "Process still runs after SIGKILL");
    }

    Ok(())
}

fn stop_process_by_env_var(name: &str) -> Result<(), String> {
    // Iterate through all processes in /proc
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(e) => return Err(format!("Failed to read /proc: {}", e)),
    };

    for entry in proc_dir.filter_map(|e| e.ok()) {
        let pid = match entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) {
            Some(pid) => pid,
            None => continue,
        };

        // Read environment variables from /proc/<pid>/environ
        let environ_path = format!("/proc/{}/environ", pid);
        let environ = match std::fs::read(&environ_path) {
            Ok(e) => e,
            Err(_) => continue, // Process may have terminated
        };

        // Parse environment variables
        let env_vars = String::from_utf8_lossy(&environ);
        for var in env_vars.split('\0') {
            if let Some((key, value)) = var.split_once('=') {
                if key == "PROCESS_MANAGER_ID" && value == name {
                    // Found matching process, stop it
                    return stop_process_by_pid(pid, name.to_owned());
                }
            }
        }
    }

    Err(format!("No process found with PROCESS_MANAGER_ID={}", name))
}
