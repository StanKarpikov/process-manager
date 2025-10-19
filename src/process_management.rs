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

/// Returns (alive, zombie): true if the process is alive, and whether it is a zombie.
pub fn is_alive(pid: i32) -> (bool, bool) {
    let pid_obj = Pid::from_raw(pid);
    let alive = match signal::kill(pid_obj, None) {
        Ok(_) => true,
        Err(nix::errno::Errno::ESRCH) => false,
        Err(_) => false,
    };
    let mut zombie = false;
    if alive {
        // Check if zombie by reading /proc/<pid>/stat
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(stat) = std::fs::read_to_string(stat_path) {
            // info!("stat: {:?}", stat);
            let fields: Vec<&str> = stat.split_whitespace().collect();
            // info!("fields: {:?}", fields);
            if fields.len() > 2 && fields[2] == "Z" {
                zombie = true;
            }
        }
    }
    (alive, zombie)
}

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
    let (alive_after_term, zombie_after_term) = is_alive(pid.as_raw());
    if alive_after_term {
        if zombie_after_term {
            log_process_warn!(name.clone(), "Process is a zombie after SIGTERM (defunct, waiting for parent to reap)");
        } else {
            log_process_warn!(name.clone(), "Process still runs after SIGTERM");
        }
        // Process still running, send SIGKILL
        if let Err(e) = signal::kill(pid, Signal::SIGKILL) {
            return Err(format!("Failed to send SIGKILL: {}", e));
        }

        // Wait 1 second after SIGKILL
        thread::sleep(Duration::from_secs(1));
    }

    let (alive_after_kill, zombie_after_kill) = is_alive(pid.as_raw());
    if alive_after_kill {
        if zombie_after_kill {
            log_process_warn!(name, "Process is a zombie after SIGKILL (defunct, waiting for parent to reap)");
        } else {
            log_process_error!(name, "Process still runs after SIGKILL");
        }
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
                if key == "PROCESS_MANAGER_UUID" && value == name {
                    // Found matching process, stop it
                    return stop_process_by_pid(pid, name.to_owned());
                }
            }
        }
    }

    Err(format!("No process found with PROCESS_MANAGER_ID={}", name))
}
