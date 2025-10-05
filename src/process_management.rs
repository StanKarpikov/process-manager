use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::thread;
use std::time::Duration;

const TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn stop_process(pid: Option<i32>, name: String) -> Result<(), String> {
    // First try to stop by PID if provided
    if let Some(pid_val) = pid {
        if let Err(e) = stop_process_by_pid(pid_val) {
            return Err(format!("Failed to stop process by PID {}: {}", pid_val, e));
        }
        return Ok(());
    }

    // If no PID or PID method failed, try by environment variable
    stop_process_by_env_var(&name)
}

fn stop_process_by_pid(pid: i32) -> Result<(), String> {
    let pid = Pid::from_raw(pid);
    
    // Send SIGTERM
    if let Err(e) = signal::kill(pid, Signal::SIGTERM) {
        return Err(format!("Failed to send SIGTERM: {}", e));
    }

    // Wait for 5 seconds to see if process terminates
    thread::sleep(TERMINATE_TIMEOUT);

    // Check if process still exists
    if signal::kill(pid, None).is_ok() {
        // Process still running, send SIGKILL
        if let Err(e) = signal::kill(pid, Signal::SIGKILL) {
            return Err(format!("Failed to send SIGKILL: {}", e));
        }
        
        // Wait 1 second after SIGKILL
        thread::sleep(Duration::from_secs(1));
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
                    return stop_process_by_pid(pid);
                }
            }
        }
    }

    Err(format!("No process found with PROCESS_MANAGER_ID={}", name))
}