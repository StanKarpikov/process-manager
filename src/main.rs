use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::process::Child;
use std::io::{BufRead, BufReader};
use arguments::Args;
use clap::Parser;
use econfmanager::generated::ParameterId;
use econfmanager::interface::InterfaceInstance;
use econfmanager::interface::ParameterUpdateCallback;
use env_logger::Env;
use log::{error, info, warn};
use std::io::Write;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use configfile::{Config, ServiceConfig, Watchdog};

pub mod arguments;
pub mod configfile;

const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(60);
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);
const PERIODIC_UPDATE_INTERVAL: Duration = Duration::from_millis(5000);

#[derive(Debug)]
struct ProcessInfo {
    child: Option<Child>,
    last_output: Instant
}

struct AppState {
    interface: InterfaceInstance,
    tx: std::sync::mpsc::Sender<ServiceCommand>,
    services: Vec<ServiceConfig>
}

#[derive(Debug)]
enum ServiceCommand {
    Start(String),
    Stop(String),
    Restart(String),
}

fn run_command(command: &str, env_vars: &HashMap<String, String>) -> Option<Child> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        error!("Empty command");
        return None;
    }

    let mut cmd = Command::new(parts[0]);
    
    cmd.envs(env_vars);
    
    if parts.len() > 1 {
        cmd.args(&parts[1..]);
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(child) => {
            info!("Process {command} started");
            Some(child)
        },
        Err(e) => {
            error!("Failed to spawn process {}: {}", command, e);
            None
        }
    }
}

fn terminate_process(pid: i32, force: bool) {
    let signal = if force { Signal::SIGKILL } else { Signal::SIGTERM };
    if let Err(e) = signal::kill(Pid::from_raw(pid), signal) {
        error!("Failed to send signal to process {}: {}", pid, e);
    }
}

async fn stop_process(processes: Arc<Mutex<HashMap<String, ProcessInfo>>>, name: String) {
    let mut processes = processes.lock().unwrap();
    if let Some(process_info) = processes.get_mut(&name) {
        if let Some(child) = &mut process_info.child {
            let pid = child.id() as i32;
            
            // Send SIGTERM first
            terminate_process(pid, false);
            
            // Wait for the process to terminate
            let start = Instant::now();
            while start.elapsed() < TERMINATE_TIMEOUT {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        info!("Process {} exited with status {}", name, status);
                        break;
                    }
                    Ok(None) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(e) => {
                        error!("Error waiting for process {}: {}", name, e);
                        break;
                    }
                }
            }
            
            // If still running, send SIGKILL
            if let Ok(None) = child.try_wait() {
                warn!("Process {} didn't terminate, sending SIGKILL", name);
                terminate_process(pid, true);
            }
        }
        
        // Remove the process from tracking
        process_info.child = None;
    }
}

async fn start_process(
    processes: Arc<Mutex<HashMap<String, ProcessInfo>>>,
    name: String,
    service_config: &ServiceConfig,
    interface: &InterfaceInstance,
) {
    stop_process(processes.clone(), name.clone()).await;
    
    let mut env_vars = HashMap::new();
    for (key, value) in std::env::vars() {
        env_vars.insert(key, value);
    }
    
    if let Some(env_config) = &service_config.env {
        for (env_var, param_name) in env_config {
            if let Some(param_id) = interface.get_parameter_id_from_name(param_name.clone()) {
                if let Ok(value) = interface.get(param_id, false) {
                    info!("Adding env value {env_var} = {value}");
                    env_vars.insert(env_var.clone(), value.to_string());
                }
            }
        }
    }
    
    let mut child = match run_command(&service_config.command, &env_vars) {
        Some(c) => c,
        None => return,
    };

    let stdout = child.stdout.take().expect("Failed to get stdout");
    let stderr = child.stderr.take().expect("Failed to get stderr");
    
    // Store the process in our tracking structure first
    let mut processes_locked = processes.lock().unwrap();
    processes_locked.insert(
        name.clone(),
        ProcessInfo {
            child: Some(child),
            last_output: Instant::now(),
        },
    );
    
    // Release the lock before starting async tasks
    drop(processes_locked);
    
    // Start output reader tasks
    let processes_clone_stdout = processes.clone();
    let processes_clone_stderr = processes.clone();
    let name_clone_stdout = name.clone();
    let name_clone_stderr = name.clone();
    let watchdog_type = service_config.watchdog.clone();
    
    if matches!(watchdog_type, Watchdog::Stdout) {
        tokio::spawn(async move {
            let stdout_reader = BufReader::new(stdout);
            for line in stdout_reader.lines() {
                match line {
                    Ok(line) => {
                        info!("[{} stdout] {}", name_clone_stdout, line);
                        let mut processes = processes_clone_stdout.lock().unwrap();
                        if let Some(process_info) = processes.get_mut(&name_clone_stdout) {
                            process_info.last_output = Instant::now();
                        }
                    }
                    Err(e) => {
                        error!("Error reading stdout from {}: {}", name_clone_stdout, e);
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            let stderr_reader = BufReader::new(stderr);
            for line in stderr_reader.lines() {
                match line {
                    Ok(line) => {
                        error!("[{} stderr] {}", name_clone_stderr, line);
                        let mut processes = processes_clone_stderr.lock().unwrap();
                        if let Some(process_info) = processes.get_mut(&name_clone_stderr) {
                            process_info.last_output = Instant::now();
                        }
                    }
                    Err(e) => {
                        error!("Error reading stderr from {}: {}", name_clone_stderr, e);
                        break;
                    }
                }
            }
        });
    }
}

fn process_callback(state: &mut AppState, id: ParameterId) {
    let name = state.interface.get_name(id);
    info!("Received update for parameter: {}", name);

    for service_config in &state.services {
        let mut requested_state_change = false;
        if service_config.enable.contains_key(&name) {
            if let Ok(value) = state.interface.get(id, false) {
                let expected_value = &service_config.enable[&name];
                
                let should_run = match state.interface.set_from_json(id, expected_value) {
                    Ok(val) => {
                        val == value
                    },
                    Err(e) => {
                        error!("Failed to convert enable variable: {e}");
                        true
                    },
                };

                if should_run {
                    let _ = state.tx.send(ServiceCommand::Start(service_config.name.clone()));
                } else {
                    let _ = state.tx.send(ServiceCommand::Stop(service_config.name.clone()));
                }
                requested_state_change = true;
            }
        }

        if !requested_state_change {
            if let Some(env_config) = &service_config.env {
                if env_config.values().any(|param_name| param_name == &name) {
                    let _ = state.tx.send(ServiceCommand::Restart(service_config.name.clone()));
                }
            }
        }
    }
}

async fn watchdog_task(processes: Arc<Mutex<HashMap<String, ProcessInfo>>>, services: Vec<ServiceConfig>, tx: std::sync::mpsc::Sender<ServiceCommand>) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        let mut processes = processes.lock().unwrap();
        let now = Instant::now();
        
        for (name, process_info) in processes.iter_mut() {
            if let Some(child) = &mut process_info.child {
                let needs_restart = match services.iter().find(|&s|s.name == *name).unwrap().watchdog {
                    Watchdog::Stdout => {
                        now.duration_since(process_info.last_output) > WATCHDOG_TIMEOUT
                    }
                    Watchdog::None => false,
                };
                
                if needs_restart {
                    warn!("Watchdog timeout for {}, restarting", name);
                    let _ = tx.send(ServiceCommand::Restart(name.clone()));
                }
                
                if let Ok(Some(_)) = child.try_wait() {
                    warn!("Process {} died, restarting", name);
                    let _ = tx.send(ServiceCommand::Restart(name.clone()));
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let file_name = record.file().unwrap_or("unknown");
            let file_name = std::path::Path::new(file_name)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();

            writeln!(
                buf,
                "{} [{}] {}:{} - {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                file_name,
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .try_init();

    let args = Args::parse();
    let config = Config::from_file(args.config);
    let services = config.services;

    let mut interface_instance = match InterfaceInstance::new(&config.database_path, &config.saved_database_path, &config.default_data_folder) {
        Ok(instance) => instance,
        Err(e) => {
            eprintln!("Failed to create interface instance: {}", e);
            return;
        }
    };

    let (tx, rx) = std::sync::mpsc::channel::<ServiceCommand>();
    
    interface_instance.start_periodic_update(PERIODIC_UPDATE_INTERVAL);
    
    let processes = Arc::new(Mutex::new(HashMap::new()));
    let state = Arc::new(Mutex::new(AppState {
        interface: interface_instance,
        tx: tx.clone(),
        services: services.clone(),
    }));

    tokio::spawn(watchdog_task(processes.clone(), services.clone(), tx.clone()));

    let state_cloned = Arc::clone(&state);
    let callback = Arc::new(move |id: ParameterId| {
        let state = Arc::clone(&state_cloned);
        let mut app = state.lock().unwrap();
        process_callback(&mut app, id);
    }) as ParameterUpdateCallback;

    {
        let mut app = state.lock().unwrap();
        
        let mut params_to_watch = Vec::new();
        
        for service in app.services.clone() {
            for param_name in service.enable.keys() {
                params_to_watch.push(param_name.clone());
            }
            
            if let Some(env_config) = &service.env {
                for param_name in env_config.values() {
                    params_to_watch.push(param_name.clone());
                }
            }
        }
        
        for param_name in params_to_watch {
            if let Some(id) = app.interface.get_parameter_id_from_name(param_name.clone()) {
                if let Err(e) = app.interface.add_callback(id, callback.clone()) {
                    error!("Failed to add callback for {}: {}", param_name, e);
                } else {
                    process_callback(&mut app, id);
                }
            } else {
                error!("Parameter not found: {}", param_name);
            }
        }
    }

    info!("Process Manager started");
    
    while let Ok(cmd) = rx.recv() {
        match cmd {
            ServiceCommand::Start(name) => {
                if let Some(service_config) = services.iter().find(|&s|s.name == *name) {
                    let interface = &state.lock().unwrap().interface;
                    start_process(
                        processes.clone(),
                        name,
                        service_config,
                        &interface,
                    ).await;
                }
            }
            ServiceCommand::Stop(name) => {
                stop_process(processes.clone(), name).await;
            }
            ServiceCommand::Restart(name) => {
                if let Some(service_config) = services.iter().find(|&s|s.name == *name) {
                    let interface = &state.lock().unwrap().interface;
                    stop_process(processes.clone(), name.clone()).await;
                    start_process(
                        processes.clone(),
                        name,
                        service_config,
                        &interface,
                    ).await;
                }
            }
        }
    }
}