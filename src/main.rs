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
    last_output: Instant,
    died_at: Option<Instant>,
    env_vars: HashMap<String, String>,
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

fn run_command(name: &String, 
    command: &str, 
    env_vars: &HashMap<String, String>,
    log_dir: &String
) -> Option<Child> {
    let shell_command = format!(
        "{} 2>&1 | multilog s100000 n5 {}",
        command,
        log_dir
    );

    let mut cmd = Command::new("sh");
    
    cmd.arg("-c").arg(&shell_command).envs(env_vars);

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(child) => {
            info!("[{name}] Process {shell_command} started");
            Some(child)
        },
        Err(e) => {
            error!("[{name}] Failed to spawn process {shell_command}: {e}");
            None
        }
    }
}

fn terminate_process(name: &String, pid: i32, force: bool) {
    let signal = if force { Signal::SIGKILL } else { Signal::SIGTERM };
    if let Err(e) = signal::kill(Pid::from_raw(pid), signal) {
        error!("[{name}] Failed to send signal to process {pid}: {e}");
    }
}

async fn stop_process(processes: Arc<Mutex<HashMap<String, ProcessInfo>>>, name: String) {
    let mut processes = processes.lock().unwrap();
    if let Some(process_info) = processes.get_mut(&name) {
        if let Some(child) = &mut process_info.child {
            let pid = child.id() as i32;
            
            // Send SIGTERM first
            terminate_process(&name, pid, false);
            
            // Wait for the process to terminate
            let start = Instant::now();
            while start.elapsed() < TERMINATE_TIMEOUT {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        info!("[{name}] Process exited with status {status}");
                        break;
                    }
                    Ok(None) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(e) => {
                        error!("[{name}] Error waiting for process: {e}");
                        break;
                    }
                }
            }
            
            // If still running, send SIGKILL
            if let Ok(None) = child.try_wait() {
                warn!("[{name}] Process didn't terminate, sending SIGKILL");
                terminate_process(&name, pid, true);
            }
        }
        
        // Remove the process from tracking
        process_info.child = None;
    }
}

fn expand_command(command: &str, env_vars: &HashMap<String, String>) -> String {
    let mut expanded = command.to_string();
    
    // Replace all occurrences of $VAR or ${VAR} with their values
    for (key, value) in env_vars {
        // Handle $VAR format
        expanded = expanded.replace(&format!("${}", key), value);
        // Handle ${VAR} format
        expanded = expanded.replace(&format!("${{{}}}", key), value);
    }
    
    expanded
}

async fn start_process(
    processes: Arc<Mutex<HashMap<String, ProcessInfo>>>,
    name: String,
    service_config: &ServiceConfig,
    interface: &InterfaceInstance,
    only_if_env_changed: bool,
    restart: bool
) {
    let mut env_vars = HashMap::new();
    for (key, value) in std::env::vars() {
        env_vars.insert(key, value);
    }    
    
    if let Some(env_config) = &service_config.env {
        for (env_var, param_name) in env_config {
            if let Some(param_id) = interface.get_parameter_id_from_name(param_name.clone()) {
                if let Ok(value) = interface.get(param_id, false) {
                    let value_str = InterfaceInstance::value_to_string(&value);
                    info!("[{name}] Adding env value {env_var} = {value_str}");
                    env_vars.insert(env_var.clone(), value_str);
                }
            }
        }
    }
    
    if only_if_env_changed{
        let mut processes = processes.lock().unwrap();
        if let Some(process_info) = processes.get_mut(&name) {
            if process_info.env_vars == env_vars {
                info!("[{name}] Env unchanged, skip restart");
                return;
            }
        }
    }

    if !restart {
        let mut processes = processes.lock().unwrap();
        if let Some(process_info) = processes.get_mut(&name) {
            if let Some(_) = &mut process_info.child {
                info!("[{name}] Already running");
                return;
            }
        }
    }

    stop_process(processes.clone(), name.clone()).await;
    
    let command = expand_command(&service_config.command, &env_vars);
    let mut child = match run_command(&name, &command, &env_vars, &service_config.log_dir) {
        Some(c) => c,
        None => {
            error!("[{}] Failed to run the process", name);
            return
        },
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
            died_at: None,
            env_vars: env_vars
        },
    );
    
    // Release the lock before starting async tasks
    drop(processes_locked);
    
    // Start output reader tasks
    let processes_clone_stdout = processes.clone();
    let processes_clone_stderr = processes.clone();
    let name_clone_stdout = name.clone();
    let name_clone_stderr = name.clone();
    // let watchdog_type = service_config.watchdog.clone();
    
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

fn process_callback(state: &mut AppState, id: ParameterId) {
    let name = state.interface.get_name(id);
    info!("Received update for parameter: {}", name);

    if let Ok(value) = state.interface.get(id, false) {
        for service_config in &state.services {
            let mut requested_state_change = false;
            if service_config.enable.contains_key(&name) {
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
                    info!("[{}] Enable parameter changed, {name} = {value}, starting", service_config.name);
                    let _ = state.tx.send(ServiceCommand::Start(service_config.name.clone()));
                } else {
                    info!("[{}] Enable parameter changed, {name} = {value}, stopping", service_config.name);
                    let _ = state.tx.send(ServiceCommand::Stop(service_config.name.clone()));
                }
                requested_state_change = true;
            }

            if !requested_state_change {
                if let Some(env_config) = &service_config.env {
                    if env_config.values().any(|param_name| param_name == &name) {
                        info!("[{}] {name} parameter changed in env, restarting", service_config.name);
                        let _ = state.tx.send(ServiceCommand::Restart(service_config.name.clone()));
                    }
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
                    warn!("[{name}] Watchdog timeout, restarting");
                    let _ = tx.send(ServiceCommand::Restart(name.clone()));
                }
                
                if let Ok(Some(_)) = child.try_wait() {
                    warn!("[{name}] ~~~ Process died ~~~");
                    process_info.died_at = Some(now);
                    process_info.child = None;
                }
            } else if let Some(died_at) = process_info.died_at {
                if now.duration_since(died_at) >= Duration::from_secs(5) {
                    warn!("[{name}] Restarting process");
                    let _ = tx.send(ServiceCommand::Start(name.clone()));
                    process_info.died_at = None;
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
            error!("Failed to create interface instance: {}", e);
            return;
        }
    };

    for service in &services {
        info!("Service [{}]: ", &service.name);
        info!("\tCommand {}", &service.command);
        info!("\tEnable {:?}", &service.enable);
        info!("\tEnv {:?}", &service.env);
        info!("\tWatchdog {:?}", &service.watchdog);
        info!("\rLog Dir {:?}", &service.log_dir);
    }

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
                }
            } else {
                error!("Parameter not found: {}", param_name);
            }
        }

        // Initial check, start the processes
        for service in app.services.clone() {
            let mut should_start = false;
            if let Some((enable_parameter_name, expected_value)) = service.enable.iter().next() {
                if let Some(id) = app.interface.get_parameter_id_from_name(enable_parameter_name.clone()) {
                    if let Ok(value) = app.interface.get(id, false) {
                        should_start = match app.interface.set_from_json(id, expected_value) {
                            Ok(val) => {
                                val == value
                            },
                            Err(e) => {
                                error!("[{}] Failed to convert enable variable: {e}", service.name);
                                true
                            },
                        };
                    }
                }
                else {
                    error!("[{}] Parameter {} not found", service.name, enable_parameter_name);
                    should_start = true;
                }
            }
            else {
                info!("[{}] No enable parameter set, always started", service.name);
                should_start = true;
            }

            if should_start{
                info!("[{}] initial state: started", service.name);
                let _ = app.tx.send(ServiceCommand::Start(service.name.clone()));
            }
            else {
                info!("[{}] initial state: stopped", service.name);
            }
        }
    }

    info!("Process Manager started");
    
    while let Ok(cmd) = rx.recv() {
        match cmd {
            ServiceCommand::Start(name) => {
                info!("[{}] Start requested, starting...", name);
                if let Some(service_config) = services.iter().find(|&s|s.name == *name) {
                    let interface = &state.lock().unwrap().interface;
                    start_process(
                        processes.clone(),
                        name,
                        service_config,
                        &interface,
                        false,
                        false
                    ).await;
                }
            }
            ServiceCommand::Stop(name) => {
                info!("[{}] Stop requested, stopping...", name);
                stop_process(processes.clone(), name).await;
            }
            ServiceCommand::Restart(name) => {
                info!("[{}] Restart received, restarting...", name);
                if let Some(service_config) = services.iter().find(|&s|s.name == *name) {
                    let interface = &state.lock().unwrap().interface;
                    stop_process(processes.clone(), name.clone()).await;
                    start_process(
                        processes.clone(),
                        name,
                        service_config,
                        &interface,
                        true,
                        true
                    ).await;
                }
            }
        }
    }
}