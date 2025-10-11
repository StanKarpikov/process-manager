use arguments::Args;
use clap::Parser;
use configfile::{Config, ServiceConfig, Watchdog, CpuSelection, BoolOrString};
use econfmanager::generated::ParameterId;
use econfmanager::interface::InterfaceInstance;
use econfmanager::interface::ParameterUpdateCallback;
use ansi_term::Colour;
use ansi_term::Style;
use env_logger::Env;
use log::{error, info, warn};
use std::sync::Mutex;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Child;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::io::Write;

pub mod arguments;
pub mod configfile;
pub mod process_management;

use std::sync::OnceLock;

static PROCESS_COLORS: OnceLock<Mutex<HashMap<String, Style>>> = OnceLock::new();

#[macro_export]
macro_rules! log_process_info {
    ($process_name:expr, $($arg:tt)*) => {{
        let process_name = $process_name;
        let message = format!($($arg)*);

        // Get color for this process
        let colors = PROCESS_COLORS.get_or_init(|| Mutex::new(HashMap::new()));
        let default_style = Style::default();
        let color = colors.lock().unwrap()
            .get(&process_name.clone())
            .cloned()
            .unwrap_or(default_style);

        info!("{}{}", color.paint(format!("[{}] ", process_name)), &message);
    }};
}

#[macro_export]
macro_rules! log_process_warn {
    ($process_name:expr, $($arg:tt)*) => {{
        let process_name = $process_name;
        let message = format!($($arg)*);

        // Get color for this process
        let colors = PROCESS_COLORS.get_or_init(|| Mutex::new(HashMap::new()));
        let default_style = Style::default();
        let color = colors.lock().unwrap()
            .get(&process_name.clone())
            .cloned()
            .unwrap_or(default_style);

        warn!("{}{}", color.paint(format!("[{}] ", process_name)), &message);
    }};
}

#[macro_export]
macro_rules! log_process_error {
    ($process_name:expr, $($arg:tt)*) => {{
        let process_name = $process_name;
        let message = format!($($arg)*);

        let colors = PROCESS_COLORS.get_or_init(|| Mutex::new(HashMap::new()));
        let default_style = Style::default();
        let color = colors.lock().unwrap()
            .get(&process_name.clone())
            .cloned()
            .unwrap_or(default_style);

        error!("{}{}", color.paint(format!("[{}] ", process_name)), &message);
    }};
}

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
    services: HashMap<String, ServiceConfig>,
}

#[derive(Debug)]
enum ServiceCommand {
    Start(String),
    Stop(String),
    Restart(String),
    ForceRestart(String),
}

/// Helper function to create CPU affinity mask
fn create_cpu_affinity_mask(cpu_selection: &CpuSelection) -> String {
    let total_cpus = num_cpus::get();

    match cpu_selection {
        CpuSelection::Single(cpu) => {
            // If CPU number is greater than available CPUs, use the last CPU
            let cpu_num = if *cpu >= total_cpus as u32 {
                (total_cpus - 1) as u32
            } else {
                *cpu
            };
            cpu_num.to_string()
        }
        CpuSelection::Multiple(cpus) => {
            // Filter out invalid CPU numbers and use only valid ones
            let valid_cpus: Vec<u32> = cpus.iter()
                .map(|cpu| {
                    if *cpu >= total_cpus as u32 {
                        (total_cpus - 1) as u32
                    } else {
                        *cpu
                    }
                })
                .collect();

            valid_cpus.iter()
                .map(|cpu| cpu.to_string())
                .collect::<Vec<String>>()
                .join(",")
        }
    }
}

/// Helper function to create CPU limit command
fn create_cpu_limit_command(cpu_limit: u32, command: &String) -> String {
    format!("cpulimit -l {} -- {}", cpu_limit, command)
}

fn run_command(
    name: &String,
    command: &str,
    env_vars: &HashMap<String, String>,
    log_dir: &String,
    cpu: Option<&CpuSelection>,
    cpu_limit: Option<u32>,
    workdir: &String,
    user: Option<&String>,
) -> Option<Child> {
    // Remove lock files using Rust's file removal implementation before starting the main process
    let lock_path1 = Path::new(log_dir).join(".lock");
    let lock_path2 = Path::new(log_dir).join("lock");

    if lock_path1.exists() {
        if let Err(e) = fs::remove_file(&lock_path1) {
            log_process_warn!(name, "Failed to remove {lock_path1:?}: {e}");
        } else {
            log_process_info!(name, "Removed lock file: {lock_path1:?}");
        }
    }

    if lock_path2.exists() {
        if let Err(e) = fs::remove_file(&lock_path2) {
            log_process_warn!(name, "Failed to remove {lock_path2:?}: {e}");
        } else {
            log_process_info!(name, "Removed lock file: {lock_path2:?}");
        }
    }

    // Now create the shell command without the rm commands
    let mut shell_command = command.to_string();

    // If user is specified, wrap the command with runuser
    if let Some(user) = user {
        shell_command = format!("runuser -u {} -- {}", user, shell_command);
    }

    // Apply CPU affinity if specified
    if let Some(cpu_selection) = cpu {
        let affinity_mask = create_cpu_affinity_mask(cpu_selection);
        shell_command = format!("taskset -c {} {}", affinity_mask, shell_command);
    }

    // Add logging pipe
    shell_command = format!("{} 2>&1 | multilog s100000 n5 {}", shell_command, log_dir);

    let mut cmd = Command::new("sh");

    if let Some(cpu_limit) = cpu_limit {
        shell_command = create_cpu_limit_command(cpu_limit, &shell_command);
    }
    cmd.arg("-c").arg(&shell_command).envs(env_vars).current_dir(workdir);

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(child) => {
            log_process_info!(name, "Process `{shell_command}` started");
            Some(child)
        }
        Err(e) => {
            log_process_error!(name, "Failed to spawn process {shell_command}: {e}");
            None
        }
    }
}

async fn stop_process(processes: Arc<Mutex<HashMap<String, ProcessInfo>>>, name: String) {
    let mut processes = processes.lock().unwrap();
    if let Some(process_info) = processes.get_mut(&name) {
            if let Some(child) = &mut process_info.child {
                let _ = process_management::stop_process(Some(child.id() as i32), name.clone());
            }

        // Remove the process from tracking
        process_info.child = None;
    }
}

fn build_env_vars(
    name: &str,
    service_config: &ServiceConfig,
    interface: &InterfaceInstance,
) -> HashMap<String, String> {
    let mut env_vars = std::env::vars().collect::<HashMap<_, _>>();
    if let Some(env_config) = &service_config.env {
        for (env_var, env_value) in env_config {
            if let Some(param_id) = interface.get_parameter_id_from_name(env_value.clone()) {
                if let Ok(value) = interface.get(param_id, false) {
                    let value_str = InterfaceInstance::value_to_string(&value);
                    log_process_info!(name.to_string(), "Adding env value {env_var} = {value_str} (from parameter {})", env_value);
                    env_vars.insert(env_var.clone(), value_str);
                } else {
                    log_process_info!(name.to_string(), "Adding env value {env_var} = {env_value} (literal)");
                    env_vars.insert(env_var.clone(), env_value.clone());
                }
            } else {
                log_process_info!(name.to_string(), "Adding env value {env_var} = {env_value} (literal)");
                env_vars.insert(env_var.clone(), env_value.clone());
            }
        }
    }
    env_vars.insert("PROCESS_MANAGER_UUID".to_string(), name.to_string());
    env_vars
}

async fn start_process(
    processes: Arc<Mutex<HashMap<String, ProcessInfo>>>,
    name: String,
    service_config: &ServiceConfig,
    interface: &InterfaceInstance,
    only_if_env_changed: bool,
    restart: bool,
) {
    let env_vars = build_env_vars(&name, service_config, interface);

    // Check if already running
    {
        let mut processes = processes.lock().unwrap();
        if let Some(process_info) = processes.get_mut(&name) {
            if service_config.one_shot && process_info.child.is_some() {
                log_process_info!(name, "Already running (one_shot)");
                return;
            }
            if !restart && process_info.child.is_some() {
                log_process_info!(name, "Already running");
                return;
            }
            if only_if_env_changed && process_info.env_vars == env_vars {
                log_process_info!(name, "Env unchanged, skip restart");
                return;
            }
        }
    }

    // For one_shot, do not stop or restart, just start if not running
    if !service_config.one_shot {
        stop_process(processes.clone(), name.clone()).await;
    }

    let mut child = match run_command(
        &name,
        &service_config.command,
        &env_vars,
        &service_config.log_dir,
        service_config.cpu.as_ref(),
        service_config.cpu_limit,
        &service_config.workdir,
        service_config.user.as_ref(),
    ) {
        Some(c) => c,
        None => {
            log_process_error!(name, "Failed to run the process{}", if service_config.one_shot { " (one_shot)" } else { "" });
            return;
        }
    };

    if service_config.one_shot {
        let mut processes_locked = processes.lock().unwrap();
        processes_locked.insert(
            name.clone(),
            ProcessInfo {
                child: Some(child),
                last_output: Instant::now(),
                died_at: None,
                env_vars,
            },
        );
        log_process_info!(name, "Started (one_shot)");
        return;
    }

    // Take stdout/stderr directly from child before inserting into map
    let stdout = child.stdout.take().expect("Failed to get stdout");
    let stderr = child.stderr.take().expect("Failed to get stderr");

    {
        let mut processes_locked = processes.lock().unwrap();
        processes_locked.insert(
            name.clone(),
            ProcessInfo {
                child: Some(child),
                last_output: Instant::now(),
                died_at: None,
                env_vars,
            },
        );
    }

    let processes_clone_stdout = processes.clone();
    let processes_clone_stderr = processes.clone();
    let name_clone_stdout = name.clone();
    let name_clone_stderr = name.clone();

    tokio::spawn(async move {
        let stdout_reader = BufReader::new(stdout);
        for line in stdout_reader.lines() {
            match line {
                Ok(line) => {
                    log_process_info!(&name_clone_stdout, "stdout {}", line);
                    let mut processes = processes_clone_stdout.lock().unwrap();
                    if let Some(process_info) = processes.get_mut(&name_clone_stdout) {
                        process_info.last_output = Instant::now();
                    }
                }
                Err(e) => {
                    log_process_error!(name_clone_stdout, "Error reading stdout: {}", e);
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
                    log_process_error!(&name_clone_stderr, "{}{}", ansi_term::Color::Red.paint("stderr: "), line);
                    let mut processes = processes_clone_stderr.lock().unwrap();
                    if let Some(process_info) = processes.get_mut(&name_clone_stderr) {
                        process_info.last_output = Instant::now();
                    }
                }
                Err(e) => {
                    log_process_error!(name_clone_stderr, "Error reading stderr: {}", e);
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
        for (service_name, service_config) in &state.services {
            let mut requested_state_change = false;

            // If enable is false, always stop the process and skip enable_parameter logic
            let enable = resolve_bool_or_string(&service_config.enable);
            let disabled = resolve_bool_or_string(&service_config.disabled);

            if !enable || disabled {
                log_process_info!(service_name, "Enable ({enable}) is false or disabled {disabled} is true, stopping process");
                let _ = state.tx.send(ServiceCommand::Stop(service_name.clone()));
                requested_state_change = true;
            } else if service_config.enable_parameter.contains_key(&name) {
                let expected_value = &service_config.enable_parameter[&name];

                let should_run = match state.interface.set_from_json(id, expected_value) {
                    Ok(val) => val == value,
                    Err(e) => {
                        error!("Failed to convert enable variable: {e}");
                        true
                    }
                };

                if should_run {
                    log_process_info!(service_name, 
                        "Enable parameter changed, {name} = {value}, starting"
                    );
                    let _ = state
                        .tx
                        .send(ServiceCommand::Start(service_name.clone()));
                } else {
                    log_process_info!(service_name, 
                        "Enable parameter changed, {name} = {value}, stopping"
                    );
                    let _ = state
                        .tx
                        .send(ServiceCommand::Stop(service_name.clone()));
                }
                requested_state_change = true;
            }

            if !requested_state_change {
                if let Some(env_config) = &service_config.env {
                    if env_config.values().any(|param_name| param_name == &name) {
                        log_process_info!(service_name, 
                            "{name} parameter changed in env, restarting"
                        );
                        let _ = state
                            .tx
                            .send(ServiceCommand::Restart(service_name.clone()));
                    }
                }
            }
        }
    }
}

async fn watchdog_task(
    processes: Arc<Mutex<HashMap<String, ProcessInfo>>>,
    services: HashMap<String, ServiceConfig>,
    tx: std::sync::mpsc::Sender<ServiceCommand>,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut processes = processes.lock().unwrap();
        let now = Instant::now();

        for (name, process_info) in processes.iter_mut() {
            let service = services.get(name).unwrap();
            if service.one_shot {
                // No watchdog, no restart for one_shot
                continue;
            }
            if let Some(child) = &mut process_info.child {
                let needs_restart = match &service.watchdog {
                    Watchdog::Stdout => {
                        now.duration_since(process_info.last_output)
                            > Duration::from_secs(service.watchdog_timeout_s)
                    }
                    Watchdog::None => false,
                };

                if needs_restart {
                    log_process_warn!(name, "Watchdog timeout, restarting");
                    let _ = tx.send(ServiceCommand::ForceRestart(name.clone()));
                }

                if let Ok(Some(_)) = child.try_wait() {
                    log_process_warn!(name, "~~~ Process died ~~~");
                    process_info.died_at = Some(now);
                    process_info.child = None;
                }
            } else if let Some(died_at) = process_info.died_at {
                if now.duration_since(died_at) >= Duration::from_secs(5) {
                    log_process_warn!(name, "Restarting process");
                    let _ = tx.send(ServiceCommand::Start(name.clone()));
                    process_info.died_at = None;
                }
            }
        }
    }
}

fn resolve_bool_or_string(val: &BoolOrString) -> bool {
    match val {
        BoolOrString::Bool(b) => *b,
        BoolOrString::String(env_var) => {
            match std::env::var(env_var) {
                Ok(v) => {
                    info!("Checking env variable {env_var} = {v}");
                    let v = v.to_ascii_lowercase();
                    v == "1" || v == "true" || v == "yes" || v == "on" || v == "enabled"
                }
                Err(std::env::VarError::NotPresent) => false,
                Err(_) => false,
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize a start time for relative timestamps
    let start_time = std::time::Instant::now();

    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format(move |buf, record| {
            let file_name = record.file().unwrap_or("unknown");
            let file_name = std::path::Path::new(file_name)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();

            // Calculate elapsed time since start in seconds with 3 decimal places
            let elapsed = start_time.elapsed();
            let timestamp = format!("{:.3}", elapsed.as_secs_f32());

            // Color the level based on its severity
            let level = match record.level() {
                log::Level::Error => Colour::Red.paint("ERROR"),
                log::Level::Warn => Colour::Yellow.paint("WARN "),
                log::Level::Info => Colour::Green.paint("INFO "),
                log::Level::Debug => Colour::Fixed(8).paint("DEBUG"),
                log::Level::Trace => Colour::Purple.paint("TRACE"),
            };

            writeln!(
                buf,
                "{} {} {} {}",
                Colour::Fixed(8).paint(timestamp),
                level,
                Colour::Fixed(8).paint(format!("{}:{}", file_name, record.line().unwrap_or(0))),
                record.args()
            )
        })
        .try_init();

    let args = Args::parse();
    let config = Config::from_file(args.config);
    let services = config.services;

    let mut interface_instance = match InterfaceInstance::new(
        &config.econfmanager.database_path,
        &config.econfmanager.saved_database_path,
        &config.econfmanager.default_data_folder,
    ) {
        Ok(instance) => instance,
        Err(e) => {
            error!("Failed to create interface instance: {}", e);
            return;
        }
    };

    for (name, service) in &services {
        log_process_info!(name, "Service: ");
        info!("\tCommand {}", &service.command);
        info!("\tEnable {:?}", &service.enable);
        info!("\tDisabled {:?}", &service.disabled);
        info!("\tEnable Parameter: {:?}", &service.enable_parameter);
        info!("\tEnv {:?}", &service.env);
        info!("\tWatchdog {:?}", &service.watchdog);
        info!("\tLog Dir {:?}", &service.log_dir);
        info!("\tCPU Config {:?}", &service.cpu);
    }

    let (tx, rx) = std::sync::mpsc::channel::<ServiceCommand>();

    interface_instance.start_periodic_update(PERIODIC_UPDATE_INTERVAL);

    let processes = Arc::new(Mutex::new(HashMap::new()));
    let state = Arc::new(Mutex::new(AppState {
        interface: interface_instance,
        tx: tx.clone(),
        services: services.clone(),
    }));

    tokio::spawn(watchdog_task(
        processes.clone(),
        services.clone(),
        tx.clone(),
    ));

    let state_cloned = Arc::clone(&state);
    let callback = Arc::new(move |id: ParameterId| {
        let state = Arc::clone(&state_cloned);
        let mut app = state.lock().unwrap();
        process_callback(&mut app, id);
    }) as ParameterUpdateCallback;

    {
        let mut app = state.lock().unwrap();

        let mut params_to_watch = Vec::new();

        for service in app.services.values() {
            for param_name in service.enable_parameter.keys() {
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
                    log_process_error!(param_name, "Failed to add callback: {}", e);
                }
            } else {
                log_process_error!(param_name, "Parameter not found");
            }
        }

        // Initial check, start the processes
        for (name, service) in &app.services {
            let mut should_start = false;
            let enable = resolve_bool_or_string(&service.enable);
            let disabled = resolve_bool_or_string(&service.disabled);
            log_process_info!(name, "Enabled - {:?}: {}", service.enable, enable);
            log_process_info!(name, "Disabled - {:?}: {}", service.disabled, disabled);

            if !enable || disabled {
                should_start = false;
            } else if !service.enable_parameter.is_empty() {
                if let Some((enable_parameter_name, expected_value)) = service.enable_parameter.iter().next() {
                    if let Some(id) = app
                        .interface
                        .get_parameter_id_from_name(enable_parameter_name.clone())
                    {
                        if let Ok(value) = app.interface.get(id, false) {
                            should_start = match app.interface.set_from_json(id, expected_value) {
                                Ok(val) => {
                                    log_process_info!(name, 
                                        "Enable parameter: {enable_parameter_name}, require {val} to start, current value is {value}. Therefore should_start = {should_start}"
                                    );
                                    val == value
                                },
                                Err(e) => {
                                    log_process_error!(name, "Failed to convert enable variable: {e}");
                                    true
                                }
                            };
                        }
                    } else {
                        log_process_error!(
                            name,
                            "Parameter {} not found",
                            enable_parameter_name
                        );
                        should_start = true;
                    }
                }
            } else {
                log_process_info!(name, "No enable_parameter set, using enable: true");
                should_start = true;
            }

            if should_start {
                log_process_info!(name, "initial state: started");
                let _ = app.tx.send(ServiceCommand::Start(name.clone()));
            } else {
                log_process_info!(name, "initial state: stopped");
            }
        }
    }

    // Initialize process colors
    {
        let available_colors = [
            ansi_term::Colour::Fixed(141),
            ansi_term::Colour::Fixed(114), 
            ansi_term::Colour::Fixed(33), 
            ansi_term::Colour::Fixed(93),
            ansi_term::Colour::Fixed(214), 
            ansi_term::Colour::Fixed(23), 
            ansi_term::Colour::Fixed(208), 
            ansi_term::Colour::Fixed(129),
            ansi_term::Colour::Fixed(105), 
            ansi_term::Colour::Fixed(69), 
            ansi_term::Colour::Fixed(27),
            ansi_term::Colour::Fixed(201), 
            ansi_term::Colour::Fixed(165),
        ];

        let colors = PROCESS_COLORS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut colors = colors.lock().unwrap();
        for (i, name) in state.lock().unwrap().services.keys().enumerate() {
            let color = available_colors[i % available_colors.len()];
            let style = Style::new().fg(color).bold();
            colors.insert(name.clone(), style);
        }
    }

    info!("Process Manager started");

    while let Ok(cmd) = rx.recv() {
        match cmd {
            ServiceCommand::Start(name) => {
                log_process_info!(&name, "Start requested, starting...");
                if let Some(service_config) = services.get(&name) {
                    let interface = &state.lock().unwrap().interface;
                    start_process(
                        processes.clone(),
                        name,
                        service_config,
                        interface,
                        false,
                        false,
                    )
                    .await;
                }
            }
            ServiceCommand::Stop(name) => {
                log_process_info!(&name, "Stop requested, stopping...");
                stop_process(processes.clone(), name).await;
            }
            ServiceCommand::Restart(name) => {
                if let Some(service_config) = services.get(&name) {
                    if service_config.one_shot {
                        log_process_info!(&name, "Restart requested, but one_shot is true. Ignoring.");
                        continue;
                    }
                    log_process_info!(&name, "Restart received, restarting...");
                    let interface = &state.lock().unwrap().interface;
                    start_process(
                        processes.clone(),
                        name,
                        service_config,
                        interface,
                        true,
                        true,
                    )
                    .await;
                }
            }
            ServiceCommand::ForceRestart(name) => {
                if let Some(service_config) = services.get(&name) {
                    if service_config.one_shot {
                        log_process_info!(&name, "ForceRestart requested, but one_shot is true. Ignoring.");
                        continue;
                    }
                    log_process_info!(&name, "ForceRestart received, restarting...");
                    let interface = &state.lock().unwrap().interface;
                    start_process(
                        processes.clone(),
                        name,
                        service_config,
                        interface,
                        false,
                        true,
                    )
                    .await;
                }
            }
        }
    }
}
