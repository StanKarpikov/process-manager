use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use arguments::Args;
use clap::Parser;
use configfile::{Config, Manager};
use econfmanager::generated::ParameterId;
use econfmanager::interface::InterfaceInstance;
use econfmanager::interface::ParameterUpdateCallback;
use env_logger::Env;
use log::error;
use log::info;
use tokio::task;
use std::io::Write;

pub mod arguments;
pub mod configfile;

const PERIODIC_UPDATE_INTERVAL: Duration = Duration::from_millis(5000);

#[derive(Debug)]
enum ServiceCommand {
    Start(String),
    Stop(String),
}

struct AppState {
    interface: InterfaceInstance,
    tx: std::sync::mpsc::Sender<ServiceCommand>,
    config: Config,
}

fn run_command(command: &str, args: &[&str]) {
    let output = Command::new(command)
        .args(args)
        .output(); // Capture both stdout and stderr
    match output {
        Ok(o) => {
            if !o.stdout.is_empty() {
                info!("stdout: {}", String::from_utf8_lossy(&o.stdout).trim());
            }
            if !o.stderr.is_empty() {
                error!("stderr: {}", String::from_utf8_lossy(&o.stderr).trim());
            }

            if !o.status.success() {
                error!("Command failed with status: {}", o.status);
            }
        },
        Err(e) => {
            error!("Error executing command: {}", e);
        }
    };
}

fn process_callback(state: &AppState, id: ParameterId)
{
    let name = state.interface.get_name(id);
    info!("Received update for {}", name);

    let enabled = state.interface.get(id, false).unwrap();
    match enabled {
        econfmanager::schema::ParameterValue::ValBool(enabled) => 
        {
            if enabled
            {
                let _ = state.tx.send(ServiceCommand::Start(name));
            }
            else {
                let _ = state.tx.send(ServiceCommand::Stop(name));
            }
        },
        _ => {
            error!("Unexpected type for {}", name);
            return;
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
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
    .init();

    let args = Args::parse();
    let config = Config::from_file(args.config);

    let mut interface_instance = match InterfaceInstance::new(&config.database_path, &config.saved_database_path, &config.default_data_folder) {
        Ok(instance) => instance,
        Err(e) => {
            eprintln!("Failed to create interface instance: {}", e);
            return;
        }
    };

    let (tx, rx) = std::sync::mpsc::channel::<ServiceCommand>();
    
    interface_instance.start_periodic_update(PERIODIC_UPDATE_INTERVAL);
    let state = Arc::new(Mutex::new(AppState {
        interface: interface_instance,
        tx: tx,
        config: config,
    }));

    let state_cloned = Arc::clone(&state);
    let callback = Arc::new(move |id: ParameterId| {
        let state = Arc::clone(&state_cloned);
        let mut app = state.lock().unwrap();
        process_callback(&mut app, id);
    }) as ParameterUpdateCallback;

    let services_clone;
    {
        let mut app = state.lock().unwrap();
        for service in app.config.services.clone() {
            info!("Adding callback for {}", service.parameter);
            let id = app.interface.get_parameter_id_from_name(service.parameter.clone());
            match id {
                Some(id) => {
                    let _ = app.interface.add_callback(id, callback.clone()).map_err(|e| format!("Could not add callback: {}", e));

                    let enabled = app.interface.get(id, false).unwrap();
                    match enabled {
                        econfmanager::schema::ParameterValue::ValBool(enabled) => 
                        {
                            if enabled
                            {
                                let _ = app.tx.send(ServiceCommand::Start(service.parameter));
                            }
                            else {
                                let _ = app.tx.send(ServiceCommand::Stop(service.parameter));
                            }
                        },
                        _ => {
                            error!("Unexpected type for {}: {}", service.parameter, enabled);
                            return;
                        }
                    };
                },
                None => {
                    error!("Could not get ID for parameter {}", service.parameter);
                }    
            };
        }
        services_clone = app.config.services.clone();
    }

    info!("Process Manager started");
    task::spawn_blocking(move || {
        while let Ok(cmd) = rx.recv() {
            match cmd {
                ServiceCommand::Start(name) => {
                    info!("Start {}", name);
                    let service = services_clone.iter().find(|&x|x.parameter == name);
                    if let Some(config) = service {
                        match config.manager {
                            Manager::Systemd => {
                                run_command("systemctl", &["start", &config.name]);
                            }
                            Manager::Runit => {
                                run_command("sv", &["up", &config.name]);
                            }
                        }
                    }
                    else {
                        error!("Could not find service description for {name}");
                    }
                },
                ServiceCommand::Stop(name) => {
                    info!("Stop {}", name);
                    let service = services_clone.iter().find(|x|x.name == name);
                    if let Some(config) = service {
                        match config.manager {
                            Manager::Systemd => {
                                run_command("systemctl", &["stop", &config.name]);
                            }
                            Manager::Runit => {
                                run_command("sv", &["down", &config.name]);
                            }
                        }
                    }
                    else {
                        error!("Could not find service description for {name}");
                    }
                }
            }
        }
    });
}
