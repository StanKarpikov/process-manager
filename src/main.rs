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
        writeln!(
            buf,
            "{} [{}] {}:{} - {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.args()
        )
    })
    .init();

    let args = Args::parse();
    let config = Config::from_file(args.config);

    let mut interface_instance = InterfaceInstance::new(&config.database_path, &config.saved_database_path, &config.default_data_folder).unwrap();

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
                            error!("Unexpected type for {}", service.parameter);
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
                    let service = services_clone.iter().find(|x|x.name == name);
                    if let Some(config) = service {
                        match config.manager {
                            Manager::Systemd => {
                                let _ = Command::new("systemctl")
                                    .arg("start")
                                    .arg(&config.name)
                                    .status();
                            }
                            Manager::Runit => {
                                let _ = Command::new("sv")
                                    .arg("up")
                                    .arg(format!("/etc/service/{}", &config.name))
                                    .status();
                            }
                        }
                    }
                },
                ServiceCommand::Stop(name) => {
                    info!("Stop {}", name);
                    let service = services_clone.iter().find(|x|x.name == name);
                    if let Some(config) = service {
                        match config.manager {
                            Manager::Systemd => {
                                let _ = Command::new("systemctl")
                                    .arg("stop")
                                    .arg(&config.name)
                                    .status();
                            }
                            Manager::Runit => {
                                let _ = Command::new("sv")
                                    .arg("down")
                                    .arg(format!("/etc/service/{}", &config.name))
                                    .status();
                            }
                        }
                    }
                }
            }
        }
    });
}
