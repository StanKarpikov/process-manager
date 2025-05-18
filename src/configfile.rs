use std::{collections::HashMap, fs};
use serde::Deserialize;

/******************************************************************************
 * PUBLIC TYPES
 ******************************************************************************/

 #[derive(Debug, Clone, Deserialize)]
 #[serde(tag = "type")]
 pub(crate) enum Watchdog {
     Stdout,
     None,
 }
 
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ServiceConfig {
    pub name: String,

    #[serde(default = "default_enable")]
    pub enable: HashMap<String, serde_json::Value>,

    #[serde(default = "default_env")]
    pub env: Option<HashMap<String, String>>, 

    pub command: String,

    #[serde(default = "default_watchdog")]
    pub watchdog: Watchdog,

    pub log_dir: String,
}

#[derive(Deserialize, Default)]
pub(crate) struct Config {
    #[serde(default = "default_database_path")]
    pub database_path: String,
    #[serde(default = "default_saved_database_path")]
    pub saved_database_path: String,
    #[serde(default = "default_default_data_folder")]
    pub default_data_folder: String,

    pub services: Vec<ServiceConfig>,
}

/******************************************************************************
 * PRIVATE FUNCTIONS
 ******************************************************************************/

fn default_enable() -> HashMap<String, serde_json::Value> {
    HashMap::new()
}

fn default_env() -> Option<HashMap<String, String>> {
    None
}

fn default_watchdog() -> Watchdog {
    Watchdog::None
}

fn default_database_path() -> String {
    "configuration.db".to_string()
}

fn default_saved_database_path() -> String {
    "configuration_saved.db".to_string()
}

fn default_default_data_folder() -> String {
    ".".to_string()
}

/******************************************************************************
 * PUBLIC FUNCTIONS
 ******************************************************************************/

impl Config {
    pub(crate) fn from_file(config_file:String) -> Config {
        let file_content = fs::read_to_string(std::path::Path::new(&config_file)).expect(&format!("Failed to read configuration file {}", config_file));
        let config: Config = serde_json::from_str(&file_content).expect("Failed to parse JSON");
        config
    }
}
