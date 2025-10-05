use std::{collections::HashMap, fs};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum CpuSelection {
    Single(u32),
    Multiple(Vec<u32>),
}

/******************************************************************************
 * PUBLIC TYPES
 ******************************************************************************/

 #[derive(Debug, Clone, Deserialize)]
 #[serde(rename_all = "lowercase")]
 pub(crate) enum Watchdog {
     Stdout,
     None,
 }
 
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ServiceConfig {
    #[serde(default = "default_enable")]
    pub enable: HashMap<String, serde_json::Value>,

    #[serde(default = "default_env")]
    pub env: Option<HashMap<String, String>>,

    pub command: String,

    #[serde(default = "default_watchdog")]
    pub watchdog: Watchdog,

    #[serde(default = "default_watchdog_timeout_s")]
    pub watchdog_timeout_s: u64,

    pub log_dir: String,

    #[serde(default)]
    pub cpu: Option<CpuSelection>,

    #[serde(default)]
    pub cpu_limit: Option<u32>,
}

#[derive(Deserialize, Default)]
pub(crate) struct EconfmanagerConfig {
    #[serde(default = "default_database_path")]
    pub database_path: String,
    #[serde(default = "default_saved_database_path")]
    pub saved_database_path: String,
    #[serde(default = "default_default_data_folder")]
    pub default_data_folder: String,
}

#[derive(Deserialize, Default)]
pub(crate) struct Config {
    pub(crate) econfmanager: EconfmanagerConfig,
    pub(crate) services: HashMap<String, ServiceConfig>,
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

fn default_watchdog_timeout_s() -> u64 {
    60
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
    pub fn from_file(config_file: String) -> Config {
        let file_content = fs::read_to_string(std::path::Path::new(&config_file))
            .unwrap_or_else(|_| panic!("Failed to read configuration file {}", config_file));

        let yaml_config: Config = serde_yaml::from_str(&file_content)
            .expect("Failed to parse YAML configuration");

        yaml_config
    }
}
