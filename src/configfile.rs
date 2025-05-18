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
    pub enable: HashMap<String, serde_json::Value>,
    pub env: Option<HashMap<String, String>>, 
    pub command: String,
    pub watchdog: Watchdog,
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
