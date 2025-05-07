use std::fs;
use serde::Deserialize;

/******************************************************************************
 * PUBLIC TYPES
 ******************************************************************************/

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Manager {
    Systemd,
    Runit,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ServiceConfig {
    pub name: String,
    pub parameter: String,
    pub manager: Manager,
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
