use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct Config {
    kaggle_url: String,
}

pub fn load_kaggle_url(app_data_dir: &Path) -> String {
    let config_path = app_data_dir.join("config.json");
    if let Ok(content) = fs::read_to_string(&config_path) {
        if let Ok(config) = serde_json::from_str::<Config>(&content) {
            return config.kaggle_url;
        }
    }
    // Check old path fallback
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let old_config = parent.join("backend/config.json");
            if let Ok(content) = fs::read_to_string(&old_config) {
                if let Ok(config) = serde_json::from_str::<Config>(&content) {
                    let _ = fs::write(&config_path, &content);
                    return config.kaggle_url;
                }
            }
        }
    }
    String::new()
}

pub fn save_kaggle_url(app_data_dir: &Path, url: &str) -> std::io::Result<()> {
    let config_path = app_data_dir.join("config.json");
    let content = serde_json::to_string(&Config {
        kaggle_url: url.to_string(),
    })
    .unwrap();
    if !app_data_dir.exists() {
        fs::create_dir_all(app_data_dir)?;
    }
    fs::write(&config_path, content)
}
