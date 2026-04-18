use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::error::AppError;
use crate::db::FunctionData;

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisResult {
    pub analysis_id: i32,
    pub project_name: String,
    pub path: String,
    pub files_scanned: i32,
    pub total_functions: i32,
    pub vuln_count: i32,
    pub functions: Vec<FunctionData>,
}

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
    let content = serde_json::to_string(&Config { kaggle_url: url.to_string() }).unwrap();
    if !app_data_dir.exists() {
        fs::create_dir_all(app_data_dir)?;
    }
    fs::write(&config_path, content)
}

pub async fn check_api_health(client: &Client, url: &str) -> bool {
    if url.is_empty() { return false; }
    if let Ok(resp) = client.get(url).timeout(std::time::Duration::from_secs(5)).send().await {
        resp.status().is_success()
    } else {
        false
    }
}

pub async fn analyze_function(client: &Client, url: &str, code: &str) -> Result<FunctionData, AppError> {
    if url.is_empty() {
        return Err(AppError::Custom("Kaggle API URL not configured (check settings)".into()));
    }

    let body = serde_json::json!({ "code": code });
    let resp = client.post(format!("{}/predict", url))
        .json(&body)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await?;
        
    if !resp.status().is_success() {
        return Err(AppError::Custom(format!("API returned error: {}", resp.status())));
    }
    
    let json: serde_json::Value = resp.json().await?;
    let mut confidence = 0.0;
    
    let mut output_str = String::new();
    
    if let Some(result) = json.get("result") {
        if let Some(conf) = result.get("confidence") {
            confidence = conf.get("value").and_then(|v| v.as_f64()).unwrap_or_else(|| conf.as_f64().unwrap_or(0.0));
        } else if let Some(conf) = json.get("confidence") {
            confidence = conf.as_f64().unwrap_or(0.0);
        }
        
        if let Some(out) = result.get("output") {
            if let Some(s) = out.as_str() {
                output_str = s.to_string();
            } else if let Some(arr) = out.as_array() {
                if !arr.is_empty() {
                    output_str = arr[0].as_str().unwrap_or("").to_string();
                }
            }
        } else if let Some(s) = result.as_str() {
            output_str = s.to_string();
        }
    } else if let Some(out) = json.get("output") {
        if let Some(conf) = json.get("confidence") {
            confidence = conf.as_f64().unwrap_or(0.0);
        }
        if let Some(s) = out.as_str() {
            output_str = s.to_string();
        } else if let Some(arr) = out.as_array() {
            if !arr.is_empty() {
                output_str = arr[0].as_str().unwrap_or("").to_string();
            }
        }
    }
    
    if output_str.to_lowercase() == "code is safe" || output_str.to_lowercase() == "safe" {
        return Ok(FunctionData {
            id: None,
            function_name: "".into(),
            code: "".into(),
            verdict: "safe".into(),
            cwe: None,
            cwe_name: None,
            severity: None,
            confidence: Some(confidence),
            start_line: None,
            end_line: None,
        });
    }
    
    let cwe_info = get_cwe_info(&output_str);
    
    Ok(FunctionData {
        id: None,
        function_name: "".into(),
        code: "".into(),
        verdict: if output_str.is_empty() { "safe".into() } else { "vulnerable".into() },
        cwe: Some(output_str),
        cwe_name: cwe_info.0,
        severity: cwe_info.1,
        confidence: Some(confidence),
        start_line: None,
        end_line: None,
    })
}

fn get_cwe_info(cwe: &str) -> (Option<String>, Option<String>) {
    match cwe {
        "CWE-125" => (Some("Out-of-bounds Read".into()), Some("High".into())),
        "CWE-787" => (Some("Out-of-bounds Write".into()), Some("Critical".into())),
        "CWE-190" => (Some("Integer Overflow or Wraparound".into()), Some("High".into())),
        "CWE-369" => (Some("Divide By Zero".into()), Some("Medium".into())),
        "CWE-415" => (Some("Double Free".into()), Some("High".into())),
        "CWE-476" => (Some("NULL Pointer Dereference".into()), Some("High".into())),
        _ => (Some("Unknown".into()), Some("Unknown".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cwe_mapping() {
        let (name, sev) = get_cwe_info("CWE-787");
        assert_eq!(name, Some("Out-of-bounds Write".into()));
        assert_eq!(sev, Some("Critical".into()));

        let (name, sev) = get_cwe_info("Unknown");
        assert_eq!(name, Some("Unknown".into()));
    }

    #[test]
    fn test_kaggle_url_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        save_kaggle_url(path, "https://test.ngrok.app").unwrap();
        let url = load_kaggle_url(path);
        assert_eq!(url, "https://test.ngrok.app");
    }
}
