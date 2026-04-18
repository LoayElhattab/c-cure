use std::path::Path;
use serde_json::Value;

use crate::AppState;
use crate::error::AppError;
use crate::db::{AnalysisSummary, Report, StatisticsData, WatchedProject};
use crate::ml_api::AnalysisResult;

#[tauri::command]
pub async fn analyze_file(state: tauri::State<'_, AppState>, file_path: String) -> Result<AnalysisResult, AppError> {
    let functions = crate::parser::extract_functions(&file_path)
        .map_err(|e| AppError::Custom(format!("Extract failed: {}", e)))?;
        
    if functions.is_empty() {
        return Err(AppError::Custom("No functions found in file. Is it a valid C++ file?".into()));
    }
    
    let db = state.db.lock().await;
    let url = crate::ml_api::load_kaggle_url(&state.app_data_dir);
    if url.is_empty() {
        return Err(AppError::Custom("Kaggle API URL not configured".into()));
    }
    
    let path = Path::new(&file_path);
    let project_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "Unknown".to_string());
    
    let analysis_id = db.save_analysis(&project_name, &file_path)?;
    let file_id = db.save_file(analysis_id, &file_path)?;
    
    let mut results = Vec::new();
    let mut vuln_count = 0;
    
    for fn_info in functions {
        let mut result = crate::ml_api::analyze_function(&state.reqwest_client, &url, &fn_info.code).await?;
        result.function_name = fn_info.function_name.clone();
        result.code = fn_info.code.clone();
        result.start_line = Some(fn_info.start_line);
        result.end_line = Some(fn_info.end_line);
        
        db.save_function(file_id, &result)?;
        if result.verdict == "vulnerable" {
            vuln_count += 1;
        }
        results.push(result);
    }
    
    Ok(AnalysisResult {
        analysis_id: analysis_id as i32,
        project_name,
        path: file_path,
        files_scanned: 1,
        total_functions: results.len() as i32,
        vuln_count,
        functions: results,
    })
}

#[tauri::command]
pub async fn analyze_folder(state: tauri::State<'_, AppState>, folder_path: String) -> Result<AnalysisResult, AppError> {
    let url = crate::ml_api::load_kaggle_url(&state.app_data_dir);
    if url.is_empty() {
        return Err(AppError::Custom("Kaggle API URL not configured".into()));
    }

    let mut cpp_files = Vec::new();
    let ext_list = ["cpp", "c", "h", "cc", "cxx"];

    for entry in walkdir::WalkDir::new(&folder_path).into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_file() {
            let relative = p.strip_prefix(&folder_path).unwrap_or(p);
            let is_excluded = relative.components().any(|c| {
                if let std::path::Component::Normal(name) = c {
                    let s = name.to_string_lossy();
                    s.starts_with('.') || s == "build" || s == "cmake" || s == "node_modules"
                } else {
                    false
                }
            });
            if is_excluded { continue; }
            
            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if ext_list.contains(&ext) {
                    cpp_files.push(p.to_string_lossy().to_string());
                }
            }
        }
    }

    if cpp_files.is_empty() {
        return Err(AppError::Custom("No C++ files found in folder.".into()));
    }

    let db = state.db.lock().await;
    let path = Path::new(&folder_path);
    let project_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "Unknown".to_string());
    
    let analysis_id = db.save_analysis(&project_name, &folder_path)?;
    
    let mut all_functions = Vec::new();
    let mut total_vuln = 0;

    for file_path in &cpp_files {
        let file_id = db.save_file(analysis_id, file_path)?;
        if let Ok(functions) = crate::parser::extract_functions(file_path) {
            for fn_info in functions {
                let mut result = crate::ml_api::analyze_function(&state.reqwest_client, &url, &fn_info.code).await?;
                result.function_name = fn_info.function_name.clone();
                result.code = fn_info.code.clone();
                result.start_line = Some(fn_info.start_line);
                result.end_line = Some(fn_info.end_line);
                
                db.save_function(file_id, &result)?;
                if result.verdict == "vulnerable" {
                    total_vuln += 1;
                }
                all_functions.push(result);
            }
        }
    }

    Ok(AnalysisResult {
        analysis_id: analysis_id as i32,
        project_name,
        path: folder_path,
        files_scanned: cpp_files.len() as i32,
        total_functions: all_functions.len() as i32,
        vuln_count: total_vuln,
        functions: all_functions,
    })
}

#[tauri::command]
pub async fn get_history(state: tauri::State<'_, AppState>) -> Result<Vec<AnalysisSummary>, AppError> {
    let db = state.db.lock().await;
    db.get_all_analyses()
}

#[tauri::command]
pub async fn get_report(state: tauri::State<'_, AppState>, analysis_id: i32) -> Result<Report, AppError> {
    let db = state.db.lock().await;
    db.get_report(analysis_id)?.ok_or_else(|| AppError::Custom("Report not found".into()))
}

#[tauri::command]
pub async fn delete_analysis(state: tauri::State<'_, AppState>, analysis_id: i32) -> Result<(), AppError> {
    let db = state.db.lock().await;
    db.delete_analysis(analysis_id)
}

#[tauri::command]
pub async fn get_statistics(state: tauri::State<'_, AppState>) -> Result<StatisticsData, AppError> {
    let db = state.db.lock().await;
    db.get_statistics()
}

#[tauri::command]
pub async fn get_vuln_count(state: tauri::State<'_, AppState>) -> Result<Value, AppError> {
    let db = state.db.lock().await;
    let count = db.get_vuln_count()?;
    Ok(serde_json::json!({ "count": count }))
}

#[tauri::command]
pub fn extract_functions(file_path: String) -> Result<Value, AppError> {
    let functions = crate::parser::extract_functions(&file_path)
        .map_err(|e| AppError::Custom(format!("Failed to extract: {}", e)))?;
    let count = functions.len();
    Ok(serde_json::json!({
        "functions": functions,
        "count": count
    }))
}

#[tauri::command]
pub async fn check_api(state: tauri::State<'_, AppState>) -> Result<Value, AppError> {
    let url = crate::ml_api::load_kaggle_url(&state.app_data_dir);
    let reachable = crate::ml_api::check_api_health(&state.reqwest_client, &url).await;
    Ok(serde_json::json!({ "reachable": reachable }))
}

#[tauri::command]
pub async fn get_settings(state: tauri::State<'_, AppState>) -> Result<Value, AppError> {
    let url = crate::ml_api::load_kaggle_url(&state.app_data_dir);
    Ok(serde_json::json!({ "kaggle_url": url }))
}

#[tauri::command]
pub fn save_settings(state: tauri::State<'_, AppState>, kaggle_url: String) -> Result<Value, AppError> {
    crate::ml_api::save_kaggle_url(&state.app_data_dir, &kaggle_url)?;
    Ok(serde_json::json!({ "saved": true }))
}

#[tauri::command]
pub async fn generate_pdf(state: tauri::State<'_, AppState>, analysis_id: u32) -> Result<Value, AppError> {
    let db = state.db.lock().await;
    let report = db.get_report(analysis_id as i32)?.ok_or_else(|| AppError::Custom("Report not found".into()))?;
    let path = crate::report::generate_pdf(&report)?;
    Ok(serde_json::json!({ "path": path }))
}

#[tauri::command]
pub fn open_path(path: String) -> Result<(), AppError> {
    open::that(&path).map_err(|e| AppError::Custom(e.to_string()))
}

#[tauri::command]
pub async fn monitor_register(state: tauri::State<'_, AppState>, folder_path: String) -> Result<Value, AppError> {
    let db = state.db.lock().await;
    crate::monitor::register_project(&db, &folder_path)
}

#[tauri::command]
pub async fn monitor_list(state: tauri::State<'_, AppState>) -> Result<Vec<WatchedProject>, AppError> {
    let db = state.db.lock().await;
    db.get_watched_projects()
}

#[tauri::command]
pub async fn monitor_check(state: tauri::State<'_, AppState>, project_id: i32) -> Result<crate::monitor::MonitorChangeResult, AppError> {
    let db = state.db.lock().await;
    crate::monitor::check_changes(&db, project_id)
}

#[tauri::command]
pub async fn monitor_refresh(state: tauri::State<'_, AppState>, project_id: i32) -> Result<Value, AppError> {
    let db = state.db.lock().await;
    crate::monitor::refresh_hashes(&db, project_id)
}

#[tauri::command]
pub async fn monitor_remove(state: tauri::State<'_, AppState>, project_id: i32) -> Result<Value, AppError> {
    let db = state.db.lock().await;
    crate::monitor::unregister_project(&db, project_id)
}
