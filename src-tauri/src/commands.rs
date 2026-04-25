use serde_json::Value;

use crate::db::{AnalysisSummary, Report, StatisticsData, WatchedProject};
use crate::error::AppError;
use crate::inference::AnalysisResult;
use crate::AppState;

#[tauri::command]
pub async fn analyze_file(
    state: tauri::State<'_, AppState>,
    file_path: String,
) -> Result<AnalysisResult, AppError> {
    let url = crate::inference::load_kaggle_url(&state.app_data_dir);
    
    let result = crate::services::analysis_service::analyze_file_service(
        &state.pool,
        state.reqwest_client.clone(),
        url,
        file_path,
    )
    .await?;

    Ok(result)
}

#[tauri::command]
pub async fn analyze_folder(
    state: tauri::State<'_, AppState>,
    folder_path: String,
) -> Result<AnalysisResult, AppError> {
    let url = crate::inference::load_kaggle_url(&state.app_data_dir);

    let result = crate::services::analysis_service::analyze_folder_service(
        &state.pool,
        state.reqwest_client.clone(),
        url,
        folder_path,
    )
    .await?;

    Ok(result)
}

#[tauri::command]
pub async fn get_history(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<AnalysisSummary>, AppError> {
    crate::db::analysis_repo::get_all_analyses(&state.pool).await
}

#[tauri::command]
pub async fn get_report(
    state: tauri::State<'_, AppState>,
    analysis_id: i32,
) -> Result<Report, AppError> {
    crate::db::analysis_repo::get_report(&state.pool, analysis_id).await?
        .ok_or_else(|| AppError::Custom("Report not found".into()))
}

#[tauri::command]
pub async fn delete_analysis(
    state: tauri::State<'_, AppState>,
    analysis_id: i32,
) -> Result<(), AppError> {
    crate::db::analysis_repo::delete_analysis(&state.pool, analysis_id).await
}

#[tauri::command]
pub async fn get_statistics(state: tauri::State<'_, AppState>) -> Result<StatisticsData, AppError> {
    crate::db::stats_repo::get_statistics(&state.pool).await
}

#[tauri::command]
pub async fn get_vuln_count(state: tauri::State<'_, AppState>) -> Result<Value, AppError> {
    let count = crate::db::stats_repo::get_vuln_count(&state.pool).await?;
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
    let url = crate::inference::load_kaggle_url(&state.app_data_dir);
    let provider = crate::inference::get_provider(state.reqwest_client.clone(), url);
    let reachable = provider.check_health().await;
    Ok(serde_json::json!({ "reachable": reachable }))
}

#[tauri::command]
pub async fn get_settings(state: tauri::State<'_, AppState>) -> Result<Value, AppError> {
    let url = crate::inference::load_kaggle_url(&state.app_data_dir);
    Ok(serde_json::json!({ "kaggle_url": url }))
}

#[tauri::command]
pub fn save_settings(
    state: tauri::State<'_, AppState>,
    kaggle_url: String,
) -> Result<Value, AppError> {
    crate::inference::save_kaggle_url(&state.app_data_dir, &kaggle_url)
        .map_err(|e| AppError::Custom(format!("Failed to save settings: {}", e)))?;
    Ok(serde_json::json!({ "saved": true }))
}

#[tauri::command]
pub async fn generate_pdf(
    state: tauri::State<'_, AppState>,
    analysis_id: u32,
) -> Result<Value, AppError> {
    let report = crate::db::analysis_repo::get_report(&state.pool, analysis_id as i32).await?
        .ok_or_else(|| AppError::Custom("Report not found".into()))?;
    let path = crate::report::generate_pdf(&report)
        .map_err(|e| AppError::Custom(format!("PDF generation failed: {}", e)))?;
    Ok(serde_json::json!({ "path": path }))
}

#[tauri::command]
pub fn open_path(path: String) -> Result<(), AppError> {
    open::that(&path).map_err(|e| AppError::Custom(e.to_string()))
}

// Consider moving these to a monitor_service in the future if they grow in complexity
#[tauri::command]
pub async fn monitor_register(
    state: tauri::State<'_, AppState>,
    folder_path: String,
) -> Result<Value, AppError> {
    crate::monitor::register_project(&state.pool, &folder_path).await
}

#[tauri::command]
pub async fn monitor_list(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<WatchedProject>, AppError> {
    crate::db::projects_repo::get_watched_projects(&state.pool).await
}

#[tauri::command]
pub async fn monitor_check(
    state: tauri::State<'_, AppState>,
    project_id: i32,
) -> Result<crate::monitor::MonitorChangeResult, AppError> {
    crate::monitor::check_changes(&state.pool, project_id).await
}

#[tauri::command]
pub async fn monitor_refresh(
    state: tauri::State<'_, AppState>,
    project_id: i32,
) -> Result<Value, AppError> {
    crate::monitor::refresh_hashes(&state.pool, project_id).await
}

#[tauri::command]
pub async fn monitor_remove(
    state: tauri::State<'_, AppState>,
    project_id: i32,
) -> Result<Value, AppError> {
    crate::monitor::unregister_project(&state.pool, project_id).await
}
