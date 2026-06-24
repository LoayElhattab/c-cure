use serde_json::Value;

use crate::db::{AnalysisListItem, AnalysisSummary, PagedFunctions, Report, StatisticsData};
use crate::error::AppError;
use crate::exports::pdf::ExportSettings;
use crate::inference::AnalysisResult;
use crate::AppState;
use std::env;
use std::path::PathBuf;
use tauri::{AppHandle, Emitter};

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
) -> Result<Vec<AnalysisListItem>, AppError> {
    crate::db::analysis_repo::get_all_analyses(&state.pool).await
}

#[tauri::command]
pub async fn get_analysis_summary(
    state: tauri::State<'_, AppState>,
    analysis_id: i32,
) -> Result<AnalysisSummary, AppError> {
    crate::db::analysis_repo::get_analysis_summary(&state.pool, analysis_id)
        .await?
        .ok_or_else(|| AppError::Custom("Analysis summary not found".into()))
}

#[tauri::command]
pub async fn get_report(
    state: tauri::State<'_, AppState>,
    analysis_id: i32,
) -> Result<Report, AppError> {
    crate::db::analysis_repo::get_report(&state.pool, analysis_id)
        .await?
        .ok_or_else(|| AppError::Custom("Report not found".into()))
}

#[tauri::command]
pub async fn delete_analysis(
    state: tauri::State<'_, AppState>,
    analysis_id: i32,
) -> Result<(), AppError> {
    crate::db::analysis_repo::delete_analysis(&state.pool, analysis_id).await
}

/// Returns the total number of functions for an analysis.
/// Call this once when opening a report to know how many pages exist.
#[tauri::command]
pub async fn get_functions_count(
    state: tauri::State<'_, AppState>,
    analysis_id: i32,
) -> Result<u64, AppError> {
    crate::db::analysis_repo::get_functions_count(&state.pool, analysis_id).await
}

/// Returns a paginated, flat list of functions for an analysis.
/// `limit`  – rows per page (default: 50 from the frontend).
/// `offset` – zero-based row offset ((page - 1) * limit).
#[tauri::command]
pub async fn get_functions_page(
    state: tauri::State<'_, AppState>,
    analysis_id: i32,
    limit: u32,
    offset: u32,
) -> Result<PagedFunctions, AppError> {
    crate::db::analysis_repo::get_functions_page(&state.pool, analysis_id, limit, offset).await
}

#[tauri::command]
pub async fn search_functions(
    state: tauri::State<'_, AppState>,
    analysis_id: i32,
    search_term: Option<String>,
    verdict_filter: Option<String>,
    sort_by: Option<String>,
    limit: u32,
    offset: u32,
) -> Result<PagedFunctions, AppError> {
    crate::db::analysis_repo::search_functions_page(
        &state.pool,
        analysis_id,
        search_term,
        verdict_filter,
        sort_by,
        limit,
        offset,
    )
    .await
}

#[tauri::command]
pub async fn get_statistics(state: tauri::State<'_, AppState>) -> Result<StatisticsData, AppError> {
    crate::db::stats_repo::get_statistics(&state.pool).await
}

#[tauri::command]
pub async fn get_analysis_file_ratios(
    state: tauri::State<'_, AppState>,
    analysis_id: i32,
) -> Result<Vec<crate::db::FileRatio>, AppError> {
    crate::db::stats_repo::get_file_ratios_for_analysis(&state.pool, analysis_id).await
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
    executive_summary_only: bool,
) -> Result<Value, AppError> {
    let report =
        crate::db::analysis_repo::get_vulnerability_report(&state.pool, analysis_id as i32)
            .await?
            .ok_or_else(|| AppError::Custom("Report not found".into()))?;
    let settings = ExportSettings {
        executive_summary_only,
        ..Default::default()
    };
    let report_id = report.id;
    let path = tauri::async_runtime::spawn_blocking(move || {
        let tier = if settings.executive_summary_only {
            "executive"
        } else {
            "technical"
        };
        let output = env::temp_dir().join(format!("c-cure-{tier}-report-{report_id}.pdf"));
        crate::exports::pdf::generate_pdf(&report, settings, &output, None::<fn(&str)>)
    })
    .await
    .map_err(|e| AppError::Custom(format!("PDF export worker failed: {e}")))?
    .map_err(|e| AppError::Custom(format!("PDF generation failed: {}", e)))?;
    Ok(serde_json::json!({ "path": path }))
}

#[tauri::command]
pub async fn export_report(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    analysis_id: i64,
    format: String,
    file_path: String,
    executive_summary_only: bool,
    max_findings: Option<usize>,
    include_source_code: Option<bool>,
) -> Result<Value, AppError> {
    match format.as_str() {
        "pdf_technical" | "pdf_executive" => {
            let _ = app.emit("export-progress", "Querying Database...");
            let report =
                crate::db::analysis_repo::get_vulnerability_report(&state.pool, analysis_id as i32)
                    .await?
                    .ok_or_else(|| AppError::Custom("Report not found".into()))?;

            let destination = PathBuf::from(&file_path);
            let settings = ExportSettings {
                executive_summary_only,
                max_findings,
                include_source_code,
            };
            let app_handle = app.clone();
            tauri::async_runtime::spawn_blocking(move || {
                crate::exports::pdf::generate_pdf(
                    &report,
                    settings,
                    &destination,
                    Some(|message: &str| {
                        let _ = app_handle.emit("export-progress", message);
                    }),
                )?;
                Ok::<(), AppError>(())
            })
            .await
            .map_err(|e| AppError::Custom(format!("PDF export worker failed: {e}")))??;
        }
        "sarif" => {
            crate::exports::sarif::export_sarif(&state.pool, analysis_id, file_path.clone())
                .await?;
        }
        "csv" => {
            crate::exports::csv::export_csv(&state.pool, analysis_id as i32, file_path.clone())
                .await?;
        }
        _ => {
            return Err(AppError::Custom(format!(
                "Unsupported export format: {format}"
            )))
        }
    }

    Ok(serde_json::json!({ "path": file_path, "format": format }))
}

#[tauri::command]
pub async fn export_sarif(
    state: tauri::State<'_, AppState>,
    analysis_id: i64,
    file_path: String,
) -> Result<(), AppError> {
    crate::exports::sarif::export_sarif(&state.pool, analysis_id, file_path).await
}

#[tauri::command]
pub async fn export_csv(
    state: tauri::State<'_, AppState>,
    analysis_id: i32,
    file_path: String,
) -> Result<(), AppError> {
    crate::exports::csv::export_csv(&state.pool, analysis_id, file_path).await
}

#[tauri::command]
pub async fn monitor_list(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<crate::db::WatchedProject>, AppError> {
    crate::db::projects_repo::get_watched_projects(&state.pool).await
}

#[tauri::command]
pub async fn start_monitoring(
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<Vec<String>, AppError> {
    crate::monitor_service::register_and_start(
        path,
        crate::monitor_service::WatcherContext {
            pool: state.pool.clone(),
            client: state.reqwest_client.clone(),
            app_data_dir: state.app_data_dir.clone(),
            app_handle,
        },
        state.watchers.clone(),
    )
    .await
}

#[tauri::command]
pub async fn stop_monitoring(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<Vec<String>, AppError> {
    crate::monitor_service::stop_and_unregister(path, &state.pool, state.watchers.clone()).await
}

#[tauri::command]
pub fn get_monitored_paths(state: tauri::State<'_, AppState>) -> Result<Vec<String>, AppError> {
    crate::monitor_service::list_active_paths(&state.watchers)
}
