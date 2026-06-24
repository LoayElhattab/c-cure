use crate::db::DbPool;
use crate::error::AppError;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use reqwest::Client;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::Emitter;
use tauri_plugin_notification::NotificationExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const DEBOUNCE_WINDOW: Duration = Duration::from_millis(500);

pub type WatcherRegistry = Arc<Mutex<HashMap<String, WatchHandle>>>;

pub struct WatchHandle {
    _watcher: RecommendedWatcher,
    debounce_task: JoinHandle<()>,
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.debounce_task.abort();
    }
}

#[derive(Clone)]
pub struct WatcherContext {
    pub pool: DbPool,
    pub client: Client,
    pub app_data_dir: PathBuf,
    pub app_handle: tauri::AppHandle,
}

pub fn new_registry() -> WatcherRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

fn normalize_directory_path(path: &str) -> Result<String, AppError> {
    let directory = PathBuf::from(path);

    if !directory.exists() {
        return Err(AppError::Custom(format!("Folder not found: {path}")));
    }

    if !directory.is_dir() {
        return Err(AppError::Custom(format!("Path is not a folder: {path}")));
    }

    Ok(directory.to_string_lossy().to_string())
}

fn project_name_for_path(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

pub(crate) fn is_supported_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "c" | "cpp" | "h" | "hpp" | "cc" | "cxx"
            )
        })
        .unwrap_or(false)
}

fn should_process_event(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Any
    )
}

fn source_paths_from_event(event: Event) -> Vec<PathBuf> {
    if !should_process_event(&event) {
        return Vec::new();
    }

    event
        .paths
        .into_iter()
        .filter(|path| path.is_file() && is_supported_source_file(path))
        .collect()
}

/// Severity levels we care about for alerting (Critical > High only).
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
enum AlertSeverity {
    High,
    Critical,
}

/// Returns the `AlertSeverity` for a known CWE string, or `None` for Low/Medium.
fn cwe_alert_severity(cwe: &str) -> Option<AlertSeverity> {
    match cwe {
        "CWE-787" | "CWE-89" => Some(AlertSeverity::Critical),
        "CWE-125" | "CWE-415" | "CWE-476" => Some(AlertSeverity::High),
        _ => None,
    }
}

/// Fires a native OS notification if any result is Critical or High severity.
/// The call is non-blocking; any OS permission error is logged and ignored.
fn send_severity_alert(
    app_handle: &tauri::AppHandle,
    file_path_str: &str,
    results: &[crate::db::FunctionData],
) {
    // Collect only vulnerable functions with a CWE that maps to Critical/High.
    let mut alerts: Vec<(AlertSeverity, &str, &str)> = results
        .iter()
        .filter(|f| f.verdict == "vulnerable")
        .filter_map(|f| {
            let cwe = f.cwe.as_deref()?;
            let severity = cwe_alert_severity(cwe)?;
            let cwe_name = f.cwe_name.as_deref().unwrap_or("Unknown");
            Some((severity, cwe, cwe_name))
        })
        .collect();

    if alerts.is_empty() {
        return;
    }

    // Sort descending so the worst offender is first.
    alerts.sort_by(|a, b| b.0.cmp(&a.0));

    let filename = std::path::Path::new(file_path_str)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| file_path_str.to_string());

    let body = if alerts.len() == 1 {
        let (sev, cwe, cwe_name) = alerts[0];
        let sev_label = if sev == AlertSeverity::Critical {
            "Critical"
        } else {
            "High"
        };
        format!("{sev_label} {cwe_name} ({cwe}) detected in {filename}")
    } else {
        let (top_sev, top_cwe, top_cwe_name) = alerts[0];
        let sev_label = if top_sev == AlertSeverity::Critical {
            "Critical"
        } else {
            "High"
        };
        format!(
            "{} vulnerabilities detected in {filename} — worst: {sev_label} {top_cwe_name} ({top_cwe})",
            alerts.len()
        )
    };

    if let Err(err) = app_handle
        .notification()
        .builder()
        .title("C-Cure Alert: Vulnerability Found")
        .body(&body)
        .show()
    {
        eprintln!("Failed to send OS notification: {err}");
    }
}

async fn analyze_changed_file(context: WatcherContext, file_path: PathBuf, folder_path: String) {
    let file_path_str = file_path.to_string_lossy().to_string();

    // 1. Determine the project_id for the monitored directory.
    let project_id =
        match crate::db::projects_repo::get_project_id_by_path(&context.pool, folder_path.clone())
            .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                eprintln!("Failed to find project ID for watched directory: {folder_path}");
                return;
            }
            Err(err) => {
                eprintln!(
                    "Failed query for project ID for watched directory: {folder_path}: {err}"
                );
                return;
            }
        };

    // 2. Read the file and compute the new u64 content hash.
    let content = match tokio::fs::read_to_string(&file_path).await {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Failed to read file for hashing {file_path_str}: {err}");
            return;
        }
    };

    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    let new_hash = hasher.finish();

    // 3. Query the database using get_file_hash to retrieve the persisted hash.
    let existing_hash = match crate::db::projects_repo::get_file_hash(
        &context.pool,
        project_id,
        file_path_str.clone(),
    )
    .await
    {
        Ok(hash) => hash,
        Err(err) => {
            eprintln!("Failed to retrieve file hash from database: {err}");
            None
        }
    };

    // 4. If they match: The content hasn't changed. Abort the scan silently.
    if let Some(h) = existing_hash {
        if h == new_hash {
            return;
        }
    }

    // 5. If they differ (or no hash exists in DB):
    // - Call upsert_file_hash to save the new hash permanently to DuckDB.
    if let Err(err) = crate::db::projects_repo::upsert_file_hash(
        &context.pool,
        project_id,
        file_path_str.clone(),
        new_hash,
    )
    .await
    {
        eprintln!("Failed to upsert file hash into database: {err}");
    }

    let url = crate::inference::load_kaggle_url(&context.app_data_dir);

    // Emit scan start event
    let _ = context.app_handle.emit(
        "monitor-scan-start",
        serde_json::json!({
            "path": file_path_str
        }),
    );

    match crate::services::analysis_service::analyze_file_service(
        &context.pool,
        context.client,
        url,
        file_path_str.clone(),
    )
    .await
    {
        Ok(result) => {
            // Fire a native OS notification for Critical / High findings.
            send_severity_alert(&context.app_handle, &file_path_str, &result.functions);

            // Emit scan success event
            let _ = context.app_handle.emit(
                "monitor-scan-success",
                serde_json::json!({
                    "path": file_path_str,
                    "analysis_id": result.analysis_id,
                    "vuln_count": result.vuln_count,
                    "total_functions": result.total_functions
                }),
            );
        }
        Err(err) => {
            let err_str = err.to_string();
            eprintln!("Automated monitoring failed for {file_path_str}: {err_str}");
            // Emit scan error event
            let _ = context.app_handle.emit(
                "monitor-scan-error",
                serde_json::json!({
                    "path": file_path_str,
                    "error": err_str
                }),
            );
        }
    }
}

async fn debounce_events(
    mut rx: mpsc::UnboundedReceiver<PathBuf>,
    context: WatcherContext,
    folder_path: String,
) {
    let mut pending_tasks: HashMap<PathBuf, JoinHandle<()>> = HashMap::new();

    while let Some(path) = rx.recv().await {
        if let Some(task) = pending_tasks.remove(&path) {
            task.abort();
        }

        let context = context.clone();
        let task_path = path.clone();
        let folder_path_clone = folder_path.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(DEBOUNCE_WINDOW).await;
            analyze_changed_file(context, task_path, folder_path_clone).await;
        });

        pending_tasks.insert(path, task);
        pending_tasks.retain(|_, task| !task.is_finished());
    }
}

pub fn start_watcher(
    directory_path: String,
    context: WatcherContext,
    registry: &WatcherRegistry,
) -> Result<(), AppError> {
    let normalized_path = normalize_directory_path(&directory_path)?;

    {
        let registry = registry
            .lock()
            .map_err(|_| AppError::Custom("Watcher registry lock poisoned".to_string()))?;
        if registry.contains_key(&normalized_path) {
            return Ok(());
        }
    }

    let (tx, rx) = mpsc::unbounded_channel();
    let watcher_tx = tx.clone();
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        let Ok(event) = result else {
            if let Err(err) = result {
                eprintln!("File watcher event error: {err}");
            }
            return;
        };

        for path in source_paths_from_event(event) {
            let _ = watcher_tx.send(path);
        }
    })
    .map_err(|err| AppError::Custom(format!("Failed to create file watcher: {err}")))?;

    watcher
        .watch(Path::new(&normalized_path), RecursiveMode::Recursive)
        .map_err(|err| AppError::Custom(format!("Failed to watch folder: {err}")))?;

    let debounce_task = tokio::spawn(debounce_events(rx, context, normalized_path.clone()));
    let handle = WatchHandle {
        _watcher: watcher,
        debounce_task,
    };

    let mut registry = registry
        .lock()
        .map_err(|_| AppError::Custom("Watcher registry lock poisoned".to_string()))?;
    registry.insert(normalized_path, handle);

    Ok(())
}

pub fn stop_watcher(directory_path: &str, registry: &WatcherRegistry) -> Result<bool, AppError> {
    let normalized_path = normalize_directory_path(directory_path)
        .unwrap_or_else(|_| PathBuf::from(directory_path).to_string_lossy().to_string());
    let mut registry = registry
        .lock()
        .map_err(|_| AppError::Custom("Watcher registry lock poisoned".to_string()))?;

    Ok(registry.remove(&normalized_path).is_some())
}

pub fn list_active_paths(registry: &WatcherRegistry) -> Result<Vec<String>, AppError> {
    let registry = registry
        .lock()
        .map_err(|_| AppError::Custom("Watcher registry lock poisoned".to_string()))?;
    let mut paths: Vec<String> = registry.keys().cloned().collect();
    paths.sort();
    Ok(paths)
}

pub async fn register_and_start(
    directory_path: String,
    context: WatcherContext,
    registry: WatcherRegistry,
) -> Result<Vec<String>, AppError> {
    let normalized_path = normalize_directory_path(&directory_path)?;
    let project_name = project_name_for_path(Path::new(&normalized_path));

    crate::db::projects_repo::upsert_watched_project(
        &context.pool,
        project_name,
        normalized_path.clone(),
    )
    .await?;

    if let Err(err) = start_watcher(normalized_path.clone(), context.clone(), &registry) {
        crate::db::projects_repo::remove_watched_project_by_path(&context.pool, normalized_path)
            .await?;
        return Err(err);
    }

    list_active_paths(&registry)
}

pub async fn stop_and_unregister(
    directory_path: String,
    pool: &DbPool,
    registry: WatcherRegistry,
) -> Result<Vec<String>, AppError> {
    let normalized_path = normalize_directory_path(&directory_path)
        .unwrap_or_else(|_| PathBuf::from(&directory_path).to_string_lossy().to_string());
    let _ = stop_watcher(&normalized_path, &registry)?;
    crate::db::projects_repo::remove_watched_project_by_path(pool, normalized_path).await?;
    list_active_paths(&registry)
}

pub async fn restore_watchers(
    context: WatcherContext,
    registry: WatcherRegistry,
) -> Result<(), AppError> {
    let watched_projects = crate::db::projects_repo::get_watched_projects(&context.pool).await?;

    for project in watched_projects {
        if let Err(err) = start_watcher(project.folder_path.clone(), context.clone(), &registry) {
            eprintln!(
                "Failed to restore watcher for {}: {}",
                project.folder_path, err
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn source_filter_accepts_only_c_cpp_and_header_files() {
        assert!(super::is_supported_source_file(Path::new("main.c")));
        assert!(super::is_supported_source_file(Path::new("main.cpp")));
        assert!(super::is_supported_source_file(Path::new("main.h")));

        assert!(super::is_supported_source_file(Path::new("main.cc")));
        assert!(super::is_supported_source_file(Path::new("main.cxx")));
        assert!(!super::is_supported_source_file(Path::new("notes.txt")));
        assert!(!super::is_supported_source_file(Path::new("Makefile")));
    }

    #[test]
    fn source_filter_is_case_insensitive() {
        assert!(super::is_supported_source_file(Path::new("WINDOWS.CPP")));
        assert!(super::is_supported_source_file(Path::new("HEADER.H")));
    }
}
