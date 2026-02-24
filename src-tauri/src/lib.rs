use std::path::PathBuf;
use std::process::Command;

fn backend_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let mut path = exe.parent().unwrap().to_path_buf();
    for _ in 0..5 {
        if path.join("backend").exists() {
            return path.join("backend");
        }
        match path.parent() {
            Some(p) => path = p.to_path_buf(),
            None => break,
        }
    }
    std::env::current_dir().unwrap().join("backend")
}

fn run_python(args: Vec<&str>) -> Result<String, String> {
    let backend = backend_path();
    let output = Command::new("python")
        .args(&args)
        .current_dir(&backend)
        .output()
        .map_err(|e| format!("Failed to launch Python: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

#[tauri::command]
fn analyze_file(file_path: String) -> Result<String, String> {
    run_python(vec!["main.py", "analyze", &file_path])
}

#[tauri::command]
fn analyze_folder(folder_path: String) -> Result<String, String> {
    run_python(vec!["main.py", "analyze_folder", &folder_path])
}

#[tauri::command]
fn get_history() -> Result<String, String> {
    run_python(vec!["main.py", "history"])
}

#[tauri::command]
fn get_report(analysis_id: i32) -> Result<String, String> {
    let id = analysis_id.to_string();
    run_python(vec!["main.py", "report", &id])
}

#[tauri::command]
fn get_dashboard() -> Result<String, String> {
    run_python(vec!["main.py", "dashboard"])
}

#[tauri::command]
fn get_trend_data() -> Result<String, String> {
    run_python(vec!["main.py", "get_trend_data"])
}

/// Replaces get_dashboard + get_trend_data — one Python spawn instead of two
#[tauri::command]
fn get_statistics() -> Result<String, String> {
    run_python(vec!["main.py", "statistics"])
}

/// Lightweight badge query — single COUNT(*), no JOINs
#[tauri::command]
fn get_vuln_count() -> Result<String, String> {
    run_python(vec!["main.py", "vuln_count"])
}

#[tauri::command]
fn extract_functions(file_path: String) -> Result<String, String> {
    run_python(vec!["main.py", "extract_functions", &file_path])
}

#[tauri::command]
fn check_api() -> Result<String, String> {
    run_python(vec!["main.py", "check_api"])
}

#[tauri::command]
fn monitor_register(folder_path: String) -> Result<String, String> {
    run_python(vec!["monitor.py", "register", &folder_path])
}

#[tauri::command]
fn monitor_list() -> Result<String, String> {
    run_python(vec!["monitor.py", "list"])
}

#[tauri::command]
fn monitor_check(project_id: i32) -> Result<String, String> {
    let id = project_id.to_string();
    run_python(vec!["monitor.py", "check", &id])
}

#[tauri::command]
fn monitor_refresh(project_id: i32) -> Result<String, String> {
    let id = project_id.to_string();
    run_python(vec!["monitor.py", "refresh", &id])
}

#[tauri::command]
fn monitor_remove(project_id: i32) -> Result<String, String> {
    let id = project_id.to_string();
    run_python(vec!["monitor.py", "remove", &id])
}

#[tauri::command]
fn delete_analysis(analysis_id: i32) -> Result<String, String> {
    let id = analysis_id.to_string();
    run_python(vec!["main.py", "delete_analysis", &id])
}

#[tauri::command]
fn get_settings() -> Result<String, String> {
    run_python(vec!["main.py", "get_settings"])
}

#[tauri::command]
fn save_settings(kaggle_url: String) -> Result<String, String> {
    run_python(vec!["main.py", "save_settings", &kaggle_url])
}

#[tauri::command]
fn generate_pdf(analysis_id: u32) -> Result<String, String> {
    run_python(vec!["main.py", "generate_pdf", &analysis_id.to_string()])
}

#[tauri::command]
fn open_path(path: String) -> Result<(), String> {
    open::that(&path).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            analyze_file,
            analyze_folder,
            get_history,
            get_report,
            get_dashboard,
            get_trend_data,
            get_statistics,
            get_vuln_count,
            extract_functions,
            check_api,
            monitor_register,
            monitor_list,
            monitor_check,
            monitor_refresh,
            monitor_remove,
            delete_analysis,
            get_settings,
            save_settings,
            generate_pdf,
            open_path
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application")
}
