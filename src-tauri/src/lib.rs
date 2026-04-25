pub mod commands;
pub mod db;
pub mod error;
pub mod inference;
pub mod monitor;
pub mod parser;
pub mod report;
pub mod services;

use reqwest::Client;
use std::path::PathBuf;
use tauri::Manager;

pub struct AppState {
    pub pool: deadpool_sqlite::Pool,
    pub reqwest_client: Client,
    pub app_data_dir: PathBuf,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));

            // Check for old db path for one-time migration
            let old_db_path = std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|p| p.join("backend").join("ccure.db")));

            let pool = tauri::async_runtime::block_on(async {
                db::create_pool(&app_data_dir, old_db_path.as_deref()).await
            })
            .expect("Failed to initialize database pool");

            app.manage(AppState {
                pool,
                reqwest_client: Client::builder()
                    .danger_accept_invalid_certs(true) // For local Kaggle ngrok
                    .build()
                    .unwrap_or_default(),
                app_data_dir,
            });

            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::analyze_file,
            commands::analyze_folder,
            commands::get_history,
            commands::get_report,
            commands::get_statistics,
            commands::get_vuln_count,
            commands::extract_functions,
            commands::check_api,
            commands::monitor_register,
            commands::monitor_list,
            commands::monitor_check,
            commands::monitor_refresh,
            commands::monitor_remove,
            commands::delete_analysis,
            commands::get_settings,
            commands::save_settings,
            commands::generate_pdf,
            commands::open_path
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
