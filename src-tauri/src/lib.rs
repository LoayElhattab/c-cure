pub mod commands;
pub mod db;
pub mod error;
pub mod exports;
pub mod inference;

pub mod monitor_service;
pub mod parser;
pub mod services;

use reqwest::Client;
use std::path::PathBuf;
use tauri::Manager;

pub struct AppState {
    pub pool: db::DbPool,
    pub reqwest_client: Client,
    pub app_data_dir: PathBuf,
    pub watchers: monitor_service::WatcherRegistry,
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

            let reqwest_client = Client::builder()
                .danger_accept_invalid_certs(true) // For local Kaggle ngrok
                .build()
                .unwrap_or_default();
            let watchers = monitor_service::new_registry();

            let app_handle = app.handle().clone();
            tauri::async_runtime::block_on(async {
                if let Err(err) = monitor_service::restore_watchers(
                    monitor_service::WatcherContext {
                        pool: pool.clone(),
                        client: reqwest_client.clone(),
                        app_data_dir: app_data_dir.clone(),
                        app_handle,
                    },
                    watchers.clone(),
                )
                .await
                {
                    eprintln!("Failed to restore file watchers on startup: {err}");
                }
            });

            app.manage(AppState {
                pool,
                reqwest_client,
                app_data_dir,
                watchers,
            });

            Ok(())
        })
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::analyze_file,
            commands::analyze_folder,
            commands::get_history,
            commands::get_analysis_summary,
            commands::get_report,
            commands::get_functions_count,
            commands::get_functions_page,
            commands::search_functions,
            commands::get_statistics,
            commands::get_analysis_file_ratios,
            commands::extract_functions,
            commands::check_api,
            commands::monitor_list,
            commands::start_monitoring,
            commands::stop_monitoring,
            commands::get_monitored_paths,
            commands::delete_analysis,
            commands::get_settings,
            commands::save_settings,
            commands::export_report,
            commands::generate_pdf,
            commands::export_sarif,
            commands::export_csv
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
