pub mod analysis_repo;
pub mod projects_repo;
pub mod stats_repo;

use deadpool_sqlite::{Config, Pool, Runtime};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::error::AppError;

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisSummary {
    pub id: i32,
    pub project_name: String,
    pub project_path: Option<String>,
    pub timestamp: String,
    pub total_functions: i32,
    pub vuln_count: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Report {
    pub id: i32,
    pub project_name: String,
    pub project_path: Option<String>,
    pub timestamp: String,
    pub files: Vec<FileData>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileData {
    pub file_path: String,
    pub functions: Vec<FunctionData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionData {
    #[serde(skip_deserializing)]
    pub id: Option<i32>,
    #[serde(alias = "name")]
    pub function_name: String,
    pub code: String,
    pub verdict: String,
    pub cwe: Option<String>,
    pub cwe_name: Option<String>,
    pub severity: Option<String>,
    pub confidence: Option<f64>,
    pub start_line: Option<i32>,
    pub end_line: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DashboardStats {
    pub kpis: Kpis,
    pub cwe_counts: Vec<CweCount>,
    pub severity_counts: Vec<SeverityCount>,
    pub file_ratios: Vec<FileRatio>,
    pub recent_analyses: Vec<AnalysisSummary>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TrendData {
    pub timestamp: String,
    pub vuln_count: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatisticsData {
    pub dashboard: DashboardStats,
    pub trend: Vec<TrendData>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Kpis {
    pub total_analyses: i32,
    pub total_files: i32,
    pub total_functions: i32,
    pub total_vulnerable: i32,
    pub total_safe: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CweCount {
    pub cwe: String,
    pub cwe_name: Option<String>,
    pub severity: Option<String>,
    pub count: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileRatio {
    pub label: String,
    pub safe: i32,
    pub vuln: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WatchedProject {
    pub id: i32,
    pub name: String,
    pub folder_path: String,
    pub registered_at: String,
}

pub async fn create_pool(app_data_dir: &Path, old_db_path: Option<&Path>) -> Result<Pool, AppError> {
    if !app_data_dir.exists() {
        fs::create_dir_all(app_data_dir)?;
    }

    let db_path = app_data_dir.join("ccure.db");

    if !db_path.exists() {
        if let Some(old_path) = old_db_path {
            if old_path.exists() {
                let _ = fs::copy(old_path, &db_path);
            }
        }
    }

    let cfg = Config::new(&db_path);
    let pool = cfg.create_pool(Runtime::Tokio1).map_err(|e| AppError::Custom(e.to_string()))?;

    init_db(&pool).await?;

    Ok(pool)
}

pub async fn init_db(pool: &Pool) -> Result<(), AppError> {
    pool.get().await?.interact(|conn| {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS analyses (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
                project_name TEXT NOT NULL,
                project_path TEXT
            );
            CREATE TABLE IF NOT EXISTS files (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                file_path   TEXT NOT NULL,
                FOREIGN KEY(analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS functions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id       INTEGER NOT NULL,
                function_name TEXT NOT NULL,
                code          TEXT NOT NULL,
                verdict       TEXT NOT NULL,
                cwe           TEXT,
                cwe_name      TEXT,
                severity      TEXT,
                confidence    REAL,
                start_line    INTEGER,
                end_line      INTEGER,
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS watched_projects (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                folder_path   TEXT NOT NULL UNIQUE,
                registered_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS file_hashes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                file_path  TEXT NOT NULL,
                file_hash  TEXT NOT NULL,
                hashed_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_id, file_path),
                FOREIGN KEY(project_id) REFERENCES watched_projects(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_files_analysis_id ON files(analysis_id);
            CREATE INDEX IF NOT EXISTS idx_functions_file_id ON functions(file_id);
            CREATE INDEX IF NOT EXISTS idx_functions_verdict ON functions(verdict);
            CREATE INDEX IF NOT EXISTS idx_functions_file_verdict ON functions(file_id, verdict);
            CREATE INDEX IF NOT EXISTS idx_file_hashes_project ON file_hashes(project_id);",
        )?;
        Ok::<_, rusqlite::Error>(())
    }).await??;
    Ok(())
}
