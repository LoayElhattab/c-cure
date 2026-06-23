pub mod analysis_repo;
pub mod projects_repo;
pub mod stats_repo;

use async_duckdb::ClientBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::AppError;

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const MIGRATION_MARKER: &str = ".duckdb_migrated";

#[derive(Clone)]
pub struct DbPool(async_duckdb::Client);

impl DbPool {
    pub async fn with_conn<F, T>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&duckdb::Connection) -> Result<T, duckdb::Error> + Send + 'static,
        T: Send + 'static,
    {
        Ok(self.0.conn(f).await?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisListItem {
    pub id: i32,
    pub project_name: String,
    pub project_path: Option<String>,
    pub timestamp: String,
    pub total_functions: i32,
    pub vuln_count: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisSummary {
    pub id: i32,
    pub project_name: String,
    pub project_path: Option<String>,
    pub timestamp: String,
    pub total_files: u32,
    pub total_functions: u32,
    pub vulnerable_functions: u32,
    pub clean_functions: u32,
    pub severity_breakdown: HashMap<String, u32>,
    pub top_vulnerabilities: Vec<CweHit>,
    pub most_critical_findings: Vec<FunctionRow>,
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
pub struct VulnerabilityReport {
    pub id: i32,
    pub project_name: String,
    pub project_path: Option<String>,
    pub timestamp: String,
    pub total_files: u32,
    pub total_functions: u32,
    pub vulnerable_functions: u32,
    pub clean_functions: u32,
    pub severity_breakdown: HashMap<String, u32>,
    pub top_vulnerabilities: Vec<CweHit>,
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
    pub asvs_id: Option<String>,
    pub severity: Option<String>,
    pub confidence: Option<f64>,
    pub start_line: Option<i32>,
    pub end_line: Option<i32>,
}

/// A flat function row that also carries its parent `file_path`.
/// Used by the paginated endpoint so the frontend never needs a second query.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionRow {
    pub id: Option<i32>,
    pub function_name: String,
    pub code: String,
    pub verdict: String,
    pub cwe: Option<String>,
    pub cwe_name: Option<String>,
    pub asvs_id: Option<String>,
    pub severity: Option<String>,
    pub confidence: Option<f64>,
    pub start_line: Option<i32>,
    pub end_line: Option<i32>,
    /// Absolute path of the file this function belongs to.
    pub file_path: String,
}

/// Envelope returned by the paginated functions endpoint.
#[derive(Serialize, Deserialize, Debug)]
pub struct PagedFunctions {
    /// Total number of functions for this analysis (for page-count math).
    pub total: u64,
    /// The `limit` that was used for this query.
    pub limit: u32,
    /// The `offset` that was used for this query.
    pub offset: u32,
    pub functions: Vec<FunctionRow>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DashboardStats {
    pub kpis: Kpis,
    pub cwe_counts: Vec<CweCount>,
    pub severity_counts: Vec<SeverityCount>,
    pub file_ratios: Vec<FileRatio>,
    pub recent_analyses: Vec<AnalysisListItem>,
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
pub struct CweHit {
    pub cwe: String,
    pub cwe_name: Option<String>,
    pub asvs_id: Option<String>,
    pub severity: Option<String>,
    pub count: u32,
}

pub fn compliance_for_cwe(cwe: &str) -> Option<&'static str> {
    match cwe {
        "CWE-125" => Some("ASVS 4.0.3 V5.4.1"),
        "CWE-787" => Some("ASVS 4.0.3 V5.4.1"),
        "CWE-190" => Some("ASVS 4.0.3 V5.4.3"),
        "CWE-369" => Some("ASVS 4.0.3 V5.1.4"),
        "CWE-415" => Some("ASVS 4.0.3 V5.4.1"),
        "CWE-476" => Some("ASVS 4.0.3 V5.4.1"),
        "CWE-79" => Some("ASVS 4.0.3 V5.3.3"),
        "CWE-89" => Some("ASVS 4.0.3 V5.3.4"),
        _ => None,
    }
}

pub fn asvs_id_for_cwe(cwe: Option<&str>) -> Option<String> {
    cwe.and_then(compliance_for_cwe).map(str::to_string)
}

impl FunctionData {
    pub fn with_compliance(mut self) -> Self {
        self.asvs_id = asvs_id_for_cwe(self.cwe.as_deref());
        self
    }
}

impl FunctionRow {
    pub fn with_compliance(mut self) -> Self {
        self.asvs_id = asvs_id_for_cwe(self.cwe.as_deref());
        self
    }
}

impl CweHit {
    pub fn with_compliance(mut self) -> Self {
        self.asvs_id = asvs_id_for_cwe(Some(self.cwe.as_str()));
        self
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WatchedProject {
    pub id: i32,
    pub name: String,
    pub folder_path: String,
    pub registered_at: String,
}

fn is_sqlite_file(path: &Path) -> std::io::Result<bool> {
    let mut file = fs::File::open(path)?;
    let mut header = [0u8; 16];
    let n = file.read(&mut header)?;
    Ok(n >= SQLITE_MAGIC.len() && header.starts_with(SQLITE_MAGIC))
}

fn migration_marker_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(MIGRATION_MARKER)
}

fn init_db_on_conn(conn: &duckdb::Connection) -> Result<(), duckdb::Error> {
    conn.execute_batch(
        "
        CREATE SEQUENCE IF NOT EXISTS seq_analyses START 1;
        CREATE SEQUENCE IF NOT EXISTS seq_files START 1;
        CREATE SEQUENCE IF NOT EXISTS seq_functions START 1;
        CREATE SEQUENCE IF NOT EXISTS seq_watched_projects START 1;
        CREATE SEQUENCE IF NOT EXISTS seq_file_hashes START 1;

        CREATE TABLE IF NOT EXISTS analyses (
            id           INTEGER PRIMARY KEY DEFAULT nextval('seq_analyses'),
            timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            project_name VARCHAR NOT NULL,
            project_path VARCHAR
        );
        CREATE TABLE IF NOT EXISTS files (
            id          INTEGER PRIMARY KEY DEFAULT nextval('seq_files'),
            analysis_id INTEGER NOT NULL,
            file_path   VARCHAR NOT NULL,
            FOREIGN KEY(analysis_id) REFERENCES analyses(id)
        );
        CREATE TABLE IF NOT EXISTS functions (
            id            INTEGER PRIMARY KEY DEFAULT nextval('seq_functions'),
            file_id       INTEGER NOT NULL,
            function_name VARCHAR NOT NULL,
            code          VARCHAR NOT NULL,
            verdict       VARCHAR NOT NULL,
            cwe           VARCHAR,
            cwe_name      VARCHAR,
            severity      VARCHAR,
            confidence    DOUBLE,
            start_line    INTEGER,
            end_line      INTEGER,
            FOREIGN KEY(file_id) REFERENCES files(id)
        );
        CREATE TABLE IF NOT EXISTS watched_projects (
            id            INTEGER PRIMARY KEY DEFAULT nextval('seq_watched_projects'),
            name          VARCHAR NOT NULL,
            folder_path   VARCHAR NOT NULL UNIQUE,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS file_hashes (
            id         INTEGER PRIMARY KEY DEFAULT nextval('seq_file_hashes'),
            project_id INTEGER NOT NULL,
            file_path  VARCHAR NOT NULL,
            file_hash  VARCHAR NOT NULL,
            hashed_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(project_id, file_path),
            FOREIGN KEY(project_id) REFERENCES watched_projects(id)
        );

        CREATE INDEX IF NOT EXISTS idx_files_analysis_id ON files(analysis_id);
        CREATE INDEX IF NOT EXISTS idx_functions_file_id ON functions(file_id);
        CREATE INDEX IF NOT EXISTS idx_functions_verdict ON functions(verdict);
        CREATE INDEX IF NOT EXISTS idx_functions_file_verdict ON functions(file_id, verdict);
        CREATE INDEX IF NOT EXISTS idx_file_hashes_project ON file_hashes(project_id);
        ",
    )?;
    Ok(())
}

fn reset_sequences(conn: &duckdb::Connection) -> Result<(), duckdb::Error> {
    for (seq, table) in [
        ("seq_analyses", "analyses"),
        ("seq_files", "files"),
        ("seq_functions", "functions"),
        ("seq_watched_projects", "watched_projects"),
        ("seq_file_hashes", "file_hashes"),
    ] {
        let sql = format!("SELECT setval('{seq}', COALESCE((SELECT MAX(id) FROM {table}), 0))");
        conn.execute_batch(&sql)?;
    }
    Ok(())
}

/// Import legacy SQLite data via DuckDB's sqlite extension.
/// First run may require network access to `INSTALL sqlite`.
fn migrate_from_sqlite(conn: &duckdb::Connection, sqlite_path: &Path) -> Result<(), duckdb::Error> {
    let path_str = sqlite_path.to_string_lossy().replace('\\', "/");
    let attach_sql = format!("ATTACH '{path_str}' AS legacy (TYPE SQLITE);");

    conn.execute_batch("INSTALL sqlite; LOAD sqlite;")?;
    conn.execute_batch(&attach_sql)?;
    conn.execute_batch(
        "
        INSERT INTO analyses SELECT * FROM legacy.analyses;
        INSERT INTO files SELECT * FROM legacy.files;
        INSERT INTO functions SELECT * FROM legacy.functions;
        INSERT INTO watched_projects SELECT * FROM legacy.watched_projects;
        INSERT INTO file_hashes SELECT * FROM legacy.file_hashes;
        DETACH legacy;
        ",
    )?;
    reset_sequences(conn)?;
    Ok(())
}

async fn open_pool(db_path: &Path) -> Result<DbPool, AppError> {
    let path_str = db_path.to_string_lossy().to_string();
    let client = ClientBuilder::new().path(path_str).open().await?;
    Ok(DbPool(client))
}

pub async fn create_pool(
    app_data_dir: &Path,
    old_db_path: Option<&Path>,
) -> Result<DbPool, AppError> {
    if !app_data_dir.exists() {
        fs::create_dir_all(app_data_dir)?;
    }

    let db_path = app_data_dir.join("ccure.db");
    let marker_path = migration_marker_path(app_data_dir);

    if !db_path.exists() {
        if let Some(old_path) = old_db_path {
            if old_path.exists() {
                let _ = fs::copy(old_path, &db_path);
            }
        }
    }

    let needs_sqlite_migration =
        db_path.exists() && !marker_path.exists() && is_sqlite_file(&db_path).unwrap_or(false);

    if needs_sqlite_migration {
        let pre_migrate = app_data_dir.join("ccure.db.pre-migrate.sqlite");
        let backup = app_data_dir.join("ccure.db.sqlite.bak");

        if pre_migrate.exists() {
            let _ = fs::remove_file(&pre_migrate);
        }
        fs::rename(&db_path, &pre_migrate)?;

        let pool = open_pool(&db_path).await?;
        let sqlite_source = pre_migrate.clone();
        pool.with_conn(move |conn| {
            init_db_on_conn(conn)?;
            migrate_from_sqlite(conn, &sqlite_source).map_err(|e| {
                duckdb::Error::InvalidParameterName(format!(
                    "Legacy SQLite migration failed (network may be required for INSTALL sqlite): {e}"
                ))
            })
        })
        .await?;

        if backup.exists() {
            let _ = fs::remove_file(&backup);
        }
        fs::rename(&pre_migrate, &backup)?;
        fs::write(&marker_path, "1")?;
        return Ok(pool);
    }

    let pool = open_pool(&db_path).await?;
    pool.with_conn(init_db_on_conn).await?;
    if db_path.exists() && !marker_path.exists() && !is_sqlite_file(&db_path).unwrap_or(true) {
        // Fresh DuckDB file created on this run — mark migrated so we don't re-check.
        let _ = fs::write(&marker_path, "1");
    }
    Ok(pool)
}

pub async fn init_db(pool: &DbPool) -> Result<(), AppError> {
    pool.with_conn(init_db_on_conn).await
}
