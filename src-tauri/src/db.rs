use rusqlite::{params, Connection, OptionalExtension};
use deadpool_sqlite::{Config, Pool, Runtime};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

#[derive(Clone)]
pub struct DatabaseManager {
    pub pool: Pool,
}

impl DatabaseManager {
    pub async fn new(app_data_dir: &Path, old_db_path: Option<&Path>) -> Result<Self, AppError> {
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

        let mut cfg = Config::new(&db_path);
        let pool = cfg.create_pool(Runtime::Tokio1).map_err(|e| AppError::Custom(e.to_string()))?;

        let manager = Self { pool };
        manager.init_db().await?;

        Ok(manager)
    }

    pub async fn init_db(&self) -> Result<(), AppError> {
        self.pool.get().await?.interact(|conn| {
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

    pub async fn save_analysis(&self, project_name: String, project_path: String) -> Result<i64, AppError> {
        let id = self.pool.get().await?.interact(move |conn| {
            conn.execute(
                "INSERT INTO analyses (project_name, project_path) VALUES (?1, ?2)",
                params![project_name, project_path],
            )?;
            Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
        }).await??;
        Ok(id)
    }

    pub async fn delete_analysis(&self, analysis_id: i32) -> Result<(), AppError> {
        self.pool.get().await?.interact(move |conn| {
            conn.execute("DELETE FROM analyses WHERE id = ?1", params![analysis_id])?;
            Ok::<_, rusqlite::Error>(())
        }).await??;
        Ok(())
    }

    pub async fn get_all_analyses(&self) -> Result<Vec<AnalysisSummary>, AppError> {
        let analyses = self.pool.get().await?.interact(|conn| {
            let mut stmt = conn.prepare(
                "SELECT
                    a.id, a.project_name, a.project_path, a.timestamp,
                    COUNT(f.id) AS total_functions,
                    SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) AS vuln_count
                FROM analyses a
                LEFT JOIN files fi ON fi.analysis_id = a.id
                LEFT JOIN functions f ON f.file_id = fi.id
                GROUP BY a.id
                ORDER BY a.timestamp DESC",
            )?;

            let iter = stmt.query_map([], |row| {
                Ok(AnalysisSummary {
                    id: row.get(0)?,
                    project_name: row.get(1)?,
                    project_path: row.get(2)?,
                    timestamp: row.get(3)?,
                    total_functions: row.get::<_, Option<i32>>(4)?.unwrap_or(0),
                    vuln_count: row.get::<_, Option<i32>>(5)?.unwrap_or(0),
                })
            })?;

            let mut results = Vec::new();
            for r in iter {
                results.push(r?);
            }
            Ok::<_, rusqlite::Error>(results)
        }).await??;
        Ok(analyses)
    }

    pub async fn get_report(&self, analysis_id: i32) -> Result<Option<Report>, AppError> {
        let report = self.pool.get().await?.interact(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, project_name, project_path, timestamp FROM analyses WHERE id = ?1",
            )?;
            let analysis_row = stmt
                .query_row(params![analysis_id], |row| {
                    Ok((
                        row.get::<_, i32>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .optional()?;

            let Some((id, project_name, project_path, timestamp)) = analysis_row else {
                return Ok::<_, rusqlite::Error>(None);
            };

            let mut files = Vec::new();
            let mut file_stmt = conn
                .prepare("SELECT id, file_path FROM files WHERE analysis_id = ?1")?;
            let file_iter = file_stmt.query_map(params![analysis_id], |row| {
                Ok((row.get::<_, i32>(0)?, row.get::<_, String>(1)?))
            })?;

            let mut fn_stmt = conn.prepare("SELECT id, function_name, code, verdict, cwe, cwe_name, severity, confidence, start_line, end_line FROM functions WHERE file_id = ?1")?;

            for f_res in file_iter {
                let (file_id, file_path) = f_res?;
                let fn_iter = fn_stmt.query_map(params![file_id], |row| {
                    Ok(FunctionData {
                        id: row.get(0)?,
                        function_name: row.get(1)?,
                        code: row.get(2)?,
                        verdict: row.get(3)?,
                        cwe: row.get(4)?,
                        cwe_name: row.get(5)?,
                        severity: row.get(6)?,
                        confidence: row.get(7)?,
                        start_line: row.get(8)?,
                        end_line: row.get(9)?,
                    })
                })?;

                let mut functions = Vec::new();
                for fn_res in fn_iter {
                    functions.push(fn_res?);
                }

                files.push(FileData {
                    file_path,
                    functions,
                });
            }

            Ok(Some(Report {
                id,
                project_name,
                project_path,
                timestamp,
                files,
            }))
        }).await??;
        Ok(report)
    }

    pub async fn save_file(&self, analysis_id: i64, file_path: String) -> Result<i64, AppError> {
        let id = self.pool.get().await?.interact(move |conn| {
            conn.execute(
                "INSERT INTO files (analysis_id, file_path) VALUES (?1, ?2)",
                params![analysis_id, file_path],
            )?;
            Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
        }).await??;
        Ok(id)
    }

    pub async fn save_function(&self, file_id: i64, func: FunctionData) -> Result<(), AppError> {
        self.pool.get().await?.interact(move |conn| {
            conn.execute(
                "INSERT INTO functions
                    (file_id, function_name, code, verdict, cwe, cwe_name, severity, confidence, start_line, end_line)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    file_id,
                    func.function_name,
                    func.code,
                    func.verdict,
                    func.cwe,
                    func.cwe_name,
                    func.severity,
                    func.confidence,
                    func.start_line,
                    func.end_line
                ],
            )?;
            Ok::<_, rusqlite::Error>(())
        }).await??;
        Ok(())
    }

    pub async fn get_vuln_count(&self) -> Result<i64, AppError> {
        let count = self.pool.get().await?.interact(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM functions WHERE verdict = 'vulnerable'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            Ok::<_, rusqlite::Error>(count)
        }).await??;
        Ok(count)
    }

    pub async fn get_statistics(&self) -> Result<StatisticsData, AppError> {
        let stats = self.pool.get().await?.interact(|conn| {
            let kpis: Kpis = conn
                .query_row(
                    "SELECT
                    COUNT(DISTINCT a.id),
                    COUNT(DISTINCT fi.id),
                    COUNT(f.id),
                    SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN f.verdict = 'safe' THEN 1 ELSE 0 END)
                FROM analyses a
                LEFT JOIN files fi ON fi.analysis_id = a.id
                LEFT JOIN functions f ON f.file_id = fi.id",
                    [],
                    |row| {
                        Ok(Kpis {
                            total_analyses: row.get::<_, Option<i32>>(0)?.unwrap_or(0),
                            total_files: row.get::<_, Option<i32>>(1)?.unwrap_or(0),
                            total_functions: row.get::<_, Option<i32>>(2)?.unwrap_or(0),
                            total_vulnerable: row.get::<_, Option<i32>>(3)?.unwrap_or(0),
                            total_safe: row.get::<_, Option<i32>>(4)?.unwrap_or(0),
                        })
                    },
                )
                .unwrap_or(Kpis {
                    total_analyses: 0,
                    total_files: 0,
                    total_functions: 0,
                    total_vulnerable: 0,
                    total_safe: 0,
                });

            let mut stmt = conn.prepare(
                "SELECT cwe, cwe_name, severity, COUNT(*) as count
                 FROM functions
                 WHERE verdict = 'vulnerable' AND cwe IS NOT NULL
                 GROUP BY cwe ORDER BY count DESC",
            )?;
            let iter = stmt.query_map([], |row| {
                Ok(CweCount {
                    cwe: row.get(0)?,
                    cwe_name: row.get(1)?,
                    severity: row.get(2)?,
                    count: row.get(3)?,
                })
            })?;
            let mut cwe_counts = Vec::new();
            for r in iter {
                cwe_counts.push(r?);
            }

            let mut stmt = conn.prepare(
                "SELECT severity, COUNT(*) as count
                 FROM functions
                 WHERE verdict = 'vulnerable' AND severity IS NOT NULL
                 GROUP BY severity",
            )?;
            let iter = stmt.query_map([], |row| {
                Ok(SeverityCount {
                    severity: row.get(0)?,
                    count: row.get(1)?,
                })
            })?;
            let mut severity_counts = Vec::new();
            for r in iter {
                severity_counts.push(r?);
            }

            let mut stmt = conn.prepare(
                "SELECT
                    fi.file_path,
                    SUM(CASE WHEN f.verdict = 'safe' THEN 1 ELSE 0 END) as safe_count,
                    SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) as vuln_count
                 FROM files fi
                 JOIN functions f ON f.file_id = fi.id
                 GROUP BY fi.id ORDER BY vuln_count DESC LIMIT 10",
            )?;
            let iter = stmt.query_map([], |row| {
                let path: String = row.get(0)?;
                let label = path
                    .replace("\\", "/")
                    .split("/")
                    .last()
                    .unwrap_or("")
                    .to_string();
                Ok(FileRatio {
                    label,
                    safe: row.get::<_, Option<i32>>(1)?.unwrap_or(0),
                    vuln: row.get::<_, Option<i32>>(2)?.unwrap_or(0),
                })
            })?;
            let mut file_ratios = Vec::new();
            for r in iter {
                file_ratios.push(r?);
            }

            let mut stmt = conn.prepare(
                "SELECT
                    a.id, a.project_name, a.project_path, a.timestamp,
                    COUNT(f.id) AS total_functions,
                    SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) AS vuln_count
                FROM analyses a
                LEFT JOIN files fi ON fi.analysis_id = a.id
                LEFT JOIN functions f ON f.file_id = fi.id
                GROUP BY a.id
                ORDER BY a.timestamp DESC LIMIT 7",
            )?;
            let iter = stmt.query_map([], |row| {
                Ok(AnalysisSummary {
                    id: row.get(0)?,
                    project_name: row.get(1)?,
                    project_path: row.get(2)?,
                    timestamp: row.get(3)?,
                    total_functions: row.get::<_, Option<i32>>(4)?.unwrap_or(0),
                    vuln_count: row.get::<_, Option<i32>>(5)?.unwrap_or(0),
                })
            })?;
            let mut recent_analyses = Vec::new();
            for r in iter {
                recent_analyses.push(r?);
            }

            let mut stmt = conn.prepare(
                "SELECT
                    a.timestamp,
                    SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) as vuln_count
                 FROM analyses a
                 LEFT JOIN files fi ON fi.analysis_id = a.id
                 LEFT JOIN functions f ON f.file_id = fi.id
                 GROUP BY a.id
                 ORDER BY a.timestamp ASC",
            )?;
            let iter = stmt.query_map([], |row| {
                Ok(TrendData {
                    timestamp: row.get(0)?,
                    vuln_count: row.get::<_, Option<i32>>(1)?.unwrap_or(0),
                })
            })?;
            let mut trend = Vec::new();
            for r in iter {
                trend.push(r?);
            }

            Ok::<_, rusqlite::Error>(StatisticsData {
                dashboard: DashboardStats {
                    kpis,
                    cwe_counts,
                    severity_counts,
                    file_ratios,
                    recent_analyses,
                },
                trend,
            })
        }).await??;
        Ok(stats)
    }

    pub async fn add_watched_project(&self, name: String, folder_path: String) -> Result<i32, AppError> {
        let res = self.pool.get().await?.interact(move |conn| {
            match conn.execute(
                "INSERT INTO watched_projects (name, folder_path) VALUES (?1, ?2)",
                params![name, folder_path],
            ) {
                Ok(_) => Ok(conn.last_insert_rowid() as i32),
                Err(e) => {
                    if let rusqlite::Error::SqliteFailure(e_code, _) = &e {
                        if e_code.code == rusqlite::ErrorCode::ConstraintViolation {
                            return Err(rusqlite::Error::InvalidParameterName("Constraint".into()));
                        }
                    }
                    Err(e)
                }
            }
        }).await??;
        Ok(res)
    }

    pub async fn get_watched_projects(&self) -> Result<Vec<WatchedProject>, AppError> {
        let projects = self.pool.get().await?.interact(|conn| {
            let mut stmt = conn.prepare("SELECT id, name, folder_path, registered_at FROM watched_projects ORDER BY registered_at DESC")?;
            let iter = stmt.query_map([], |row| {
                Ok(WatchedProject {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    folder_path: row.get(2)?,
                    registered_at: row.get(3)?,
                })
            })?;
            let mut projects = Vec::new();
            for r in iter {
                projects.push(r?);
            }
            Ok::<_, rusqlite::Error>(projects)
        }).await??;
        Ok(projects)
    }

    pub async fn save_file_hashes(
        &self,
        project_id: i32,
        hashes: HashMap<String, String>,
    ) -> Result<(), AppError> {
        self.pool.get().await?.interact(move |conn| {
            let mut stmt = conn.prepare(
                "INSERT INTO file_hashes (project_id, file_path, file_hash)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(project_id, file_path)
                 DO UPDATE SET file_hash = excluded.file_hash, hashed_at = CURRENT_TIMESTAMP",
            )?;
            for (path, hash) in &hashes {
                stmt.execute(params![project_id, path, hash])?;
            }
            Ok::<_, rusqlite::Error>(())
        }).await??;
        Ok(())
    }

    pub async fn get_file_hashes(&self, project_id: i32) -> Result<HashMap<String, String>, AppError> {
        let hashes = self.pool.get().await?.interact(move |conn| {
            let mut stmt = conn
                .prepare("SELECT file_path, file_hash FROM file_hashes WHERE project_id = ?1")?;
            let iter = stmt.query_map(params![project_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut hashes = HashMap::new();
            for r in iter {
                let (path, hash) = r?;
                hashes.insert(path, hash);
            }
            Ok::<_, rusqlite::Error>(hashes)
        }).await??;
        Ok(hashes)
    }

    pub async fn remove_watched_project(&self, project_id: i32) -> Result<(), AppError> {
        self.pool.get().await?.interact(move |conn| {
            conn.execute(
                "DELETE FROM watched_projects WHERE id = ?1",
                params![project_id],
            )?;
            Ok::<_, rusqlite::Error>(())
        }).await??;
        Ok(())
    }
}
