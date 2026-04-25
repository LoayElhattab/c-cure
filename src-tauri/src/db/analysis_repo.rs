use deadpool_sqlite::Pool;
use rusqlite::{params, OptionalExtension};

use crate::db::{AnalysisSummary, FileData, FunctionData, Report};
use crate::error::AppError;

pub async fn save_analysis(pool: &Pool, project_name: String, project_path: String) -> Result<i64, AppError> {
    let id = pool.get().await?.interact(move |conn| {
        conn.execute(
            "INSERT INTO analyses (project_name, project_path) VALUES (?1, ?2)",
            params![project_name, project_path],
        )?;
        Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
    }).await??;
    Ok(id)
}

pub async fn delete_analysis(pool: &Pool, analysis_id: i32) -> Result<(), AppError> {
    pool.get().await?.interact(move |conn| {
        conn.execute("DELETE FROM analyses WHERE id = ?1", params![analysis_id])?;
        Ok::<_, rusqlite::Error>(())
    }).await??;
    Ok(())
}

pub async fn get_all_analyses(pool: &Pool) -> Result<Vec<AnalysisSummary>, AppError> {
    let analyses = pool.get().await?.interact(|conn| {
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

pub async fn get_report(pool: &Pool, analysis_id: i32) -> Result<Option<Report>, AppError> {
    let report = pool.get().await?.interact(move |conn| {
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

pub async fn save_file(pool: &Pool, analysis_id: i64, file_path: String) -> Result<i64, AppError> {
    let id = pool.get().await?.interact(move |conn| {
        conn.execute(
            "INSERT INTO files (analysis_id, file_path) VALUES (?1, ?2)",
            params![analysis_id, file_path],
        )?;
        Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
    }).await??;
    Ok(id)
}

pub async fn save_function(pool: &Pool, file_id: i64, func: FunctionData) -> Result<(), AppError> {
    pool.get().await?.interact(move |conn| {
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
