use duckdb::params;
use std::collections::HashMap;

use crate::db::{
    AnalysisListItem, AnalysisSummary, CweHit, DbPool, FileData, FunctionData, FunctionRow,
    PagedFunctions, Report, VulnerabilityReport,
};
use crate::error::AppError;

pub async fn save_analysis(
    pool: &DbPool,
    project_name: String,
    project_path: String,
) -> Result<i64, AppError> {
    pool.with_conn(move |conn| {
        let mut stmt = conn.prepare(
            "INSERT INTO analyses (project_name, project_path) VALUES (?, ?) RETURNING id",
        )?;
        let id: i64 = stmt.query_row(params![project_name, project_path], |row| row.get(0))?;
        Ok(id)
    })
    .await
}

pub async fn delete_analysis(pool: &DbPool, analysis_id: i32) -> Result<(), AppError> {
    pool.with_conn(move |conn| {
        // DuckDB does not support ON DELETE CASCADE; delete children explicitly.
        conn.execute(
            "DELETE FROM functions
             WHERE file_id IN (SELECT id FROM files WHERE analysis_id = ?)",
            params![analysis_id],
        )?;
        conn.execute(
            "DELETE FROM files WHERE analysis_id = ?",
            params![analysis_id],
        )?;
        conn.execute("DELETE FROM analyses WHERE id = ?", params![analysis_id])?;
        Ok(())
    })
    .await
}

pub async fn get_all_analyses(pool: &DbPool) -> Result<Vec<AnalysisListItem>, AppError> {
    pool.with_conn(|conn| {
        let mut stmt = conn.prepare(
            "SELECT
                a.id, a.project_name, a.project_path, CAST(a.timestamp AS VARCHAR),
                COUNT(f.id) AS total_functions,
                SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) AS vuln_count
            FROM analyses a
            LEFT JOIN files fi ON fi.analysis_id = a.id
            LEFT JOIN functions f ON f.file_id = fi.id
            GROUP BY a.id, a.project_name, a.project_path, a.timestamp
            ORDER BY a.timestamp DESC",
        )?;

        let iter = stmt.query_map([], |row| {
            Ok(AnalysisListItem {
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
        Ok(results)
    })
    .await
}

pub async fn get_analysis_summary(
    pool: &DbPool,
    analysis_id: i32,
) -> Result<Option<AnalysisSummary>, AppError> {
    pool.with_conn(move |conn| {
        let analysis_row = match conn.query_row(
            "SELECT
                a.id,
                a.project_name,
                a.project_path,
                CAST(a.timestamp AS VARCHAR),
                COUNT(DISTINCT fi.id) AS total_files,
                COUNT(f.id) AS total_functions,
                SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) AS vulnerable_functions,
                SUM(CASE WHEN f.verdict <> 'vulnerable' THEN 1 ELSE 0 END) AS clean_functions
             FROM analyses a
             LEFT JOIN files fi ON fi.analysis_id = a.id
             LEFT JOIN functions f ON f.file_id = fi.id
             WHERE a.id = ?
             GROUP BY a.id, a.project_name, a.project_path, a.timestamp",
            params![analysis_id],
            |row| {
                Ok((
                    row.get::<_, i32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(5)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(6)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(7)?.unwrap_or(0),
                ))
            },
        ) {
            Ok(row) => row,
            Err(duckdb::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e),
        };

        let (
            id,
            project_name,
            project_path,
            timestamp,
            total_files,
            total_functions,
            vulnerable_functions,
            clean_functions,
        ) = analysis_row;

        let mut severity_stmt = conn.prepare(
            "SELECT severity, COUNT(*) AS count
             FROM functions f
             JOIN files fi ON f.file_id = fi.id
             WHERE fi.analysis_id = ?
               AND f.verdict = 'vulnerable'
               AND f.severity IS NOT NULL
             GROUP BY severity",
        )?;
        let severity_rows = severity_stmt.query_map(params![analysis_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;

        let mut severity_breakdown = HashMap::new();
        for row in severity_rows {
            let (severity, count) = row?;
            severity_breakdown.insert(severity, count as u32);
        }

        let mut cwe_stmt = conn.prepare(
            "SELECT cwe, cwe_name, severity, COUNT(*) AS count
             FROM functions f
             JOIN files fi ON f.file_id = fi.id
             WHERE fi.analysis_id = ?
               AND f.verdict = 'vulnerable'
               AND f.cwe IS NOT NULL
             GROUP BY cwe, cwe_name, severity
             ORDER BY count DESC
             LIMIT 5",
        )?;
        let cwe_rows = cwe_stmt.query_map(params![analysis_id], |row| {
            Ok(CweHit {
                cwe: row.get(0)?,
                cwe_name: row.get(1)?,
                asvs_id: None,
                severity: row.get(2)?,
                count: row.get::<_, i64>(3)? as u32,
            }
            .with_compliance())
        })?;

        let mut top_vulnerabilities = Vec::new();
        for row in cwe_rows {
            top_vulnerabilities.push(row?);
        }

        let mut findings_stmt = conn.prepare(
            "SELECT
                f.id,
                f.function_name,
                f.code,
                f.verdict,
                f.cwe,
                f.cwe_name,
                f.severity,
                f.confidence,
                f.start_line,
                f.end_line,
                fi.file_path
             FROM functions f
             JOIN files fi ON f.file_id = fi.id
             WHERE fi.analysis_id = ?
               AND f.verdict = 'vulnerable'
             ORDER BY
                CASE f.severity
                    WHEN 'Critical' THEN 4
                    WHEN 'High' THEN 3
                    WHEN 'Medium' THEN 2
                    WHEN 'Low' THEN 1
                    ELSE 0
                END DESC,
                f.confidence DESC NULLS LAST,
                f.id ASC
             LIMIT 5",
        )?;
        let finding_rows = findings_stmt.query_map(params![analysis_id], |row| {
            Ok(FunctionRow {
                id: row.get(0)?,
                function_name: row.get(1)?,
                code: row.get(2)?,
                verdict: row.get(3)?,
                cwe: row.get(4)?,
                cwe_name: row.get(5)?,
                asvs_id: None,
                severity: row.get(6)?,
                confidence: row.get(7)?,
                start_line: row.get(8)?,
                end_line: row.get(9)?,
                file_path: row.get(10)?,
            }
            .with_compliance())
        })?;

        let mut most_critical_findings = Vec::new();
        for row in finding_rows {
            most_critical_findings.push(row?);
        }

        Ok(Some(AnalysisSummary {
            id,
            project_name,
            project_path,
            timestamp,
            total_files: total_files as u32,
            total_functions: total_functions as u32,
            vulnerable_functions: vulnerable_functions as u32,
            clean_functions: clean_functions as u32,
            severity_breakdown,
            top_vulnerabilities,
            most_critical_findings,
        }))
    })
    .await
}

pub async fn get_report(pool: &DbPool, analysis_id: i32) -> Result<Option<Report>, AppError> {
    pool.with_conn(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, project_name, project_path, CAST(timestamp AS VARCHAR) FROM analyses WHERE id = ?",
        )?;

        let analysis_row = match stmt.query_row(params![analysis_id], |row| {
            Ok((
                row.get::<_, i32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        }) {
            Ok(row) => row,
            Err(duckdb::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e),
        };

        let (id, project_name, project_path, timestamp) = analysis_row;

        let mut files = Vec::new();
        let mut file_stmt =
            conn.prepare("SELECT id, file_path FROM files WHERE analysis_id = ?")?;
        let file_iter = file_stmt.query_map(params![analysis_id], |row| {
            Ok((row.get::<_, i32>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut fn_stmt = conn.prepare(
            "SELECT id, function_name, code, verdict, cwe, cwe_name, severity, confidence, start_line, end_line
             FROM functions WHERE file_id = ?",
        )?;

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
                    asvs_id: None,
                    severity: row.get(6)?,
                    confidence: row.get(7)?,
                    start_line: row.get(8)?,
                    end_line: row.get(9)?,
                }
                .with_compliance())
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
    })
    .await
}

pub async fn get_vulnerability_report(
    pool: &DbPool,
    analysis_id: i32,
) -> Result<Option<VulnerabilityReport>, AppError> {
    pool.with_conn(move |conn| {
        let summary_row = match conn.query_row(
            "SELECT
                a.id,
                a.project_name,
                a.project_path,
                CAST(a.timestamp AS VARCHAR),
                COUNT(DISTINCT fi.id) AS total_files,
                COUNT(f.id) AS total_functions,
                SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) AS vulnerable_functions,
                SUM(CASE WHEN f.verdict <> 'vulnerable' THEN 1 ELSE 0 END) AS clean_functions
             FROM analyses a
             LEFT JOIN files fi ON fi.analysis_id = a.id
             LEFT JOIN functions f ON f.file_id = fi.id
             WHERE a.id = ?
             GROUP BY a.id, a.project_name, a.project_path, a.timestamp",
            params![analysis_id],
            |row| {
                Ok((
                    row.get::<_, i32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(5)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(6)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(7)?.unwrap_or(0),
                ))
            },
        ) {
            Ok(row) => row,
            Err(duckdb::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e),
        };

        let (
            id,
            project_name,
            project_path,
            timestamp,
            total_files,
            total_functions,
            vulnerable_functions,
            clean_functions,
        ) = summary_row;

        let mut severity_stmt = conn.prepare(
            "SELECT severity, COUNT(*) AS count
             FROM functions f
             JOIN files fi ON f.file_id = fi.id
             WHERE fi.analysis_id = ?
               AND f.verdict = 'vulnerable'
               AND f.severity IS NOT NULL
             GROUP BY severity",
        )?;
        let severity_rows = severity_stmt.query_map(params![analysis_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut severity_breakdown = HashMap::new();
        for row in severity_rows {
            let (severity, count) = row?;
            severity_breakdown.insert(severity, count as u32);
        }

        let mut cwe_stmt = conn.prepare(
            "SELECT cwe, cwe_name, severity, COUNT(*) AS count
             FROM functions f
             JOIN files fi ON f.file_id = fi.id
             WHERE fi.analysis_id = ?
               AND f.verdict = 'vulnerable'
               AND f.cwe IS NOT NULL
             GROUP BY cwe, cwe_name, severity
             ORDER BY count DESC
             LIMIT 10",
        )?;
        let cwe_rows = cwe_stmt.query_map(params![analysis_id], |row| {
            Ok(CweHit {
                cwe: row.get(0)?,
                cwe_name: row.get(1)?,
                asvs_id: None,
                severity: row.get(2)?,
                count: row.get::<_, i64>(3)? as u32,
            }
            .with_compliance())
        })?;
        let mut top_vulnerabilities = Vec::new();
        for row in cwe_rows {
            top_vulnerabilities.push(row?);
        }

        let mut vuln_stmt = conn.prepare(
            "SELECT
                fi.file_path,
                f.id,
                f.function_name,
                f.code,
                f.verdict,
                f.cwe,
                f.cwe_name,
                f.severity,
                f.confidence,
                f.start_line,
                f.end_line
             FROM functions f
             JOIN files fi ON f.file_id = fi.id
             WHERE fi.analysis_id = ?
               AND f.verdict = 'vulnerable'
             ORDER BY
                fi.file_path ASC,
                CASE f.severity
                    WHEN 'Critical' THEN 4
                    WHEN 'High' THEN 3
                    WHEN 'Medium' THEN 2
                    WHEN 'Low' THEN 1
                    ELSE 0
                END DESC,
                f.id ASC",
        )?;
        let vuln_rows = vuln_stmt.query_map(params![analysis_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                FunctionData {
                    id: row.get(1)?,
                    function_name: row.get(2)?,
                    code: row.get(3)?,
                    verdict: row.get(4)?,
                    cwe: row.get(5)?,
                    cwe_name: row.get(6)?,
                    asvs_id: None,
                    severity: row.get(7)?,
                    confidence: row.get(8)?,
                    start_line: row.get(9)?,
                    end_line: row.get(10)?,
                }
                .with_compliance(),
            ))
        })?;

        let mut files = Vec::new();
        let mut current_file_path: Option<String> = None;
        let mut current_functions = Vec::new();

        for row in vuln_rows {
            let (file_path, function) = row?;
            if current_file_path.as_deref() != Some(file_path.as_str()) {
                if let Some(path) = current_file_path.replace(file_path) {
                    files.push(FileData {
                        file_path: path,
                        functions: current_functions,
                    });
                    current_functions = Vec::new();
                }
            }
            current_functions.push(function);
        }

        if let Some(path) = current_file_path {
            files.push(FileData {
                file_path: path,
                functions: current_functions,
            });
        }

        Ok(Some(VulnerabilityReport {
            id,
            project_name,
            project_path,
            timestamp,
            total_files: total_files as u32,
            total_functions: total_functions as u32,
            vulnerable_functions: vulnerable_functions as u32,
            clean_functions: clean_functions as u32,
            severity_breakdown,
            top_vulnerabilities,
            files,
        }))
    })
    .await
}

pub async fn save_file(
    pool: &DbPool,
    analysis_id: i64,
    file_path: String,
) -> Result<i64, AppError> {
    pool.with_conn(move |conn| {
        let mut stmt =
            conn.prepare("INSERT INTO files (analysis_id, file_path) VALUES (?, ?) RETURNING id")?;
        let id: i64 = stmt.query_row(params![analysis_id, file_path], |row| row.get(0))?;
        Ok(id)
    })
    .await
}

/// Bulk-append function scan results via DuckDB Appender (OLAP insert path).
pub async fn save_functions_bulk(
    pool: &DbPool,
    file_id: i64,
    functions: &[FunctionData],
) -> Result<(), AppError> {
    if functions.is_empty() {
        return Ok(());
    }

    let batch: Vec<FunctionData> = functions.to_vec();
    pool.with_conn(move |conn| {
        let mut appender = conn.appender("functions")?;
        appender.add_column("file_id")?;
        appender.add_column("function_name")?;
        appender.add_column("code")?;
        appender.add_column("verdict")?;
        appender.add_column("cwe")?;
        appender.add_column("cwe_name")?;
        appender.add_column("severity")?;
        appender.add_column("confidence")?;
        appender.add_column("start_line")?;
        appender.add_column("end_line")?;

        for func in &batch {
            appender.append_row(params![
                file_id,
                func.function_name,
                func.code,
                func.verdict,
                func.cwe,
                func.cwe_name,
                func.severity,
                func.confidence,
                func.start_line,
                func.end_line,
            ])?;
        }
        Ok(())
    })
    .await
}

/// Returns the total number of functions belonging to an analysis.
/// Used by the frontend to calculate the total number of pages.
pub async fn get_functions_count(
    pool: &DbPool,
    analysis_id: i32,
) -> Result<u64, crate::error::AppError> {
    pool.with_conn(move |conn| {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM functions f
             JOIN files fi ON f.file_id = fi.id
             WHERE fi.analysis_id = ?",
            params![analysis_id],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    })
    .await
}

/// Returns a paginated, flat list of functions for one analysis.
/// Each row also carries the `file_path` so the UI can group by file
/// without a separate query.
pub async fn get_functions_page(
    pool: &DbPool,
    analysis_id: i32,
    limit: u32,
    offset: u32,
) -> Result<PagedFunctions, crate::error::AppError> {
    pool.with_conn(move |conn| {
        // Total count (cheap – uses the index on files.analysis_id)
        let total: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM functions f
             JOIN files fi ON f.file_id = fi.id
             WHERE fi.analysis_id = ?",
            params![analysis_id],
            |row| row.get(0),
        )?;

        let mut stmt = conn.prepare(
            "SELECT
                f.id,
                f.function_name,
                f.code,
                f.verdict,
                f.cwe,
                f.cwe_name,
                f.severity,
                f.confidence,
                f.start_line,
                f.end_line,
                fi.file_path
             FROM functions f
             JOIN files fi ON f.file_id = fi.id
             WHERE fi.analysis_id = ?
             ORDER BY fi.id ASC, f.id ASC
             LIMIT ? OFFSET ?",
        )?;

        let rows = stmt.query_map(params![analysis_id, limit, offset], |row| {
            Ok(FunctionRow {
                id: row.get(0)?,
                function_name: row.get(1)?,
                code: row.get(2)?,
                verdict: row.get(3)?,
                cwe: row.get(4)?,
                cwe_name: row.get(5)?,
                asvs_id: None,
                severity: row.get(6)?,
                confidence: row.get(7)?,
                start_line: row.get(8)?,
                end_line: row.get(9)?,
                file_path: row.get(10)?,
            }
            .with_compliance())
        })?;

        let mut functions = Vec::new();
        for r in rows {
            functions.push(r?);
        }

        Ok(PagedFunctions {
            total: total as u64,
            limit,
            offset,
            functions,
        })
    })
    .await
}

/// Returns a filtered, sorted, and paginated list of functions for an analysis.
pub async fn search_functions_page(
    pool: &DbPool,
    analysis_id: i32,
    search_term: Option<String>,
    verdict_filter: Option<String>,
    sort_by: Option<String>,
    limit: u32,
    offset: u32,
) -> Result<PagedFunctions, crate::error::AppError> {
    pool.with_conn(move |conn| {
        let mut filters = Vec::new();
        filters.push("fi.analysis_id = ?".to_string());
        let mut params_vec: Vec<duckdb::types::Value> = vec![duckdb::types::Value::Int(analysis_id)];

        if let Some(ref term) = search_term {
            if !term.trim().is_empty() {
                filters.push(
                    "(LOWER(f.function_name) LIKE ? OR LOWER(f.cwe) LIKE ? OR LOWER(f.cwe_name) LIKE ? OR LOWER(fi.file_path) LIKE ?)".to_string()
                );
                let like_term = format!("%{}%", term.to_lowercase());
                params_vec.push(duckdb::types::Value::Text(like_term.clone()));
                params_vec.push(duckdb::types::Value::Text(like_term.clone()));
                params_vec.push(duckdb::types::Value::Text(like_term.clone()));
                params_vec.push(duckdb::types::Value::Text(like_term));
            }
        }

        if let Some(ref v) = verdict_filter {
            if v != "all" {
                filters.push("f.verdict = ?".to_string());
                params_vec.push(duckdb::types::Value::Text(v.clone()));
            }
        }

        let where_clause = filters.join(" AND ");

        let count_query = format!(
            "SELECT COUNT(*) FROM functions f JOIN files fi ON f.file_id = fi.id WHERE {}",
            where_clause
        );

        let total: i64 = conn.query_row_and_then(&count_query, duckdb::params_from_iter(params_vec.iter()), |row| row.get(0))?;

        let order_clause = match sort_by.as_deref() {
            Some("severity") => "CASE f.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END DESC, fi.id ASC, f.id ASC",
            Some("name") => "f.function_name ASC, fi.id ASC, f.id ASC",
            Some("line") => "COALESCE(f.start_line, 0) ASC, fi.id ASC, f.id ASC",
            _ => "fi.id ASC, f.id ASC",
        };

        let data_query = format!(
            "SELECT f.id, f.function_name, f.code, f.verdict, f.cwe, f.cwe_name, f.severity, f.confidence, f.start_line, f.end_line, fi.file_path 
             FROM functions f JOIN files fi ON f.file_id = fi.id 
             WHERE {} 
             ORDER BY {} 
             LIMIT ? OFFSET ?",
            where_clause, order_clause
        );

        let mut data_params = params_vec;
        data_params.push(duckdb::types::Value::UInt(limit));
        data_params.push(duckdb::types::Value::UInt(offset));

        let mut stmt = conn.prepare(&data_query)?;
        
        let rows = stmt.query_map(duckdb::params_from_iter(data_params.iter()), |row| {
            Ok(FunctionRow {
                id: row.get(0)?,
                function_name: row.get(1)?,
                code: row.get(2)?,
                verdict: row.get(3)?,
                cwe: row.get(4)?,
                cwe_name: row.get(5)?,
                asvs_id: None,
                severity: row.get(6)?,
                confidence: row.get(7)?,
                start_line: row.get(8)?,
                end_line: row.get(9)?,
                file_path: row.get(10)?,
            }.with_compliance())
        })?;

        let mut functions = Vec::new();
        for r in rows {
            functions.push(r?);
        }

        Ok(PagedFunctions {
            total: total as u64,
            limit,
            offset,
            functions,
        })
    })
    .await
}
