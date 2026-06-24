use duckdb::params;
use std::path::Path;

use crate::db::DbPool;
use crate::error::AppError;

#[derive(Debug)]
struct CsvFinding {
    file_path: String,
    function_name: String,
    cwe: Option<String>,
    cwe_name: Option<String>,
    severity: Option<String>,
    confidence: Option<f64>,
    start_line: Option<i32>,
    end_line: Option<i32>,
    code: String,
}

pub async fn export_csv(
    pool: &DbPool,
    analysis_id: i32,
    file_path: String,
) -> Result<(), AppError> {
    let findings = fetch_vulnerable_findings(pool, analysis_id).await?;
    let csv = build_csv(&findings);

    tauri::async_runtime::spawn_blocking(move || std::fs::write(Path::new(&file_path), csv))
        .await
        .map_err(|e| AppError::Custom(format!("CSV export worker failed: {e}")))??;

    Ok(())
}

async fn fetch_vulnerable_findings(
    pool: &DbPool,
    analysis_id: i32,
) -> Result<Vec<CsvFinding>, AppError> {
    pool.with_conn(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT
                fi.file_path,
                f.function_name,
                f.cwe,
                f.cwe_name,
                f.severity,
                f.confidence,
                f.start_line,
                f.end_line,
                f.code
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

        let rows = stmt.query_map(params![analysis_id], |row| {
            Ok(CsvFinding {
                file_path: row.get(0)?,
                function_name: row.get(1)?,
                cwe: row.get(2)?,
                cwe_name: row.get(3)?,
                severity: row.get(4)?,
                confidence: row.get(5)?,
                start_line: row.get(6)?,
                end_line: row.get(7)?,
                code: row.get(8)?,
            })
        })?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(row?);
        }

        Ok(findings)
    })
    .await
}

fn build_csv(findings: &[CsvFinding]) -> String {
    let mut csv = String::from(
        "file_path,function_name,cwe,cwe_name,severity,confidence,start_line,end_line,code\r\n",
    );

    for finding in findings {
        let confidence = finding
            .confidence
            .map(|value| value.to_string())
            .unwrap_or_default();
        let start_line = finding
            .start_line
            .map(|value| value.to_string())
            .unwrap_or_default();
        let end_line = finding
            .end_line
            .map(|value| value.to_string())
            .unwrap_or_default();

        append_record(
            &mut csv,
            &[
                finding.file_path.as_str(),
                finding.function_name.as_str(),
                finding.cwe.as_deref().unwrap_or(""),
                finding.cwe_name.as_deref().unwrap_or(""),
                finding.severity.as_deref().unwrap_or(""),
                confidence.as_str(),
                start_line.as_str(),
                end_line.as_str(),
                finding.code.as_str(),
            ],
        );
    }

    csv
}

fn append_record(csv: &mut String, fields: &[&str]) {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            csv.push(',');
        }
        append_field(csv, field);
    }
    csv.push_str("\r\n");
}

fn append_field(csv: &mut String, field: &str) {
    let requires_quotes = field.contains([',', '"', '\r', '\n']);
    if !requires_quotes {
        csv.push_str(field);
        return;
    }

    csv.push('"');
    for ch in field.chars() {
        if ch == '"' {
            csv.push('"');
        }
        csv.push(ch);
    }
    csv.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_commas_and_newlines() {
        let finding = CsvFinding {
            file_path: "src/main.cpp".into(),
            function_name: "dangerous, \"copy\"".into(),
            cwe: Some("CWE-787".into()),
            cwe_name: Some("Out-of-bounds Write".into()),
            severity: Some("Critical".into()),
            confidence: Some(0.98),
            start_line: Some(10),
            end_line: Some(12),
            code: "strcpy(dst, \"abc\");\nreturn dst;".into(),
        };

        let csv = build_csv(&[finding]);

        assert!(csv.contains("\"dangerous, \"\"copy\"\"\""));
        assert!(csv.contains("\"strcpy(dst, \"\"abc\"\");\nreturn dst;\""));
        assert!(csv.ends_with("\r\n"));
    }
}
