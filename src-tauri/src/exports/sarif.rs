use serde::Serialize;
use std::collections::BTreeMap;

use crate::db::{DbPool, FunctionData, VulnerabilityReport};
use crate::error::AppError;

const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    results: Vec<ResultItem>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
struct Driver {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<ReportingDescriptor>,
}

#[derive(Serialize)]
struct ReportingDescriptor {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: Message,
}

#[derive(Serialize)]
struct ResultItem {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: Message,
    locations: Vec<Location>,
}

#[derive(Serialize)]
struct Message {
    text: String,
}

#[derive(Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: i32,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    end_line: Option<i32>,
    snippet: Snippet,
}

#[derive(Serialize)]
struct Snippet {
    text: String,
}

pub async fn export_sarif(
    pool: &DbPool,
    analysis_id: i64,
    file_path: String,
) -> Result<(), AppError> {
    let report = crate::db::analysis_repo::get_vulnerability_report(pool, analysis_id as i32)
        .await?
        .ok_or_else(|| AppError::Custom("Report not found".into()))?;

    tauri::async_runtime::spawn_blocking(move || {
        let sarif = build_sarif(&report);
        let json = serde_json::to_string_pretty(&sarif)
            .map_err(|e| AppError::Custom(format!("Failed to serialize SARIF: {e}")))?;
        std::fs::write(file_path, json)?;
        Ok::<(), AppError>(())
    })
    .await
    .map_err(|e| AppError::Custom(format!("SARIF export worker failed: {e}")))??;

    Ok(())
}

fn build_sarif(report: &VulnerabilityReport) -> SarifLog {
    let mut rules = BTreeMap::<String, ReportingDescriptor>::new();
    let mut results = Vec::new();

    for file in &report.files {
        for function in &file.functions {
            let rule_id = function.cwe.as_deref().unwrap_or("UNKNOWN").to_string();
            let cwe_name = function
                .cwe_name
                .as_deref()
                .unwrap_or("Unknown vulnerability");

            rules
                .entry(rule_id.clone())
                .or_insert_with(|| ReportingDescriptor {
                    id: rule_id.clone(),
                    name: cwe_name.to_string(),
                    short_description: Message {
                        text: cwe_name.to_string(),
                    },
                });

            results.push(ResultItem {
                rule_id,
                level: sarif_level(function.severity.as_deref()),
                message: Message {
                    text: result_message(function),
                },
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation {
                            uri: file.file_path.clone(),
                        },
                        region: Region {
                            start_line: function.start_line.unwrap_or(1).max(1),
                            end_line: function.end_line.filter(|line| *line > 0),
                            snippet: Snippet {
                                text: function.code.clone(),
                            },
                        },
                    },
                }],
            });
        }
    }

    SarifLog {
        schema: SARIF_SCHEMA,
        version: "2.1.0",
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "C-Cure",
                    version: "1.0.0",
                    information_uri: "https://github.com/LoayElHattab/C-Cure",
                    rules: rules.into_values().collect(),
                },
            },
            results,
        }],
    }
}

fn sarif_level(severity: Option<&str>) -> &'static str {
    match severity {
        Some("Critical" | "High") => "error",
        Some("Medium") => "warning",
        Some("Low") => "note",
        _ => "warning",
    }
}

fn result_message(function: &FunctionData) -> String {
    let cwe = function.cwe.as_deref().unwrap_or("Unknown CWE");
    let cwe_name = function.cwe_name.as_deref().unwrap_or("vulnerability");
    format!(
        "{} detected in function `{}` ({})",
        cwe_name, function.function_name, cwe
    )
}
