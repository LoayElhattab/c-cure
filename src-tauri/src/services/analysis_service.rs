use crate::error::AppError;
use reqwest::Client;
use std::path::Path;

use crate::inference::{dispatch_analysis, get_provider, AnalysisResult};

pub async fn analyze_file_service(
    pool: &deadpool_sqlite::Pool,
    client: Client,
    url: String,
    file_path: String,
) -> Result<AnalysisResult, AppError> {
    let functions = crate::parser::extract_functions(&file_path)?;

    if functions.is_empty() {
        return Err(AppError::Custom(
            "No functions found in file. Is it a valid C++ file?".to_string(),
        ));
    }

    if url.is_empty() && std::env::var("MOCK_API").unwrap_or_default() != "true" {
        return Err(AppError::Custom(
            "Kaggle API URL not configured".to_string(),
        ));
    }

    let path = Path::new(&file_path);
    let project_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let analysis_id =
        crate::db::analysis_repo::save_analysis(pool, project_name.clone(), file_path.clone())
            .await?;
    let file_id = crate::db::analysis_repo::save_file(pool, analysis_id, file_path.clone()).await?;

    let provider = get_provider(client, url);
    let results = dispatch_analysis(provider, functions, 5).await?;

    let mut vuln_count = 0;
    let mut saved_results = Vec::new();

    for result in results {
        crate::db::analysis_repo::save_function(pool, file_id, result.clone()).await?;
        if result.verdict == "vulnerable" {
            vuln_count += 1;
        }
        saved_results.push(result);
    }

    Ok(AnalysisResult {
        analysis_id: analysis_id as i32,
        project_name,
        path: file_path,
        files_scanned: 1,
        total_functions: saved_results.len() as i32,
        vuln_count,
        functions: saved_results,
    })
}

pub async fn analyze_folder_service(
    pool: &deadpool_sqlite::Pool,
    client: Client,
    url: String,
    folder_path: String,
) -> Result<AnalysisResult, AppError> {
    if url.is_empty() && std::env::var("MOCK_API").unwrap_or_default() != "true" {
        return Err(AppError::Custom(
            "Kaggle API URL not configured".to_string(),
        ));
    }

    let mut cpp_files = Vec::new();
    let ext_list = ["cpp", "c", "h", "cc", "cxx"];

    for entry in walkdir::WalkDir::new(&folder_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if p.is_file() {
            let relative = p.strip_prefix(&folder_path).unwrap_or(p);
            let is_excluded = relative.components().any(|c| {
                if let std::path::Component::Normal(name) = c {
                    let s = name.to_string_lossy();
                    s.starts_with('.') || s == "build" || s == "cmake" || s == "node_modules"
                } else {
                    false
                }
            });
            if is_excluded {
                continue;
            }

            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if ext_list.contains(&ext) {
                    cpp_files.push(p.to_string_lossy().to_string());
                }
            }
        }
    }

    if cpp_files.is_empty() {
        return Err(AppError::Custom(
            "No C++ files found in folder.".to_string(),
        ));
    }

    let path = Path::new(&folder_path);
    let project_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let analysis_id =
        crate::db::analysis_repo::save_analysis(pool, project_name.clone(), folder_path.clone())
            .await?;

    let mut all_functions = Vec::new();
    let mut total_vuln = 0;

    let provider = get_provider(client, url);

    for file_path in &cpp_files {
        let file_id =
            crate::db::analysis_repo::save_file(pool, analysis_id, file_path.clone()).await?;
        if let Ok(functions) = crate::parser::extract_functions(file_path) {
            let results = dispatch_analysis(provider.clone(), functions, 5).await?;
            for result in results {
                crate::db::analysis_repo::save_function(pool, file_id, result.clone()).await?;
                if result.verdict == "vulnerable" {
                    total_vuln += 1;
                }
                all_functions.push(result);
            }
        }
    }

    Ok(AnalysisResult {
        analysis_id: analysis_id as i32,
        project_name,
        path: folder_path,
        files_scanned: cpp_files.len() as i32,
        total_functions: all_functions.len() as i32,
        vuln_count: total_vuln,
        functions: all_functions,
    })
}
