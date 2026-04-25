pub mod config;
pub mod dispatcher;
pub mod kaggle;
pub mod mock;
pub mod provider;

use serde::{Deserialize, Serialize};
use crate::db::FunctionData;

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisResult {
    pub analysis_id: i32,
    pub project_name: String,
    pub path: String,
    pub files_scanned: i32,
    pub total_functions: i32,
    pub vuln_count: i32,
    pub functions: Vec<FunctionData>,
}

pub use config::{load_kaggle_url, save_kaggle_url};
pub use provider::InferenceProvider;
pub use kaggle::KaggleProvider;
pub use mock::MockProvider;
pub use dispatcher::dispatch_analysis;

pub fn get_cwe_info(cwe: &str) -> (Option<String>, Option<String>) {
    match cwe {
        "CWE-125" => (Some("Out-of-bounds Read".into()), Some("High".into())),
        "CWE-787" => (Some("Out-of-bounds Write".into()), Some("Critical".into())),
        "CWE-190" => (
            Some("Integer Overflow or Wraparound".into()),
            Some("High".into()),
        ),
        "CWE-369" => (Some("Divide By Zero".into()), Some("Medium".into())),
        "CWE-415" => (Some("Double Free".into()), Some("High".into())),
        "CWE-476" => (Some("NULL Pointer Dereference".into()), Some("High".into())),
        _ => (Some("Unknown".into()), Some("Unknown".into())),
    }
}

pub fn get_provider(client: reqwest::Client, url: String) -> std::sync::Arc<dyn InferenceProvider> {
    if std::env::var("MOCK_API").unwrap_or_default() == "true" {
        std::sync::Arc::new(MockProvider)
    } else {
        std::sync::Arc::new(KaggleProvider::new(client, url))
    }
}
