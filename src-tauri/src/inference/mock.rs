use super::provider::InferenceProvider;
use crate::db::FunctionData;
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

pub struct MockProvider;

impl InferenceProvider for MockProvider {
    fn check_health(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move { true })
    }

    fn analyze_function<'a>(
        &'a self,
        code: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<FunctionData>> + Send + '_>> {
        Box::pin(async move {
            let is_vulnerable =
                code.contains("strcpy") || code.contains("malloc") || code.contains("gets");
            if is_vulnerable {
                let (cwe_name, severity) = super::get_cwe_info("CWE-787");
                return Ok(FunctionData {
                    id: None,
                    function_name: "".into(),
                    code: "".into(),
                    verdict: "vulnerable".into(),
                    cwe: Some("CWE-787".into()),
                    cwe_name,
                    severity,
                    confidence: Some(0.85),
                    start_line: None,
                    end_line: None,
                });
            } else {
                return Ok(FunctionData {
                    id: None,
                    function_name: "".into(),
                    code: "".into(),
                    verdict: "safe".into(),
                    cwe: None,
                    cwe_name: None,
                    severity: None,
                    confidence: Some(0.95),
                    start_line: None,
                    end_line: None,
                });
            }
        })
    }
}
