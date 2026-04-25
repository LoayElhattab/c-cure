use super::provider::InferenceProvider;
use crate::db::FunctionData;
use anyhow::Result;
use reqwest::Client;
use std::future::Future;
use std::pin::Pin;

pub struct KaggleProvider {
    client: Client,
    url: String,
}

impl KaggleProvider {
    pub fn new(client: Client, url: String) -> Self {
        Self { client, url }
    }
}

impl InferenceProvider for KaggleProvider {
    fn check_health(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            if self.url.is_empty() {
                return false;
            }
            if let Ok(resp) = self
                .client
                .get(&self.url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
            {
                resp.status().is_success()
            } else {
                false
            }
        })
    }

    fn analyze_function<'a>(
        &'a self,
        code: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<FunctionData>> + Send + '_>> {
        Box::pin(async move {
            if self.url.is_empty() {
                return Err(anyhow::anyhow!(
                    "Kaggle API URL not configured (check settings)"
                ));
            }

            let body = serde_json::json!({ "code": code });
            let resp = self
                .client
                .post(format!("{}/predict", self.url))
                .json(&body)
                .timeout(std::time::Duration::from_secs(60))
                .send()
                .await?;

            if !resp.status().is_success() {
                return Err(anyhow::anyhow!("API returned error: {}", resp.status()));
            }

            let json: serde_json::Value = resp.json().await?;
            let mut confidence = 0.0;
            let mut output_str = String::new();

            if let Some(result) = json.get("result") {
                if let Some(conf) = result.get("confidence") {
                    confidence = conf
                        .get("value")
                        .and_then(|v| v.as_f64())
                        .unwrap_or_else(|| conf.as_f64().unwrap_or(0.0));
                } else if let Some(conf) = json.get("confidence") {
                    confidence = conf.as_f64().unwrap_or(0.0);
                }

                if let Some(out) = result.get("output") {
                    if let Some(s) = out.as_str() {
                        output_str = s.to_string();
                    } else if let Some(arr) = out.as_array() {
                        if !arr.is_empty() {
                            output_str = arr[0].as_str().unwrap_or("").to_string();
                        }
                    }
                } else if let Some(s) = result.as_str() {
                    output_str = s.to_string();
                }
            } else if let Some(out) = json.get("output") {
                if let Some(conf) = json.get("confidence") {
                    confidence = conf.as_f64().unwrap_or(0.0);
                }
                if let Some(s) = out.as_str() {
                    output_str = s.to_string();
                } else if let Some(arr) = out.as_array() {
                    if !arr.is_empty() {
                        output_str = arr[0].as_str().unwrap_or("").to_string();
                    }
                }
            }

            if output_str.to_lowercase() == "code is safe" || output_str.to_lowercase() == "safe" {
                return Ok(FunctionData {
                    id: None,
                    function_name: "".into(),
                    code: "".into(),
                    verdict: "safe".into(),
                    cwe: None,
                    cwe_name: None,
                    severity: None,
                    confidence: Some(confidence),
                    start_line: None,
                    end_line: None,
                });
            }

            let cwe_info = super::get_cwe_info(&output_str);

            Ok(FunctionData {
                id: None,
                function_name: "".into(),
                code: "".into(),
                verdict: if output_str.is_empty() {
                    "safe".into()
                } else {
                    "vulnerable".into()
                },
                cwe: Some(output_str),
                cwe_name: cwe_info.0,
                severity: cwe_info.1,
                confidence: Some(confidence),
                start_line: None,
                end_line: None,
            })
        })
    }
}
