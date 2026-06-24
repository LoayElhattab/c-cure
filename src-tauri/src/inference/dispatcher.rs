use super::provider::InferenceProvider;
use crate::db::FunctionData;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

pub async fn dispatch_analysis(
    provider: Arc<dyn InferenceProvider>,
    functions: Vec<crate::parser::ExtractedFunction>,
    max_concurrency: usize,
) -> Result<Vec<FunctionData>> {
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut join_set = JoinSet::new();

    for fn_info in functions {
        let provider = provider.clone();
        let semaphore = semaphore.clone();

        join_set.spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let mut result = provider.analyze_function(&fn_info.code).await?;
            result.function_name = fn_info.function_name;
            result.code = fn_info.code;
            result.start_line = Some(fn_info.start_line);
            result.end_line = Some(fn_info.end_line);
            Ok::<FunctionData, anyhow::Error>(result)
        });
    }

    let mut results = Vec::new();
    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(Ok(fn_data)) => results.push(fn_data),
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(anyhow::anyhow!("Task failed: {}", e)),
        }
    }

    Ok(results)
}
