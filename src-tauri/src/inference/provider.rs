use std::future::Future;
use std::pin::Pin;
use anyhow::Result;
use crate::db::FunctionData;

pub trait InferenceProvider: Send + Sync {
    fn check_health(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
    fn analyze_function<'a>(
        &'a self,
        code: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<FunctionData>> + Send + '_>>;
}
