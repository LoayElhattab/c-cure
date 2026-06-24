use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] duckdb::Error),
    #[error("Database client error: {0}")]
    AsyncDb(#[from] async_duckdb::Error),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Service error: {0}")]
    Service(String),
    #[error("{0}")]
    Custom(String),
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        AppError::Custom(s)
    }
}

impl From<&str> for AppError {
    fn from(s: &str) -> Self {
        AppError::Custom(s.to_string())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Service(format!("{:#}", e))
    }
}
