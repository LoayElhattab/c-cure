use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Database pool error: {0}")]
    Pool(#[from] deadpool_sqlite::PoolError),
    #[error("Database interaction error: {0}")]
    Interact(#[from] deadpool_sqlite::InteractError),
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
