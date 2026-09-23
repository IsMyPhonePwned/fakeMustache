use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("policy error: {0}")]
    Policy(String),
    #[error("parse failure: {0}")]
    Parse(String),
    #[error("unhandled member (fail-closed): {0}")]
    UnhandledMember(String),
    #[error("residual PII detected: {0}")]
    ResidualPii(String),
    #[error("vault error: {0}")]
    Vault(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("unsupported archive kind")]
    UnsupportedArchive,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitHint {
    Clean = 0,
    ResidualPii = 1,
    UnhandledMember = 2,
    ParseFailure = 3,
}
