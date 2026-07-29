//! Error types for FCEP-2

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Fcep2Error {
    #[error("MLS error: {0}")]
    Mls(String),

    #[error("Invalid envelope format: {0}")]
    InvalidEnvelope(String),

    #[error("Invalid fragment: {0}")]
    InvalidFragment(String),

    #[error("Fragment assembly failed: {0}")]
    FragmentAssembly(String),

    #[error("Base64url decode error: {0}")]
    Base64(String),

    #[error("TLS serialization error: {0}")]
    TlsCodec(String),

    #[error("Group not found: {0}")]
    GroupNotFound(String),

    #[error("Commit conflict detected for group {group_id}")]
    CommitConflict { group_id: String },

    #[error("Persistence error: {0}")]
    Persistence(String),

    #[error("KeyPackage error: {0}")]
    KeyPackage(String),

    #[error("Invalid identity: {0}")]
    InvalidIdentity(String),

    #[error("Relay error: {0}")]
    Relay(String),

    #[error("Line overflow: object too large for IRC transport")]
    LineOverflow,

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Group state lost: device must rejoin as new member")]
    StateLost,

    #[error("Late join: no valid Welcome received for group {0}")]
    LateJoin(String),
}

impl From<tls_codec::Error> for Fcep2Error {
    fn from(e: tls_codec::Error) -> Self {
        Fcep2Error::TlsCodec(e.to_string())
    }
}

impl From<base64::DecodeError> for Fcep2Error {
    fn from(e: base64::DecodeError) -> Self {
        Fcep2Error::Base64(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Fcep2Error>;
