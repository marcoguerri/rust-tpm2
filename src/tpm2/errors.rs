use std::error::Error;
use std::fmt;

// TpmError represents a generic error occurrend while carrying
// out TPM operations.
#[derive(Debug)]
pub enum TpmError {
    Serialization(String),
    Deserialization(String),
    Generic(String),
}

impl Error for TpmError {}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TpmError::Serialization(msg) => {
                write!(f, "serialization error for TMP operation: {}", msg)
            }
            TpmError::Deserialization(msg) => {
                write!(f, "deserialization error for TPM operation: {}", msg)
            }
            TpmError::Generic(msg) => {
                write!(f, "generic TPM error: {}", msg)
            }
        }
    }
}

// TpmCommandError represents an error code raised while issuing
// a command to the TPM.
pub enum TpmCommandError {}
