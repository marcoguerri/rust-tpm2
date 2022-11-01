use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct TpmError {
    pub msg: String,
}

impl Error for TpmError {}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TpmError: {}", self.msg)
    }
}

// TpmIoError is an error encountered while talking to the TPM
#[derive(Debug)]
pub struct TpmIoError {
    pub msg: String,
}

impl Error for TpmIoError {}

impl fmt::Display for TpmIoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TpmIoError: {}", self.msg)
    }
}

// TpmCommandError wraps a TPM error code
#[derive(Debug)]
pub struct TpmCommandError {
    pub error_code: u32,
}

impl Error for TpmCommandError {}

impl fmt::Display for TpmCommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TpmCommandError: {:02x?}", self.error_code)
    }
}

// SerializationError indicates an error while serializing a TPM command
#[derive(Debug)]
pub struct SerializationError {
    pub msg: String,
}

impl Error for SerializationError {}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SerializationError: {}", self.msg)
    }
}

// DeserializationError indicates an error while deserializing a TPM command
#[derive(Debug)]
pub struct DeserializationError {
    pub msg: String,
}

impl Error for DeserializationError {}

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SerializationError: {}", self.msg)
    }
}

// TpmStructFormatError indicates that a TPM struct is not properly formatted
#[derive(Debug)]
pub struct TpmStructFormatError {
    pub msg: String,
}

impl Error for TpmStructFormatError {}

impl fmt::Display for TpmStructFormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TpmStructFormatError: {}", self.msg)
    }
}

// RunCommandError is an error raised while running a command towards the TPM
#[derive(Debug)]
pub enum RunCommandError {
    TpmIoError(TpmIoError),
    TpmCommandError(TpmCommandError),
}
