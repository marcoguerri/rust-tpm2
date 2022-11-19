use std::error::Error;
use std::fmt;

// IoError is an error encountered while talking to the TPM
#[derive(Debug)]
pub struct IoError {
    pub msg: String,
}

impl Error for IoError {}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IoError: {}", self.msg)
    }
}

// ResponseError wraps a TPM error code
#[derive(Debug)]
pub struct ResponseError {
    pub error_code: u32,
}

impl Error for ResponseError {}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ResponseError: {:02x?}", self.error_code)
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

// InputParameterError indicates an error in input parameter
#[derive(Debug)]
pub struct InputParameterError {
    pub msg: String,
}

impl Error for InputParameterError {}

impl fmt::Display for InputParameterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "InputParameterError: {}", self.msg)
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

// CommandError is an error raised while running a command towards the TPM
#[derive(Debug)]
pub enum CommandError {
    IoError(IoError),
    ResponseError(ResponseError),
    DeserializationError(DeserializationError),
    InputParameterError(InputParameterError),
}

impl Error for CommandError {}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CommandError: {}", self)
    }
}
impl From<DeserializationError> for CommandError {
    fn from(err: DeserializationError) -> Self {
        CommandError::DeserializationError(err)
    }
}

// TpmError indicates a generic TPM error
#[derive(Debug)]
pub struct TpmError {
    pub msg: String,
}

impl Error for TpmError {}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TpmError: {}", self)
    }
}
