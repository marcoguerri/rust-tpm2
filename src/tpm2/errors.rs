use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct TpmError {
    pub msg: String,
}

impl Error for TpmError {}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TpmError: {}", self.msg)
    }
}
