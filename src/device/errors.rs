use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct DeviceIoError {
    pub msg: String,
}

impl Error for DeviceIoError {}

impl fmt::Display for DeviceIoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DeviceIoError: {}", self.msg)
    }
}

impl From<std::io::Error> for DeviceIoError {
    fn from(e: std::io::Error) -> Self {
        Self { msg: e.to_string() }
    }
}
