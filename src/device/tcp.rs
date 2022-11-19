use std::io;
use std::io::{Error, ErrorKind};
use std::net::TcpStream;
use crate::device::errors;

// TpmSwtpmIO implements communication with the TPM via socket
pub struct TpmSwtpmIO {
    pub stream: Option<TcpStream>,
}

impl TpmSwtpmIO {
    pub fn new() -> Self {
        TpmSwtpmIO { stream: None }
    }
}

impl io::Read for TpmSwtpmIO {
    fn read(&mut self, buf: &mut [u8]) -> result::Result<usize, errors::DeviceIoError> {
        match &mut self.stream {
            None => {
                return Err(errors::DeviceIoError {
                    msg: "stream not open for reading".to_string(),
                })
            }
            Some(s) => {
                let n = s.read(buf)?;
                Ok(n)
            }
        }
    }
}

impl io::Write for TpmSwtpmIO {
    fn write(&mut self, buf: &[u8]) -> result::Result<usize, errors::DeviceIoError> {
        match self.stream {
            None => match TcpStream::connect("localhost:2322") {
                Err(err) => {
                    return Err(errors::DeviceIoError {
                        msg: format!("could not open TPM stream connecion: {}", err),
                    })
                }
                Ok(s) => {
                    self.stream = Some(s);
                }
            },
            Some(_) => (),
        }

        match &mut self.stream {
            None => Err(errors::DeviceIoError {
                msg: "stream is not configured for writing ".to_string(),
            }),
            Some(s) => {
                let n = s.write(buf)?
            },
        }
    }

    fn flush(&mut self) -> result::Result<usize, errors::DeviceIoError> {
        Err(errors::DeviceIoError {
            msg: "flush is not supported on TpmSwtpmIO".to_string(),
        })
    }
}
