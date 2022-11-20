use std::io;
use std::io::{Error, ErrorKind};
use std::net::TcpStream;
use std::result;

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
    fn read(&mut self, buf: &mut [u8]) -> result::Result<usize, std::io::Error> {
        match &mut self.stream {
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "stream not open for reading".to_string(),
                ))
            }
            Some(s) => {
                let n = s.read(buf)?;
                Ok(n)
            }
        }
    }
}

impl io::Write for TpmSwtpmIO {
    fn write(&mut self, buf: &[u8]) -> result::Result<usize, std::io::Error> {
        match self.stream {
            None => {
                let stream = TcpStream::connect("localhost:2322")?;
                self.stream = Some(stream);
            }
            Some(_) => (),
        }

        match &mut self.stream {
            None => Err(Error::new(
                ErrorKind::Other,
                "stream is not configured for writing ".to_string(),
            )),
            Some(s) => {
                let n = s.write(buf)?;
                Ok(n)
            }
        }
    }

    fn flush(&mut self) -> result::Result<(), std::io::Error> {
        Err(Error::new(
            ErrorKind::Other,
            "flush is not supported on TpmSwtpmIO".to_string(),
        ))
    }
}
