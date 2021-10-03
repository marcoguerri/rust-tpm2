use std::io;
use std::io::{Error, ErrorKind};
use std::net::TcpStream;

// TpmSwtpmIO implements communication with the TPM via socket
pub struct TpmSwtpmIO {
    stream: Option<TcpStream>,
}

impl TpmSwtpmIO {
    pub fn new() -> Self {
        TpmSwtpmIO { stream: None }
    }
}

impl io::Read for TpmSwtpmIO {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.stream {
            None => return Err(Error::new(ErrorKind::Other, "stream not open for reading")),
            Some(s) => match s.read(buf) {
                Err(err) => return Err(err),
                Ok(n) => Ok(n),
            },
        }
    }
}

impl io::Write for TpmSwtpmIO {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream {
            None => match TcpStream::connect("localhost:2322") {
                Err(err) => {
                    return Err(Error::new(
                        err.kind(),
                        format!("could not open TPM stream connecion: {}", err),
                    ))
                }
                Ok(s) => {
                    self.stream = Some(s);
                }
            },
            Some(_) => (),
        }

        match &mut self.stream {
            None => Err(Error::new(ErrorKind::Other, "stream is not configured")),
            Some(s) => match s.write(buf) {
                Err(err) => Err(Error::new(
                    err.kind(),
                    format!("could not write buffer to TCP stream {}", err),
                )),
                Ok(_) => Ok(buf.len()),
            },
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "flush is not supported on TpmSwtpmIO",
        ))
    }
}
