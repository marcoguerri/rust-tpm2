#![feature(with_options)]
use bytebuffer::ByteBuffer;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Error;
use std::path::Path;

// TpmRawIO implements communication with the TPM via /dev/tpm* device file
pub struct TpmRawIO {}

// Define a combined ReadWrite trait
pub trait ReadWrite: io::Read + io::Write {}
impl<T: io::Read + io::Write> ReadWrite for T {}

// Implementation of ReadWrite trait for TpmRawIO
impl io::Read for TpmRawIO {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        println!("read on TpmRawIO called");
        Ok(10)
    }
}

impl io::Write for TpmRawIO {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let file = OpenOptions::new().read(true).write(true).open("/dev/tpm0");
        let mut device_file = match file {
            Err(err) => {
                return Err(Error::new(
                    err.kind(),
                    format!("could not open /dev/tpm0: {}", err),
                ))
            }
            Ok(device_file) => device_file,
        };
        match device_file.write_all(buf) {
            Err(err) => return Err(err),
            Ok(_) => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "flush is not supported on TpmRawIO",
        ))
    }
}

// TpmDevice represents a TPM device implementing I/O operation
// via internal rw object
pub struct TpmDevice<'a> {
    pub rw: &'a mut ReadWrite,
}

// TpmDeviceOps is a trait defining operations supported by TpmDevice objects
pub trait TpmDeviceOps {
    fn send_recv(
        &mut self,
        buff_command: &ByteBuffer,
        buff_answer: &mut ByteBuffer,
    ) -> io::Result<()>;
}

impl TpmDeviceOps for TpmDevice<'_> {
    fn send_recv(
        &mut self,
        buff_command: &ByteBuffer,
        buff_answer: &mut ByteBuffer,
    ) -> io::Result<()> {
        // send output buffer and read answer back
        match self.rw.write(&buff_command.to_bytes()) {
            Err(err) => {
                return Err(Error::new(
                    err.kind(),
                    format!("could not write output buffer to TPM: {}", err),
                ))
            }
            Ok(_) => (),
        }
        let mut buff_in = Vec::new();
        match self.rw.read(&mut buff_in) {
            Err(err) => {
                return Err(Error::new(
                    err.kind(),
                    format!("could not read answer from TPM: {}", err),
                ))
            }
            Ok(_) => (),
        };
        buff_answer.write_bytes(&buff_in);
        Ok(())
    }
}
