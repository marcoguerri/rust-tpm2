// TpmRawIO implements communication with the TPM via /dev/tpm* device file
struct TpmRawIO {}

// Define a combined ReadWrite trait
trait ReadWrite: io::Read + io::Write {}
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
        println!("write on TpmRawIO called");
        Ok(10)
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
struct TpmDevice<'a> {
    rw: &'a ReadWrite,
}

// TpmDeviceOps is a trait defining operations supported by TpmDevice objects
trait TpmDeviceOps {
    fn send_recv(&self, buff_out: &ByteBuffer, buff_in: &mut ByteBuffer);
}

impl TpmDeviceOps for TpmDevice<'_> {
    fn send_recv(&self, buff_out: &ByteBuffer, buff_in: &mut ByteBuffer) {
        println!("send_recv was called, all good at this point");
    }
}
