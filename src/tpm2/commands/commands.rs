// tpm2_pcr_read command
struct PcrReadCommand<'a> {
    tag: TpmiStCommandTag,
    command_size: u32,
    command_code: TpmCc,
    pcr_selection_in: TpmlPcrSelection<'a>,
}

impl Tpm2StructOut for PcrReadCommand<'_> {
    fn pack(&self, buff: &mut ByteBuffer) {
        self.tag.pack(buff);
        self.command_size.pack(buff);
        self.command_code.pack(buff);
        self.pcr_selection_in.pack(buff);
    }
}

// tpm2_pcr_read response
struct PcrReadResponse<'a> {
    tag: TpmiStCommandTag,
    response_size: u32,
    response_code: TpmCc,
    random_bytes: Tpm2bDigest<'a>,
    pcr_update_counter: u32,
    pcr_selection_in: TpmlPcrSelection<'a>,
    pcr_values: TpmlDigest<'a>,
}

impl Tpm2StructIn for PcrReadResponse<'_> {
    fn unpack(&self, buff: &mut ByteBuffer) -> result::Result<(), TpmError> {
        Ok(())
    }
}
