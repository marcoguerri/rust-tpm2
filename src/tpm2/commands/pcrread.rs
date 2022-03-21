use crate::device::raw;
use crate::device::raw::TpmDeviceOps;
use crate::device::tcp;
use crate::tpm2::commands::commands::CommandHeader;
use crate::tpm2::commands::commands::ResponseHeader;
use crate::tpm2::commands::pcrs::PCRSelection;
use crate::tpm2::commands::pcrs::PCRs;
use crate::tpm2::commands::pcrs::MAX_PCR;
use crate::tpm2::errors;
use crate::tpm2::serialization::inout;
use crate::tpm2::serialization::inout::RwBytes;
use crate::tpm2::serialization::inout::Tpm2StructIn;
use crate::tpm2::serialization::inout::Tpm2StructOut;
use crate::tpm2::types::tcg;
use std::mem;
use std::result;

// TPM2_PCR_Read command
pub struct PcrReadCommand {
    header: CommandHeader,
    pcr_selection_in: tcg::TpmlPcrSelection,
}

impl PcrReadCommand {
    // new creates a new PcrReadCommand object based on tag and
    // TPML_PCR_SELECTION structure
    pub fn new(
        tag: tcg::TpmiStCommandTag,
        pcr_selection: tcg::TpmlPcrSelection,
    ) -> result::Result<Self, errors::TpmError> {
        let mut buff = inout::StaticByteBuffer::new();
        pcr_selection.pack(&mut buff);
        let pcr_selection_size = buff.to_bytes().len();

        if pcr_selection_size > u32::MAX as usize {
            errors::TpmError::Generic(format!(
                "pcr_selection size ({})is too big (max: {})",
                pcr_selection_size,
                u32::MAX,
            ));
        }

        Ok(PcrReadCommand {
            header: CommandHeader::new(
                tag,
                mem::size_of::<tcg::TpmiStCommandTag>() as u32
                    + mem::size_of::<u32>() as u32
                    + mem::size_of::<tcg::TpmCc>() as u32
                    + pcr_selection_size as u32,
                tcg::TPM_CC_PCR_READ,
            ),
            pcr_selection_in: pcr_selection,
        })
    }
}

impl inout::Tpm2StructOut for PcrReadCommand {
    fn pack(&self, buff: &mut dyn inout::RwBytes) {
        self.header.pack(buff);
        self.pcr_selection_in.pack(buff);
    }
}

// TPM2_PCR_Read response
pub struct PcrReadResponse {
    header: ResponseHeader,
    pcr_update_counter: u32,
    pcr_selection_in: tcg::TpmlPcrSelection,
    pcr_values: tcg::TpmlDigest,
}

impl inout::Tpm2StructIn for PcrReadResponse {
    fn unpack(&mut self, buff: &mut dyn inout::RwBytes) -> result::Result<(), errors::TpmError> {
        match self.header.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        match self.pcr_update_counter.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }

        match self.pcr_selection_in.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }

        match self.pcr_values.unpack(buff) {
            Err(err) => return Err(err),
            _ => (),
        }
        Ok(())
    }
}

impl PcrReadResponse {
    // new builds a PcrReadResponse structure from a a bytes buffer
    pub fn new(buff: &mut dyn inout::RwBytes) -> result::Result<Self, errors::TpmError> {
        let mut resp = PcrReadResponse {
            header: ResponseHeader::new(),
            pcr_update_counter: 0,
            pcr_selection_in: tcg::TpmlPcrSelection::new(),
            pcr_values: tcg::TpmlDigest::new(),
        };
        let unpack_result = resp.unpack(buff);
        match unpack_result {
            Ok(_) => Ok(resp),
            Err(error) => Err(error),
        }
    }

    // to_pcr_values turns TpmlPcrSelection and TpmlDigest structures into
    // a PCRValues
    pub fn to_pcr_values(&self) -> result::Result<PCRs, errors::TpmError> {
        let mut pcrs: PCRs = PCRs::new();

        for tpms_selection in &self.pcr_selection_in.pcr_selections {
            // TpmsPcrSelection for a specific algorithm as specified by tpms_selection.hash
            for (index, pcr_bitmap) in tpms_selection.pcr_select.iter().enumerate() {
                // For each byte bitmap in TpmsPcrSelection.pcr_select, decode which
                // PCR is being referenced and de-serialize the corresponding
                // TpmlDigest, which can carry at most 8 Tpm2bDigest structures
                for n in 0..self.pcr_values.num_digests() {
                    if pcr_bitmap >> n & 0x1 == 0x1 {
                        match self.pcr_values.get_digest(n) {
                            Ok(digest) => {
                                pcrs.add(
                                    tpms_selection.hash,          // algorithm
                                    n + 8 * index as u32,         // pcr register number
                                    digest.get_buffer().to_vec(), // digest
                                );
                            }
                            Err(err) => {
                                return Err(errors::TpmError {
                                    msg: format!("cannot get digest number {}", err.to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(pcrs)
    }
}

// tpm2_pcr_read issues a TPM2_PCR_Read command with a PCR selection based on input PCRSelection
// Response structure holds a TpmlDigest structure which can hold at most 8 Tpm2bDigest.
// Therefore, we need to issue multiple commands with TpmsPcrSelection configured accordingly.
pub fn tpm2_pcr_read(selection: &[PCRSelection]) -> result::Result<PCRs, errors::TpmError> {
    let mut tpm_device: raw::TpmDevice = raw::TpmDevice {
        rw: &mut tcp::TpmSwtpmIO::new(),
    };

    let mut all_pcrs: PCRs = PCRs::new();

    for pcr_selection in selection {
        let mut pcr_map = [0x00, 0x00, 0x00];
        let mut pcr_count = 0;

        for (index, pcr) in pcr_selection.get_pcrs().iter().enumerate() {
            if *pcr > (MAX_PCR as u8) {
                return Err(errors::TpmError {
                    msg: format!(
                        "pcr register requested {} is beyond the maximum supported pcr {}",
                        pcr, MAX_PCR
                    ),
                });
            }

            let pcr_map_index: usize = (pcr / 8) as usize;
            pcr_map[pcr_map_index] = pcr_map[pcr_map_index] | (0x1 << pcr % 8);
            pcr_count += 1;

            // issue the command if we reached the maximum numer of PCRs
            // per TpmlDigest or if we have reeached the end of the
            // pcr_selection data structure
            let mut pcr_selections = [tcg::TpmsPcrSelection::new(); 16];
            pcr_selections[0] = tcg::TpmsPcrSelection {
                hash: pcr_selection.get_algo(),
                sizeof_select: 3,
                pcr_select: pcr_map,
            };
            if pcr_count == 8 || index == pcr_selection.get_pcrs().len() - 1 {
                let pcr_selection = tcg::TpmlPcrSelection {
                    count: 1,
                    pcr_selections: pcr_selections,
                };

                let cmd_pcr_read = match PcrReadCommand::new(tcg::TPM_ST_NO_SESSION, pcr_selection)
                {
                    Ok(cmd_pcr_read) => cmd_pcr_read,
                    Err(error) => return Err(error),
                };

                let mut buffer = inout::StaticByteBuffer::new();
                inout::pack(&[cmd_pcr_read], &mut buffer);

                let mut resp_buffer = inout::StaticByteBuffer::new();
                match tpm_device.send_recv(&mut buffer, &mut resp_buffer) {
                    Err(err) => {
                        return Err(errors::TpmError {
                            msg: err.to_string(),
                        })
                    }
                    _ => (),
                }
                let resp = PcrReadResponse::new(&mut resp_buffer);
                match resp {
                    Ok(pcr_read_response) => match pcr_read_response.to_pcr_values() {
                        Ok(pcrs) => all_pcrs.merge(pcrs.get_map()),
                        Err(err) => return Err(err),
                    },
                    Err(err) => return Err(err),
                };

                pcr_map = [0x00, 0x00, 0x00];
                pcr_count = 0;
            }
        }
    }

    println!("{}", all_pcrs);

    Err(errors::TpmError {
        msg: "not implemented".to_string(),
    })
}
