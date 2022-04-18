use crate::tpm2::types::tcg;
use pem::parse;
use rsa;
use rsa::pkcs8::DecodePublicKey;

/*

* TPM2B_DATA: the optional symmetric encryption key used as the inner wrapper. Could be very well
* null at this point
* TPM2B_PUBLIC: the public area of the object to be imported
* TPM2B_PRIVATE: symmetrically encrypted duplicate object that may contain an inner symmetric
* wrapper. This is used to decrypt the inner blob. The TPMT_SYM_DEF_OBJECT defines the
* symmetric algorithm used for the inner wrapper.
*
* TPM2B_ENCRYPTED_SECRET: the seed of the symmetric key and HMAC key:
*   if this is specified, the asymmetric parameters and private key of parentHandle are used to
*   recover the seed. So, the seed shoulD BE ENCRYpted with the parentHandle asymmetric parameters.
*   The symmetric key obtained is used to decrypt the data blob.
* TPMT_SYM_DEF_OBJECT: definition for the symmetric algorithm to use for the inner wrapper
*
*
* Rough outline of TPM2_Import algorithm:
*
* if TPMT_SYM_DEF_OBJECT is not null
    TPM2B_DATA contains the encryption key for the inner wrapper
* TPM2B_ENCRYPTED_SECRET inSymSeed is the seed for the outer wrapper, which is encrpyted with the parent,
* which must be able to do key exhange (so, the parent object cannot be a Symmetric algorithM)
* The inSymSeed is decrypted with parent object.
* Compute then the name of TPM2B_PUBLIC object, based on the public area.
* Use inSymSeed to generate private key to retrieve content of TPM2B_PRIVATE. If an inner wrapper
* was specified, the the object needs to be further encrypted with TPM2B_DATA from
* TPMT_SYM_DEF_OBJECT
*/

/*
 *
 * Steps to be implemented:
 * Create public area of the object to be importated
 * Create private area, i.e. TPM2B_PRIVATE
 * Create RSA or ECC seed based on EK type. The seed needs to be encrypted with EK public key
 * Create duplicate object, i.e. TPM2B_PRIVATE
 * Encrypt the secret using the symmetric seed, obtaining TPM2B_ENCRYPTED_SECRET
 * Create HMAC over the encrypted secret, and the name built over the public area
 * Profit
 *
 * */

const SAMPLE: &'static str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmxvJXDAr3S7+/uc32zLf
+hSpB5LNY94IYrUXytIn6pU1yT6WIivyAdwuwF3lU76eC/HbGERTqczVqZ2Twmh3
ONLViFGERfNQ5H7j/krl9evo9DEpZeD6g3hQ40uLLHX0pc4pzB7xV/8Xg9CCCkO2
36p+9mXUtJBLfYNwP5S9fcz9ajv17i/WsddLh06y1D7FN3YWK0jWKoVNa3Wht21U
tiumXn8kNTfVPZ4c2sC4asrTBj4aTyrwPyj2gC4hwvNHXdKv5rqoSlFUSYY/Z42Y
/GFOh7XcNHTYWLDdcvce83SUxrNDdLQBLw3bJlTmyQOrMTRdhrzITq80iialY6xs
pwIDAQAB
-----END PUBLIC KEY-----
";

pub fn tpm2_import() {
    println!("Hello world from import path..");

    let pem_result = parse(SAMPLE);
    match pem_result {
        Ok(_) => (),
        Err(err) => panic!("pem error"),
    }
    let pem = pem_result.unwrap();
    println!("{}", pem.tag);

    // Create TPM2B_PUBLIC, i.e. EK public key area
    //
    // pub struct Tpm2BPublic {
    //  size: u16,
    //  public: TpmtPublic,
    //}
    //
    let public_key_result = rsa::RsaPublicKey::from_public_key_pem(SAMPLE);
    match public_key_result {
        Ok(_) => (),
        Err(rr) => panic!("pem error"),
    }
    let public_key = public_key_result.unwrap();

    let sensitive: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    // Create the duplicate (TPM2B_PRIVATE) object
    let duplicate = tcg::Tpm2bPrivate::new_data_object(&public_key);
    // Create the objectPublic (TPM2B_PUBLIC) object
    let public = tcg::Tpm2bPublic::new_data_object(&public_key, &sensitive);
}
