use std::{convert::TryInto, fmt::Display};
use hkdf::Hkdf;
use sha2::Sha384;
use scrypt::{scrypt, Params};
use rand::{RngCore, rngs::OsRng};
use aes_gcm::{aead::Aead, NewAead, Nonce};
use aes_gcm_siv::Aes256GcmSiv;
use zeroize::Zeroize;

pub const IV_LEN: usize = 12;
pub const AES_TAG_LEN: usize = 16;
pub const SALT_LEN: usize = 32;
const PASSWORD_HASH_LEN: usize = 32;
pub const MASTER_KEY_LEN: usize = 32;

pub fn generate_fingerprint(public_key: &[u8]) -> String {
    let mut raw_fingerprint = [0; 16];
    Hkdf::<Sha384>::new(None, public_key).expand(&[], &mut raw_fingerprint).unwrap();
    hex::encode(raw_fingerprint).to_uppercase()
}


pub fn generate_master_key() -> [u8; MASTER_KEY_LEN] {
    let mut master_key = [0; MASTER_KEY_LEN];
    OsRng.fill_bytes(&mut master_key);
    master_key
}

pub fn encrypt_data(data: &[u8], master_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if master_key.len() != MASTER_KEY_LEN {
        return Err(CryptoError::InvalidLength);
    }
    let cipher = Aes256GcmSiv::new_from_slice(master_key).unwrap();
    let mut iv = [0; IV_LEN];
    OsRng.fill_bytes(&mut iv); //use it for IV for now
    let mut cipher_text = iv.to_vec();
    cipher_text.extend(cipher.encrypt(Nonce::from_slice(&iv), data).unwrap());
    Ok(cipher_text)
}

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    DecryptionFailed,
    InvalidLength
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CryptoError::DecryptionFailed => "Decryption failed",
            CryptoError::InvalidLength => "Invalid length",
        })
    }
}

pub fn decrypt_data(data: &[u8], master_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() <= IV_LEN || master_key.len() != MASTER_KEY_LEN {
        return Err(CryptoError::InvalidLength);
    }
    let cipher = Aes256GcmSiv::new_from_slice(master_key).unwrap();
    match cipher.decrypt(Nonce::from_slice(&data[..IV_LEN]), &data[IV_LEN..]) {
        Ok(data) => {
            Ok(data)
        },
        Err(_) => Err(CryptoError::DecryptionFailed)
    }
}

fn scrypt_params() -> Params {
    Params::new(16, 8, 1).unwrap()
}

pub fn encrypt_master_key(mut master_key: [u8; MASTER_KEY_LEN], password: &[u8]) -> (
    [u8; SALT_LEN], //salt
    [u8; IV_LEN+MASTER_KEY_LEN+AES_TAG_LEN] //encrypted masterkey with IV
) {
    let mut salt = [0; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut password_hash = [0; PASSWORD_HASH_LEN];
    scrypt(password, &salt, &scrypt_params(), &mut password_hash).unwrap();
    let mut output = [0; IV_LEN+MASTER_KEY_LEN+AES_TAG_LEN];
    OsRng.fill_bytes(&mut output); //use it for IV for now
    let cipher = Aes256GcmSiv::new_from_slice(&password_hash).unwrap();
    let encrypted_master_key = cipher.encrypt(Nonce::from_slice(&output[..IV_LEN]), master_key.as_ref()).unwrap();
    master_key.zeroize();
    password_hash.zeroize();
    encrypted_master_key.into_iter().enumerate().for_each(|i|{
        output[IV_LEN+i.0] = i.1; //append encrypted master key to IV
    });
    (salt, output)
}

pub fn decrypt_master_key(encrypted_master_key: &[u8], password: &[u8], salt: &[u8]) -> Result<[u8; MASTER_KEY_LEN], CryptoError> {
    if encrypted_master_key.len() != IV_LEN+MASTER_KEY_LEN+AES_TAG_LEN || salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidLength);
    }
    let mut password_hash = [0; PASSWORD_HASH_LEN];
    scrypt(password, salt, &scrypt_params(), &mut password_hash).unwrap();
    let cipher = Aes256GcmSiv::new_from_slice(&password_hash).unwrap();
    let result = match cipher.decrypt(Nonce::from_slice(&encrypted_master_key[..IV_LEN]), &encrypted_master_key[IV_LEN..]) {
        Ok(master_key) => {
            if master_key.len() == MASTER_KEY_LEN {
                Ok(master_key.try_into().unwrap())
            } else {
                return Err(CryptoError::InvalidLength)
            }
        },
        Err(_) => Err(CryptoError::DecryptionFailed)
    };
    password_hash.zeroize();
    result
}
