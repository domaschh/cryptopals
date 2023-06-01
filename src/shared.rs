pub fn pad_to_length(src: &[u8], block_len: usize) -> Vec<u8> {
    if block_len == 1 || block_len == src.len() {
        src.to_vec()
    } else {
        let padding_length = block_len - (src.len() % block_len);
        let mut padded_data = src.to_vec();
        padded_data.extend(vec![padding_length as u8; padding_length]);
        padded_data
    }
}

pub fn hex_to_64(hex: impl AsRef<[u8]>) -> String {
    base64::encode(hex::decode(hex).unwrap())
}

pub fn xor_buffers(bytes1: impl AsRef<[u8]>, bytes2: impl AsRef<[u8]>) -> Vec<u8> {
    bytes1
        .as_ref()
        .iter()
        .zip(bytes2.as_ref().iter())
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect()
}

pub fn hamming_distance(str1: impl AsRef<[u8]>, str2: impl AsRef<[u8]>) -> u32 {
    str1.as_ref()
        .iter()
        .zip(str2.as_ref().iter())
        .fold(0, |acc, (&b1, &b2)| acc + (b1 ^ b2).count_ones())
}

use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, BlockModeError, Cbc, Ecb};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes128Ecb = Ecb<Aes128, Pkcs7>;

pub fn aes128_ecb_encrypt(msg: &[u8], key: &[u8]) -> Result<Vec<u8>, BlockModeError> {
    let cipher = Aes128Ecb::new_from_slices(&key, &[0; 16]).unwrap();
    let pos = msg.len();
    let mut buffer = vec![0u8; pos + 16];
    buffer[..pos].copy_from_slice(msg);
    cipher
        .encrypt(&mut buffer, msg.len())
        .and_then(|v| Ok(v.to_vec()))
}

pub fn aes128_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, BlockModeError> {
    let cipher = Aes128Ecb::new_from_slices(&key, &[0; 16]).unwrap();
    let mut buffer = ciphertext.to_vec();
    cipher.decrypt(&mut buffer).and_then(|v| Ok(v.to_vec()))
}

pub fn aes128_cbc_encrypt(msg: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, BlockModeError> {
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
    let pos = msg.len();
    let mut buffer = vec![0u8; pos + 16];
    buffer[..pos].copy_from_slice(msg);
    cipher
        .encrypt(&mut buffer, pos)
        .and_then(|v| Ok(v.to_vec()))
}

pub fn aes128_cbc_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, BlockModeError> {
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
    let mut buffer = ciphertext.to_vec();
    cipher.decrypt(&mut buffer).and_then(|v| Ok(v.to_vec()))
}
