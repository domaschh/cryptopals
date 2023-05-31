use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

use crate::utils::utils;

// [1,2,3], 2 -> [1,2,3,1]
// [1,2,3,4] 3 -> [1,2,3,4,2,2]
// [1,2,3,4,5,6,7] -> [1,2,3,4,5,6,7,2,2]
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

pub fn encrypt_aes_cbc(message: &str, key_str: &str, iv_str: u8, block_size: usize) -> String {
    let msg_bytes = pad_to_length(message.as_bytes(), block_size);
    let iv: Vec<u8> = std::iter::repeat(iv_str).take(block_size).collect();

    let key = GenericArray::clone_from_slice(key_str.as_bytes());
    let cipher = Aes128::new(&key);

    let result = msg_bytes
        .chunks(block_size)
        .scan(iv, |last_encr, chunk| {
            let xor_block = utils::xor_bytes(last_encr, chunk);
            let mut block = GenericArray::clone_from_slice(&xor_block);
            cipher.encrypt_block(&mut block);
            let encrypted = block.into_iter().collect::<Vec<u8>>();

            *last_encr = encrypted.clone();
            Some(encrypted)
        })
        .flatten()
        .collect::<Vec<u8>>();

    hex::encode(result)
}

pub fn decrypt_aes_cbc(cipher_hex: &str, key_str: &str, iv_str: u8, block_size: usize) -> String {
    let encrypted_bytes = hex::decode(cipher_hex).unwrap();
    let key = GenericArray::clone_from_slice(key_str.as_bytes());
    let iv: Vec<u8> = std::iter::repeat(iv_str).take(block_size).collect();

    let cipher = Aes128::new(&key);

    let result: Vec<u8> = (0..encrypted_bytes.len())
        .step_by(16)
        .map(|x| {
            // Take last of encrypted block or IV in case of first block iteration
            let last = if x == 0 {
                &iv
            } else {
                &encrypted_bytes[x - 16..x]
            };

            // Decrypt AES
            let mut block = GenericArray::clone_from_slice(&encrypted_bytes[x..x + 16]);
            cipher.decrypt_block(&mut block);
            let decrypted_block = block.into_iter().collect::<Vec<u8>>();

            // XOR decrypted block with last encrypted block to undo xor during encryption
            let xor_block = utils::xor_bytes(last, &decrypted_block);
            xor_block
        })
        .flatten()
        .collect();

    // Get number of padding bytes applied during encryption & remove padding
    let padding_byte = *result.last().unwrap() as usize;
    result
        .into_iter()
        .take(encrypted_bytes.len() - padding_byte)
        .map(|x| x as char)
        .collect::<String>()
}

#[cfg(test)]
mod test {
    use crate::challengetwo::two::pad_to_length;

    use super::{decrypt_aes_cbc, encrypt_aes_cbc};
    #[test]
    fn test_c10() {
        let msg = "Some secret message";
        let key = "YELLOW SUBMARINE";
        let iv = "\x00".repeat(16);

        let encrypted_msg_hex = encrypt_aes_cbc(msg, key, '\x00' as u8, 16);
        let decrypted_msg = decrypt_aes_cbc(encrypted_msg_hex.as_str(), key, '\x00' as u8, 16);
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn u9_pad_to_length2() {
        assert_eq!(vec![1, 2, 3], pad_to_length(&[1, 2, 3], 1));
        assert_eq!(vec![1, 2, 3], pad_to_length(&[1, 2, 3], 3));
        assert_eq!(vec![1, 2, 3, 1], pad_to_length(&[1, 2, 3], 2));
        assert_eq!(vec![1, 2, 3, 1], pad_to_length(&[1, 2, 3], 4));
        assert_eq!(vec![1, 2, 3, 1], pad_to_length(&[1, 2, 3], 4));
        assert_eq!(vec![1, 2, 3, 2, 2], pad_to_length(&[1, 2, 3], 5));
        assert_eq!(vec![1, 2, 3, 4, 2, 2], pad_to_length(&[1, 2, 3, 4], 3));
    }
}
