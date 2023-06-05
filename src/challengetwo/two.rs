use crate::{
    shared::{aes128_cbc_encrypt, aes128_ecb_encrypt, pad_to_length},
    utils::utils,
};
use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt},
    Aes128, NewBlockCipher,
};

// [1,2,3], 2 -> [1,2,3,1]
// [1,2,3,4] 3 -> [1,2,3,4,2,2]
// [1,2,3,4,5,6,7] -> [1,2,3,4,5,6,7,2,2]

pub fn encrypt_aes_cbc(
    message: impl AsRef<[u8]>,
    key_str: impl AsRef<[u8]>,
    iv_str: u8,
    block_size: usize,
) -> String {
    let msg_bytes = pad_to_length(message.as_ref(), block_size);
    let iv: Vec<u8> = std::iter::repeat(iv_str).take(block_size).collect();

    let key = GenericArray::clone_from_slice(key_str.as_ref());
    let cipher = <Aes128 as aes::NewBlockCipher>::new(&key);

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

pub fn encrypt_aes_cbc2(message: &mut Vec<u8>, key: [u8; 16], iv: [u8; 16]) {
    *message = pad_to_length(message, 16);
    let cipher = Aes128::new(GenericArray::from_slice(&key));

    let mut previous_block_encrypted: &[u8] = &iv;
    for block in message.chunks_exact_mut(16) {
        block
            .iter_mut()
            .zip(previous_block_encrypted)
            .for_each(|(a, b)| *a ^= b);
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
        previous_block_encrypted = block;
    }
}

pub fn decrypt_aes_cbc(message: &mut Vec<u8>, key_str: [u8; 16], iv_str: [u8; 16]) {
    let cipher = Aes128::new(GenericArray::from_slice(&key_str));
    println!("Hallo {:?}", message);

    let result: Vec<u8> = (0..message.len())
        .step_by(16)
        .map(|x| {
            // Take last of encrypted block or IV in case of first block iteration
            let last = if x == 0 { &iv_str } else { &message[x - 16..x] };

            // Decrypt AES
            let mut block = GenericArray::clone_from_slice(&message[x..x + 16]);
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
    *message = result
        .into_iter()
        .take(message.len() - padding_byte)
        .collect()
}

pub fn decrypt_aes_cbc2(message: &mut Vec<u8>, key_str: [u8; 16], iv: [u8; 16]) {
    let cipher = Aes128::new(GenericArray::from_slice(&key_str));
    let mut previous_block_encrypted: Vec<u8> = iv.into();

    for block in message.chunks_exact_mut(16) {
        let mut ga_block = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut ga_block);
        let tmp = block.into();

        block
            .iter_mut()
            .zip(ga_block.iter())
            .zip(previous_block_encrypted.iter())
            .for_each(|((a, b), c)| *a = b ^ c);

        previous_block_encrypted = tmp;
    }
    let last = *message.last().unwrap_or(&0);
    let uncut_len = message.len();
    message.truncate(uncut_len - last as usize);
}

use rand::Rng;

#[derive(Debug, PartialEq)]
pub enum EncryptionMode {
    ECB,
    CBC,
}

fn random_encryption(msg: &[u8]) -> (Vec<u8>, EncryptionMode) {
    let mut rng = rand::thread_rng();
    let use_ecb: bool = rand::random();
    let rand_key = std::iter::repeat(rng.gen_range(0..255)).take(16);
    let rand_iv = std::iter::repeat(rng.gen_range(0..255)).take(16);

    let n_prepend = rand::thread_rng().gen_range(0..=10);
    let prepend_bytes = std::iter::repeat(n_prepend as u8).take(n_prepend);
    let n_append = rand::thread_rng().gen_range(0..=10);
    let append_bytes = std::iter::repeat(n_append as u8).take(n_append);

    let msg_bytes: Vec<u8> = prepend_bytes
        .chain(msg.iter().copied())
        .chain(append_bytes)
        .collect();

    let mode: EncryptionMode;
    let cipherbytes;
    if use_ecb {
        mode = EncryptionMode::ECB;
        cipherbytes = aes128_ecb_encrypt(&msg_bytes, &rand_key.collect::<Vec<u8>>()).unwrap();
    } else {
        cipherbytes = aes128_cbc_encrypt(
            &msg_bytes,
            &rand_key.collect::<Vec<u8>>(),
            &rand_iv.collect::<Vec<u8>>(),
        )
        .unwrap();
        mode = EncryptionMode::CBC;
    }

    (cipherbytes, mode)
}

#[cfg(test)]
mod test {
    use crate::challengetwo::two::pad_to_length;

    use super::{decrypt_aes_cbc, decrypt_aes_cbc2, encrypt_aes_cbc2};
    #[test]
    fn test_c10() {
        let mut msg = "Some secret message";

        let mut message: Vec<u8> = msg.as_bytes().into();
        let key = "YELLOW SUBMARINE";
        let iv = "\x00".repeat(16);
        let ivslice: [u8; 16] = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        encrypt_aes_cbc2(&mut message, ivslice, ivslice);
        decrypt_aes_cbc2(&mut message, ivslice, ivslice);
        assert_eq!(&message, "Some secret message".as_bytes());
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
