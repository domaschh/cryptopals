use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};

pub fn pad_to_length(src: &[u8], len: usize) -> Vec<u8> {
    if src.len() >= len {
        return src[0..16].into();
    } else {
        //can't use vec::with_capacity here because of min size and size differnence
        //https://stackoverflow.com/questions/63426583/performance-penalty-of-using-clone-from-slice-instead-of-copy-from-slice#:~:text=In%20Rust%2C%20there%20are%20two,the%20type%20to%20implement%20Copy%20.
        let mut new_slice = vec![0; len];
        new_slice[0..src.len()].copy_from_slice(src);
        new_slice[src.len()..len].fill(len as u8 - src.len() as u8);
        return new_slice;
    }
}

pub fn encrypt_aes_block_str(block: &str, key_str: &str, last: &str) -> Vec<u8> {
    let padded_block = pad_to_length(block.as_bytes(), 16);
    let padded_last = pad_to_length(last.as_bytes(), 16);
    let mut xored: Vec<_> = padded_last
        .iter()
        .zip(padded_block.iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect();

    let key = GenericArray::clone_from_slice(key_str.as_bytes());
    let mut block = GenericArray::clone_from_slice(&xored);
    let cipher = aes::Aes128::new(&key);
    cipher.encrypt_block(&mut block);

    block.into_iter().collect::<Vec<_>>()
}

pub fn encrypt_aes_block(block: &[u8], key_str: &[u8], last: &[u8]) -> Vec<u8> {
    let padded_block = pad_to_length(block, 16);
    let padded_last = pad_to_length(last, 16);
    let mut xored: Vec<_> = padded_last
        .iter()
        .zip(padded_block.iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect();

    let key = GenericArray::clone_from_slice(key_str);
    let mut block = GenericArray::clone_from_slice(&xored);
    let cipher = aes::Aes128::new(&key);
    cipher.encrypt_block(&mut block);

    block.into_iter().collect::<Vec<_>>()
}

pub fn encrypt_with_aes(text: &str, iv_key: u8, key: &str) -> Vec<u8> {
    let mut last: Vec<u8> = std::iter::repeat(iv_key).take(16).collect();
    text.as_bytes()
        .chunks(16)
        .for_each(|chunk| last = encrypt_aes_block(chunk, key.as_bytes(), &last));
    last
}

#[test]
fn u9_pad_to_length() {
    assert_eq!(vec![1, 2, 3, 2, 2], pad_to_length(&[1, 2, 3], 5));
}

#[test]
fn u10_encrypt_aes_block() {
    let result = encrypt_aes_block_str("hallo", "YELLOW SUBMARINE", "hallo");
    assert_eq!(
        result,
        &[118, 209, 203, 75, 175, 162, 70, 226, 227, 175, 3, 93, 108, 19, 195, 114]
    )
}
#[test]
fn u10_encrypt_aes() {
    // println!(
    //     "from utf{:?}",
    //     std::str::from_utf8(&[193, 52, 7, 4, 160, 35, 212, 99, 65, 139, 150, 251, 170, 254, 153])
    //         .unwrap()
    // );
    let result = encrypt_with_aes("Hallo wie geht es dir", 10, "YELLOW SUBMARINE");
    assert_eq!(
        result,
        &[193, 52, 7, 4, 160, 35, 239, 212, 99, 65, 139, 150, 251, 170, 254, 153],
    );
}
