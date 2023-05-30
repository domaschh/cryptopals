#![feature(slice_partition_dedup)]

use std::arch::aarch64::*;
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use base64;
use hex;

const LETTER_FREQ: [f64; 27] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.19181,
];

pub fn hex_to_64(hex: &str) -> String {
    base64::encode(hex::decode(hex).unwrap())
}

pub fn xor_buffers(hex1: &str, hex2: &str) -> String {
    let bytes1 = hex::decode(hex1).unwrap();
    let bytes2 = hex::decode(hex2).unwrap();

    let xor_bytes: Vec<u8> = bytes1
        .iter()
        .zip(bytes2.iter())
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect();
    hex::encode(xor_bytes)
}

pub fn sum_letter_freq(s: &str) -> f64 {
    let mut counts = vec![0_u32; 27];
    let mut sum_score: f64 = 0_f64;

    s.chars().for_each(|c| match c {
        'a'..='z' => counts[c as usize - 97] += 1,
        'A'..='Z' => counts[c as usize - 65] += 1,
        ' ' => counts[26] += 1,
        _ => {}
    });
    for i in 0..27 {
        sum_score += (counts[i] as f64) * LETTER_FREQ[i];
    }

    sum_score
}

pub fn decipher(hex: &str) -> (String, f64) {
    let cypher_bytes = hex::decode(hex).unwrap();
    let mut message = String::new();
    let mut best_score = f64::MIN;
    for key_byte in 0..=255 {
        let msg_bytes: Vec<u8> = cypher_bytes.iter().map(|&b| b ^ key_byte).collect();

        let msg = String::from_utf8_lossy(&msg_bytes);
        let score = sum_letter_freq(&msg);

        if score > best_score {
            best_score = score;
            message = String::from(msg);
        }
    }

    (message, best_score)
}

pub fn find_encrypted(filename: &str) -> io::Result<(String, f64)> {
    use std::fs::File;
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut best: (String, f64) = ("".into(), f64::MIN);

    for line in reader.lines() {
        let line_string = &line?;
        let decpiherd = decipher(line_string);

        if decpiherd.1 > best.1 {
            best.1 = decpiherd.1;
            best.0 = decpiherd.0;
        }
    }

    return Ok(best);
}

// fn repeat_char_simd(ch: u8, n: usize) -> String {
//     // Safety: Make sure n is a multiple of 16 and ch is a valid ASCII character.
//     assert!(n % 16 == 0 && ch.is_ascii());

//     // Create a SIMD vector with the character repeated 16 times.
//     let vec = unsafe { vdupq_n_s8(ch as i8) };

//     // Create a buffer to store the repeated characters.
//     let mut buffer = vec![0; n];

//     // Use SIMD instructions to fill the buffer with repeated characters.
//     for i in (0..n).step_by(16) {
//         unsafe {
//             vst1q_s8(buffer[i..].as_mut_ptr() as *mut i8, vec);
//         }
//     }

//     // Convert the buffer into a &str slice.
//     let res = unsafe { std::str::from_utf8_unchecked(&buffer) };
//     String::from(res)
// }

fn repeating_key_encryption(message: &str, key: &str) -> String {
    let key_seq: String = key.chars().cycle().take(message.len()).collect::<String>();

    let key_bytes = key_seq.as_bytes();
    let msg_bytes = message.as_bytes();

    let xor_bytes: Vec<u8> = msg_bytes
        .iter()
        .zip(key_bytes.iter())
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect();

    hex::encode(xor_bytes)
}

fn hamming_distance(str1: &str, str2: &str) -> u32 {
    str1.as_bytes()
        .iter()
        .zip(str2.as_bytes().iter())
        .fold(0, |acc, (&b1, &b2)| acc + (b1 ^ b2).count_ones())
}

fn hamming_distance_bytes(b1: &[u8], b2: &[u8]) -> u32 {
    b1.iter()
        .zip(b2.iter())
        .fold(0, |acc, (&b1, &b2)| acc + (b1 ^ b2).count_ones())
}

fn avg_ham_dist(key_sz: usize, txt_bytes: &[u8]) -> f64 {
    let mut i: usize = 0;

    let dist_sum = txt_bytes
        .chunks(key_sz)
        .zip(txt_bytes.chunks(key_sz).skip(1))
        .fold(0, |acc: u32, (block1, block2)| {
            i += 1;
            return acc + (hamming_distance_bytes(block1, block2) / (key_sz as u32));
        });

    (dist_sum as f64) / (i as f64 + 1.0)
}

fn break_single_char_xor(xor_bytes: &[u8]) -> u8 {
    let mut key: u8 = 0;
    let mut best_score = f64::MIN;

    for key_byte in 0..255 {
        let msg_bytes: Vec<u8> = xor_bytes.iter().map(|&b| b ^ key_byte).collect();

        let msg = String::from_utf8_lossy(&msg_bytes);
        let score = sum_letter_freq(&msg);

        if score > best_score {
            best_score = score;
            key = key_byte;
        }
    }

    key
}

fn read_bytes(path: &str) -> Vec<u8> {
    let base64_s = std::fs::read_to_string(path)
        .and_then(|res| Ok(res.replace("\n", "")))
        .expect("Error reading file");
    base64::decode(base64_s).unwrap()
}

pub fn break_repeating_key_xor(path: &str) -> String {
    let text_bytes = read_bytes(path);

    let mut smalles_avg: f64 = f64::MAX;
    let mut smalles_keysize: usize = 0;
    for key_sz in 2..=40 {
        let dist = avg_ham_dist(key_sz, &text_bytes);
        if dist < smalles_avg {
            smalles_avg = dist;
            smalles_keysize = key_sz;
        }
    }

    let mut result = String::with_capacity(smalles_keysize);

    let mut idx;
    let mut ith_bytes: Vec<u8> = Vec::new();
    for i in 0..smalles_keysize {
        // Take ith byte of every block of sm_keysize len
        idx = i;
        ith_bytes.clear();
        while idx < text_bytes.len() {
            ith_bytes.push(text_bytes[idx]);
            idx += smalles_keysize;
        }

        let key_i = break_single_char_xor(&ith_bytes);
        result.push(key_i as char);
    }
    result
}
pub fn decrypt_aes(key_str: &str, path: &str) -> String {
    let base64_bytes = read_bytes(path);

    let mut blocks: Vec<GenericArray<u8, _>> = base64_bytes
        .chunks(16)
        .map(|chunk| aes::cipher::generic_array::GenericArray::clone_from_slice(chunk))
        .collect();

    // Initialize cipher
    let key = aes::cipher::generic_array::GenericArray::clone_from_slice(key_str.as_bytes());
    let cipher = Aes128::new(&key);
    cipher.decrypt_blocks(&mut blocks);

    blocks.iter().flatten().map(|&x| x as char).collect()
}

/*
* Given a file with multiple encrypted lines
* find the one most likely to be encrypted using ECB Mode
* ECB -> each cleartext block is encrypted seperately in 16
* Meaning that same clear text results in the same cipher meaning that structure is preserved
*/
pub fn detect_aes_ecb_mode(path: &str) -> (usize, usize) {
    use std::fs::File;
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let mut maxdup = 0;
    let mut line_nr = 0;

    for (i, l) in reader.lines().enumerate() {
        let line_b_hex = l.unwrap();
        let line = hex::decode(line_b_hex).unwrap();

        let chunks: Vec<_> = line.chunks(16).collect();
        let chunks_dedup: HashSet<_> = line.chunks(16).collect();
        let nr_dup = chunks.len() - chunks_dedup.len();

        if maxdup < nr_dup {
            maxdup = nr_dup;
            line_nr = i;
        }
    }
    (line_nr, maxdup)
}

pub mod onetest {
    use super::*;
    #[test]
    fn c1_sconvert_empty() {
        assert_eq!(hex_to_64(""), "");
    }

    #[test]
    fn c1_website_string_encoding() {
        assert_eq!(hex_to_64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    }

    #[test]
    fn c2_xor_buffers() {
        assert_eq!(
            xor_buffers(
                "1c0111001f010100061a024b53535009181c",
                "686974207468652062756c6c277320657965"
            ),
            "746865206b696420646f6e277420706c6179"
        )
    }
    #[test]
    fn c3_decipher_word_freq() {
        assert_eq!(
            decipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"),
            (
                String::from("Cooking MC's like a pound of bacon"),
                2.5315899999999996
            )
        )
    }

    #[test]
    fn c4_file_decipher() {
        let result = find_encrypted("encrypted.txt");
        assert_eq!(
            result.unwrap().0,
            String::from("Now that the party is jumping\n")
        )
    }

    #[test]
    fn c5_repeating_key_encryption() {
        let encrypted_result = repeating_key_encryption(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            "ICE",
        );
        assert_eq!(
            encrypted_result,
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }

    #[test]
    fn c6_hamming_distance() {
        assert_eq!(37, hamming_distance("this is a test", "wokka wokka!!!"))
    }

    #[test]
    fn c6_hamming_distance_bytes() {
        assert_eq!(
            37,
            hamming_distance_bytes("this is a test".as_bytes(), "wokka wokka!!!".as_bytes())
        )
    }

    #[test]
    fn u6_final_decrypt() {
        assert_eq!(
            "Terminator X: Bring the noise",
            break_repeating_key_xor("repkey.txt")
        )
    }

    #[test]
    fn u7_decrypt_aes() {
        let result = decrypt_aes("YELLOW SUBMARINE", "aes_ecb_mode.txt");
        println!(" {:?}", result);
        assert!(result.starts_with("I'm back"));
        assert!(result
            .ends_with("Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}"));
    }

    #[test]
    fn u8_detect_aes() {
        let result = detect_aes_ecb_mode("detect_aes_ecbmode.txt");
        assert_eq!((132, 3), result)
    }
}
