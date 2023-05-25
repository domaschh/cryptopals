use std::io::{self, BufRead, BufReader};

use base64;
use hex;

const LETTER_FREQ: [f64; 27] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.19181, // V-Z & space char
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
    }
}
