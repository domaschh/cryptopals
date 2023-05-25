use base64::encode;

fn hex_to_64(input: &str) -> String {
    encode(hex_to_bytes(input))
}

fn hex_to_bytes(hex_string: &str) -> Vec<u8> {
    let input_chars: Vec<_> = hex_string.chars().collect();

    input_chars
        .chunks(2)
        .map(|chunk| {
            let first_byte = chunk[0].to_digit(16).unwrap();
            let second_byte = chunk[1].to_digit(16).unwrap();
            ((first_byte << 4) | second_byte) as u8
        })
        .collect()
}

#[test]
fn convert_empty() {
    assert_eq!(hex_to_64(""), "");
}

#[test]
fn website_string_encoding() {
    assert_eq!(hex_to_64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
}
