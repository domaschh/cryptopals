pub mod utils {
    pub fn xor_bytes(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
        bytes1
            .iter()
            .zip(bytes2.iter())
            .map(|(&b1, &b2)| b1 ^ b2)
            .collect()
    }
}
