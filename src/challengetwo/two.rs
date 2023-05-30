pub fn pad_to_length(src: &[u8], len: usize) -> Vec<u8> {
    if src.len() >= len {
        return src.into();
    } else {
        //can't use vec::with_capacity here because of min size and size differnence
        //https://stackoverflow.com/questions/63426583/performance-penalty-of-using-clone-from-slice-instead-of-copy-from-slice#:~:text=In%20Rust%2C%20there%20are%20two,the%20type%20to%20implement%20Copy%20.
        let mut new_slice = vec![0; len];
        new_slice[0..src.len()].copy_from_slice(src);
        new_slice[src.len()..len].fill(len as u8 - src.len() as u8);
        return new_slice;
    }
}

#[test]
fn u9_pad_to_length() {
    assert_eq!(vec![1, 2, 3, 2, 2], pad_to_length(&[1, 2, 3], 5));
}
