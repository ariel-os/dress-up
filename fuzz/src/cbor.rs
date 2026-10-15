use crate::consts::cbor;

pub fn cbor_bstr_header(len: usize) -> Vec<u8> {
    // Major type 2 (byte string): initial byte is 0b010_aaaaa == 0x40 + additional info
    if len <= 23 {
        // additional info = len
        vec![cbor::bstr_len_small(len as u8)]
    } else if len <= 0xff {
        // additional info = 24, followed by 1-byte length
        vec![cbor::BSTR_LEN_U8, len as u8]
    } else if len <= 0xffff {
        // additional info = 25, followed by 2-byte length (big-endian)
        vec![
            cbor::BSTR_LEN_U16,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]
    } else if len <= 0xffff_ffff {
        // additional info = 26, followed by 4-byte length (big-endian)
        let n = len as u32;
        vec![
            cbor::BSTR_LEN_U32,
            ((n >> 24) & 0xff) as u8,
            ((n >> 16) & 0xff) as u8,
            ((n >> 8) & 0xff) as u8,
            (n & 0xff) as u8,
        ]
    } else if (len as u128) <= 0xffff_ffff_ffff_ffffu128 {
        // additional info = 27, followed by 8-byte length (big-endian)
        let n = len as u64;
        vec![
            cbor::BSTR_LEN_U64,
            ((n >> 56) & 0xff) as u8,
            ((n >> 48) & 0xff) as u8,
            ((n >> 40) & 0xff) as u8,
            ((n >> 32) & 0xff) as u8,
            ((n >> 24) & 0xff) as u8,
            ((n >> 16) & 0xff) as u8,
            ((n >> 8) & 0xff) as u8,
            (n & 0xff) as u8,
        ]
    } else {
        panic!("byte string too large for CBOR definite-length encoding");
    }
}
