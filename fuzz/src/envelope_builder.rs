use crate::consts::{cbor, cose, suit};
use sha2::{Digest, Sha256};

fn cbor_bstr_header(len: usize) -> Vec<u8> {
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

/// Generate valid SUIT Authentication Block.
///
/// Calculates hash digest of manifest and wraps it in SUIT digest container
fn gen_auth(manifest: &[u8]) -> Vec<u8> {
    // --- manifest hash ---
    let mut man: Vec<u8> = vec![];
    man.extend(cbor_bstr_header(manifest.len())); // add length header of manifest
    man.extend(manifest); // manifest itself

    // hash the manifest TODO: implement oher hash algs
    let man_hash = Sha256::digest(man);

    // --- digest container ---
    let mut digest_cont: Vec<u8> = vec![];
    digest_cont.push(cbor::array(2)); // Array with 2 fields
    digest_cont.push(cose::ALG_SHA_256); // digest algorithm (here Sha256) TODO: implement other hash algs
    digest_cont.extend(cbor_bstr_header(man_hash.len())); // length header for manifest hash
    digest_cont.extend(man_hash); // actual hash from manifest

    // --- auth block ---
    let mut auth_block: Vec<u8> = vec![];
    auth_block.push(cbor::array(2)); // Array with 2 fields
    auth_block.extend(cbor_bstr_header(digest_cont.len())); // length of digest
    auth_block.extend(digest_cont); // digest block

    // --- COSE ---
    auth_block.push(cbor::BSTR_MAJOR_BASE); // empty bstr (placeholder for COSE block)

    auth_block
}

/// Build SUIT Envelope for inner manifest.
///
/// Generates SUIT Authentication Block and wraps it with the inner manifest in syntactically valid
/// SUIT Envelope (**with empty COSE block**).
pub fn build_envelope(manifest: &[u8]) -> Vec<u8> {
    let auth_block = gen_auth(manifest);

    // --- envelope header ---
    let mut envlp: Vec<u8> = vec![];
    envlp.extend(suit::MANIFEST_TAG); // Tag for SUIT Manifest
    envlp.push(cbor::map(2)); // map with 2 entries

    // --- auth block header ---
    envlp.push(suit::ENVLP_AUTHENTICATION); // envelop key "Authentication"
    envlp.extend(cbor_bstr_header(auth_block.len())); // auth block length

    // --- auth block ---
    envlp.extend_from_slice(&auth_block);

    // --- manifest header ---
    envlp.push(suit::ENVLP_MANIFEST); // envelop key "Manifest"
    envlp.extend(cbor_bstr_header(manifest.len())); // manifest length

    // --- inner manifest ---
    envlp.extend_from_slice(manifest);

    envlp
}
