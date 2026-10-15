use crate::{
    cbor::cbor_bstr_header,
    consts::{cbor, cose::HashAlg, labels, suit},
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use shake::{ExtendableOutput, Shake128, Shake256, Update, XofReader};

fn calc_hash(data: &[u8], alg: &HashAlg) -> Vec<u8> {
    match alg {
        HashAlg::Sha256 => Sha256::digest(data).to_vec(),
        HashAlg::Sha384 => Sha384::digest(data).to_vec(),
        HashAlg::Sha512 => Sha512::digest(data).to_vec(),
        HashAlg::Shake128 => {
            let mut hasher = Shake128::default();
            hasher.update(data);

            let mut reader = hasher.finalize_xof();
            let mut out = [0u8; 32];
            reader.read(&mut out);

            out.to_vec()
        }
        HashAlg::Shake256 => {
            let mut hasher = Shake256::default();
            hasher.update(data);

            let mut reader = hasher.finalize_xof();
            let mut out = [0u8; 64];
            reader.read(&mut out);

            out.to_vec()
        }
    }
}

/// Generate valid SUIT Authentication Block.
///
/// Calculates hash digest of manifest and wraps it in SUIT digest container
fn gen_auth(manifest: &[u8], alg: HashAlg) -> Vec<u8> {
    // --- manifest hash ---
    let mut man: Vec<u8> = vec![];
    man.extend(cbor_bstr_header(manifest.len())); // add length header of manifest
    man.extend(manifest); // manifest itself

    // hash the manifest
    let man_hash = calc_hash(&man, &alg);

    // --- digest container ---
    let mut digest_cont: Vec<u8> = vec![];
    digest_cont.push(cbor::array(2)); // Array with 2 fields
    digest_cont.push(alg.val()); // digest algorithm
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
pub fn build_envelope(manifest: &[u8], alg: HashAlg) -> Vec<u8> {
    let auth_block = gen_auth(manifest, alg);

    // --- envelope header ---
    let mut envlp: Vec<u8> = vec![];
    envlp.extend(suit::MANIFEST_TAG); // Tag for SUIT Manifest
    envlp.push(cbor::map(2)); // map with 2 entries

    // --- auth block header ---
    envlp.push(labels::envelope_elements::AUTHENTICATION_WRAPPER); // envelop key "Authentication"
    envlp.extend(cbor_bstr_header(auth_block.len())); // auth block length

    // --- auth block ---
    envlp.extend_from_slice(&auth_block);

    // --- manifest header ---
    envlp.push(labels::envelope_elements::MANIFEST); // envelop key "Manifest"
    envlp.extend(cbor_bstr_header(manifest.len())); // manifest length

    // --- inner manifest ---
    envlp.extend_from_slice(manifest);

    envlp
}
