//! Manual digest inspection, independent from (but consistent with) the digest check performed
//! internally by `dress-up`'s `SuitManifest::authenticate`.
use minicbor::Decoder;

use crate::log::{log_data, log_step, log_warn};

/// Builds the canonical CBOR byte-string header for a byte string of the given length.
///
/// The manifest field is a `bstr .cbor SUIT_Manifest`, and its digest is computed over this
/// header followed by the manifest content, not the content alone.
fn bstr_header(len: usize) -> Vec<u8> {
    match len {
        0..=23 => vec![0x40 + len as u8],
        24..=0xff => vec![0x58, len as u8],
        0x100..=0xffff => {
            let mut header = vec![0x59];
            header.extend_from_slice(&(len as u16).to_be_bytes());
            header
        }
        _ => {
            let mut header = vec![0x5a];
            header.extend_from_slice(&(len as u32).to_be_bytes());
            header
        }
    }
}

/// Hashes `data` with the algorithm identified by a COSE algorithm id, if supported here.
fn hash(algo_id: i64, data: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    use sha2::Digest;
    match algo_id {
        -16 => Some(("sha-256", sha2::Sha256::digest(data).to_vec())),
        -43 => Some(("sha-384", sha2::Sha384::digest(data).to_vec())),
        -44 => Some(("sha-512", sha2::Sha512::digest(data).to_vec())),
        _ => None,
    }
}

/// Parses the raw authentication object, prints the manifest digest read from it next to the
/// digest recomputed locally over the manifest bytes, and returns the number of COSE
/// authentication (signature) blocks found alongside it.
pub fn check(
    auth_object: &[u8],
    manifest_bytes: &[u8],
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut decoder = Decoder::new(auth_object);
    let len = decoder
        .array()?
        .ok_or("authentication object has indefinite length")?;
    let num_signatures = usize::try_from(len.saturating_sub(1))?;

    let digest_bytes = decoder.bytes()?;
    let mut digest_decoder = Decoder::new(digest_bytes);
    if digest_decoder.array()? != Some(2) {
        return Err("unexpected digest structure".into());
    }
    let algo_id = digest_decoder.i64()?;
    let manifest_digest = digest_decoder.bytes()?;

    log_step!("checking manifest digest");
    log_data!("digest algorithm id: {algo_id}");
    log_data!("digest read from manifest:   {manifest_digest:02x?}");

    let mut wrapped = bstr_header(manifest_bytes.len());
    wrapped.extend_from_slice(manifest_bytes);
    match hash(algo_id, &wrapped) {
        Some((name, computed)) => {
            log_data!("digest computed locally ({name}): {computed:02x?}");
            if computed == manifest_digest {
                log_data!("digest check: match");
            } else {
                log_warn!("digest check: MISMATCH");
            }
        }
        None => log_warn!(
            "digest algorithm {algo_id} is not supported by this example, skipping local recomputation"
        ),
    }

    Ok(num_signatures)
}
