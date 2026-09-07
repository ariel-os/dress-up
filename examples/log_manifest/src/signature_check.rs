//! Signature (COSE authentication block) reporting and optional verification.
use std::path::Path;

use cose::keys::CoseKey;
use cose::message::CoseMessage;
use dress_up::error::Error;

use crate::log::{log_data, log_step, log_warn};

/// Logs whether the manifest carries any COSE authentication (signature) block.
pub fn report_presence(num_signatures: usize) {
    if num_signatures == 0 {
        log_warn!(
            "no COSE authentication (signature) block present, skipping signature verification"
        );
    } else {
        log_step!("found {num_signatures} COSE authentication (signature) block(s)");
    }
}

/// Reads an EC public key from a PEM file and logs its coordinates.
///
/// Returns `None` (after logging why) when no key path is supplied; callers must then treat any
/// signature as unverified.
pub fn load_key(
    pubkey_path: Option<&Path>,
) -> Result<Option<CoseKey>, Box<dyn std::error::Error>> {
    let Some(path) = pubkey_path else {
        log_warn!(
            "no --pubkey supplied, signature content will be logged but not cryptographically verified"
        );
        return Ok(None);
    };

    log_step!("reading public key {path:?}");
    let pem = std::fs::read(path)?;
    let pub_key = openssl::ec::EcKey::public_key_from_pem(&pem)?;
    let group = pub_key.group();
    let mut x = openssl::bn::BigNum::new()?;
    let mut y = openssl::bn::BigNum::new()?;
    let mut ctx = openssl::bn::BigNumContext::new()?;
    pub_key
        .public_key()
        .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;
    log_data!("public key x: {:02x?}", x.to_vec());
    log_data!("public key y: {:02x?}", y.to_vec());

    let mut key = CoseKey::new();
    key.kty(cose::keys::EC2);
    key.alg(cose::algs::ES256);
    key.crv(cose::keys::P_256);
    key.x(x.to_vec());
    key.y(y.to_vec());
    key.key_ops(vec![cose::keys::KEY_OPS_VERIFY]);
    Ok(Some(key))
}

/// Logs a single COSE authentication block and, if a key was loaded, verifies it against the
/// signed manifest digest structure.
///
/// Mirrors the digest check: the signature and (when available) the key are printed so the
/// result can be visually confirmed, in addition to the pass/fail outcome.
pub fn verify(key: &Option<CoseKey>, cose: &[u8], payload: &[u8]) -> Result<bool, Error> {
    log_data!("signature block: {} bytes = {cose:02x?}", cose.len());
    log_data!(
        "signed payload (manifest digest structure): {} bytes = {payload:02x?}",
        payload.len()
    );

    let Some(key) = key else {
        log_warn!("no public key available, accepting signature unconditionally (testing mode)");
        return Ok(true);
    };

    let mut message = CoseMessage::new_sign();
    message.bytes = cose.to_vec();
    let verified = message
        .init_decoder(Some(payload.to_vec()))
        .and_then(|()| message.key(key))
        .and_then(|()| message.decode(None, None))
        .is_ok();

    if verified {
        log_data!("signature check: match");
    } else {
        log_warn!("signature check: MISMATCH");
    }
    Ok(verified)
}
