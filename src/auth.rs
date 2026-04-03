//! SUIT authentication structure
//!
//! Packed in the manifest as bstr wrapper array.
//! Contains the digest of the manifest, and a set of authentication blocks.

use minicbor::{bytes::ByteSlice, Decoder};

use crate::{digest::SuitDigest, error::Error};
use digest::Update;

/// Authentication structure in a SUIT manifest
#[derive(Clone, Debug)]
pub(crate) struct Authentication<'a> {
    digest: &'a ByteSlice,
    decoder: Decoder<'a>,
    num_auth: usize,
}

impl<'a> Authentication<'a> {
    pub(crate) fn new(authentication: &'a ByteSlice, manifest: &ByteSlice) -> Result<Self, Error> {
        let mut decoder = Decoder::new(authentication);
        let len = decoder.array()?;
        let len = len.ok_or(Error::UnexpectedIndefiniteLength {
            position: decoder.position(),
        })?;

        // Structure must contain at least one suit_digest and one COSE auth
        if len < 2 {
            return Err(Error::InvalidAuthenticationStructure);
        }
        let digest = decoder.bytes()?;
        let mut digest_decoder = Decoder::new(digest);
        let suit_digest = digest_decoder.decode::<SuitDigest>()?;
        let mut hasher = suit_digest.hasher()?;
        hasher.update(manifest);
        if !suit_digest.match_hasher(hasher)? {
            return Err(Error::AuthenticationFailure);
        }
        Ok(Self {
            digest: digest.into(),
            decoder,
            num_auth: (len - 1) as usize,
        })
    }

    pub(crate) fn authenticate<F>(&self, authenticate: F) -> Result<(), Error>
    where
        F: Fn(&[u8], &[u8]) -> Result<bool, Error>,
    {
        let mut decoder = self.decoder.clone();
        for _ in 0..self.num_auth {
            let auth_block = decoder.bytes()?;
            let res = authenticate(auth_block, self.digest)?;
            if res {
                return Ok(());
            }
        }
        Err(Error::AuthenticationFailure)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn auth_decode() {
        // Very dummy manifest
        let manifest: &[u8] = &std::vec![];
        let input: &[u8] = &std::vec![
            0x82, 0x58, 0x24, 0x82, 0x2F, 0x58, 0x20, 0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C,
            0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64,
            0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55, 0x40,
        ];

        let auth = Authentication::new(input.into(), manifest.into()).unwrap();
        assert_eq!(auth.num_auth, 1);

        let res = auth.authenticate(|_cose, _payload| Ok(true));
        assert_eq!(res, Ok(()));

        let res = auth.authenticate(|_cose, _payload| Ok(false));
        assert_eq!(res, Err(Error::AuthenticationFailure));
    }
}
