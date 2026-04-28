#![no_std]
#![allow(dead_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(missing_docs)]

//! Dress‑Up provides a parser-only implementation of the [SUIT][suit-rfc] manifest format,
//! for `no_std` environments. It relies on [minicbor] for CBOR parsing.
//! Dress‑Up parses CBOR on the fly during manifest execution and is zero-copy.
//!
//! Dress‑Up is OS-agnostic, it provides an [`OperatingHooks`] trait that allow an operating system
//! to provide integration into the manifest processing.
//! While Dress‑Up is developed under the Ariel OS banner, it is not tied to Ariel OS.
//!
//! The full manifest must be in memory during parsing. The authentication object covers the inner
//! manifest. Both must be in memory for the authentication process. The other reason is that
//! Dress‑Up is zero-copy. All text and byte strings are references into the CBOR data.
//!
//! Dress‑Up only supports sequential processing of components. Each component described in a
//! manifest processes serially. This saves the amount of memory required during the manifest
//! processing.
//!
//! ## Supported RFC features
//!
//! Dress‑Up supports the following features from the SUIT manifest specification:
//!
//! - Multiple components
//!
//! Dress‑Up does not yet support the following features:
//!
//! - Severable elements
//! - Reporting policy
//!
//! Dress‑Up will never support the following features. These are out of scope:
//!
//! - Parallel processing
//! - Manifest creation
//!
//! ### SUIT command support
//!
//! Dress‑Up strives to support all commands of the SUIT specification.
//! The commands from the table below are currently supported.
//!
//! | Command               |    |
//! |:----------------------|----|
//! | Vendor Identifier     | ✅ |
//! | Class Identifier      | ✅ |
//! | Image Match           | ✅ |
//! | Component Slot        | ✅ |
//! | Check Content         | ✅ |
//! | Set Component Index   | ✅ |
//! | Abort                 | ✅ |
//! | Try Each              | ✅ |
//! | Write Content         | ✅ |
//! | Override Parameters   | ✅ |
//! | Fetch                 | ✅ |
//! | Copy                  | 🚧 |
//! | Invoke                | 🚧 |
//! | Device Identifier     | ✅ |
//! | Swap                  | 🚧 |
//! | Run Sequence          | 🚧 |
//! | Custom commands       | 🚧 |
//!
//! ### Parameter support
//!
//! Dress‑Up supports the following parameters
//!
//! | Parameter             |    |
//! |:----------------------|----|
//! | Vendor ID             | ✅ |
//! | Class ID              | ✅ |
//! | Image Digest          | ✅ |
//! | Component Slot        | ✅ |
//! | Strict Order          | ❌ |
//! | Soft Failure          | 🚧 |
//! | Image Size            | ✅ |
//! | Content               | ✅ |
//! | URI                   | ✅ |
//! | Source Component      | 🚧 |
//! | Invoke Args           | 🚧 |
//! | Device ID             | ✅ |
//!
//! ## Overview
//!
//! This section gives a brief overview of the primary types in this crate.
//!
//! - [`SuitManifest`]: This starts the SUIT manifest parsing. Contains the functions required to
//!   check manifest validity. The [`Envelope`] structure derives from this.
//! - [`Envelope`]: Describes the SUIT Envelope structure. The Envelope contains both the
//!   authentication object and the manifest itself.
//! - [`manifest::Manifest`]: Contains the inner SUIT manifest. It provides access to the command
//!   sequences in the manifest.
//! - [`OperatingHooks`]: This trait provides the interface to the operating system functions
//!   required by Dress‑Up. The operating system or application running Dress‑Up must provide an
//!   implementation.
//!
//! ## Workflow
//!
//! A typical flow with Dress‑Up consists of multiple steps:
//!
//! 1. Start the parsing by creating a [`SuitManifest`].
//! 2. Authenticate the manifest via [`SuitManifest::authenticate`].
//! 3. Derive the [`Envelope`] from the [`SuitManifest`] via [`SuitManifest::envelope`].
//! 4. Deriver the inner [`Manifest`] from the [`Envelope`] via [`Envelope::manifest`].
//! 5. check the existence of different command sequences and execute them when available.
//!
//! ## Example
//!
//! ```
//! use cbor_edn::StandaloneItem;
//! use dress_up::SuitManifest;
//! # use minicbor::bytes::ByteSlice;
//! # use dress_up::error::Error;
//! # fn authenticate(_cose: &[u8], _auth: &[u8]) -> Result<bool, Error> {
//! #    Ok(true)
//! # }
//!
//! let input = &r#"
//! 107({
//!         / authentication-wrapper / 2:<< [
//!             / digest: / << [
//!                 / algorithm-id / -16 / "sha256" /,
//!                 / digest-bytes /
//! h'1f2e7acca0dc2786f2fe4eb947f50873a6a3cfaa98866c5b02e621f42074daf2'
//!             ] >>,
//!             / signature: / << 18([
//!                 / protected / << {
//!                     / alg / 1:-7 / "ES256" /
//!                 } >>,
//!                 / unprotected / {
//!                 },
//!                 / payload / null / nil /,
//!                 / signature / h'27a3d7986eddcc1bee04e1436746408c308ed3
//! c15ac590a1ca0cf96f85671ccac216cb9a1497fc59e21c15f33c95cf75203e25c287b3
//! 1a57d6cd2ef950b27a7a'
//!             ]) >>
//!         ] >>,
//!         / manifest / 3:<< {
//!             / manifest-version / 1:1,
//!             / manifest-sequence-number / 2:1,
//!             / common / 3:<< {
//!                 / components / 2:[
//!                     [h'00']
//!                 ],
//!                 / shared-sequence / 4:<< [
//!                     / directive-override-parameters / 20,{
//!                         / vendor-id /
//! 1:h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-
//! be9d-e663e4d41ffe /,
//!                         / class-id /
//! 2:h'1492af1425695e48bf429b2d51f2ab45' /
//! 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
//!                         / image-digest / 3:<< [
//!                             / algorithm-id / -16 / "sha256" /,
//!                             / digest-bytes /
//! h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
//!                         ] >>,
//!                         / image-size / 14:34768
//!                     },
//!                     / condition-vendor-identifier / 1,15,
//!                     / condition-class-identifier / 2,15
//!                 ] >>
//!             } >>,
//!             / validate / 7:<< [
//!                 / condition-image-match / 3,15
//!             ] >>,
//!             / install / 20:<< [
//!                 / directive-override-parameters / 20,{
//!                     / uri / 21:"http://example.com/file.bin"
//!                 },
//!                 / directive-fetch / 21,2,
//!                 / condition-image-match / 3,15
//!             ] >>
//!         } >>
//!     })
//! "#;
//!
//! let cbor = StandaloneItem::parse(input).unwrap().to_cbor().unwrap();
//! let suit = SuitManifest::from_bytes(&cbor);
//! let suit = suit.authenticate(|cose, payload| { authenticate(cose, payload) })?;
//! let envelope = suit.envelope()?;
//! let manifest = envelope.manifest()?;
//!
//! assert_eq!(manifest.version()?, 1);
//! assert_eq!(manifest.sequence_number()?, 1);
//! # Ok::<(), Error>(())
//! ```
//! [suit-rfc]: https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest-34
use core::marker::PhantomData;

use generic_array::ArrayLength;
use minicbor::bytes::ByteSlice;
use minicbor::decode::Decoder;

use uuid::Uuid;

pub mod auth;
mod cbor;
pub mod command;
pub mod component;
pub mod consts;
pub mod digest;
pub mod error;
pub mod manifest;
pub mod manifeststate;
pub mod operatinghooks;
pub mod report;

use crate::auth::Authentication;
use crate::cbor::SubCbor;
use crate::consts::*;
use crate::error::Error;
use crate::manifest::Manifest;

pub use crate::operatinghooks::OperatingHooks;

/// Authentication state of the manifest
pub trait AuthState {}
/// Manifest is new.
#[derive(Debug)]
pub struct New;
/// Manifest is authenticated.
#[derive(Debug)]
pub struct Authenticated;

impl AuthState for New {}
impl AuthState for Authenticated {}

/// Represent the full SUIT manifest.
///
/// The starting point of parsing a SUIT manifest
#[derive(Clone)]
pub struct SuitManifest<'a, S: AuthState> {
    decoder: Decoder<'a>,
    phantom: PhantomData<S>,
}

/// SUIT envelope.
///
/// Processes the elements inside the SUIT envelope.
#[derive(Clone)]
pub struct Envelope<'a, S: AuthState> {
    decoder: Decoder<'a>,
    phantom: PhantomData<S>,
}

impl<'a, S: AuthState> SuitManifest<'a, S> {
    /// Retrieve the envelope of the manifest.
    pub fn envelope(&self) -> Result<Envelope<'a, S>, Error> {
        let mut decoder = self.decoder.clone();
        let position = decoder.position();
        let tag = decoder.tag()?;
        if tag != SUIT_TAG_ENVELOPE {
            return Err(Error::UnexpectedCbor { position });
        }
        Ok(Envelope {
            decoder,
            phantom: PhantomData,
        })
    }
}

impl<'a> SuitManifest<'a, New> {
    /// Create a SUIT manifest from a byte slice.
    pub fn from_bytes(bytes: &'a impl AsRef<[u8]>) -> Self {
        Self {
            decoder: Decoder::new(bytes.as_ref()),
            phantom: PhantomData,
        }
    }

    /// Authenticate a manifest.
    pub fn authenticate<F>(self, authenticate: F) -> Result<SuitManifest<'a, Authenticated>, Error>
    where
        F: Fn(&[u8], &[u8]) -> Result<bool, Error>,
    {
        let envelope = self.envelope()?;
        // Consists of a bstr wrapped digest + *bstr wrapped auth blocks
        let manifest = envelope.get_object_wrapped(SuitEnvelope::Manifest)?;
        let auth_object = envelope.get_object(SuitEnvelope::Authentication)?;

        match (auth_object, manifest) {
            (None, _) => Err(Error::NoAuthObject),
            (_, None) => Err(Error::NoManifestObject),
            (Some(auth_object), Some(manifest)) => {
                let auth_object = Authentication::new(auth_object, manifest)?;
                auth_object.authenticate(authenticate)?;
                Ok(SuitManifest::<Authenticated> {
                    decoder: self.decoder,
                    phantom: PhantomData,
                })
            }
        }
    }
}

impl<'a> SuitManifest<'a, Authenticated> {}

impl<'a, S: AuthState> Envelope<'a, S> {
    fn get_object(&self, search_key: SuitEnvelope) -> Result<Option<&'a ByteSlice>, Error> {
        let mut decoder = self.decoder.clone();
        Ok(decoder
            .map_iter::<i16, &ByteSlice>()?
            .find_map(|item| match item {
                Ok((key, item)) if key == search_key.into() => Some(item),
                _ => None,
            }))
    }

    fn get_object_wrapped(&self, search_key: SuitEnvelope) -> Result<Option<&'a ByteSlice>, Error> {
        let mut decoder = self.decoder.clone();
        let position = decoder.position();
        let len = decoder.map()?.ok_or(Error::UnexpectedCbor { position })?;
        for _ in 0..len {
            let key = decoder.i16()?;
            if key == search_key.into() {
                let buffer = decoder.sub_cbor()?;
                return Ok(Some(buffer.into()));
            } else {
                decoder.skip()?;
            }
        }
        Ok(None)
    }

    /// Retrieve the raw authentication object.
    ///
    /// Returns a reference to a byte slice containing the CBOR-encoded authentication object.
    pub fn auth_object(&self) -> Result<&'a ByteSlice, Error> {
        let auth_object = self.get_object(SuitEnvelope::Authentication)?;
        auth_object.ok_or(Error::NoAuthObject)
    }

    /// Retrieve the manifest object as CBOR.
    ///
    /// Returns a reference to a byte slice containing the CBOR-encoded manifest.
    ///
    /// See [`Envelope::manifest`] for retrieving a [`manifest::Manifest`] to operate on the manifest.
    pub fn manifest_bytes(&self) -> Result<&'a ByteSlice, Error> {
        let manifest_object = self.get_object(SuitEnvelope::Manifest)?;
        manifest_object.ok_or(Error::NoManifestObject)
    }

    /// Retrieve the inner manifest.
    pub fn manifest(&self) -> Result<Manifest<'a, S>, Error> {
        let manifest_bytes = self.manifest_bytes()?;
        Ok(Manifest::<S>::from_bytes(manifest_bytes))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    extern crate std;

    use cose::{keys::CoseKey, message::CoseMessage};

    fn build_key(pub_key: std::vec::Vec<u8>) -> CoseKey {
        // Parse EC public key into coordinates
        let pub_key = openssl::ec::EcKey::public_key_from_pem(&pub_key).unwrap();
        let coordinates = pub_key.public_key();
        let group = pub_key.group();
        let mut x = openssl::bn::BigNum::new().unwrap();
        let mut y = openssl::bn::BigNum::new().unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        coordinates
            .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
            .unwrap();

        let mut key = CoseKey::new();
        key.kty(cose::keys::EC2);
        key.alg(cose::algs::ES256);
        key.crv(cose::keys::P_256);
        key.x(x.to_vec());
        key.y(y.to_vec());
        key.key_ops(std::vec![cose::keys::KEY_OPS_VERIFY]);
        key
    }

    #[test]
    fn test_verify() {
        const PUB_KEY: &str = "
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhJaBGq4LqqvSYVcYnuzaJr6qi/Eb
bz/m4rVlnIXbwK07HypLbAmBMcCjbazR14vTgdzfsJwFLbM5kdtzOLSolg==
-----END PUBLIC KEY-----
";

        let manifest = hex::decode(
            "d86ba2025873825824822f58206658ea560262696dd1f13b782239a064da\
             7c6c5cbaf52fded428a6fc83c7e5af584ad28443a10126a0f65840408d08\
             16f9b510749bf6a51b066951e08a4438f849eb092a1ac768eed9de696c1b\
             1dd35d82ef149e6a73a61976ad2cfe78444b8064293350a122f332cb49f0\
             da035871a50101020003585fa202818141000458568614a40150fa6b4a53\
             d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45\
             035824822f582000112233445566778899aabbccddeeff0123456789abcd\
             effedcba98765432100e1987d0010f020f074382030f0943821702",
        )
        .unwrap();

        let manifest = SuitManifest::from_bytes(&manifest);
        let key = build_key(std::vec::Vec::from(PUB_KEY));
        let _ = manifest
            .authenticate(|cose, payload| {
                let mut verify = CoseMessage::new_sign();
                verify.bytes = cose.to_vec();
                verify
                    .init_decoder(Some(payload.to_vec()))
                    .map_err(|_| Error::AuthenticationFailure)?;
                verify.key(&key).map_err(|_| Error::AuthenticationFailure)?;
                verify
                    .decode(None, None)
                    .map_err(|_| Error::AuthenticationFailure)?;
                Ok(true)
            })
            .unwrap();
    }
}
