#![no_std]
#![allow(dead_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Dress-Up provides a parser-only implementation of the [SUIT][suit-rfc] manifest format,
//! for `no_std` environments.
//!
//! 🚧 This crate is still under heavy construction 🚧
//!
//! ## Overview
//!
//! ## Example
//!
//! ```
//! use cbor_edn::StandaloneItem;
//! use dress_up::SuitManifest;
//!
//! let input = &r#"
//! 107({
//!        / authentication-wrapper / 2:<< [
//!            / digest: / << [
//!                / algorithm-id / -16 / "sha256" /,
//!                / digest-bytes /
//!h'1f2e7acca0dc2786f2fe4eb947f50873a6a3cfaa98866c5b02e621f42074daf2'
//!            ] >>,
//!            / signature: / << 18([
//!                / protected / << {
//!                    / alg / 1:-7 / "ES256" /
//!                } >>,
//!                / unprotected / {
//!                },
//!                / payload / null / nil /,
//!                / signature / h'27a3d7986eddcc1bee04e1436746408c308ed3
//!c15ac590a1ca0cf96f85671ccac216cb9a1497fc59e21c15f33c95cf75203e25c287b3
//!1a57d6cd2ef950b27a7a'
//!            ]) >>
//!        ] >>,
//!        / manifest / 3:<< {
//!            / manifest-version / 1:1,
//!            / manifest-sequence-number / 2:1,
//!            / common / 3:<< {
//!                / components / 2:[
//!                    [h'00']
//!                ],
//!                / shared-sequence / 4:<< [
//!                    / directive-override-parameters / 20,{
//!                        / vendor-id /
//!1:h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-
//!be9d-e663e4d41ffe /,
//!                        / class-id /
//!2:h'1492af1425695e48bf429b2d51f2ab45' /
//!1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
//!                        / image-digest / 3:<< [
//!                            / algorithm-id / -16 / "sha256" /,
//!                            / digest-bytes /
//!h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
//!                        ] >>,
//!                        / image-size / 14:34768
//!                    },
//!                    / condition-vendor-identifier / 1,15,
//!                    / condition-class-identifier / 2,15
//!                ] >>
//!            } >>,
//!            / validate / 7:<< [
//!                / condition-image-match / 3,15
//!            ] >>,
//!            / install / 20:<< [
//!                / directive-override-parameters / 20,{
//!                    / uri / 21:"http://example.com/file.bin"
//!                },
//!                / directive-fetch / 21,2,
//!                / condition-image-match / 3,15
//!            ] >>
//!        } >>
//!    })
//!"#;
//!
//!let cbor = StandaloneItem::parse(input).unwrap().to_cbor().unwrap();
//!let suit = SuitManifest::from_bytes(&cbor);
//! ```
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
pub mod report;

use crate::auth::Authentication;
use crate::cbor::SubCbor;
use crate::consts::*;
use crate::error::Error;
use crate::manifest::Manifest;

/// Authentication state of the manifest
pub trait AuthState {}
/// Manifest is new.
#[derive(Debug)]
pub struct New;
/// Manifest has been authenticated.
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

/// A trait to expose operating system functionality to the SUIT manifest parsing
///
/// A SUIT manifest contains a set of check and directives to verify the applicability of the
/// payload, retrieve the payload and install payload. Often this requires input from the operating
/// system.
pub trait OperatingHooks {
    type ReadWriteBufferSize: ArrayLength;

    /// Match the vendor ID from the manifest.
    ///
    /// Installations without multiple components can ignore the `component` parameter.
    fn match_vendor_id(&self, uuid: Uuid, component: &component::Component) -> Result<bool, Error>;

    /// Match the class ID from the manifest.
    ///
    /// Installations without multiple components can ignore the `component` parameter.
    fn match_class_id(&self, uuid: Uuid, component: &component::Component) -> Result<bool, Error>;

    /// Match the device ID from the manifest.
    ///
    /// Installations without multiple components can ignore the `component` parameter.
    fn match_device_id(
        &self,
        _uuid: Uuid,
        _component: &component::Component,
    ) -> Result<bool, Error> {
        Err(Error::UnsupportedCommand(
            SuitCommand::DeviceIdentifier.into(),
        ))
    }

    /// Verify that the component slot index of the supplied component is valid
    ///
    /// Some components can have multiple slots to install into. This condition allows the
    /// to verify that the target slot is valid.
    fn match_component_slot(
        &self,
        _component: &component::Component,
        _component_slot: u64,
    ) -> Result<bool, Error> {
        Err(Error::UnsupportedCommand(
            SuitCommand::DeviceIdentifier.into(),
        ))
    }

    /// Read the data from a component (with slot) into the supplied buffer.
    fn component_read(
        &self,
        component: &component::Component,
        slot: Option<u64>,
        offset: usize,
        bytes: &mut [u8],
    ) -> Result<(), Error>;

    /// Write the supplied data into the component (with slot).
    fn component_write(
        &self,
        component: &component::Component,
        slot: Option<u64>,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Error>;

    /// Get the size of the component installed.
    fn component_size(&self, component: &component::Component) -> Result<usize, Error>;

    /// Get the capacity of what can be installed in the component.
    fn component_capacity(&self, component: &component::Component) -> Result<usize, Error>;

    // Check if the component exists on the system.
    fn has_component(&self, component: &component::Component) -> Result<(), Error> {
        self.component_capacity(component).map(|_| ())
    }

    /// Retrieve the payload from the url and store it in the component.
    fn fetch(
        &self,
        _component: &component::Component,
        _slot: Option<u64>,
        _uri: &str,
    ) -> Result<(), Error> {
        Err(Error::UnsupportedCommand(SuitCommand::Fetch.into()))
    }
}

impl<'a, S: AuthState> SuitManifest<'a, S> {
    pub fn envelope(&self) -> Result<Envelope<'a, S>, Error> {
        let mut decoder = self.decoder.clone();
        let tag = decoder.tag()?;
        if tag != SUIT_TAG_ENVELOPE {
            return Err(Error::UnexpectedCbor(self.decoder.position()));
        }
        Ok(Envelope {
            decoder,
            phantom: PhantomData,
        })
    }
}

impl<'a> SuitManifest<'a, New> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Self {
            decoder: Decoder::new(bytes),
            phantom: PhantomData,
        }
    }

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
    fn from_manifest(manifest: &SuitManifest<'a, S>) -> Self {
        let decoder = manifest.decoder.clone();
        Self {
            decoder,
            phantom: PhantomData,
        }
    }

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
        let len = decoder
            .map()?
            .ok_or(Error::UnexpectedCbor(decoder.position()))?;
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

    pub fn auth_object(&self) -> Result<&'a ByteSlice, Error> {
        let auth_object = self.get_object(SuitEnvelope::Authentication)?;
        auth_object.ok_or(Error::NoAuthObject)
    }

    pub fn manifest_bytes(&self) -> Result<&'a ByteSlice, Error> {
        let manifest_object = self.get_object(SuitEnvelope::Manifest)?;
        manifest_object.ok_or(Error::NoManifestObject)
    }

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
