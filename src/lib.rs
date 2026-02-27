#![no_std]
#![allow(dead_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Dress-Up provides a parser-only implementation of the [SUIT][suit-rfc] manifest format,
//! for `no_std` environments.
//!
//! 🚧 This crate is still under heavy construction 🚧

use core::marker::PhantomData;

use generic_array::ArrayLength;
use minicbor::bytes::ByteSlice;
use minicbor::decode::Decoder;

use uuid::Uuid;

pub mod auth;
pub mod component;
pub mod consts;
pub mod digest;
pub mod error;
pub mod manifest;
pub mod manifeststate;
pub mod report;

use crate::auth::Authentication;
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
pub struct EnvelopeDecoder<'a, S: AuthState> {
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
}

impl<'a, S: AuthState> SuitManifest<'a, S> {
    pub fn envelope(&self) -> Result<EnvelopeDecoder<'a, S>, Error> {
        let mut decoder = self.decoder.clone();
        let tag = decoder.tag()?;
        if tag != SUIT_TAG_ENVELOPE {
            return Err(Error::UnexpectedCbor(self.decoder.position()));
        }
        Ok(EnvelopeDecoder {
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

impl<'a, S: AuthState> EnvelopeDecoder<'a, S> {
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
            let start = decoder.position();
            decoder.skip()?;
            if key == search_key.into() {
                let end = decoder.position();
                if let Some(buffer) = decoder.input().get(start..end) {
                    return Ok(Some(buffer.into()));
                }
                return Err(Error::UnexpectedCbor(decoder.position()));
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
