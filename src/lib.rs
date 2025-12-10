#![no_std]
#![allow(dead_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::marker::PhantomData;

use generic_array::ArrayLength;
use minicbor::bytes::ByteSlice;
use minicbor::decode::Decoder;

use uuid::Uuid;

pub mod component;
pub mod consts;
pub mod digest;
pub mod error;
pub mod manifest;
pub mod manifeststate;
pub mod report;

use crate::consts::*;
use crate::error::Error;
use crate::manifest::Manifest;

pub trait State {}
#[derive(Debug)]
pub struct New;
#[derive(Debug)]
pub struct Authenticated;

impl State for New {}
impl State for Authenticated {}

#[derive(Clone)]
pub struct SuitManifest<'a, S: State> {
    decoder: Decoder<'a>,
    phantom: PhantomData<S>,
}

#[derive(Clone)]
pub struct EnvelopeDecoder<'a, S: State> {
    decoder: Decoder<'a>,
    phantom: PhantomData<S>,
}

pub trait OperatingHooks {
    type ReadWriteBufferSize: ArrayLength;

    fn match_vendor_id(&self, uuid: Uuid, component: &component::Component) -> Result<bool, Error>;
    fn match_class_id(&self, uuid: Uuid, component: &component::Component) -> Result<bool, Error>;

    fn match_device_id(
        &self,
        _uuid: Uuid,
        _component: &component::Component,
    ) -> Result<bool, Error> {
        Err(Error::UnsupportedCommand(
            SuitCommand::DeviceIdentifier.into(),
        ))
    }

    fn match_component_slot(
        &self,
        _component: &component::Component,
        _component_slot: u64,
    ) -> Result<bool, Error> {
        Err(Error::UnsupportedCommand(
            SuitCommand::DeviceIdentifier.into(),
        ))
    }

    fn component_read(
        &self,
        component: &component::Component,
        slot: Option<u64>,
        offset: usize,
        bytes: &mut [u8],
    ) -> Result<(), Error>;

    fn component_size(&self, component: &component::Component) -> Result<usize, Error>;

    fn component_capacity(&self, component: &component::Component) -> Result<usize, Error>;
}

impl<'a, S: State> SuitManifest<'a, S> {
    fn decode(&mut self) -> Result<(), Error> {
        let mut envelope_decoder = EnvelopeDecoder::from_manifest(self);
        envelope_decoder.decode()?;
        Ok(())
    }

    pub fn authenticate(self) -> Result<SuitManifest<'a, Authenticated>, Error> {
        Ok(SuitManifest::<'a, Authenticated> {
            decoder: self.decoder,
            phantom: PhantomData,
        })
    }
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
}

impl<'a> SuitManifest<'a, Authenticated> {}

impl<'a, S: State> EnvelopeDecoder<'a, S> {
    fn from_manifest(manifest: &SuitManifest<'a, S>) -> Self {
        let decoder = manifest.decoder.clone();
        Self {
            decoder,
            phantom: PhantomData,
        }
    }

    pub fn decode(&mut self) -> Result<(), Error> {
        Ok(())
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
