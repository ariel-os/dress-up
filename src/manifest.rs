//! Inner SUIT manifest.
use core::marker::PhantomData;

use minicbor::bytes::ByteSlice;
use minicbor::data::Token;
use minicbor::decode::Decoder;

use crate::command::CommandSequenceExecutor;
use crate::component::{ComponentInfo, ComponentIter};
use crate::error::Error;
use crate::manifeststate::ManifestState;
use crate::{AuthState, Authenticated, OperatingHooks};

/// Inner SUIT manifest.
#[derive(Debug, Clone)]
pub struct Manifest<'a, S: AuthState> {
    decoder: Decoder<'a>,
    phantom: PhantomData<S>,
}

fn try_into_u64(token: Token) -> Result<u64, Error> {
    match token {
        Token::U8(n) => Ok(n.into()),
        Token::U16(n) => Ok(n.into()),
        Token::U32(n) => Ok(n.into()),
        Token::U64(n) => Ok(n),
        _ => Err(Error::UnexpectedCbor(0)),
    }
}

impl<'a, S: AuthState> Manifest<'a, S> {
    pub(crate) fn from_bytes<STATE: AuthState>(bytes: &'a ByteSlice) -> Manifest<'a, STATE> {
        Manifest::<'a, STATE> {
            decoder: Decoder::new(bytes),
            phantom: PhantomData,
        }
    }

    pub fn version(&self) -> Result<u8, Error> {
        let mut decoder = self.decoder.clone();
        let version = decoder
            .map_iter::<i16, Token>()?
            .find_map(|item| match item {
                Ok((key, value)) if key == crate::consts::Manifest::EncodingVersion.into() => {
                    Some(value)
                }
                _ => None,
            });
        if let Some(Token::U8(version)) = version {
            if version == crate::consts::SUIT_SUPPORTED_VERSION {
                return Ok(version);
            }
        }
        Err(Error::UnsupportedManifestVersion)
    }

    pub fn sequence_number(&self) -> Result<u64, Error> {
        let mut decoder = self.decoder.clone();
        let seq_no = decoder
            .map_iter::<i16, Token>()?
            .find_map(|item| match item {
                Ok((key, value)) if key == crate::consts::Manifest::SequenceNumber.into() => {
                    Some(value)
                }
                _ => None,
            })
            .ok_or(Error::UnsupportedManifestVersion)?;
        let seq_no = try_into_u64(seq_no)?;
        Ok(seq_no)
    }
}

impl<'a> Manifest<'a, Authenticated> {
    fn find_command_sequence(
        &self,
        section: crate::consts::Manifest,
    ) -> Result<Option<&'a ByteSlice>, Error> {
        let mut decoder = self.decoder.clone();
        Ok(decoder
            .map_iter::<i16, Token>()?
            .find_map(|item| match item {
                Ok((key, Token::Bytes(value))) if key == section.into() => Some(value.into()),
                _ => None,
            }))
    }

    fn get_common(&self) -> Result<&'a ByteSlice, Error> {
        self.find_command_sequence(crate::consts::Manifest::CommonData)?
            .ok_or(Error::NoCommonSection)
    }

    fn decode_common(
        &self,
        common: &'a ByteSlice,
    ) -> Result<(&'a ByteSlice, &'a ByteSlice), Error> {
        // Only contains the component identifiers and the common command sequence
        let mut decoder = Decoder::new(common);
        let mut components = None;
        let mut commands = None;
        let len = decoder.map()?.ok_or(Error::InvalidCommonSection)?;
        for _ in 0..len {
            let key = decoder.i16()?;
            match key {
                2 => {
                    let start = decoder.position();
                    decoder.skip()?; // Skip over the full component section
                    let end = decoder.position();
                    components = decoder.input().get(start..end).map(|c| c.into());
                }
                4 => {
                    commands = Some(decoder.bytes()?.into());
                }
                _ => return Err(Error::InvalidCommonSection),
            }
        }
        if let (Some(components), Some(commands)) = (components, commands) {
            Ok((components, commands))
        } else {
            Err(Error::InvalidCommonSection)
        }
    }

    fn execute_section_with_common(
        &self,
        os_hooks: &impl OperatingHooks,
        section: crate::consts::Manifest,
    ) -> Result<(), Error> {
        let start_state = ManifestState::default();
        let common = self.get_common()?;
        let section = self
            .find_command_sequence(section)?
            .ok_or(Error::NoCommandSection(section.into()))?;
        let (components, common) = self.decode_common(common)?;
        let mut component_decoder = Decoder::new(components);
        for (idx, component) in ComponentIter::new(&mut component_decoder)?.enumerate() {
            if let Ok(component) = component {
                let idx = idx
                    .try_into()
                    .map_err(|_| Error::UnexpectedCbor(self.decoder.position()))?;
                let component_info = ComponentInfo::new(component, idx);

                let common_sequence = CommandSequenceExecutor::new(common, os_hooks);
                let state = common_sequence.process(start_state.clone(), &component_info)?;
                let section = CommandSequenceExecutor::new(section, os_hooks);
                section.process(state, &component_info)?;
            }
        }
        Ok(())
    }

    pub fn execute_payload_fetch(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        self.execute_section_with_common(os_hooks, crate::consts::Manifest::PayloadFetch)
    }

    pub fn execute_payload_installation(
        &self,
        os_hooks: &impl OperatingHooks,
    ) -> Result<(), Error> {
        self.execute_section_with_common(os_hooks, crate::consts::Manifest::PayloadInstallation)
    }

    pub fn execute_image_validation(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        self.execute_section_with_common(os_hooks, crate::consts::Manifest::ImageValidation)
    }

    pub fn execute_image_loading(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        self.execute_section_with_common(os_hooks, crate::consts::Manifest::ImageLoading)
    }
    pub fn execute_invoke(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        self.execute_section_with_common(os_hooks, crate::consts::Manifest::ImageInvocation)
    }

    pub fn execute_full(&self) -> Result<(), Error> {
        let _state = ManifestState::default();
        let common = self.get_common()?;
        let (_components, _common) = self.decode_common(common)?;
        // Separate out per component, common first, then the step
        todo!();
        Ok(())
    }
}
