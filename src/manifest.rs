//! Inner SUIT manifest.
use core::marker::PhantomData;

use digest::Update;
use minicbor::bytes::ByteSlice;
use minicbor::data::Token;
use minicbor::decode::Decoder;

use crate::cbor::SubCbor;
use crate::command::{CommandSequenceExecutor, CommandSequenceIterator};
use crate::component::{ComponentInfo, ComponentIter};
use crate::consts::SuitCommand;
use crate::error::Error;
use crate::manifeststate::ManifestState;
use crate::{AuthState, Authenticated, Envelope, OperatingHooks};

/// Inner SUIT manifest.
#[derive(Debug, Clone)]
pub struct Manifest<'a, S: AuthState> {
    decoder: Decoder<'a>,
    envelope_decoder: Decoder<'a>,
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
    pub(crate) fn new<STATE: AuthState>(
        bytes: &'a ByteSlice,
        envelope_decoder: Decoder<'a>,
    ) -> Manifest<'a, STATE> {
        Manifest::<'a, STATE> {
            decoder: Decoder::new(bytes),
            envelope_decoder,
            phantom: PhantomData,
        }
    }

    /// Retrieve the SUIT manifest encoding version number in the manifest.
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

    /// Retrieve the manifest sequence number in the manifest.
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
struct Section<'a> {
    cbor: &'a ByteSlice,
    offset: usize,
}

impl<'a> Section<'a> {
    fn new(cbor: &'a ByteSlice, offset: usize) -> Self {
        Section { cbor, offset }
    }
}

impl<'a> Manifest<'a, Authenticated> {
    fn find_severable(
        &self,
        section: crate::consts::SuitEnvelope,
        digest_bytes: &'a [u8],
    ) -> Result<Option<&'a ByteSlice>, Error> {
        let digest: crate::digest::SuitDigest = minicbor::decode(digest_bytes)?;
        let wrapped_section = Envelope {
            decoder: self.envelope_decoder.clone(),
            phantom: PhantomData::<Authenticated>,
        }
        // Integrity check values are computed over entire bstr enlosing
        // manifest element (section 8.4.12).
        .get_object_wrapped(section)?;

        if let Some(section_wrapped_bytes) = wrapped_section {
            let mut hasher = digest.hasher()?;
            hasher.update(section_wrapped_bytes);
            if !digest.match_hasher(hasher)? {
                Err(Error::AuthenticationFailure)
            } else {
                Ok(Some(Decoder::new(section_wrapped_bytes).bytes()?.into()))
            }
        } else {
            Ok(None)
        }
    }

    fn find_command_sequence(
        &self,
        section: crate::consts::Manifest,
    ) -> Result<Option<Section<'a>>, Error> {
        let mut decoder = self.decoder.clone();
        let len = decoder
            .map()?
            .ok_or(Error::UnexpectedCbor(decoder.position()))?;
        for _ in 0..len {
            let key = decoder.i16()?;
            let offset = decoder.position();
            if key == section.into() {
                match decoder.datatype()? {
                    minicbor::data::Type::Bytes => {
                        let value = decoder.bytes()?;
                        return Ok(Some(Section::new(value.into(), offset)));
                    }
                    // Array means that this is a digest relative to a severed element
                    minicbor::data::Type::Array => {
                        let section_key = section.try_into()?;
                        let section_bytes =
                            self.find_severable(section_key, decoder.sub_cbor()?)?;
                        return Ok(section_bytes.map(|b| Section::new(b, offset)));
                    }
                    _ => return Err(Error::UnexpectedCbor(offset)),
                }
            } else {
                decoder.skip()?;
            }
        }
        Ok(None)
    }

    fn get_common(&self) -> Result<Section<'a>, Error> {
        self.find_command_sequence(crate::consts::Manifest::CommonData)?
            .ok_or(Error::NoCommonSection)
    }

    fn component_count(&self) -> Result<usize, Error> {
        let common_section = self.get_common()?;
        let mut decoder = Decoder::new(common_section.cbor);
        let len = decoder.map()?.ok_or(Error::InvalidCommonSection)?;
        for _ in 0..len {
            let key = decoder.i16()?;
            if key == crate::consts::SuitCommon::ComponentIdentifiers as i16 {
                if let Some(num_components) = decoder
                    .array()
                    .map_err(|e| Error::from(e).add_offset(common_section.offset))?
                {
                    return Ok(num_components as usize);
                } else {
                    return Err(Error::UnexpectedIndefiniteLength(decoder.position()))
                        .map_err(|e| e.add_offset(common_section.offset));
                }
            }
        }
        Err(Error::InvalidCommonSection)
    }

    fn verify_components(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        let (components, _, common_offset) = self.decode_common()?;
        let mut decoder = Decoder::new(components);
        for component in
            ComponentIter::new(&mut decoder).map_err(|e| e.add_offset(common_offset))?
        {
            os_hooks.has_component(&component.map_err(|e| e.add_offset(common_offset))?)?;
        }
        Ok(())
    }

    fn check_shared_sequence(&self) -> Result<bool, Error> {
        // The shared sequence in the common section must contain a vendor and device class check and
        // is not allowed to contain any custom command
        let (_, common, common_offset) = self.decode_common()?;
        let decoder = Decoder::new(common);
        if !CommandSequenceIterator::new(decoder.clone())
            .map_err(|e| e.add_offset(common_offset))?
            .any(|cmd| cmd.is_ok_and(|c| c.command == SuitCommand::VendorIdentifier))
        {
            return Ok(false);
        }
        if !CommandSequenceIterator::new(decoder.clone())
            .map_err(|e| e.add_offset(common_offset))?
            .any(|cmd| cmd.is_ok_and(|c| c.command == SuitCommand::ClassIdentifier))
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn decode_common(&self) -> Result<(&'a ByteSlice, &'a ByteSlice, usize), Error> {
        let common_section = self.get_common()?;
        // Only contains the component identifiers and the common command sequence
        let mut decoder = Decoder::new(common_section.cbor);
        let mut components = None;
        let mut commands = None;
        let len = decoder.map()?.ok_or(Error::InvalidCommonSection)?;
        for _ in 0..len {
            let key = decoder.i16()?;
            match key {
                2 => {
                    components = Some(decoder.sub_cbor()?.into());
                }
                4 => {
                    commands = Some(decoder.bytes()?.into());
                }
                _ => return Err(Error::InvalidCommonSection),
            }
        }
        if let (Some(components), Some(commands)) = (components, commands) {
            Ok((components, commands, common_section.offset))
        } else {
            Err(Error::InvalidCommonSection)
        }
    }

    fn has_section(&self, section: crate::consts::Manifest) -> Result<bool, Error> {
        self.find_command_sequence(section).map(|s| s.is_some())
    }

    /// Check if the manifest contains a payload fetch command sequence
    pub fn has_payload_fetch(&self) -> Result<bool, Error> {
        self.has_section(crate::consts::Manifest::PayloadFetch)
    }

    /// Check if the manifest contains a payload installation command sequence
    pub fn has_payload_installation(&self) -> Result<bool, Error> {
        self.has_section(crate::consts::Manifest::PayloadInstallation)
    }

    /// Check if the manifest contains an image validation command sequence
    pub fn has_image_validation(&self) -> Result<bool, Error> {
        self.has_section(crate::consts::Manifest::ImageValidation)
    }

    /// Check if the manifest contains an image loading command sequence
    pub fn has_image_loading(&self) -> Result<bool, Error> {
        self.has_section(crate::consts::Manifest::ImageLoading)
    }

    /// Check if the manifest contains an invoke command sequence
    pub fn has_invoke(&self) -> Result<bool, Error> {
        self.has_section(crate::consts::Manifest::ImageInvocation)
    }

    fn execute_section_with_common(
        &self,
        os_hooks: &impl OperatingHooks,
        section: crate::consts::Manifest,
    ) -> Result<(), Error> {
        let start_state = ManifestState::default();
        let command_section = self
            .find_command_sequence(section)?
            .ok_or(Error::NoCommandSection(section.into()))?;
        let (components, common, common_offset) = self.decode_common()?;
        let mut component_decoder = Decoder::new(components);
        for (idx, component) in ComponentIter::new(&mut component_decoder)
            .map_err(|e| e.add_offset(common_offset))?
            .enumerate()
        {
            if let Ok(component) = component {
                let idx = idx
                    .try_into()
                    .map_err(|_| Error::UnexpectedCbor(self.decoder.position()))?;
                let component_info = ComponentInfo::new(component, idx);

                let common_sequence = CommandSequenceExecutor::new(common, os_hooks);
                let state = common_sequence
                    .process(start_state.clone(), &component_info)
                    .map_err(|e| e.add_offset(common_offset))?;
                let section = CommandSequenceExecutor::new(command_section.cbor, os_hooks);
                section
                    .process(state, &component_info)
                    .map_err(|e| e.add_offset(command_section.offset))?;
            }
        }
        Ok(())
    }

    /// Execute the command sequence in the payload fetch section.
    ///
    /// The command sequence in the common section is executed before the command sequence in the
    /// payload fetch is executed.
    pub fn execute_payload_fetch(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        self.execute_section_with_common(os_hooks, crate::consts::Manifest::PayloadFetch)
    }

    /// Execute the command sequence in the payload installation section.
    ///
    /// The command sequence in the common section is executed before the command sequence in the
    /// payload installation is executed.
    pub fn execute_payload_installation(
        &self,
        os_hooks: &impl OperatingHooks,
    ) -> Result<(), Error> {
        self.execute_section_with_common(os_hooks, crate::consts::Manifest::PayloadInstallation)
    }

    /// Execute the command sequence in the image validation section.
    ///
    /// The command sequence in the common section is executed before the command sequence in the
    /// image validation is executed.
    pub fn execute_image_validation(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        self.execute_section_with_common(os_hooks, crate::consts::Manifest::ImageValidation)
    }

    /// Execute the command sequence in the image loading section.
    ///
    /// The command sequence in the common section is executed before the command sequence in the
    /// image loading is executed.
    pub fn execute_image_loading(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        self.execute_section_with_common(os_hooks, crate::consts::Manifest::ImageLoading)
    }

    /// Execute the command sequence in the image loading section.
    ///
    /// The command sequence in the common section is executed before the command sequence in the
    /// invoke is executed.
    pub fn execute_invoke(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        self.execute_section_with_common(os_hooks, crate::consts::Manifest::ImageInvocation)
    }

    /// Execute all command sequences in the manifest.
    pub fn execute_full(&self) -> Result<(), Error> {
        let _state = ManifestState::default();
        let (_components, _common, _common_offset) = self.decode_common()?;
        // Separate out per component, common first, then the step
        todo!();
        Ok(())
    }
}
