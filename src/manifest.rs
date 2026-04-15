//! Inner SUIT manifest.
use core::marker::PhantomData;

use minicbor::bytes::ByteSlice;
use minicbor::data::Token;
use minicbor::decode::Decoder;

use crate::cbor::SubCbor;
use crate::command::CommandSequence;
use crate::component::{ComponentInfo, ComponentIter};
use crate::consts::SuitCommand;
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
        _ => Err(Error::UnexpectedCbor { position: 0 }),
    }
}

impl<'a, S: AuthState> Manifest<'a, S> {
    pub(crate) fn from_bytes<STATE: AuthState>(bytes: &'a ByteSlice) -> Manifest<'a, STATE> {
        Manifest::<'a, STATE> {
            decoder: Decoder::new(bytes),
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

impl<'a> Manifest<'a, Authenticated> {
    fn find_section(
        &self,
        section: crate::consts::Manifest,
    ) -> Result<Option<(&'a ByteSlice, usize)>, Error> {
        let mut decoder = self.decoder.clone();
        let len = decoder.map()?.ok_or(Error::UnexpectedCbor {
            position: decoder.position(),
        })?;
        for _ in 0..len {
            let key = decoder.i16()?;
            let offset = decoder.position();
            if key == section.into() {
                let value = decoder.bytes()?;
                return Ok(Some((value.into(), offset)));
            } else {
                decoder.skip()?;
            }
        }
        Ok(None)
    }

    fn find_command_sequence(
        &self,
        section: crate::consts::Manifest,
    ) -> Result<Option<CommandSequence<'a>>, Error> {
        self.find_section(section)
            .map(|o| o.map(|(cbor, offset)| CommandSequence::new(cbor, offset)))
    }

    fn get_common(&self) -> Result<CommonSection<'a>, Error> {
        self.find_section(crate::consts::Manifest::CommonData)?
            .ok_or(Error::NoCommonSection)
            .and_then(|(cbor, offset)| CommonSection::new(cbor, offset))
    }

    // Checks if the first command in a command sequence is a SetComponentIndex, if there is more
    // than one component in the manifest
    fn check_sequences(&self) -> Result<bool, Error> {
        if self.get_common()?.component_count()? > 1 {
            for section in crate::consts::SUIT_COMMAND_SECTIONS {
                if let Some(command_sequence) = self.find_command_sequence(section)? {
                    if let Some(command) = command_sequence.iter()?.next() {
                        let command = command?;
                        if command.command != crate::consts::SuitCommand::SetComponentIndex {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        Ok(true)
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
        let command_section =
            self.find_command_sequence(section)?
                .ok_or(Error::NoCommandSection {
                    section: section.into(),
                })?;

        let common = self.get_common()?;
        let mut component_decoder = Decoder::new(common.components);
        for (idx, component) in ComponentIter::new(&mut component_decoder)
            .map_err(|e| e.add_offset(common.component_offset))?
            .enumerate()
        {
            if let Ok(component) = component {
                let idx = idx.try_into().map_err(|_| Error::UnexpectedCbor {
                    position: self.decoder.position(),
                })?;
                let component_info = ComponentInfo::new(component, idx);

                let state = common.shared_sequence().execute(
                    start_state.clone(),
                    &component_info,
                    os_hooks,
                )?;
                command_section.execute(state, &component_info, os_hooks)?;
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
    pub fn execute_full(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        for section in crate::consts::SUIT_COMMAND_SECTIONS {
            let res = self.execute_section_with_common(os_hooks, section);
            // Ignore NoCommandSequence errors
            if res.is_err_and(|e| !matches!(e, Error::NoCommandSection { .. })) {
                return res;
            }
        }
        Ok(())
    }
}

struct CommonSection<'a> {
    components: &'a ByteSlice,
    component_offset: usize,
    shared_sequence: CommandSequence<'a>,
}

impl<'a> CommonSection<'a> {
    fn new(cbor: &'a ByteSlice, offset: usize) -> Result<Self, Error> {
        let (components, component_offset, shared_sequence) = Self::decode_common(cbor, offset)?;
        // todo: fix offset
        Ok(Self {
            components,
            component_offset,
            shared_sequence,
        })
    }

    fn decode_common(
        cbor: &'a ByteSlice,
        offset: usize,
    ) -> Result<(&'a ByteSlice, usize, CommandSequence<'a>), Error> {
        // Only contains the component identifiers and the common command sequence
        let mut decoder = Decoder::new(cbor);
        let mut components = None;
        let mut component_offset = 0;
        let mut commands = None;
        let len = decoder.map()?.ok_or(Error::InvalidCommonSection)?;
        for _ in 0..len {
            let key = decoder.i16()?;
            match key {
                2 => {
                    component_offset = decoder.position();
                    components = Some(decoder.sub_cbor()?.into());
                }
                4 => {
                    let position = decoder.position() + offset;
                    commands = Some(CommandSequence::new(decoder.bytes()?.into(), position));
                }
                _ => return Err(Error::InvalidCommonSection),
            }
        }
        if let (Some(components), Some(commands)) = (components, commands) {
            Ok((components, component_offset, commands))
        } else {
            Err(Error::InvalidCommonSection)
        }
    }

    fn shared_sequence<'b>(&'b self) -> &'b CommandSequence<'a> {
        &self.shared_sequence
    }

    fn component_count(&self) -> Result<usize, Error> {
        if let Some(num_components) = Decoder::new(self.components)
            .array()
            .map_err(|e| Error::from(e).add_offset(self.component_offset))?
        {
            Ok(num_components as usize)
        } else {
            Err(Error::UnexpectedIndefiniteLength {
                position: self.component_offset,
            })
        }
    }

    fn verify_components(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        let mut decoder = Decoder::new(self.components);
        for component in
            ComponentIter::new(&mut decoder).map_err(|e| e.add_offset(self.component_offset))?
        {
            os_hooks.has_component(&component.map_err(|e| e.add_offset(self.component_offset))?)?;
        }
        Ok(())
    }

    fn verify_shared_sequence(&self) -> Result<bool, Error> {
        // The shared sequence in the common section must contain a vendor and device class check and
        // is not allowed to contain any custom command
        //
        // TODO: recurse into try-each and run-sequence commands
        if !self
            .shared_sequence()
            .iter()?
            .any(|cmd| cmd.is_ok_and(|c| c.command == SuitCommand::VendorIdentifier))
        {
            return Ok(false);
        }
        if !self
            .shared_sequence()
            .iter()?
            .any(|cmd| cmd.is_ok_and(|c| c.command == SuitCommand::VendorIdentifier))
        {
            return Ok(false);
        }

        // Custom commands and commands with side effects are not permitted in the common section
        if !self
            .shared_sequence()
            .iter()?
            .any(|cmd| cmd.is_ok_and(|c| c.command.has_side_effect()))
        {
            return Ok(false);
        }
        Ok(true)
    }
}
