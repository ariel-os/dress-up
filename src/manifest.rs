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
    ) -> Result<Option<(&'a ByteSlice, usize)>, Error> {
        let mut decoder = self.decoder.clone();
        let len = decoder
            .map()?
            .ok_or(Error::UnexpectedCbor(decoder.position()))?;
        for _ in 0..len {
            let key = decoder.i16()?;
            let position = decoder.position();
            if key == section.into() {
                match decoder.datatype()? {
                    minicbor::data::Type::Bytes => {
                        let value = decoder.bytes()?;
                        return Ok(Some((value.into(), position)));
                    }
                    // Array means that this is a digest relative to a severed element
                    minicbor::data::Type::Array => {
                        let section_key = section.try_into()?;
                        let section_bytes =
                            self.find_severable(section_key, decoder.sub_cbor()?)?;
                        return Ok(section_bytes.map(|b| (b, position)));
                    }
                    _ => return Err(Error::UnexpectedCbor(position)),
                }
            } else {
                decoder.skip()?;
            }
        }
        Ok(None)
    }

    fn get_common(&self) -> Result<(&'a ByteSlice, usize), Error> {
        self.find_command_sequence(crate::consts::Manifest::CommonData)?
            .ok_or(Error::NoCommonSection)
    }

    fn component_count(&self) -> Result<usize, Error> {
        let (common_section, common_offset) = self.get_common()?;
        let mut decoder = Decoder::new(common_section);
        let len = decoder.map()?.ok_or(Error::InvalidCommonSection)?;
        for _ in 0..len {
            let key = decoder.i16()?;
            if key == crate::consts::SuitCommon::ComponentIdentifiers as i16 {
                if let Some(num_components) = decoder
                    .array()
                    .map_err(|e| Error::from(e).add_offset(common_offset))?
                {
                    return Ok(num_components as usize);
                } else {
                    return Err(Error::UnexpectedIndefiniteLength(decoder.position()))
                        .map_err(|e| e.add_offset(common_offset));
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
        let (common_section, common_offset) = self.get_common()?;
        // Only contains the component identifiers and the common command sequence
        let mut decoder = Decoder::new(common_section);
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
            Ok((components, commands, common_offset))
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
        let (section, section_offset) = self
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
                let section = CommandSequenceExecutor::new(section, os_hooks);
                section
                    .process(state, &component_info)
                    .map_err(|e| e.add_offset(section_offset))?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::SuitManifest;

    #[test]
    fn severable_element_present() {
        let hex_str = "d86ba4025873825824822f58206a5197ed8f9dccf733d1c89a359441708e\
070b4c6dcb9a1c2c82c6165f609b90584ad28443a10126a0f65840073d8d\
80ca67d61cdf04d813c748b2de98fe786fc67b764431307c8dbcbe91dc6f\
762c2c4d7bb998ff9ead4798e03c8ee26b89ef7a9ad4569f6e187ce89e16\
c50358d1a80101020203585fa202818141000458568614a40150fa6b4a53\
d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45\
035824822f582000112233445566778899aabbccddeeff0123456789abcd\
effedcba98765432100e1987d0010f020f047468747470733a2f2f676974\
2e696f2f4a4a596f6a074382030f094382170214822f5820cfa90c5c5859\
5e7f5119a72f803fd0370b3e6abbec6315cd38f63135281bc49817822f58\
20302196d452bce5e8bfeaf71e395645ede6d365e63507a081379721eeec\
f0000714583c8614a1157832687474703a2f2f6578616d706c652e636f6d\
2f766572792f6c6f6e672f706174682f746f2f66696c652f66696c652e62\
696e1502030f1759020ba165656e2d5553a20179019d2323204578616d70\
6c6520323a2053696d756c74616e656f757320446f776e6c6f61642c2049\
6e7374616c6c6174696f6e2c2053656375726520426f6f742c2053657665\
726564204669656c64730a0a2020202054686973206578616d706c652063\
6f766572732074686520666f6c6c6f77696e672074656d706c617465733a\
0a202020200a202020202a20436f6d7061746962696c6974792043686563\
6b20287b7b74656d706c6174652d636f6d7061746962696c6974792d6368\
65636b7d7d290a202020202a2053656375726520426f6f7420287b7b7465\
6d706c6174652d7365637572652d626f6f747d7d290a202020202a204669\
726d7761726520446f776e6c6f616420287b7b6669726d776172652d646f\
776e6c6f61642d74656d706c6174657d7d290a202020200a202020205468\
6973206578616d706c6520616c736f2064656d6f6e737472617465732073\
6576657261626c6520656c656d656e747320287b7b6f76722d7365766572\
61626c657d7d292c20616e64207465787420287b7b6d616e69666573742d\
6469676573742d746578747d7d292e814100a2036761726d2e636f6d0578\
525468697320636f6d706f6e656e7420697320612064656d6f6e73747261\
74696f6e2e205468652064696765737420697320612073616d706c652070\
61747465726e2c206e6f742061207265616c206f6e652e";
        let manifest_bytes = hex::decode(hex_str).unwrap();
        let suit_manifest = SuitManifest::from_bytes(&manifest_bytes);
        let suit_manifest = suit_manifest
            .authenticate(|_cose, _payload| Ok(true))
            .unwrap();
        let envelope = suit_manifest.envelope().unwrap();
        let manifest = envelope.manifest().unwrap();

        // Install and text are severable and present in the envelope.
        let install_payload = manifest
            .find_command_sequence(crate::consts::Manifest::PayloadInstallation)
            .unwrap();
        assert!(install_payload.is_some());

        let text = manifest
            .find_command_sequence(crate::consts::Manifest::TextDescription)
            .unwrap();
        assert!(text.is_some());
    }

    #[test]
    fn severable_element_absent() {
        let hex_str = "d86ba2025873825824822f58206a5197ed8f9dccf733d1c89a359441708e\
070b4c6dcb9a1c2c82c6165f609b90584ad28443a10126a0f65840073d8d\
80ca67d61cdf04d813c748b2de98fe786fc67b764431307c8dbcbe91dc6f\
762c2c4d7bb998ff9ead4798e03c8ee26b89ef7a9ad4569f6e187ce89e16\
c50358d1a80101020203585fa202818141000458568614a40150fa6b4a53\
d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45\
035824822f582000112233445566778899aabbccddeeff0123456789abcd\
effedcba98765432100e1987d0010f020f047468747470733a2f2f676974\
2e696f2f4a4a596f6a074382030f094382170214822f5820cfa90c5c5859\
5e7f5119a72f803fd0370b3e6abbec6315cd38f63135281bc49817822f58\
20302196d452bce5e8bfeaf71e395645ede6d365e63507a081379721eeec\
f00007";
        let manifest_bytes = hex::decode(hex_str).unwrap();
        let suit_manifest = SuitManifest::from_bytes(&manifest_bytes);
        let suit_manifest = suit_manifest
            .authenticate(|_cose, _payload| Ok(true))
            .unwrap();
        let envelope = suit_manifest.envelope().unwrap();
        let manifest = envelope.manifest().unwrap();

        // Install and texte are severable but absent in the envelope.
        let install_payload = manifest
            .find_command_sequence(crate::consts::Manifest::PayloadInstallation)
            .unwrap();
        assert!(install_payload.is_none());

        let text = manifest
            .find_command_sequence(crate::consts::Manifest::TextDescription)
            .unwrap();
        assert!(text.is_none());
    }
}
