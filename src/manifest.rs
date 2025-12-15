use core::marker::PhantomData;

use digest::Update;
use generic_array::{ArrayLength, GenericArray};

use minicbor::bytes::ByteSlice;
use minicbor::data::Token;
use minicbor::decode::Decoder;

use crate::component::{Component, ComponentInfo, ComponentIter};
use crate::consts::SuitCommand;
use crate::error::Error;
use crate::manifeststate::ManifestState;
use crate::report::ReportingPolicy;
use crate::{Authenticated, OperatingHooks, State};

#[derive(Debug, Clone)]
pub struct Manifest<'a, S: State> {
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

struct RwBuf<N: ArrayLength> {
    pub buf: GenericArray<u8, N>,
}

impl<N: ArrayLength> RwBuf<N> {
    fn new() -> Self {
        RwBuf {
            buf: GenericArray::default(),
        }
    }
}

impl<'a, S: State> Manifest<'a, S> {
    pub(crate) fn from_bytes<STATE: State>(bytes: &'a ByteSlice) -> Manifest<'a, STATE> {
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
    fn get_common(&self) -> Result<&'a ByteSlice, Error> {
        let mut decoder = self.decoder.clone();
        decoder
            .map_iter::<i16, Token>()?
            .find_map(|item| match item {
                Ok((key, Token::Bytes(value)))
                    if key == crate::consts::Manifest::CommonData.into() =>
                {
                    Some(Ok(value.into()))
                }
                _ => None,
            })
            .ok_or(Error::NoCommonSection)?
    }

    fn decode_common(
        &self,
        common: &'a ByteSlice,
    ) -> Result<(&'a ByteSlice, &'a ByteSlice), Error> {
        // Only contains the component identifiers and the common command sequence
        let mut decoder = Decoder::new(common);
        let mut components = None;
        let mut commands = None;
        let iter = decoder.map_iter()?;
        for item in iter {
            match item {
                Ok((2, value)) => components = Some(value), // components
                Ok((4, value)) => commands = Some(value),
                Err(err) => return Err(err.into()),
                Ok((_, _)) => (), // TODO add break
            }
        }
        if let (Some(components), Some(commands)) = (components, commands) {
            Ok((components, commands))
        } else {
            Err(Error::InvalidCommonSection)
        }
    }

    pub fn process_full(&self) -> Result<u64, Error> {
        let _state = ManifestState::default();
        let common = self.get_common()?;
        let (_components, _common) = self.decode_common(common)?;
        // Separate out per component, common first, then the step
        Ok(0)
    }

    fn cond_class_identifier(
        &self,
        state: &ManifestState,
        component: &Component,
        os_hooks: &impl OperatingHooks,
    ) -> Result<(), Error> {
        if let Some(class_id) = state.class_id {
            os_hooks.match_class_id(class_id, component).and_then(|b| {
                if b {
                    Ok(())
                } else {
                    Err(Error::ConditionMatchFail(0))
                }
            })
        } else {
            Err(Error::ParameterNotSet(0))
        }
    }

    fn cond_vendor_identifier(
        &self,
        state: &ManifestState,
        component: &Component,
        os_hooks: &impl OperatingHooks,
    ) -> Result<(), Error> {
        if let Some(vendor_id) = state.vendor_id {
            os_hooks
                .match_vendor_id(vendor_id, component)
                .and_then(|b| {
                    if b {
                        Ok(())
                    } else {
                        Err(Error::ConditionMatchFail(0))
                    }
                })
        } else {
            Err(Error::ParameterNotSet(0))
        }
    }

    fn cond_device_identifier(
        &self,
        state: &ManifestState,
        component: &Component,
        os_hooks: &impl OperatingHooks,
    ) -> Result<(), Error> {
        if let Some(device_id) = state.device_id {
            os_hooks
                .match_device_id(device_id, component)
                .and_then(|b| {
                    if b {
                        Ok(())
                    } else {
                        Err(Error::ConditionMatchFail(0))
                    }
                })
        } else {
            Err(Error::ParameterNotSet(0))
        }
    }

    fn cond_component_slot(
        &self,
        state: &ManifestState,
        component: &Component,
        os_hooks: &impl OperatingHooks,
    ) -> Result<(), Error> {
        if let Some(component_slot) = state.component_slot {
            os_hooks
                .match_component_slot(component, component_slot)
                .and_then(|b| {
                    if b {
                        Ok(())
                    } else {
                        Err(Error::ConditionMatchFail(0))
                    }
                })
        } else {
            Err(Error::ParameterNotSet(0))
        }
    }

    fn cond_image_match<O: OperatingHooks>(
        &self,
        state: &ManifestState,
        component: &Component,
        os_hooks: &O,
    ) -> Result<(), Error> {
        if let Some(digest) = state.image_digest {
            let size = os_hooks.component_size(component)?;
            let mut hasher = digest.hasher()?;
            let mut buf = RwBuf::<O::ReadWriteBufferSize>::new().buf;
            for offset in (0..size).step_by(buf.len()) {
                let diff = size.saturating_sub(offset);
                let read_size = if diff < buf.len() { diff } else { buf.len() };
                let buf = &mut buf[0..read_size];
                os_hooks.component_read(component, state.component_slot, offset, buf)?;
                hasher.update(buf)
            }
            digest.match_hasher(hasher).and_then(|b| {
                if b {
                    Ok(())
                } else {
                    Err(Error::ConditionMatchFail(0))
                }
            })
        } else {
            Err(Error::ParameterNotSet(0))
        }
    }

    fn directive_write(
        &self,
        state: &ManifestState,
        component: &Component,
        os_hooks: &impl OperatingHooks,
    ) -> Result<(), Error> {
        if let Some(content) = state.content {
            os_hooks.component_write(component, state.component_slot, 0, content)
        } else {
            Err(Error::ParameterNotSet(0))
        }
    }

    fn try_each(
        &self,
        state: &mut ManifestState<'a>,
        component: &'a ComponentInfo<'a>,
        decoder: &mut Decoder<'a>,
        os_hooks: &impl OperatingHooks,
    ) -> Result<(), Error> {
        for sequence in decoder.array_iter::<&ByteSlice>()? {
            let seq = sequence?;
            if seq.is_empty() {
                return Ok(());
            }
            let sub_state = state.clone();
            let res = self.process_sequence(seq, sub_state, component, os_hooks);
            if let Ok(res) = res {
                *state = res;
                return Ok(());
            }
        }
        Err(Error::TryEachFail(decoder.position()))
    }

    fn decode_reporting_policy(decoder: &mut Decoder) -> Result<ReportingPolicy, Error> {
        Ok(decoder.decode::<ReportingPolicy>()?)
    }

    fn enter_sequence(decoder: &mut Decoder) -> Result<u64, Error> {
        let length = decoder.array()?;
        let length = match length {
            Some(n) if n % 2 == 1 => return Err(Error::InvalidCommandSequence(decoder.position())),
            None => return Err(Error::InvalidCommandSequence(decoder.position())),
            Some(n) => n / 2,
        };
        Ok(length)
    }

    /// Todo: Extract
    fn process_sequence(
        &self,
        command_sequence: &'a ByteSlice,
        mut state: ManifestState<'a>,
        component: &'a ComponentInfo,
        os_hooks: &impl OperatingHooks,
    ) -> Result<ManifestState<'a>, Error> {
        let mut decoder = Decoder::new(command_sequence);
        let mut match_component = true;
        let length = Self::enter_sequence(&mut decoder)?;
        for _ in 0..length {
            let command = decoder.i32()?.into();
            if !match_component {
                if matches!(command, SuitCommand::SetComponentIndex) {
                    match_component = component.in_applylist(&mut decoder)?;
                } else {
                    decoder.skip()?; // skip argument
                }
            } else {
                match command {
                    SuitCommand::Unset => return Err(Error::UnsupportedCommand(command.into())),
                    SuitCommand::Abort => {
                        return Err(Error::ConditionMatchFail(self.decoder.position()))
                    }
                    SuitCommand::OverrideParameters => {
                        state.update_parameter(&mut decoder)?;
                    }
                    SuitCommand::SetComponentIndex => {
                        match_component = component.in_applylist(&mut decoder)?;
                    }
                    SuitCommand::CheckContent => todo!(), // 1:1 bytewise check
                    SuitCommand::ClassIdentifier => {
                        self.cond_class_identifier(&state, component.component(), os_hooks)?;
                        Self::decode_reporting_policy(&mut decoder)?;
                    }
                    SuitCommand::ComponentSlot => {
                        self.cond_component_slot(&state, component.component(), os_hooks)?;
                        Self::decode_reporting_policy(&mut decoder)?;
                    }
                    SuitCommand::Copy => todo!(),
                    SuitCommand::DeviceIdentifier => {
                        self.cond_device_identifier(&state, component.component(), os_hooks)?;
                        Self::decode_reporting_policy(&mut decoder)?;
                    }
                    SuitCommand::Fetch => todo!(),
                    SuitCommand::ImageMatch => {
                        // Digest check
                        self.cond_image_match(&state, component.component(), os_hooks)?;
                        Self::decode_reporting_policy(&mut decoder)?;
                    }

                    SuitCommand::Invoke => todo!(),
                    SuitCommand::RunSequence => todo!(),
                    SuitCommand::Swap => todo!(),
                    SuitCommand::TryEach => {
                        self.try_each(&mut state, component, &mut decoder, os_hooks)?;
                    }
                    SuitCommand::VendorIdentifier => {
                        self.cond_vendor_identifier(&state, component.component(), os_hooks)?;
                        Self::decode_reporting_policy(&mut decoder)?;
                    }
                    SuitCommand::WriteContent => {
                        self.directive_write(&state, component.component(), os_hooks)?;
                        Self::decode_reporting_policy(&mut decoder)?;
                    }
                    SuitCommand::Custom(_n) => todo!(),
                }
            }
        }
        Ok(state)
    }

    pub fn process_validate(&self, os_hooks: &impl OperatingHooks) -> Result<(), Error> {
        let start_state = ManifestState::default();
        let common = self.get_common()?;
        let (components, common) = self.decode_common(common)?;
        let mut component_decoder = Decoder::new(components);
        for (idx, component) in ComponentIter::new(&mut component_decoder)?.enumerate() {
            if let Ok(component) = component {
                let idx = idx
                    .try_into()
                    .map_err(|_| Error::UnexpectedCbor(self.decoder.position()))?;
                let component_info = ComponentInfo::new(component, idx);
                let _state =
                    self.process_sequence(common, start_state.clone(), &component_info, os_hooks)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct CommandSequenceExecutor<'a> {
    decoder: Decoder<'a>,
    component: &'a ComponentInfo<'a>,
    state: ManifestState<'a>,
    match_component: bool,
    remaining: u64,
}

struct CommandSequenceExecutorIterator<'a, 'b> {
    cmd_sequence_exec: &'b mut CommandSequenceExecutor<'a>,
}

#[derive(Clone)]
struct Command<'a> {
    command: SuitCommand,
    decoder: Decoder<'a>,
    state: ManifestState<'a>,
}

impl<'a> CommandSequenceExecutor<'a> {
    fn new(
        command_sequence: &'a ByteSlice,
        component: &'a ComponentInfo<'a>,
        state: ManifestState<'a>,
    ) -> Result<Self, Error> {
        let mut decoder = Decoder::new(command_sequence);
        let length = decoder.array()?;
        let length = match length {
            Some(n) if n % 2 == 1 => return Err(Error::InvalidCommandSequence(decoder.position())),
            None => return Err(Error::InvalidCommandSequence(decoder.position())),
            Some(n) => n / 2,
        };

        Ok(Self {
            decoder,
            component,
            state,
            match_component: true,
            remaining: length,
        })
    }

    fn state(&self) -> ManifestState<'a> {
        self.state.clone()
    }

    fn multiple_commands(&mut self) -> Result<Option<Command<'a>>, Error> {
        while self.remaining > 0 {
            self.remaining -= 1;
            let command = self.decoder.i32()?.into();
            let cmd = if !self.match_component {
                if matches!(command, SuitCommand::SetComponentIndex) {
                    self.match_component = self.component.in_applylist(&mut self.decoder)?;
                } else {
                    self.decoder.skip()?; // skip argument
                }
                Ok(None)
                // todo: implement and skip over reporting policy
            } else {
                Ok(Some(Command {
                    command,
                    decoder: self.decoder.clone(),
                    state: self.state.clone(),
                }))
            };
            if cmd.clone().is_ok_and(|cmd| cmd.is_some()) {
                return cmd;
            }
        }
        Ok(None)
    }

    fn iter<'b>(&'b mut self) -> CommandSequenceExecutorIterator<'a, 'b> {
        CommandSequenceExecutorIterator {
            cmd_sequence_exec: self,
        }
    }
}

impl<'a, 'b> Iterator for CommandSequenceExecutorIterator<'a, 'b> {
    type Item = Result<Command<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.cmd_sequence_exec.multiple_commands().transpose()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::*;
    use crate::digest::{SuitDigest, SuitDigestAlgorithm};
    use std::cell::Cell;
    use uuid::{uuid, Uuid};

    struct TestHooks {
        class: Uuid,
        vendor: Uuid,
        buf: Cell<[u8; 4]>,
    }

    impl TestHooks {
        fn new(class: Uuid, vendor: Uuid) -> Self {
            TestHooks {
                class,
                vendor,
                buf: [0u8; _].into(),
            }
        }
    }

    impl OperatingHooks for TestHooks {
        type ReadWriteBufferSize = generic_array::typenum::U64;

        fn match_vendor_id(
            &self,
            uuid: uuid::Uuid,
            _component: &crate::component::Component,
        ) -> Result<bool, Error> {
            Ok(uuid == self.vendor)
        }

        fn match_class_id(
            &self,
            uuid: uuid::Uuid,
            _component: &crate::component::Component,
        ) -> Result<bool, Error> {
            Ok(uuid == self.class)
        }

        fn component_read(
            &self,
            _component: &crate::component::Component,
            _slot: Option<u64>,
            offset: usize,
            bytes: &mut [u8],
        ) -> Result<(), Error> {
            if bytes.len() + offset > self.buf.get().len() {
                return Err(Error::InvalidCommandSequence(0));
            }
            bytes.copy_from_slice(&self.buf.get()[offset..offset + bytes.len()]);
            Ok(())
        }

        fn component_write(
            &self,
            _component: &crate::component::Component,
            _slot: Option<u64>,
            offset: usize,
            bytes: &[u8],
        ) -> Result<(), Error> {
            if bytes.len() + offset > self.buf.get().len() {
                return Err(Error::InvalidCommandSequence(0));
            }
            let mut buf = self.buf.get();
            buf[offset..offset + bytes.len()].copy_from_slice(bytes);
            self.buf.set(buf);
            Ok(())
        }

        fn component_capacity(
            &self,
            _component: &crate::component::Component,
        ) -> Result<usize, Error> {
            Ok(self.buf.get().len())
        }

        fn component_size(&self, _component: &crate::component::Component) -> Result<usize, Error> {
            Ok(self.buf.get().len())
        }
    }

    #[test]
    fn simple_sequence() {
        let input: &[u8] = &std::vec![
            0x86, 0x14, 0xA4, 0x01, 0x50, 0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF, 0xBE,
            0x9D, 0xE6, 0x63, 0xE4, 0xD4, 0x1F, 0xFE, 0x02, 0x50, 0x14, 0x92, 0xAF, 0x14, 0x25,
            0x69, 0x5E, 0x48, 0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45, 0x03, 0x58, 0x24,
            0x82, 0x2F, 0x58, 0x20, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0E, 0x19, 0x87, 0xD0, 0x01, 0x0F,
            0x02, 0x0F
        ];
        let manifest = Manifest::<Authenticated>::from_bytes::<Authenticated>(input.into());
        let component_name = &std::vec![0x81, 0x41, 0x00];
        let component = Component::from_bytes(component_name);
        let info = ComponentInfo::new(component, 0);
        let mut state = ManifestState::default();
        let vendor = uuid!("fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe");
        let class = uuid!("1492af14-2569-5e48-bf42-9b2d51f2ab45");

        let hooks = TestHooks::new(class, vendor);
        let res = manifest.process_sequence(input.into(), state.clone(), &info, &hooks);

        let digest_bytes: &[u8] = &std::vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10
        ];
        let digest = SuitDigest::new(SuitDigestAlgorithm::Sha256, digest_bytes.into());
        state.set_vendor_id(vendor);
        state.set_class_id(class);
        state.set_image_digest(digest);
        state.set_image_size(34768);

        assert_eq!(res.unwrap(), state);
    }

    #[test]
    fn write_verify_sequence() {
        let input: &[u8] = &std::vec![
            0x8A, 0x14, 0xA5, 0x01, 0x50, 0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF, 0xBE,
            0x9D, 0xE6, 0x63, 0xE4, 0xD4, 0x1F, 0xFE, 0x02, 0x50, 0x14, 0x92, 0xAF, 0x14, 0x25,
            0x69, 0x5E, 0x48, 0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45, 0x03, 0x58, 0x24,
            0x82, 0x2F, 0x58, 0x20, 0xB1, 0x6A, 0xA5, 0x6B, 0xE3, 0x88, 0x0D, 0x18, 0xCD, 0x41,
            0xE6, 0x83, 0x84, 0xCF, 0x1E, 0xC8, 0xC1, 0x76, 0x80, 0xC4, 0x5A, 0x02, 0xB1, 0x57,
            0x5D, 0xC1, 0x51, 0x89, 0x23, 0xAE, 0x8B, 0x0E, 0x0E, 0x19, 0x87, 0xD0, 0x12, 0x44,
            0x74, 0xBA, 0x25, 0x21, 0x01, 0x0F, 0x02, 0x0F, 0x12, 0x0F, 0x03, 0x0F
        ];
        let manifest = Manifest::<Authenticated>::from_bytes::<Authenticated>(input.into());
        let component_name = &std::vec![0x81, 0x41, 0x00];
        let component = Component::from_bytes(component_name);
        let info = ComponentInfo::new(component, 0);
        let mut state = ManifestState::default();
        let vendor = uuid!("fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe");
        let class = uuid!("1492af14-2569-5e48-bf42-9b2d51f2ab45");
        let hooks = TestHooks::new(class, vendor);
        let res = manifest.process_sequence(input.into(), state.clone(), &info, &hooks);
        assert!(res.is_ok());
    }
}
