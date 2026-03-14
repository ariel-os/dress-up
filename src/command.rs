//! Provides SUIT command decoding
//!
//! The command decoding covers parsing and execution for command sequences in a SUIT manifest.
use ctutils::{Choice, CtEq};
use digest::Update;
use minicbor::bytes::ByteSlice;
use minicbor::Decoder;

use crate::cbor::SubCbor;
use crate::component::{Component, ComponentInfo, ComponentIter};
use crate::consts::SuitCommand;
use crate::error::Error;
use crate::manifeststate::ManifestState;
use crate::report::ReportingPolicy;
use crate::OperatingHooks;

#[derive(Clone, Debug)]
pub(crate) enum CommandArgument<'a> {
    Report(ReportingPolicy),
    Cbor { decoder: Decoder<'a>, offset: usize },
}

impl<'a> CommandArgument<'a> {
    fn new(command: SuitCommand, d: &mut Decoder<'a>) -> Result<Self, Error> {
        if command.has_report_policy() {
            let policy = d.decode::<ReportingPolicy>()?;
            Ok(CommandArgument::Report(policy))
        } else {
            let offset = d.position();
            let bytes = d.sub_cbor()?;
            Ok(CommandArgument::Cbor {
                decoder: Decoder::new(bytes),
                offset,
            })
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Command<'a> {
    pub(crate) command: SuitCommand,
    pub(crate) argument: CommandArgument<'a>,
    pub(crate) position: usize,
}

impl<'a> Command<'a> {
    fn get_argument_cbor<'b>(&'b mut self) -> Result<&'b mut Decoder<'a>, Error> {
        if let CommandArgument::Cbor {
            ref mut decoder, ..
        } = self.argument
        {
            return Ok(decoder);
        }
        Err(Error::InvalidCommandSequence(0))
    }

    fn get_argument_offset(&self) -> usize {
        if let CommandArgument::Cbor { offset, .. } = self.argument {
            offset
        } else {
            0
        }
    }

    fn get_report_policy(&self) -> Result<ReportingPolicy, Error> {
        if let CommandArgument::Report(policy) = self.argument {
            return Ok(policy);
        }
        Err(Error::InvalidCommandSequence(0))
    }
}

pub(crate) struct CommandSequenceIterator<'a> {
    d: Decoder<'a>,
    remaining: u64,
}

impl<'a> CommandSequenceIterator<'a> {
    pub(crate) fn new(mut d: Decoder<'a>) -> Result<Self, Error> {
        let length = Self::enter_sequence(&mut d)?;
        Ok(CommandSequenceIterator {
            d,
            remaining: length,
        })
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

    fn decode_command(&mut self) -> Result<Command<'a>, Error> {
        let position = self.d.position();
        let command = self.d.i32()?.into();
        let argument = CommandArgument::new(command, &mut self.d)?;
        Ok(Command {
            command,
            argument,
            position,
        })
    }
}

impl<'a> Iterator for CommandSequenceIterator<'a> {
    type Item = Result<Command<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining > 0 {
            self.remaining -= 1;
            return Some(self.decode_command());
        }
        None
    }
}

struct RwBuf<N: generic_array::ArrayLength> {
    pub buf: generic_array::GenericArray<u8, N>,
}

impl<N: generic_array::ArrayLength> RwBuf<N> {
    fn new() -> Self {
        RwBuf {
            buf: generic_array::GenericArray::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CommandSequenceExecutor<'a, O: OperatingHooks> {
    command_sequence: &'a ByteSlice,
    // Components list is needed by Copy and swap
    components: &'a ByteSlice,
    os_hooks: &'a O,
}

impl<'a, O: OperatingHooks> CommandSequenceExecutor<'a, O> {
    pub(crate) fn new(
        command_sequence: &'a ByteSlice,
        components: &'a ByteSlice,
        os_hooks: &'a O,
    ) -> Self {
        Self {
            command_sequence,
            components,
            os_hooks,
        }
    }

    fn try_each(
        &self,
        state: &mut ManifestState<'a>,
        component: &'a ComponentInfo<'a>,
        decoder: &mut Decoder<'a>,
    ) -> Result<(), Error> {
        for sequence in decoder.array_iter::<&ByteSlice>()? {
            let seq = sequence?;
            if seq.is_empty() {
                return Ok(());
            }
            let try_sequence = CommandSequenceExecutor::new(seq, self.components, self.os_hooks);
            let res = try_sequence.process(state.clone(), component);
            if let Ok(res) = res {
                *state = res;
                return Ok(());
            }
            // Bail out on any error except the ConditionMatchFail
            if !matches!(res, Err(Error::ConditionMatchFail(_))) {
                return res.map(|_| ());
            }
        }
        Err(Error::TryEachFail(decoder.position()))
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

    pub(crate) fn process(
        &self,
        mut state: ManifestState<'a>,
        component: &'a ComponentInfo,
    ) -> Result<ManifestState<'a>, Error> {
        let decoder = Decoder::new(self.command_sequence);
        let mut match_component = true;
        for command in CommandSequenceIterator::new(decoder)? {
            let mut command = command?;
            if !match_component {
                if matches!(command.command, SuitCommand::SetComponentIndex) {
                    if let CommandArgument::Cbor {
                        ref mut decoder,
                        offset,
                    } = command.argument
                    {
                        match_component = component
                            .in_applylist(decoder)
                            .map_err(|e| e.add_offset(offset))?;
                    }
                }
            } else {
                match command.command {
                    SuitCommand::Unset => {
                        return Err(Error::UnsupportedCommand(command.command.into()))
                    }
                    SuitCommand::Abort => return Err(Error::ConditionMatchFail(command.position)),
                    SuitCommand::OverrideParameters => {
                        state
                            .update_parameter(command.get_argument_cbor()?)
                            .map_err(|e| e.add_offset(command.get_argument_offset()))?;
                    }
                    SuitCommand::SetComponentIndex => {
                        match_component = component
                            .in_applylist(command.get_argument_cbor()?)
                            .map_err(|e| e.add_offset(command.get_argument_offset()))?;
                    }
                    SuitCommand::CheckContent => {
                        // byte by byte check
                        self.cond_check_content(&state, component.component())?;
                    }
                    SuitCommand::ClassIdentifier => {
                        self.cond_class_identifier(&state, component.component())?;
                    }
                    SuitCommand::ComponentSlot => {
                        self.cond_component_slot(&state, component.component())?;
                    }
                    SuitCommand::Copy => self.directive_copy(&state, component, self.components)?,
                    SuitCommand::DeviceIdentifier => {
                        self.cond_device_identifier(&state, component.component())?;
                    }
                    SuitCommand::Fetch => {
                        self.directive_fetch(&state, component.component())?;
                    }
                    SuitCommand::ImageMatch => {
                        // Digest check
                        self.cond_image_match(&state, component.component())?;
                    }

                    SuitCommand::Invoke => {
                        Err(Error::UnsupportedCommand(SuitCommand::Invoke.into()))?
                    }
                    SuitCommand::RunSequence => {
                        Err(Error::UnsupportedCommand(SuitCommand::RunSequence.into()))?
                    }
                    SuitCommand::Swap => {
                        Err(Error::UnsupportedCommand(SuitCommand::RunSequence.into()))?
                    }
                    SuitCommand::TryEach => {
                        self.try_each(&mut state, component, command.get_argument_cbor()?)
                            .map_err(|e| e.add_offset(command.get_argument_offset()))?;
                    }
                    SuitCommand::VendorIdentifier => {
                        self.cond_vendor_identifier(&state, component.component())?;
                    }
                    SuitCommand::WriteContent => {
                        self.directive_write(&state, component.component())?;
                    }
                    SuitCommand::Custom(_n) => todo!(),
                }
            }
        }
        Ok(state)
    }

    fn cond_class_identifier(
        &self,
        state: &ManifestState,
        component: &Component,
    ) -> Result<(), Error> {
        if let Some(class_id) = state.class_id {
            self.os_hooks
                .match_class_id(class_id, component)
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

    fn cond_vendor_identifier(
        &self,
        state: &ManifestState,
        component: &Component,
    ) -> Result<(), Error> {
        if let Some(vendor_id) = state.vendor_id {
            self.os_hooks
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
    ) -> Result<(), Error> {
        if let Some(device_id) = state.device_id {
            self.os_hooks
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
    ) -> Result<(), Error> {
        if let Some(component_slot) = state.component_slot {
            self.os_hooks
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

    fn cond_check_content(
        &self,
        state: &ManifestState,
        component: &Component,
    ) -> Result<(), Error> {
        if let Some(content) = &state.content {
            let size = self.os_hooks.component_size(component)?;
            if size != content.len() {
                return Err(Error::ConditionMatchFail(0));
            }
            let mut choice = Choice::TRUE;
            let mut buf = RwBuf::<O::ReadWriteBufferSize>::new().buf;
            for offset in (0..size).step_by(buf.len()) {
                let diff = size.saturating_sub(offset);
                let read_size = if diff < buf.len() { diff } else { buf.len() };
                let buf = &mut buf[0..read_size];
                self.os_hooks
                    .component_read(component, state.component_slot, offset, buf)?;
                let manifest_content = content
                    .get(offset..(offset + read_size))
                    .ok_or(Error::ConditionMatchFail(0))?;
                choice = choice.and(manifest_content.ct_eq(buf));
            }
            if choice.to_bool() {
                Ok(())
            } else {
                Err(Error::ConditionMatchFail(0))
            }
        } else {
            Err(Error::ParameterNotSet(0))
        }
    }

    fn cond_image_match(&self, state: &ManifestState, component: &Component) -> Result<(), Error> {
        if let Some(digest) = &state.image_digest {
            let size = self.os_hooks.component_size(component)?;
            let mut hasher = digest.hasher()?;
            let mut buf = RwBuf::<O::ReadWriteBufferSize>::new().buf;
            for offset in (0..size).step_by(buf.len()) {
                let diff = size.saturating_sub(offset);
                let read_size = if diff < buf.len() { diff } else { buf.len() };
                let buf = &mut buf[0..read_size];
                self.os_hooks
                    .component_read(component, state.component_slot, offset, buf)?;
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

    fn directive_fetch(&self, state: &ManifestState, component: &Component) -> Result<(), Error> {
        if let Some(uri) = state.uri {
            self.os_hooks.fetch(component, state.component_slot, uri)
        } else {
            Err(Error::ParameterNotSet(0))
        }
    }

    fn directive_write(&self, state: &ManifestState, component: &Component) -> Result<(), Error> {
        if let Some(content) = state.content {
            self.os_hooks
                .component_write(component, state.component_slot, 0, content)
        } else {
            Err(Error::ParameterNotSet(0))
        }
    }

    fn directive_copy(
        &self,
        state: &ManifestState,
        component: &ComponentInfo,
        components: &'a ByteSlice,
    ) -> Result<(), Error> {
        let source_index = state.source_component.ok_or(Error::ParameterNotSet(0))?;
        if source_index == component.index {
            return Err(Error::SameSourceAndTarget(source_index));
        }
        let mut decoder = Decoder::new(components);
        for (idx, source) in ComponentIter::new(&mut decoder)?.enumerate() {
            if (idx as u32) == source_index {
                let source_component = source?;
                let size = self.os_hooks.component_size(&source_component)?;

                if state.image_digest.is_some() && state.image_size.is_some() {
                    // Check if data is different before copying
                    if self.cond_image_match(state, component.component()).is_ok() {
                        return Ok(());
                    }

                    // Avoid copy of corrupted image
                    self.cond_image_match(state, &source_component)?;
                }

                let mut buf = RwBuf::<O::ReadWriteBufferSize>::new().buf;
                for offset in (0..size).step_by(buf.len()) {
                    let diff = size.saturating_sub(offset);
                    let read_size = if diff < buf.len() { diff } else { buf.len() };
                    let buf = &mut buf[0..read_size];
                    self.os_hooks.component_read(
                        &source_component,
                        state.component_slot,
                        offset,
                        buf,
                    )?;
                    self.os_hooks.component_write(
                        component.component(),
                        state.component_slot,
                        offset,
                        buf,
                    )?;
                }
                return Ok(());
            }
        }
        Err(Error::InvalidSourceComponent(source_index))
    }

    fn decode_reporting_policy(decoder: &mut Decoder) -> Result<ReportingPolicy, Error> {
        Ok(decoder.decode::<ReportingPolicy>()?)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::*;
    use crate::component::Component;
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

    fn test_vendor_uuid() -> Uuid {
        uuid!("fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe")
    }

    fn test_class_uuid() -> Uuid {
        uuid!("1492af14-2569-5e48-bf42-9b2d51f2ab45")
    }

    fn create_test_hooks() -> TestHooks {
        let vendor = test_vendor_uuid();
        let class = test_class_uuid();
        TestHooks::new(class, vendor)
    }

    const COMPONENT_NAME: [u8; 3] = [0x81, 0x41, 0x00];

    fn create_test_component() -> ComponentInfo<'static> {
        let component = Component::from_bytes(&COMPONENT_NAME);
        ComponentInfo::new(component, 0)
    }

    fn create_empty_components() -> &'static ByteSlice {
        (&[] as &[u8]).into()
    }

    #[test]
    fn invalid_sequence() {
        let input: &[u8] = &std::vec![0x83, 0x14, 0x05, 0x15,];

        let hooks = create_test_hooks();
        let info = create_test_component();
        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);
        let state = ManifestState::default();
        let res = sequence.process(state, &info).unwrap_err();
        assert_eq!(res, Error::InvalidCommandSequence(1));
    }

    #[test]
    fn indefinite_length_sequence() {
        let input: &[u8] = &std::vec![0x9F, 0x14, 0x05, 0xFF];

        let hooks = create_test_hooks();
        let info = create_test_component();
        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);
        let state = ManifestState::default();
        let res = sequence.process(state, &info).unwrap_err();
        assert_eq!(res, Error::InvalidCommandSequence(1));
    }

    #[test]
    fn unset_detection() {
        let input: &[u8] = &std::vec![0x82, 0x00, 0x05];

        let hooks = create_test_hooks();
        let info = create_test_component();
        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);
        let state = ManifestState::default();
        let res = sequence.process(state.clone(), &info).unwrap_err();
        assert_eq!(res, Error::UnsupportedCommand(0));
    }

    #[test]
    fn component_switch() {
        let input: &[u8] = &std::vec![0x86, 0x0C, 0x01, 0x14, 0xA1, 0x05, 0x01, 0x0C, 0x00];
        let state = ManifestState::default();
        let hooks = create_test_hooks();
        let info = create_test_component();
        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);

        let res = sequence.process(state, &info).unwrap();
        assert_eq!(res.component_slot, None);
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

        let hooks = create_test_hooks();
        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);
        let mut state = ManifestState::default();
        let info = create_test_component();

        let res = sequence.process(state.clone(), &info);

        let digest_bytes: &[u8] = &std::vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10
        ];
        let digest = SuitDigest::new(SuitDigestAlgorithm::Sha256, digest_bytes.into());
        state.set_vendor_id(test_vendor_uuid());
        state.set_class_id(test_class_uuid());
        state.set_image_digest(digest);
        state.set_image_size(34768);

        assert_eq!(res.unwrap(), state);
    }

    #[test]
    fn write_verify_sequence() {
        let input: &[u8] = &std::vec![
            0x8C, 0x14, 0xA5, 0x01, 0x50, 0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF, 0xBE,
            0x9D, 0xE6, 0x63, 0xE4, 0xD4, 0x1F, 0xFE, 0x02, 0x50, 0x14, 0x92, 0xAF, 0x14, 0x25,
            0x69, 0x5E, 0x48, 0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45, 0x03, 0x58, 0x24,
            0x82, 0x2F, 0x58, 0x20, 0xB1, 0x6A, 0xA5, 0x6B, 0xE3, 0x88, 0x0D, 0x18, 0xCD, 0x41,
            0xE6, 0x83, 0x84, 0xCF, 0x1E, 0xC8, 0xC1, 0x76, 0x80, 0xC4, 0x5A, 0x02, 0xB1, 0x57,
            0x5D, 0xC1, 0x51, 0x89, 0x23, 0xAE, 0x8B, 0x0E, 0x0E, 0x19, 0x87, 0xD0, 0x12, 0x44,
            0x74, 0xBA, 0x25, 0x21, 0x01, 0x0F, 0x02, 0x0F, 0x12, 0x0F, 0x03, 0x0F, 0x06, 0x0F,
        ];
        let state = ManifestState::default();
        let hooks = create_test_hooks();
        let info = create_test_component();

        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);
        let res = sequence.process(state.clone(), &info);
        assert!(res.is_ok());
    }

    #[test]
    fn try_each() {
        // Try each statement with abort in first arm and set component slot in second
        let input: &[u8] = &std::vec![
            0x82, 0x0F, 0x82, 0x47, 0x84, 0x0E, 0x05, 0x14, 0xA1, 0x05, 0x01, 0x45, 0x82, 0x14,
            0xA1, 0x05, 0x02
        ];
        let hooks = create_test_hooks();
        let info = create_test_component();

        let state = ManifestState::default();
        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);
        let res = sequence.process(state.clone(), &info).unwrap();
        assert_eq!(res.component_slot, Some(2));
    }

    #[test]
    fn try_each_fail() {
        let input: &[u8] = &std::vec![0x82, 0x0F, 0x81, 0x43, 0x82, 0x0E, 0x05];
        let hooks = create_test_hooks();
        let info = create_test_component();

        let state = ManifestState::default();
        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);
        let res = sequence.process(state.clone(), &info).unwrap_err();
        assert_eq!(res, Error::TryEachFail(7));
    }

    #[test]
    fn try_each_invalid() {
        let input: &[u8] = &std::vec![
            0x82, 0x0F, 0x82, 0x45, 0x82, 0x14, 0xA1, 0x00, 0x02, 0x45, 0x82, 0x14, 0xA1, 0x05,
            0x02,
        ];
        let hooks = create_test_hooks();
        let info = create_test_component();

        let state = ManifestState::default();
        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);
        let res = sequence.process(state.clone(), &info).unwrap_err();
        assert_eq!(res, Error::UnsupportedParameter(0));
    }

    #[test]
    fn try_each_first() {
        let input: &[u8] = &std::vec![
            0x82, 0x0F, 0x82, 0x45, 0x82, 0x14, 0xA1, 0x05, 0x02, 0x43, 0x82, 0x0E, 0x05
        ];
        let hooks = create_test_hooks();
        let info = create_test_component();

        let state = ManifestState::default();
        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);
        let res = sequence.process(state.clone(), &info).unwrap();
        assert_eq!(res.component_slot, Some(2));
    }

    #[test]
    fn try_each_empty() {
        let input: &[u8] = &std::vec![0x82, 0x0F, 0x81, 0x40];
        let hooks = create_test_hooks();
        let info = create_test_component();

        let state = ManifestState::default();
        let sequence =
            CommandSequenceExecutor::new(input.into(), create_empty_components(), &hooks);
        let res = sequence.process(state.clone(), &info);
        assert_eq!(res, Ok(state));
    }
}
