use minicbor::data::Tag;

pub const SUIT_TAG_ENVELOPE: Tag = Tag::new(107);
pub const SUIT_SUPPORTED_VERSION: u8 = 1;

#[derive(Copy, Clone, Debug, num_enum::IntoPrimitive)]
#[non_exhaustive]
#[repr(i16)]
pub enum SuitEnvelope {
    Unset = 0,
    Authentication = 2,
    Manifest = 3,
    PayloadFetch = 16,
    PayloadInstallation = 20,
    PayloadText = 23,
}

#[derive(Copy, Clone, Debug, num_enum::IntoPrimitive)]
#[non_exhaustive]
#[repr(i16)]
pub enum Manifest {
    Unset = 0,
    EncodingVersion = 1,
    SequenceNumber = 2,
    CommonData = 3,
    ReferenceUri = 4,
    ImageValidation = 7,
    ImageLoading = 8,
    ImageInvocation = 9,
    PayloadFetch = 16,
    PayloadInstallation = 20,
    TextDescription = 23,
}

#[derive(Copy, Clone, Debug, num_enum::IntoPrimitive)]
#[non_exhaustive]
#[repr(i8)]
pub enum SuitCommon {
    Unset = 0,
    ComponentIdentifiers = 2,
    CommonCommandSequence = 4,
}

#[derive(Copy, Clone, Debug, num_enum::IntoPrimitive)]
#[non_exhaustive]
#[repr(i32)]
pub enum SuitParameter {
    Unset = 0,
    VendorId = 1,
    ClassId = 2,
    ImageDigest = 3,
    ComponentSlot = 5,
    StrictOrder = 12,
    SoftFailure = 13,
    ImageSize = 14,
    Content = 18,
    Uri = 21,
    SourceComponent = 22,
    InvokeArgs = 23,
    DeviceId = 24,
}

impl TryFrom<i32> for SuitParameter {
    type Error = crate::error::Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Unset,
            1 => Self::VendorId,
            2 => Self::ClassId,
            3 => Self::ImageDigest,
            4 => Self::ComponentSlot,
            5 => Self::ComponentSlot,
            12 => Self::StrictOrder,
            13 => Self::SoftFailure,
            14 => Self::ImageSize,
            18 => Self::Content,
            21 => Self::Uri,
            22 => Self::SourceComponent,
            23 => Self::InvokeArgs,
            24 => Self::DeviceId,
            n => return Err(Self::Error::UnsupportedParameter(n)),
        })
    }
}

#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
#[repr(i32)]
pub enum SuitCommand {
    Unset = 0,
    VendorIdentifier = 1,
    ClassIdentifier = 2,
    ImageMatch = 3,
    ComponentSlot = 5,
    CheckContent = 6,
    SetComponentIndex = 12,
    Abort = 14,
    TryEach = 15,
    WriteContent = 18,
    OverrideParameters = 20,
    Fetch = 21,
    Copy = 22,
    Invoke = 23,
    DeviceIdentifier = 24,
    Swap = 31,
    RunSequence = 32,
    Custom(i32),
}

impl From<i32> for SuitCommand {
    fn from(value: i32) -> Self {
        match value {
            1 => SuitCommand::VendorIdentifier,
            2 => SuitCommand::ClassIdentifier,
            3 => SuitCommand::ImageMatch,
            5 => SuitCommand::ComponentSlot,
            6 => SuitCommand::CheckContent,
            12 => SuitCommand::SetComponentIndex,
            14 => SuitCommand::Abort,
            15 => SuitCommand::TryEach,
            18 => SuitCommand::WriteContent,
            20 => SuitCommand::OverrideParameters,
            21 => SuitCommand::Fetch,
            22 => SuitCommand::Copy,
            23 => SuitCommand::Invoke,
            24 => SuitCommand::DeviceIdentifier,
            31 => SuitCommand::Swap,
            32 => SuitCommand::RunSequence,
            n => SuitCommand::Custom(n),
        }
    }
}

impl From<SuitCommand> for i32 {
    fn from(value: SuitCommand) -> Self {
        match value {
            SuitCommand::Unset => 0,
            SuitCommand::VendorIdentifier => 1,
            SuitCommand::ClassIdentifier => 2,
            SuitCommand::ImageMatch => 3,
            SuitCommand::ComponentSlot => 5,
            SuitCommand::CheckContent => 6,
            SuitCommand::SetComponentIndex => 12,
            SuitCommand::Abort => 14,
            SuitCommand::TryEach => 15,
            SuitCommand::WriteContent => 18,
            SuitCommand::OverrideParameters => 20,
            SuitCommand::Fetch => 21,
            SuitCommand::Copy => 22,
            SuitCommand::Invoke => 23,
            SuitCommand::DeviceIdentifier => 24,
            SuitCommand::Swap => 31,
            SuitCommand::RunSequence => 32,
            SuitCommand::Custom(n) => n,
        }
    }
}
