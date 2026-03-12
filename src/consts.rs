//! SUIT IANA constants.
use minicbor::data::Tag;

/// SUIT envelope tag.
pub const SUIT_TAG_ENVELOPE: Tag = Tag::new(107);
/// SUIT manifest encoding version support.
pub const SUIT_SUPPORTED_VERSION: u8 = 1;

/// Suit envelope elements
///
/// All elements are bstr wrapped.
///
/// See <https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest-34#name-suit-envelope-elements>
#[derive(Copy, Clone, Debug, num_enum::IntoPrimitive)]
#[non_exhaustive]
#[repr(i16)]
pub enum SuitEnvelope {
    /// Unset detection
    Unset = 0,
    /// Authentication wrapper
    Authentication = 2,
    /// Manifest content
    Manifest = 3,
    /// Payload fetch
    ///
    /// Used when the payload fetch stage is severable
    PayloadFetch = 16,
    /// Payload installation
    ///
    /// Used when the payload installation stage is severable
    PayloadInstallation = 20,
    /// Text description of the manifest
    Text = 23,
}

/// Manifest elements
///
/// See <https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest-34#name-suit-manifest-elements>
#[derive(Copy, Clone, Debug, num_enum::IntoPrimitive)]
#[non_exhaustive]
#[repr(i16)]
pub enum Manifest {
    /// Unset detection.
    Unset = 0,
    /// Manifest encoding version number.
    EncodingVersion = 1,
    /// Manifest sequence number.
    ///
    /// Monotonically increasing anti-rollback counter.
    /// *May* be implemented as a timestamp.
    SequenceNumber = 2,
    /// Encodes all information shared between command sequences.
    CommonData = 3,
    /// URI where the full manifest can be found.
    ReferenceUri = 4,
    /// SUIT command sequence to validate the result of applying the update is correct.
    ///
    /// Typical actions involve image validation.
    ImageValidation = 7,
    /// SUIT command sequence to prepare a payload for execution.
    ///
    /// Typical actions include copying an image from permanent storage into RAM.
    ImageLoading = 8,
    /// SUIT command sequence to invoke an image.
    ///
    /// typically only contains the [[SuitCommand::Invoke] action.
    ImageInvocation = 9,
    /// SUIT command sequence to obtain a payload.
    ///
    /// Might be integrated into the [Manifest::PayloadInstallation] stage when the download
    /// streams the payload into the installation location.
    PayloadFetch = 16,
    /// SUIT command sequence to install a payload.
    ///
    /// Typical actions include verifying the payload in temporary storage, and copying the staged
    /// payload from temporary storage.
    PayloadInstallation = 20,

    /// SUIT text description in the manifest.
    TextDescription = 23,
}

/// SUIT common section elements.
///
/// See <https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest-34#name-suit-common-elements>
#[derive(Copy, Clone, Debug, num_enum::IntoPrimitive)]
#[non_exhaustive]
#[repr(i16)]
pub enum SuitCommon {
    /// Unset detection.
    Unset = 0,
    /// List of component identifiers affected by this manifest.
    ComponentIdentifiers = 2,
    /// SUIT command sequence to execute prior to executing any other command sequence.
    CommonCommandSequence = 4,
}

/// SUIT parameter numbers.
///
/// See <https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest-34#name-suit-parameters>
#[derive(Copy, Clone, Debug, num_enum::IntoPrimitive)]
#[non_exhaustive]
#[repr(i32)]
pub enum SuitParameter {
    /// Unset detection.
    Unset = 0,
    /// Vendor identifier.
    ///
    /// Contains an UUID encoded as byte string.
    /// Argument for [`SuitCommand::VendorIdentifier`].
    VendorId = 1,
    /// Class Identifier.
    ///
    /// Contains an UUID encoded as byte string.
    /// Argument for [`SuitCommand::ClassIdentifier`].
    ClassId = 2,
    /// Digest of a component.
    ///
    /// Contains an suit_digest structure.
    /// Argument for [`SuitCommand::ImageMatch`].
    // Decodes into a [`crate::digest::SuitDigest`].
    ImageDigest = 3,
    /// Specify a slot within a slot.
    ComponentSlot = 5,
    /// Strict order execution of the current command sequence.
    StrictOrder = 12,
    /// Soft failure execution of the current command sequence.
    SoftFailure = 13,
    /// Component payload image size in bytes.
    ImageSize = 14,
    /// Direct content for a component.
    ///
    /// Encodes a payload as direct byte string in the parameter.
    /// Argument for [`SuitCommand::WriteContent`].
    Content = 18,
    /// URI for a fetch command.
    /// Argument for [`SuitCommand::Fetch`].
    Uri = 21,
    /// Source component for copy and swap commands.
    /// Argument for [`SuitCommand::Copy`] and [`SuitCommand::Swap`].
    SourceComponent = 22,
    /// Arguments for the invoke command.
    /// Argument for [`SuitCommand::Invoke`].
    InvokeArgs = 23,
    /// Device Identifier, contains an UUID encoded as byte string.
    /// Argument for [`SuitCommand::DeviceIdentifier`].
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

/// SUIT command numbers
///
/// See <https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest-34#name-suit-commands>
#[derive(Copy, Clone, Debug, PartialEq)]
#[non_exhaustive]
#[repr(i32)]
pub enum SuitCommand {
    /// Unset detection.
    Unset = 0,
    /// Check the supplied vendor identifier in [`SuitParameter::VendorId`] with the vendor identifier stored on the device.
    VendorIdentifier = 1,
    /// Check the supplied device class identifier in [`SuitParameter::ClassId`] with the device class identifier stored on the device.
    ClassIdentifier = 2,
    /// Verify the content in the component based on the digest.
    ImageMatch = 3,
    /// Verify if the component slot is valid for the current component.
    ComponentSlot = 5,
    /// Check the content in the component based on the [`SuitParameter::Content`].
    CheckContent = 6,
    /// Set the component index for the next commands in the sequence.
    SetComponentIndex = 12,
    /// Abort the manifest processing.
    Abort = 14,
    /// Sequentially execute a set of command sequences until one succeeds.
    TryEach = 15,
    /// Write the content of the [`SuitParameter::Content`] in the current component.
    WriteContent = 18,
    /// Set or override a set of parameters.
    ///
    /// See [`SuitParameter`] for supported parameters.
    OverrideParameters = 20,
    /// Fetch a payload from [`SuitParameter::Uri`] into the current component.
    Fetch = 21,
    /// Copy a payload from [`SuitParameter::SourceComponent`] into the current component.
    Copy = 22,
    /// Invoke the current component.
    ///
    /// Stops manifest processing to start execution of the component.
    Invoke = 23,
    /// Check the supplied vendor identifier in [`SuitParameter::VendorId`] with the vendor identifier stored on the device.
    DeviceIdentifier = 24,
    /// Swap the content of two components.
    ///
    /// Uses the current component index and the source component in [`SuitParameter::SourceComponent`] for the swap.
    Swap = 31,
    /// Run a sequence of commands.
    RunSequence = 32,
    /// Run a custom, application specific command.
    ///
    /// The processort passes the command to the [`crate::OperatingHooks`] for the operating system to process the
    /// command.
    Custom(i32),
}

impl From<i32> for SuitCommand {
    fn from(value: i32) -> Self {
        match value {
            0 => SuitCommand::Unset,
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

impl SuitCommand {
    pub(crate) fn has_report_policy(&self) -> bool {
        match self {
            SuitCommand::Unset => false,
            SuitCommand::VendorIdentifier => true,
            SuitCommand::ClassIdentifier => true,
            SuitCommand::ImageMatch => true,
            SuitCommand::ComponentSlot => true,
            SuitCommand::CheckContent => true,
            SuitCommand::SetComponentIndex => false,
            SuitCommand::Abort => true,
            SuitCommand::TryEach => false,
            SuitCommand::WriteContent => true,
            SuitCommand::OverrideParameters => false,
            SuitCommand::Fetch => true,
            SuitCommand::Copy => true,
            SuitCommand::Invoke => true,
            SuitCommand::DeviceIdentifier => true,
            SuitCommand::Swap => true,
            SuitCommand::RunSequence => false,
            SuitCommand::Custom(_) => false,
        }
    }
}
