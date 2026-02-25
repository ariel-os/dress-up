//! SUIT parsing errors.
use core::convert::From;

/// SUIT manifest parsing errors
///
/// TODO! ensure error locations match the location within the manifest.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// String Capacity exhausted.
    CapacityError,
    /// SUIT Condition match failure.
    ///
    /// Returned when a SUIT command condition did not match the expected.
    ConditionMatchFail(usize),
    /// SUIT Try Each command sequence failed every sequence.
    TryEachFail(usize),
    /// Unexpected end of the CBOR input.
    EndOfInput,
    /// Invalid command sequence.
    InvalidCommandSequence(usize),
    /// Invalid common section.
    InvalidCommonSection,
    /// No authentication object found inside the SUIT envelope.
    NoAuthObject,
    /// No common section found inside the SUIT manifest.
    NoCommonSection,
    /// Missing command section inside the SUIT manifest.
    NoCommandSection(i16),
    /// No component list inside the SUIT common section
    NoComponentList,
    /// No manifest object found inside the SUIT envelope.
    NoManifestObject,
    /// Parameter required for the condition is not set.
    ParameterNotSet(usize),
    /// CBOR element type at location is unexpected.
    UnexpectedCbor(usize),
    /// CBOR array or map is of indefinite length where it is not allowed.
    UnexpectedIndefiniteLength(usize),
    /// SUIT Command is not supported by the processor.
    UnsupportedCommand(i32),
    /// SUIT component identifier is not supported by the processor.
    UnsupportedComponentIdentifier(i64),
    /// SUIT digest algorithm is not supported by the processor.
    UnsupportedDigestAlgo(i64),
    /// SUIT manifest version number is not supported by the processor.
    UnsupportedManifestVersion,
    /// SUIT parameter is not supported by the processor.
    UnsupportedParameter(i32),
    /// UTF-8 error while decoding the component identifier.
    Utf8Error(usize),
}

impl Error {
    pub(crate) fn digest_algo_error(value: i64) -> Self {
        Error::UnsupportedDigestAlgo(value)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CapacityError => write!(f, "string capacity exhausted"),
            Self::ConditionMatchFail(pos) => write!(f, "condition mismatch at {pos}"),
            Self::TryEachFail(pos) => write!(f, "try each sequence failed at {pos}"),
            Self::EndOfInput => write!(f, "end of CBOR input"),
            Self::InvalidCommandSequence(n) => write!(f, "invalid command sequence at {n}"),
            Self::InvalidCommonSection => write!(f, "invalid common section found in manifest"),
            Self::NoAuthObject => write!(f, "no Authentication object in manifest"),
            Self::NoCommonSection => write!(f, "no common section found in manifest"),
            Self::NoCommandSection(n) => write!(f, "no command sequence {n} found in manifest"),
            Self::NoComponentList => write!(f, "no component list found in manifest"),
            Self::NoManifestObject => write!(f, "no Manifest object in manifest"),
            Self::ParameterNotSet(n) => {
                write!(f, "parameter required for condition at {n} not set")
            }
            Self::UnexpectedCbor(pos) => write!(f, "unexpected CBOR found at {pos}"),
            Self::UnexpectedIndefiniteLength(n) => {
                write!(f, "unexpected indefinite length cbor container at {n}")
            }
            Self::UnsupportedCommand(n) => write!(f, "command {n} not supported"),
            Self::UnsupportedComponentIdentifier(n) => {
                write!(f, "component identifier {n} not supported")
            }
            Self::UnsupportedDigestAlgo(n) => write!(f, "digest algorithm {n} not supported"),
            Self::UnsupportedManifestVersion => write!(f, "manifest version not supported"),
            Self::UnsupportedParameter(n) => write!(f, "parameter {n} not supported"),
            Self::Utf8Error(n) => write!(f, "unable to interpret bytes as string at {n}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<minicbor::decode::Error> for Error {
    fn from(err: minicbor::decode::Error) -> Self {
        if err.is_end_of_input() {
            Self::EndOfInput
        } else {
            let pos = err.position().unwrap_or(0);
            Self::UnexpectedCbor(pos)
        }
    }
}
