//! SUIT parsing errors.
use core::convert::From;

/// SUIT manifest parsing errors
///
/// TODO! ensure error locations match the location within the manifest.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// Authentication of the manifest failed
    ///
    /// Any processing of the manifest *must* stop when this error is returned and any persistent
    /// state must be erased.
    AuthenticationFailure,
    /// String Capacity exhausted.
    CapacityError,
    /// SUIT Condition match failure.
    ///
    /// Returned when a SUIT command condition did not match the expected.
    ConditionMatchFail {
        /// Position of the condition match failure in the manifest.
        position: usize,
    },
    /// SUIT Try Each command sequence failed every sequence.
    TryEachFail {
        /// Position of the try each command failure in the manifest.
        position: usize,
    },
    /// Unexpected end of the CBOR input.
    EndOfInput,
    /// Authentication structure is not valid.
    InvalidAuthenticationStructure,
    /// Invalid command sequence.
    InvalidCommandSequence {
        /// Position of the command sequence parsing failure in the manifest.
        position: usize,
    },
    /// Invalid common section.
    InvalidCommonSection,
    /// No authentication object found inside the SUIT envelope.
    NoAuthObject,
    /// No common section found inside the SUIT manifest.
    NoCommonSection,
    /// Missing command section inside the SUIT manifest.
    NoCommandSection {
        /// The missing section number.
        section: i16,
    },
    /// No component list inside the SUIT common section
    NoComponentList,
    /// No manifest object found inside the SUIT envelope.
    NoManifestObject,
    /// Parameter required for the condition is not set.
    ParameterNotSet {
        /// Position of the command for which the parameter is not set in the manifest.
        position: usize,
    },
    /// CBOR element type at location is unexpected.
    UnexpectedCbor {
        /// Position of the unexpected CBOR element.
        position: usize,
    },
    /// CBOR array or map is of indefinite length where it is not allowed.
    UnexpectedIndefiniteLength {
        /// Position of the indefinite length CBOR element in the manifest.
        position: usize,
    },
    /// SUIT Command is not supported by the processor.
    UnsupportedCommand {
        /// The unsupported command number.
        command: i32,
    },
    /// SUIT component identifier is not supported by the processor.
    UnsupportedComponentIdentifier {
        /// The identifier of the component that is not supported.
        identifier: i64,
    },
    /// SUIT digest algorithm is not supported by the processor.
    UnsupportedDigestAlgo {
        /// The algorithm number.
        algorithm: i64,
    },
    /// SUIT manifest version number is not supported by the processor.
    UnsupportedManifestVersion,
    /// SUIT parameter is not supported by the processor.
    UnsupportedParameter {
        /// The parameter number.
        parameter: i32,
    },
    /// UTF-8 error while decoding the component identifier.
    Utf8Error {
        /// Position of the UTF-8 decoding error in the manifest.
        position: usize,
    },
}

impl Error {
    pub(crate) fn digest_algo_error(value: i64) -> Self {
        Error::UnsupportedDigestAlgo { algorithm: value }
    }

    /// Use to modify error position on bytes-string wrapped CBOR
    pub(crate) fn add_offset(self, offset: usize) -> Self {
        match self {
            Error::ConditionMatchFail { position } => Error::ConditionMatchFail {
                position: position + offset,
            },
            Error::TryEachFail { position } => Error::TryEachFail {
                position: position + offset,
            },
            Error::InvalidCommandSequence { position } => Error::InvalidCommandSequence {
                position: position + offset,
            },
            Error::ParameterNotSet { position } => Error::ParameterNotSet {
                position: position + offset,
            },
            Error::UnexpectedCbor { position } => Error::UnexpectedCbor {
                position: position + offset,
            },
            Error::UnexpectedIndefiniteLength { position } => Error::UnexpectedIndefiniteLength {
                position: position + offset,
            },
            Error::Utf8Error { position } => Error::Utf8Error {
                position: position + offset,
            },
            e => e,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AuthenticationFailure => write!(f, "authentication of manifest failed"),
            Self::CapacityError => write!(f, "string capacity exhausted"),
            Self::ConditionMatchFail { position } => write!(f, "condition mismatch at {position}"),
            Self::TryEachFail { position } => write!(f, "try each sequence failed at {position}"),
            Self::EndOfInput => write!(f, "end of CBOR input"),
            Self::InvalidAuthenticationStructure => write!(f, "invalide authentication structure"),
            Self::InvalidCommandSequence { position } => {
                write!(f, "invalid command sequence at {position}")
            }
            Self::InvalidCommonSection => write!(f, "invalid common section found in manifest"),
            Self::NoAuthObject => write!(f, "no Authentication object in manifest"),
            Self::NoCommonSection => write!(f, "no common section found in manifest"),
            Self::NoCommandSection { section } => {
                write!(f, "no command sequence {section} found in manifest")
            }
            Self::NoComponentList => write!(f, "no component list found in manifest"),
            Self::NoManifestObject => write!(f, "no Manifest object in manifest"),
            Self::ParameterNotSet { position } => {
                write!(f, "parameter required for condition at {position} not set")
            }
            Self::UnexpectedCbor { position } => write!(f, "unexpected CBOR found at {position}"),
            Self::UnexpectedIndefiniteLength { position } => {
                write!(
                    f,
                    "unexpected indefinite length cbor container at {position}"
                )
            }
            Self::UnsupportedCommand { command } => write!(f, "command {command} not supported"),
            Self::UnsupportedComponentIdentifier { identifier } => {
                write!(f, "component identifier {identifier} not supported")
            }
            Self::UnsupportedDigestAlgo { algorithm } => {
                write!(f, "digest algorithm {algorithm} not supported")
            }
            Self::UnsupportedManifestVersion => write!(f, "manifest version not supported"),
            Self::UnsupportedParameter { parameter } => {
                write!(f, "parameter {parameter} not supported")
            }
            Self::Utf8Error { position } => {
                write!(f, "unable to interpret bytes as string at {position}")
            }
        }
    }
}

impl core::error::Error for Error {}

impl From<minicbor::decode::Error> for Error {
    fn from(err: minicbor::decode::Error) -> Self {
        if err.is_end_of_input() {
            Self::EndOfInput
        } else {
            let position = err.position().unwrap_or(0);
            Self::UnexpectedCbor { position }
        }
    }
}
