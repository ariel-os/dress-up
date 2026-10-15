//! SUIT parsing errors.
use core::convert::From;

use crate::{
    consts::{SuitCommand, SuitParameter},
    digest::SuitDigestAlgorithm,
};

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
        /// SUIT Command that failed because of this match failure.
        command: SuitCommand,
        /// Position of the condition match failure in the manifest.
        position: usize,
    },
    /// Mismatch between the expected and provided hash algorithm
    HashAlgoMismatch {
        /// Algorithm described in the manifest,
        algo: SuitDigestAlgorithm,
        /// Position of the hash-algorithm in the manifest.
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
    /// Source component doesn't exists in the component list.
    InvalidSourceComponent {
        /// Identifier of the invalid component.
        identifier: u32,
    },
    /// Missing CBOR argument for a SUIT command
    MissingCborArgument {
        /// Command that expected the argument
        command: SuitCommand,
        /// Position of the command in the manifest
        position: usize,
    },
    /// Missing Report Policy for a SUIT command
    MissingReportPolicy {
        /// Command that expected the argument
        command: SuitCommand,
        /// Position of the command in the manifest
        position: usize,
    },
    /// No authentication object found inside the SUIT envelope.
    NoAuthObject,
    /// Missing command section inside the SUIT manifest.
    NoCommandSection {
        /// The missing section number.
        section: i16,
    },
    /// No common section found inside the SUIT manifest.
    NoCommonSection,
    /// No component list inside the SUIT common section
    NoComponentList,
    /// No manifest object found inside the SUIT envelope.
    NoManifestObject,
    /// No manifest encoding version found inside the manifest object.
    NoManifestVersion,
    /// No manifest sequence number found inside the manifest object.
    NoSequenceNumber,
    /// SUIT command is not recognized as such by the processor.
    NotACommand {
        /// Integer representation of the command.
        label: i32,
    },
    /// SUIT Digest Algorithm is not recognized as such by the processor.
    NotADigestAlgo {
        /// integer representation of the digest algorithm.
        label: i64,
    },
    /// SUIT parameter is not recognized as such by the processor.
    NotAParameter {
        /// Integer representation of the parameter.
        label: i32,
    },
    /// Parameter required for the condition is not set.
    ParameterNotSet {
        /// Position of the command for which the parameter is not set in the manifest.
        position: usize,
    },
    /// Source and target component are the same in the copy directive.
    SameSourceAndTarget {
        /// Identifier of the components.
        identifier: u32,
    },
    /// SUIT Try Each command sequence failed every sequence.
    TryEachFail {
        /// Position of the try each command failure in the manifest.
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
        /// The unsupported command.
        command: SuitCommand,
    },
    /// SUIT component identifier is not supported by the processor.
    UnsupportedComponentIdentifier {
        /// The identifier of the component that is not supported.
        identifier: i64,
    },
    /// SUIT digest algorithm is not supported by the processor.
    UnsupportedDigestAlgo {
        /// The unsupported algorithm.
        algorithm: SuitDigestAlgorithm,
    },
    /// SUIT manifest version number is not supported by the processor.
    UnsupportedManifestVersion {
        /// The unsupported SUIT manifest version.
        version: u8,
    },
    /// SUIT parameter is not supported by the processor.
    UnsupportedParameter {
        /// The unsupported parameter.
        parameter: SuitParameter,
    },
    /// UTF-8 error while decoding the component identifier.
    Utf8Error {
        /// Position of the UTF-8 decoding error in the manifest.
        position: usize,
    },
}

impl Error {
    pub(crate) fn digest_algo_error(value: i64) -> Self {
        Error::NotADigestAlgo { label: value }
    }

    /// Use to modify error position on bytes-string wrapped CBOR
    pub(crate) fn add_offset(self, offset: usize) -> Self {
        match self {
            Error::ConditionMatchFail { command, position } => Error::ConditionMatchFail {
                command,
                position: position + offset,
            },
            Error::HashAlgoMismatch { algo, position } => Error::HashAlgoMismatch {
                algo,
                position: position + offset,
            },
            Error::MissingCborArgument { command, position } => Error::MissingCborArgument {
                command,
                position: position + offset,
            },
            Error::MissingReportPolicy { command, position } => Error::MissingReportPolicy {
                command,
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
            Self::MissingReportPolicy { command, position } => write!(
                f,
                "missing report policy for command {command} at {position}"
            ),
            Self::MissingCborArgument { command, position } => write!(
                f,
                "missing cbor argument for command {command} at {position}"
            ),
            Self::HashAlgoMismatch { algo, position } => write!(
                f,
                "expected to use algo {algo} got something else instead; at position {position}"
            ),
            Self::AuthenticationFailure => write!(f, "authentication of manifest failed"),
            Self::CapacityError => write!(f, "string capacity exhausted"),
            Self::ConditionMatchFail { command, position } => {
                write!(f, "condition mismatch as part of {command} at {position}")
            }
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
            Self::NoManifestVersion => write!(f, "no Manifest version in manifest"),
            Self::NoSequenceNumber => write!(f, "no Manifest sequence number in manifest"),
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
            Self::SameSourceAndTarget { identifier } => {
                write!(
                    f,
                    "source component at index {identifier} is the same than target in copy directive"
                )
            }
            Self::InvalidSourceComponent { identifier } => {
                write!(
                    f,
                    "source component index {identifier} not found in the component list"
                )
            }
            Self::NotACommand { label } => write!(
                f,
                "integer {label} not recognized as a SUIT command by the processor"
            ),
            Self::NotADigestAlgo { label } => write!(
                f,
                "integer {label} not recognized as a SUIT digest algorithm by the processor"
            ),
            Self::NotAParameter { label } => write!(
                f,
                "integer {label} not recognized as a SUIT parameter by the processor"
            ),
            Self::UnsupportedCommand { command } => write!(f, "command {command} not supported"),
            Self::UnsupportedComponentIdentifier { identifier } => {
                write!(f, "component identifier {identifier} not supported")
            }
            Self::UnsupportedDigestAlgo { algorithm } => {
                write!(f, "digest algorithm {algorithm} not supported")
            }
            Self::UnsupportedManifestVersion { version } => {
                write!(f, "manifest version {version} not supported")
            }
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
