use core::convert::From;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    CapacityError,
    ConditionMatchFail(usize),
    TryEachFail(usize),
    EndOfInput,
    InvalidCommandSequence(usize),
    InvalidCommonSection,
    NoAuthObject,
    NoCommonSection,
    NoComponentList,
    NoManifestObject,
    ParameterNotSet(usize),
    UnexpectedCbor(usize),
    UnexpectedIndefiniteLength(usize),
    UnsupportedCommand(i32),
    UnsupportedComponentIdentifier(i64),
    UnsupportedDigestAlgo(i64),
    UnsupportedManifestVersion,
    UnsupportedParameter(i32),
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
            Self::NoComponentList => write!(f, "no component list found in manifest"),
            Self::NoManifestObject => write!(f, "no Manifest object in manifest"),
            Self::ParameterNotSet(n) => write!(f, "parameter required for condition at {n} not set"),
            Self::UnexpectedCbor(pos) => write!(f, "unexpected CBOR found at {pos}"),
            Self::UnexpectedIndefiniteLength(n) => write!(f, "unexpected indefinite length cbor container at {n}"),
            Self::UnsupportedCommand(n) => write!(f, "command {n} not supported"),
            Self::UnsupportedComponentIdentifier(n) => write!(f, "component identifier {n} not supported"),
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
        }
        else {
            let pos = err.position().unwrap_or(0);
            Self::UnexpectedCbor(pos)
        }
    }
}
