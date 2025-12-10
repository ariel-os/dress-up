use minicbor::{bytes::ByteSlice, data::Type, encode::Write, Decode, Encode, Encoder};

use crate::error::Error;
use digest::{ExtendableOutput, FixedOutput, OutputSizeUser, Update};

#[derive(Copy, Clone, Debug, PartialEq, num_enum::IntoPrimitive, num_enum::TryFromPrimitive)]
#[num_enum(error_type(name = Error, constructor = Error::digest_algo_error))]
#[non_exhaustive]
#[repr(i64)]
pub enum SuitDigestAlgorithm {
    Sha256 = -16,
    Shake128 = -18,
    Sha384 = -43,
    Sha512 = -44,
    Shake256 = -45,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct SuitDigest<'a> {
    algo: SuitDigestAlgorithm,
    digest: &'a ByteSlice,
}

pub enum Hasher {
    Sha2(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Shake128(sha3::Shake128),
    Shake256(sha3::Shake256),
}

impl<'a> SuitDigest<'a> {
    pub fn new(algo: SuitDigestAlgorithm, digest: &'a ByteSlice) -> Self {
        Self { algo, digest }
    }

    pub fn hasher(&self) -> Result<Hasher, Error> {
        Hasher::new(self.algo)
    }

    pub fn match_hasher(&self, hasher: Hasher) -> Result<bool, Error> {
        match (self.algo, hasher) {
            (SuitDigestAlgorithm::Sha256, Hasher::Sha2(digest)) => {
                let output = digest.finalize_fixed();
                Ok(**self.digest == *output)
            }
            (SuitDigestAlgorithm::Sha384, Hasher::Sha384(digest)) => {
                let output = digest.finalize_fixed();
                Ok(**self.digest == *output)
            }
            (SuitDigestAlgorithm::Sha512, Hasher::Sha512(digest)) => {
                let output = digest.finalize_fixed();
                Ok(**self.digest == *output)
            }
            (SuitDigestAlgorithm::Shake128, Hasher::Shake128(digest)) => {
                let mut output = [0u8; 32];
                digest.finalize_xof_into(&mut output);
                Ok(**self.digest == output)
            }
            (SuitDigestAlgorithm::Shake256, Hasher::Shake256(digest)) => {
                let mut output = [0u8; 64];
                digest.finalize_xof_into(&mut output);
                Ok(**self.digest == output)
            }
            (_, _) => Err(Error::ConditionMatchFail(0)),
        }
    }
}

impl<'a, C> Decode<'a, C> for SuitDigest<'a> {
    fn decode(
        d: &mut minicbor::Decoder<'a>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let len = d.array()?;
        if len.is_some_and(|l| l == 2) {
            let algo = d.i64()?;
            let digest = d.bytes()?;
            let algo = SuitDigestAlgorithm::try_from(algo)
                .map_err(|_| minicbor::decode::Error::type_mismatch(Type::I64))?;
            Ok(SuitDigest::new(algo, digest.into()))
        } else {
            Err(minicbor::decode::Error::type_mismatch(d.datatype()?))
        }
    }
}

impl<C> Encode<C> for SuitDigest<'_> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;
        let algo: i64 = self.algo.into();
        algo.encode(e, ctx)?;
        self.digest.encode(e, ctx)?;
        Ok(())
    }
}

impl Hasher {
    fn new(algo: SuitDigestAlgorithm) -> Result<Self, Error> {
        Ok(match algo {
            SuitDigestAlgorithm::Sha256 => Self::Sha2(sha2::Sha256::default()),
            SuitDigestAlgorithm::Shake128 => Self::Shake128(sha3::Shake128::default()),
            SuitDigestAlgorithm::Sha384 => Self::Sha384(sha2::Sha384::default()),
            SuitDigestAlgorithm::Sha512 => Self::Sha512(sha2::Sha512::default()),
            SuitDigestAlgorithm::Shake256 => Self::Shake256(sha3::Shake256::default()),
        })
    }

    fn output_size(&self) -> usize {
        match self {
            Hasher::Sha2(_) => sha2::Sha256::output_size(),
            Hasher::Sha384(_) => sha2::Sha384::output_size(),
            Hasher::Sha512(_) => sha2::Sha512::output_size(),
            Hasher::Shake128(_) => 32, // RFC 9054 defined
            Hasher::Shake256(_) => 64, // RFC 9054 defined
        }
    }

    fn finalize_into(self, out: &mut [u8]) {
        match self {
            Hasher::Sha2(core_wrapper) => core_wrapper.finalize_into(out.into()),
            Hasher::Sha384(core_wrapper) => core_wrapper.finalize_into(out.into()),
            Hasher::Sha512(core_wrapper) => core_wrapper.finalize_into(out.into()),
            Hasher::Shake128(core_wrapper) => core_wrapper.finalize_xof_into(out),
            Hasher::Shake256(core_wrapper) => core_wrapper.finalize_xof_into(out),
        }
    }
}

impl Update for Hasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha2(core_wrapper) => core_wrapper.update(data),
            Hasher::Sha384(core_wrapper) => core_wrapper.update(data),
            Hasher::Sha512(core_wrapper) => core_wrapper.update(data),
            Hasher::Shake128(core_wrapper) => core_wrapper.update(data),
            Hasher::Shake256(core_wrapper) => core_wrapper.update(data),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    extern crate std;

    #[test]
    fn sha2() {
        let input: &[u8] = &std::vec![];
        let solution: &[u8] = &std::vec![
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55
        ];
        let digest = SuitDigest::new(SuitDigestAlgorithm::Sha256, solution.into());
        let mut hasher = digest.hasher().unwrap();
        hasher.update(input);
        assert_eq!(digest.match_hasher(hasher), Ok(true));
    }

    #[test]
    fn sha384() {
        let input: &[u8] = &std::vec![0x8d, 0x45, 0xa5, 0x5d, 0x5c, 0xe1, 0xf9, 0x28, 0xe6];
        let solution: &[u8] = &std::vec![
            0xde, 0x76, 0x68, 0x35, 0x75, 0xa0, 0x50, 0xe2, 0xeb, 0x5e, 0xf9, 0x5e, 0xe2, 0x01,
            0xf8, 0x24, 0x16, 0x47, 0x8a, 0x1d, 0x14, 0xbf, 0x3d, 0x96, 0xd1, 0xfd, 0x4e, 0xfd,
            0x52, 0xb1, 0xa2, 0x8f, 0xed, 0x8d, 0xfe, 0xe1, 0x83, 0x00, 0x70, 0x00, 0x1d, 0xc1,
            0x02, 0xa2, 0x1f, 0x76, 0x1d, 0x20
        ];
        let digest = SuitDigest::new(SuitDigestAlgorithm::Sha384, solution.into());
        let mut hasher = digest.hasher().unwrap();
        hasher.update(input);
        assert_eq!(digest.match_hasher(hasher), Ok(true));
    }

    #[test]
    fn sha512() {
        let input: &[u8] = &std::vec![0x16, 0x2b, 0x0c, 0xf9, 0xb3, 0x75, 0x0f, 0x94, 0x38];
        let solution: &[u8] = &std::vec![
            0xad, 0xe2, 0x17, 0x30, 0x5d, 0xc3, 0x43, 0x92, 0xaa, 0x4b, 0x8e, 0x57, 0xf6, 0x4f,
            0x5a, 0x3a, 0xfd, 0xd2, 0x7f, 0x1f, 0xa9, 0x69, 0xa9, 0xa2, 0x60, 0x83, 0x53, 0xf8,
            0x2b, 0x95, 0xcf, 0xb4, 0xae, 0x84, 0x59, 0x8d, 0x01, 0x57, 0x5a, 0x57, 0x8a, 0x10,
            0x68, 0xa5, 0x9b, 0x34, 0xb5, 0x04, 0x5f, 0xf6, 0xd5, 0x29, 0x9c, 0x5c, 0xb7, 0xee,
            0x17, 0x18, 0x07, 0x01, 0xb2, 0xd1, 0xd6, 0x95
        ];
        let digest = SuitDigest::new(SuitDigestAlgorithm::Sha512, solution.into());
        let mut hasher = digest.hasher().unwrap();
        hasher.update(input);
        assert_eq!(digest.match_hasher(hasher), Ok(true));
    }

    #[test]
    fn shake128() {
        let input: &[u8] = &std::vec![
            0x22, 0x63, 0x4f, 0x6b, 0xa7, 0xb4, 0xfc, 0xca, 0xa3, 0xba, 0x40, 0x40, 0xb6, 0x64,
            0xdb, 0xe5
        ];
        let solution: &[u8] = &std::vec![
            0x1a, 0x3e, 0x90, 0x82, 0x1c, 0xd0, 0xa8, 0x8e, 0x5a, 0x6d, 0xa7, 0x28, 0xba, 0xca,
            0xa3, 0x0f, 0x7a, 0x10, 0x86, 0x22, 0x0e, 0x72, 0xd1, 0xbf, 0xcf, 0xf9, 0x22, 0x03,
            0x4d, 0x29, 0xe6, 0x29
        ];
        let digest = SuitDigest::new(SuitDigestAlgorithm::Shake128, solution.into());
        let mut hasher = digest.hasher().unwrap();
        hasher.update(input);
        assert_eq!(digest.match_hasher(hasher), Ok(true));
    }

    #[test]
    fn shake256() {
        let input: &[u8] = &std::vec![
            0xdc, 0x88, 0x6d, 0xf3, 0xf6, 0x9c, 0x49, 0x51, 0x3d, 0xe3, 0x62, 0x7e, 0x94, 0x81,
            0xdb, 0x58, 0x71, 0xe8, 0xee, 0x88, 0xeb, 0x9f, 0x99, 0x61, 0x15, 0x41, 0x93, 0x0a,
            0x8b, 0xc8, 0x85, 0xe0
        ];
        let solution: &[u8] = &std::vec![
            0x00, 0x64, 0x8a, 0xfb, 0xc5, 0xe6, 0x51, 0x64, 0x9d, 0xb1, 0xfd, 0x82, 0x93, 0x6b,
            0x00, 0xdb, 0xbc, 0x12, 0x2f, 0xb4, 0xc8, 0x77, 0x86, 0x0d, 0x38, 0x5c, 0x49, 0x50,
            0xd5, 0x6d, 0xe7, 0xe0, 0x96, 0xd6, 0x13, 0xd7, 0xa3, 0xf2, 0x7e, 0xd8, 0xf2, 0x63,
            0x34, 0xb0, 0xcc, 0xc1, 0x40, 0x7b, 0x41, 0xdc, 0xcb, 0x23, 0xdf, 0xaa, 0x52, 0x98,
            0x18, 0xd1, 0x12, 0x5c, 0xd5, 0x34, 0x80, 0x92
        ];
        let digest = SuitDigest::new(SuitDigestAlgorithm::Shake256, solution.into());
        let mut hasher = digest.hasher().unwrap();
        hasher.update(input);
        assert_eq!(digest.match_hasher(hasher), Ok(true));
    }
}
