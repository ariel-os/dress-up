/// CBOR constant definitions.
pub mod cbor {
    // --- Major types (high 3 bits of initial byte) ---
    /// CBOR Major type 0 (unsigned int): 0b000_xxxxx => base 0x00
    pub const UINT_MAJOR_BASE: u8 = 0x00;
    /// CBOR Major type 1 (negative int): 0b001_xxxxx => base 0x20
    pub const NINT_MAJOR_BASE: u8 = 0x20;
    /// CBOR Major type 2 (byte string): 0b010_xxxxx => base 0x40
    pub const BSTR_MAJOR_BASE: u8 = 0x40;
    /// CBOR Major type 3 (text string): 0b011_xxxxx => base 0x60
    pub const TSTR_MAJOR_BASE: u8 = 0x60;
    /// CBOR Major type 4 (array): 0b100_xxxxx => base 0x80
    pub const ARRAY_MAJOR_BASE: u8 = 0x80;
    /// CBOR Major type 5 (map): 0b101_xxxxx => base 0xA0
    pub const MAP_MAJOR_BASE: u8 = 0xA0;
    /// CBOR Major type 6 (tag): 0b110_xxxxx => base 0xC0
    pub const TAG_MAJOR_BASE: u8 = 0xC0;

    // --- Additional information values (low 5 bits of initial byte) ---
    // 0..=23 encode the value directly.
    /// Next 1 byte is the argument (u8)
    pub const AI_ONE_BYTE: u8 = 24;
    /// Next 2 bytes (u16, big‑endian)
    pub const AI_TWO_BYTES: u8 = 25;
    /// Next 4 bytes (u32, big‑endian)
    pub const AI_FOUR_BYTES: u8 = 26;
    /// Next 8 bytes (u64, big‑endian)
    pub const AI_EIGHT_BYTES: u8 = 27;

    // --- bstr length header constants for n >= 24 ---
    /// Next 1 byte states length of bstr
    pub const BSTR_LEN_U8: u8 = BSTR_MAJOR_BASE + AI_ONE_BYTE;
    /// Next 2 bytes state length of bstr
    pub const BSTR_LEN_U16: u8 = BSTR_MAJOR_BASE + AI_TWO_BYTES;
    /// Next 4 bytes state length of bstr
    pub const BSTR_LEN_U32: u8 = BSTR_MAJOR_BASE + AI_FOUR_BYTES;
    /// Next 8 bytes state length of bstr
    pub const BSTR_LEN_U64: u8 = BSTR_MAJOR_BASE + AI_EIGHT_BYTES;

    // --- convenience functions for headers ---
    /// bstr length header for n < 24
    pub const fn bstr_len_small(n: u8) -> u8 {
        BSTR_MAJOR_BASE + n
    }
    /// header for array with n fields
    pub const fn array(n: u8) -> u8 {
        ARRAY_MAJOR_BASE + n
    }
    /// header for map with n entries
    pub const fn map(n: u8) -> u8 {
        MAP_MAJOR_BASE + n
    }
}

// COSE constant definitions.
pub mod cose {
    use super::cbor;
    // --- digest algorithm constants ---
    // represented by negative int => -1 - value
    /// Sha256 algorithm (-16)
    pub const ALG_SHA_256: u8 = cbor::NINT_MAJOR_BASE + 15;
    /// Shake128 algorithm (-18)
    pub const ALG_SHAKE_128: u8 = cbor::NINT_MAJOR_BASE + 17;
    /// Sha384 algorithm (-43)
    pub const ALG_SHA_384: u8 = cbor::NINT_MAJOR_BASE + 42;
    /// Sha512 algorithm (-44)
    pub const ALG_SHA_512: u8 = cbor::NINT_MAJOR_BASE + 43;
    /// Shake256 algorithm (-45)
    pub const ALG_SHAKE_256: u8 = cbor::NINT_MAJOR_BASE + 44;
}

// SUIT Manifest constant definitions.
pub mod suit {
    use super::cbor;
    // --- SUIT Manifest tag ---
    /// Tag for SUIT Manifest (107)
    /// => tag major type + additional info one byte + 107 in next byte
    pub const MANIFEST_TAG: [u8; 2] = [cbor::TAG_MAJOR_BASE + cbor::AI_ONE_BYTE, 107];

    // --- Envelope field constants ---
    /// Unset detection
    pub const ENVLP_UNSET: u8 = 0;
    /// Authentication wrapper
    pub const ENVLP_AUTHENTICATION: u8 = 2;
    /// Manifest content
    pub const ENVLP_MANIFEST: u8 = 3;
    /// Payload fetch
    ///
    /// Used when the payload fetch stage is severable
    pub const ENVLP_PAYLOAD_FETCH: u8 = 16;
    /// Payload installation
    ///
    /// Used when the payload installation stage is severable
    pub const ENVLP_PAYLOAD_INSTALLATION: u8 = 20;
    /// Text description of the manifest
    pub const ENVLP_TEXT: u8 = 23;
}
