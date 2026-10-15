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

    #[repr(u8)]
    pub enum HashAlg {
        Sha256 = cbor::NINT_MAJOR_BASE + 15,
        Sha384 = cbor::NINT_MAJOR_BASE + 17,
        Sha512 = cbor::NINT_MAJOR_BASE + 42,
        Shake128 = cbor::NINT_MAJOR_BASE + 43,
        Shake256 = cbor::NINT_MAJOR_BASE + 44,
    }

    impl HashAlg {
        pub fn val(self) -> u8 {
            self as u8
        }
    }
}

// SUIT Manifest constant definitions.
pub mod suit {
    use super::cbor;
    /// Tag for SUIT Manifest (107)
    /// => tag major type + additional info one byte + 107 in next byte
    pub const MANIFEST_TAG: [u8; 2] = [cbor::TAG_MAJOR_BASE + cbor::AI_ONE_BYTE, 107];
}

// =======================================================

// labels used in SUIT Manifests as declared in
// https://www.ietf.org/archive/id/draft-ietf-suit-manifest-36.html#name-iana-considerations
pub mod labels {
    // SUIT Envelope Element Labels
    pub mod envelope_elements {
        pub const UNSET_DETECTION: u8 = 0;

        pub const AUTHENTICATION_WRAPPER: u8 = 2;
        pub const MANIFEST: u8 = 3;

        pub const PAYLOAD_FETCH: u8 = 16;
        pub const PAYLOAD_INSTALLATION: u8 = 20;
        pub const TEXT_DESCRIPTION: u8 = 23;
    }

    // SUIT Manifest Element Labels
    pub mod manifest_elements {
        pub const UNSET_DETECTION: u8 = 0;

        pub const ENCODING_VERSION: u8 = 1;
        pub const SEQUENCE_NUMBER: u8 = 2;
        pub const COMMON_DATA: u8 = 3;
        pub const REFERENCE_URI: u8 = 4;

        pub const IMAGE_VALIDATION: u8 = 7;
        pub const IMAGE_LOADING: u8 = 8;
        pub const IMAGE_INVOCATION: u8 = 9;

        pub const PAYLOAD_FETCH: u8 = 16;
        pub const PAYLOAD_INSTALLATION: u8 = 20;
        pub const TEXT_DESCRIPTION: u8 = 23;
    }

    // SUIT Common Element Labels
    pub mod common_elements {
        pub const UNSET_DETECTION: u8 = 0;

        pub const COMPONENT_IDENTIFIERS: u8 = 2;
        pub const COMMON_COMMAND_SEQUENCE: u8 = 4;
    }

    // SUIT Command Labels
    pub mod commands {
        pub const UNSET_DETECTION: u8 = 0;

        pub const VENDOR_IDENTIFIER: u8 = 1;
        pub const CLASS_IDENTIFIER: u8 = 2;
        pub const IMAGE_MATCH: u8 = 3;

        pub const COMPONENT_SLOT: u8 = 5;
        pub const CHECK_CONTENT: u8 = 6;

        pub const SET_COMPONENT_INDEX: u8 = 12;
        pub const ABORT: u8 = 14;
        pub const TRY_EACH: u8 = 15;

        pub const WRITE_CONTENT: u8 = 18;

        pub const OVERRIDE_PARAMETERS: u8 = 20;
        pub const FETCH: u8 = 21;
        pub const COPY: u8 = 22;
        pub const INVOKE: u8 = 23;
        pub const DEVICE_IDENTIFIER: u8 = 24;

        pub const SWAP: u8 = 31;
        pub const RUN_SEQUENCE: u8 = 32;
    }

    // SUIT Parameter Labels
    pub mod parameters {
        pub const UNSET_DETECTION: u8 = 0;

        pub const VENDOR_ID: u8 = 1;
        pub const CLASS_ID: u8 = 2;
        pub const IMAGE_DIGEST: u8 = 3;

        pub const COMPONENT_SLOT: u8 = 5;

        pub const STRICT_ORDER: u8 = 12;
        pub const SOFT_FAILURE: u8 = 13;
        pub const IMAGE_SIZE: u8 = 14;

        pub const CONTENT: u8 = 18;

        pub const URI: u8 = 21;
        pub const SOURCE_COMPONENT: u8 = 22;
        pub const INVOKE_ARGS: u8 = 23;
        pub const DEVICE_ID: u8 = 24;
    }
}
