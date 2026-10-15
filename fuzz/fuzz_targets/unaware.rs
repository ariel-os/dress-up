#![no_main]

use libfuzzer_sys::fuzz_target;

use uuid::Uuid;

use dress_up::SuitManifest;
use fuzz::{os_hooks::OsHooks, reader::Reader};

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data);

    // take random number of bytes as payload
    let n = reader.u8();
    let payload = reader.bytes(n as usize);

    let fun_select = reader.u8();

    // use random class id in 2/3 of times
    let class_id = match reader.choice(3) {
        0 => vec![
            0x01, 0x9c, 0x9a, 0x96, 0x34, 0x7b, 0x7d, 0x98, 0xac, 0xc9, 0xb9, 0x01, 0x17, 0xf4,
            0xa6, 0x65,
        ],
        _ => reader.bytes(16),
    };

    // use random vendor id in 2/3 of times
    let vendor_id = match reader.choice(3) {
        0 => vec![
            0x01, 0x9c, 0x9a, 0x95, 0xf6, 0xcb, 0x71, 0xa7, 0xa0, 0xa6, 0xaa, 0xc1, 0x48, 0xfc,
            0x47, 0x43,
        ],
        _ => reader.bytes(16),
    };

    let vendor_uuid = Uuid::from_slice(&vendor_id).unwrap();
    let class_uuid = Uuid::from_slice(&class_id).unwrap();

    let hooks = OsHooks::new(4096, vendor_uuid, class_uuid, &payload);

    let data = reader.remaining();

    let suit = SuitManifest::from_bytes(&data);

    // test functions on unauthenticated manifest
    if let Ok(envelope) = suit.envelope() {
        if let Ok(manifest) = envelope.manifest() {
            let _ = manifest.version();
            let _ = manifest.sequence_number();
        }
    }

    // test functions on authenticated manifest
    // circumvent authentication by just returning true
    if let Ok(suit) = suit.authenticate(|_cose, _payload| Ok(true)) {
        if let Ok(envelope) = suit.envelope() {
            if let Ok(manifest) = envelope.manifest() {
                let _ = manifest.has_payload_fetch();
                let _ = manifest.has_payload_installation();
                let _ = manifest.has_image_validation();
                let _ = manifest.has_image_loading();
                let _ = manifest.has_invoke();

                let _ = match fun_select % 6 {
                    0 => manifest.execute_payload_fetch(&hooks),
                    1 => manifest.execute_payload_installation(&hooks),
                    2 => manifest.execute_image_validation(&hooks),
                    3 => manifest.execute_image_loading(&hooks),
                    4 => manifest.execute_invoke(&hooks),
                    5 => manifest.execute_full(&hooks),
                    _ => unreachable!(),
                };
            }
        }
    }
});
