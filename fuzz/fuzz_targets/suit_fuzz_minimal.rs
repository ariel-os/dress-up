#![no_main]

use dress_up::SuitManifest;
use libfuzzer_sys::fuzz_target;
extern crate dress_up;

use cbor_edn::StandaloneItem;

fuzz_target!(|data: &[u8]| {

    if let Ok(input) = std::str::from_utf8(data) {
        if let Ok(p) = StandaloneItem::parse(input) {
            if let Ok(cbor) = p.to_cbor() {
                let _ = SuitManifest::from_bytes(&cbor);
            }
        }
    }

});
