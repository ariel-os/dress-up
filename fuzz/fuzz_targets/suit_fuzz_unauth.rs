#![no_main]

use libfuzzer_sys::fuzz_target;

use dress_up::SuitManifest;

fuzz_target!(|data: &[u8]| {
    let suit = SuitManifest::from_bytes(&data);

    if let Ok(envelope) = suit.envelope() {
        if let Ok(manifest) = envelope.manifest() {
            let _ = manifest.version();
            let _ = manifest.sequence_number();
        }
    }
});
