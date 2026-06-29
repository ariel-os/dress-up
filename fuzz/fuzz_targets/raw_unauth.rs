#![no_main]

use libfuzzer_sys::fuzz_target;

use dress_up::SuitManifest;

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or(0);
    let input = data.get(1..).unwrap_or(data);

    let suit = SuitManifest::from_bytes(&input);

    if let Ok(envelope) = suit.envelope() {
        if let Ok(manifest) = envelope.manifest() {
            match selector % 2 {
                0 => {
                    let _ = manifest.version();
                }
                _ => {
                    let _ = manifest.sequence_number();
                }
            }
        }
    }
});
