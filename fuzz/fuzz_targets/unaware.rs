#![no_main]

use libfuzzer_sys::fuzz_target;

use uuid::uuid;

use dress_up::SuitManifest;
use fuzz::os_hooks::OsHooks;

fuzz_target!(|data: &[u8]| {
    // class_id and vendor_id taken from minimal example
    // TODO: check if this makes any difference
    let class_id = uuid!("019c9a96-347b-7d98-acc9-b90117f4a665");
    let vendor_id = uuid!("019c9a95-f6cb-71a7-a0a6-aac148fc4743");

    // use sample string as payload like in example
    let payload = "hello world!";
    let hooks = OsHooks::new(4096, vendor_id, class_id, payload.as_bytes());

    let suit = SuitManifest::from_bytes(&data);

    // test functions on unauthenticated manifest
    if let Ok(envelope) = suit.envelope() {
        if let Ok(manifest) = envelope.manifest() {
            let _ = manifest.version();
            let _ = manifest.sequence_number();
        }
    }

    // test functions on authenticated manifest
    if let Ok(suit) = suit.authenticate(|_, _| Ok(true)) {
        if let Ok(envelope) = suit.envelope() {
            if let Ok(manifest) = envelope.manifest() {
                let _ = manifest.execute_full(&hooks);
            }
        }
    }
});
