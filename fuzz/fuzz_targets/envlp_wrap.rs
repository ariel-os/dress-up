#![no_main]

use libfuzzer_sys::fuzz_target;

use uuid::uuid;

use dress_up::SuitManifest;
use fuzz::{consts::cose::HashAlg, envelope_builder::build_envelope, os_hooks::OsHooks};

fuzz_target!(|data: &[u8]| {
    let payload = "hello world!";

    let hash_select = data.first().copied().unwrap_or(0);
    let fun_select = data.get(1).copied().unwrap_or(0);
    let data = data.get(2..).unwrap_or(data);

    let hash_alg = match hash_select % 5 {
        0 => HashAlg::Sha256,
        1 => HashAlg::Sha384,
        2 => HashAlg::Sha512,
        3 => HashAlg::Shake128,
        4 => HashAlg::Shake256,
        _ => unreachable!(),
    };

    // repair auth-constraint by wrapping inner manifest in valid SUIT envelope with valid auth block
    let input = build_envelope(data, hash_alg);

    // class_id and vendor_id taken from minimal example
    // TODO: check if this also needs to be fuzzed
    let class_id = uuid!("019c9a96-347b-7d98-acc9-b90117f4a665");
    let vendor_id = uuid!("019c9a95-f6cb-71a7-a0a6-aac148fc4743");

    let hooks = OsHooks::new(4096, vendor_id, class_id, payload.as_bytes());

    let suit = SuitManifest::from_bytes(&input);

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
                    _ => unreachable!()
                };
            }
        }
    }
});
