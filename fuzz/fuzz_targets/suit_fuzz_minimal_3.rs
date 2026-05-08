#![no_main]

use libfuzzer_sys::fuzz_target;

use std::cell::Cell;
use uuid::{uuid, Uuid};

use dress_up::{error::Error, OperatingHooks, SuitManifest};

// OsHooks copied from examples/minimal/main.rs
struct OsHooks<'a> {
    payload: &'a [u8],
    storage: Cell<Vec<u8>>,
    capacity: usize,
    vendor_id: Uuid,
    class_id: Uuid,
}

impl<'a> OsHooks<'a> {
    fn new(capacity: usize, vendor_id: Uuid, class_id: Uuid, payload: &'a [u8]) -> Self {
        Self {
            payload,
            storage: Cell::new(Vec::with_capacity(capacity)),
            capacity,
            vendor_id,
            class_id,
        }
    }
}

impl<'a> OperatingHooks for OsHooks<'a> {
    type ReadWriteBufferSize = generic_array::typenum::U64;

    fn match_vendor_id(
        &self,
        uuid: Uuid,
        _component: &dress_up::component::Component,
    ) -> Result<bool, dress_up::error::Error> {
        Ok(self.vendor_id == uuid)
    }

    fn match_class_id(
        &self,
        uuid: Uuid,
        _component: &dress_up::component::Component,
    ) -> Result<bool, dress_up::error::Error> {
        Ok(self.class_id == uuid)
    }

    fn component_read(
        &self,
        _component: &dress_up::component::Component,
        _slot: Option<u64>,
        offset: usize,
        bytes: &mut [u8],
    ) -> Result<(), dress_up::error::Error> {
        let storage = self.storage.take();
        if bytes.len() + offset > storage.len() {
            self.storage.set(storage);
            return Err(Error::InvalidCommandSequence { position: 0 });
        }
        bytes.copy_from_slice(&storage[offset..offset + bytes.len()]);
        self.storage.set(storage);
        Ok(())
    }

    fn component_write(
        &self,
        _component: &dress_up::component::Component,
        _slot: Option<u64>,
        _offset: usize,
        _bytes: &[u8],
    ) -> Result<(), dress_up::error::Error> {
        todo!()
    }

    fn component_size(
        &self,
        _component: &dress_up::component::Component,
    ) -> Result<usize, dress_up::error::Error> {
        let storage = self.storage.take();
        let len = storage.len();
        self.storage.set(storage);
        Ok(len)
    }

    fn component_capacity(
        &self,
        _component: &dress_up::component::Component,
    ) -> Result<usize, dress_up::error::Error> {
        Ok(self.capacity)
    }

    fn fetch(
        &self,
        _component: &dress_up::component::Component,
        _slot: Option<u64>,
        _uri: &str,
    ) -> Result<(), Error> {
        let mut storage = self.storage.take();
        storage.clear();
        storage.extend_from_slice(self.payload);
        self.storage.set(storage);
        Ok(())
    }
}

const MAX_INPUT_LEN: usize = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    // class_id and vendor_id taken from minimal example
    // TODO: check if this makes any difference
    let class_id = uuid!("019c9a96-347b-7d98-acc9-b90117f4a665");
    let vendor_id = uuid!("019c9a95-f6cb-71a7-a0a6-aac148fc4743");

    // use payload.bin as in the example
    // TODO: randomize payload content
    let payload = std::fs::read("payload.bin").unwrap();
    let hooks = OsHooks::new(4096, vendor_id, class_id, &payload);

    let suit = SuitManifest::from_bytes(&data);

    // circumvent authentication by just returning true
    if let Ok(suit) = suit.authenticate(|_, _| Ok(true)) {
        if let Ok(envelope) = suit.envelope() {
            if let Ok(manifest) = envelope.manifest() {
                let _ = manifest.execute_payload_installation(&hooks);
                // TODO: test with other functions of authenticated manifest
                // let _ = manifest.
            }
        }
    }
});
