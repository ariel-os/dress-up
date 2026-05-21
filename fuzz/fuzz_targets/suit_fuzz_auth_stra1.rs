#![no_main]

use libfuzzer_sys::fuzz_target;

use cose::{keys::CoseKey, message::CoseMessage};
use sha2::{Digest, Sha256};
use std::{cell::Cell, path::PathBuf};
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

fn cbor_bstr_header(len: usize) -> Vec<u8> {
    if len <= 23 {
        vec![0x40u8 + (len as u8)]
    } else if len <= 0xff {
        vec![0x58, len as u8]
    } else if len <= 0xffff {
        vec![0x59, ((len >> 8) & 0xff) as u8, (len & 0xff) as u8]
    } else {
        // TODO: Extend if needed: 0x5a (u32), 0x5b (u64)
        panic!("manifest too large for this minimal encoder");
    }
}

fn gen_auth(manifest: &[u8]) -> Vec<u8> {
    // prepend header for manifest to be hashed
    let mut man_prep = cbor_bstr_header(manifest.len());
    man_prep.extend_from_slice(manifest);
    let manifest = &man_prep;

    let man_hash = Sha256::digest(manifest);

    // auth block header
    let mut auth_blk: Vec<u8> = vec![0x82]; // array(2)
    auth_blk.extend([0x58, 1 + 1 + 2 + man_hash.len() as u8].iter()); // length of complete digest

    // digest
    auth_blk.push(0x82); // array(2)
    auth_blk.push(0x2f); // algorithm (here -16 --> SHA256)
    auth_blk.extend([0x58, man_hash.len() as u8]); // length of manifest hash
    auth_blk.extend_from_slice(&man_hash); // actual hash from manifest

    // COSE (empty dummy)
    auth_blk.push(0x40);

    auth_blk
}

fn build_envelope(auth_block: &[u8], manifest: &[u8]) -> Vec<u8> {
    // envelope header
    let mut envlp: Vec<u8> = vec![0xd8, 0x6b]; // Tag 107 (SUIT Manifest)
    envlp.push(0xa2); // map(2)

    // auth block header
    envlp.push(0x02); // key "Authentication"
    envlp.extend(cbor_bstr_header(auth_block.len())); // auth block length

    // actual auth block itself
    envlp.extend_from_slice(auth_block);
    // manifest header
    envlp.push(0x03); // key "Manifest"
    envlp.extend(cbor_bstr_header(manifest.len())); // manifest length

    // actual manifest itself
    envlp.extend_from_slice(manifest);

    envlp
}

fuzz_target!(|data: &[u8]| {
    let selector = data.get(0).copied().unwrap_or(0);
    let manifest = data.get(1..).unwrap_or(data);
    let payload = "hello world!";

    // minimal structure-awareness by appending "valid" auth block at beginning of input
    let auth_block = gen_auth(manifest);
    let input = build_envelope(&auth_block, manifest);

    // class_id and vendor_id taken from minimal example
    // TODO: check if this makes any difference
    let class_id = uuid!("019c9a96-347b-7d98-acc9-b90117f4a665");
    let vendor_id = uuid!("019c9a95-f6cb-71a7-a0a6-aac148fc4743");

    // let pub_key = std::fs::read("public.pem").expect("public.pem should be available");
    // let key = build_key(pub_key);

    let hooks = OsHooks::new(4096, vendor_id, class_id, payload.as_bytes());

    let suit = SuitManifest::from_bytes(&input);

    // circumvent authentication by just returning true
    if let Ok(suit) = suit.authenticate(|_cose, _payload| Ok(true)) {
        if let Ok(envelope) = suit.envelope() {
            if let Ok(manifest) = envelope.manifest() {
                // randomly select which function is called based on first byte of data
                match selector % 10 {
                    0 => {
                        let _ = manifest.has_payload_fetch();
                    }
                    1 => {
                        let _ = manifest.has_payload_installation();
                    }
                    2 => {
                        let _ = manifest.has_image_validation();
                    }
                    3 => {
                        let _ = manifest.has_image_loading();
                    }
                    4 => {
                        let _ = manifest.has_invoke();
                    }
                    5 => {
                        let _ = manifest.execute_payload_fetch(&hooks);
                    }
                    6 => {
                        let _ = manifest.execute_payload_installation(&hooks);
                    }
                    7 => {
                        let _ = manifest.execute_image_validation(&hooks);
                    }
                    8 => {
                        let _ = manifest.execute_image_loading(&hooks);
                    }
                    9 => {
                        let _ = manifest.execute_invoke(&hooks);
                    }
                    _ => {
                        let _ = manifest.execute_full(&hooks);
                    }
                }
            }
        }
    }
});
