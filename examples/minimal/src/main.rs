use clap::Parser;
use cose::{keys::CoseKey, message::CoseMessage};
use std::cell::Cell;
use std::path::PathBuf;
use uuid::{uuid, Uuid};

use dress_up::{error::Error, OperatingHooks, SuitManifest};

// Real applications have to retrieve this from persistent storage
const STORED_SEQUENCE: u32 = 500;

#[derive(Parser, Debug)]
struct Args {
    manifest: PathBuf,
    payload: PathBuf,
    pub_key: PathBuf,
}

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
        component: &dress_up::component::Component,
    ) -> Result<bool, dress_up::error::Error> {
        Ok(self.vendor_id == uuid)
    }

    fn match_class_id(
        &self,
        uuid: Uuid,
        component: &dress_up::component::Component,
    ) -> Result<bool, dress_up::error::Error> {
        Ok(self.class_id == uuid)
    }

    fn component_read(
        &self,
        component: &dress_up::component::Component,
        slot: Option<u64>,
        offset: usize,
        bytes: &mut [u8],
    ) -> Result<(), dress_up::error::Error> {
        let storage = self.storage.take();
        if bytes.len() + offset > storage.len() {
            self.storage.set(storage);
            return Err(Error::InvalidCommandSequence(0));
        }
        bytes.copy_from_slice(&storage[offset..offset + bytes.len()]);
        self.storage.set(storage);
        Ok(())
    }

    fn component_write(
        &self,
        component: &dress_up::component::Component,
        slot: Option<u64>,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), dress_up::error::Error> {
        todo!()
    }

    fn component_size(
        &self,
        component: &dress_up::component::Component,
    ) -> Result<usize, dress_up::error::Error> {
        let storage = self.storage.take();
        let len = storage.len();
        self.storage.set(storage);
        Ok(len)
    }

    fn component_capacity(
        &self,
        component: &dress_up::component::Component,
    ) -> Result<usize, dress_up::error::Error> {
        Ok(self.capacity)
    }

    fn fetch(
        &self,
        component: &dress_up::component::Component,
        slot: Option<u64>,
        uri: &str,
    ) -> Result<(), Error> {
        let mut storage = self.storage.take();
        storage.clear();
        storage.extend_from_slice(self.payload);
        self.storage.set(storage);
        Ok(())
    }
}

fn build_key(pub_key: Vec<u8>) -> CoseKey {
    // Parse EC public key into coordinates
    let pub_key = openssl::ec::EcKey::public_key_from_pem(&pub_key).unwrap();
    let coordinates = pub_key.public_key();
    let group = pub_key.group();
    let mut x = openssl::bn::BigNum::new().unwrap();
    let mut y = openssl::bn::BigNum::new().unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    coordinates
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
        .unwrap();

    let mut key = CoseKey::new();
    key.kty(cose::keys::EC2);
    key.alg(cose::algs::ES256);
    key.crv(cose::keys::P_256);
    key.x(x.to_vec());
    key.y(y.to_vec());
    key.key_ops(vec![cose::keys::KEY_OPS_VERIFY]);
    key
}

fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    println!("minimal suit manifest example");
    let args = Args::parse();

    let input = std::fs::read(args.manifest)?;
    let pub_key = std::fs::read(args.pub_key)?;
    let payload = std::fs::read(args.payload)?;

    let class_id = uuid!("019c9a96-347b-7d98-acc9-b90117f4a665");
    let vendor_id = uuid!("019c9a95-f6cb-71a7-a0a6-aac148fc4743");
    let hooks = OsHooks::new(4096, vendor_id, class_id, &payload);

    let key = build_key(pub_key);
    let suit = SuitManifest::from_bytes(&input);

    let suit = suit.authenticate(|cose, payload| {
        let mut verify = CoseMessage::new_sign();
        verify.bytes = cose.to_vec();
        verify
            .init_decoder(Some(payload.to_vec()))
            .map_err(|_| Error::AuthenticationFailure)?;
        verify.key(&key).map_err(|_| Error::AuthenticationFailure)?;
        verify
            .decode(None, None)
            .map_err(|_| Error::AuthenticationFailure)?;
        Ok(true)
    })?;
    println!("Verified manifest signature");
    let envelope = suit.envelope()?;
    let manifest = envelope.manifest()?;
    manifest.execute_payload_installation(&hooks)?;
    let storage = hooks.storage.take();
    println!("Storage now contains: {:02x?}", storage);
    Ok(())
}
