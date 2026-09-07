//! `OperatingHooks` implementation that logs every operation instead of performing real I/O.
//!
//! This is a testing/debugging aid only: it accepts every vendor, class and device check, and
//! backs component reads/writes/fetches with an in-memory buffer instead of talking to real
//! storage or the network.
use std::cell::RefCell;

use dress_up::component::Component;
use dress_up::error::Error;
use dress_up::manifeststate::ManifestState;
use dress_up::OperatingHooks;
use uuid::Uuid;

use crate::log::{log_hook, log_warn};

/// Records every hook invocation to stdout and simulates component storage in memory.
pub struct LoggingHooks {
    capacity: usize,
    storage: RefCell<Vec<u8>>,
    fetch_payload: Vec<u8>,
}

impl LoggingHooks {
    /// Creates new logging hooks with the given simulated component capacity.
    ///
    /// `fetch_payload` is handed back verbatim whenever the manifest instructs a fetch.
    pub fn new(capacity: usize, fetch_payload: Vec<u8>) -> Self {
        Self {
            capacity,
            storage: RefCell::new(Vec::new()),
            fetch_payload,
        }
    }

    /// Returns a copy of the current simulated component contents, for reporting after execution.
    pub fn storage_snapshot(&self) -> Vec<u8> {
        self.storage.borrow().clone()
    }
}

impl OperatingHooks for LoggingHooks {
    type ReadWriteBufferSize = generic_array::typenum::U64;

    fn match_vendor_id(&self, uuid: Uuid, component: &Component) -> Result<bool, Error> {
        log_hook!("match_vendor_id(uuid={uuid}, component={component:?}) -> accepted (testing mode)");
        Ok(true)
    }

    fn match_class_id(&self, uuid: Uuid, component: &Component) -> Result<bool, Error> {
        log_hook!("match_class_id(uuid={uuid}, component={component:?}) -> accepted (testing mode)");
        Ok(true)
    }

    fn match_device_id(&self, uuid: Uuid, component: &Component) -> Result<bool, Error> {
        log_hook!("match_device_id(uuid={uuid}, component={component:?}) -> accepted (testing mode)");
        Ok(true)
    }

    fn match_component_slot(
        &self,
        component: &Component,
        component_slot: u64,
    ) -> Result<bool, Error> {
        log_hook!(
            "match_component_slot(component={component:?}, slot={component_slot}) -> accepted (testing mode)"
        );
        Ok(true)
    }

    fn component_read(
        &self,
        component: &Component,
        slot: Option<u64>,
        offset: usize,
        bytes: &mut [u8],
    ) -> Result<(), Error> {
        let storage = self.storage.borrow();
        if offset + bytes.len() > storage.len() {
            log_warn!(
                "component_read(component={component:?}, slot={slot:?}, offset={offset}, len={}) -> out of bounds",
                bytes.len()
            );
            return Err(Error::InvalidCommandSequence { position: offset });
        }
        bytes.copy_from_slice(&storage[offset..offset + bytes.len()]);
        log_hook!(
            "component_read(component={component:?}, slot={slot:?}, offset={offset}, len={}) -> {:02x?}",
            bytes.len(),
            bytes
        );
        Ok(())
    }

    fn component_write(
        &self,
        component: &Component,
        slot: Option<u64>,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let mut storage = self.storage.borrow_mut();
        if storage.len() < offset + bytes.len() {
            storage.resize(offset + bytes.len(), 0);
        }
        storage[offset..offset + bytes.len()].copy_from_slice(bytes);
        log_hook!(
            "component_write(component={component:?}, slot={slot:?}, offset={offset}, len={}) -> {:02x?}",
            bytes.len(),
            bytes
        );
        Ok(())
    }

    fn component_size(&self, component: &Component) -> Result<usize, Error> {
        let size = self.storage.borrow().len();
        log_hook!("component_size(component={component:?}) -> {size}");
        Ok(size)
    }

    fn component_capacity(&self, component: &Component) -> Result<usize, Error> {
        log_hook!(
            "component_capacity(component={component:?}) -> {}",
            self.capacity
        );
        Ok(self.capacity)
    }

    fn has_component(&self, component: &Component) -> Result<(), Error> {
        log_hook!("has_component(component={component:?}) -> present (testing mode)");
        Ok(())
    }

    fn fetch(&self, component: &Component, slot: Option<u64>, uri: &str) -> Result<(), Error> {
        log_hook!(
            "fetch(component={component:?}, slot={slot:?}, uri={uri:?}) -> {} bytes",
            self.fetch_payload.len()
        );
        *self.storage.borrow_mut() = self.fetch_payload.clone();
        Ok(())
    }

    fn invoke(
        &self,
        component: &Component,
        arguments: &minicbor::bytes::ByteSlice,
    ) -> Result<(), Error> {
        log_hook!(
            "invoke(component={component:?}, arguments={:02x?})",
            &arguments[..]
        );
        Ok(())
    }

    fn swap(&self, component: &Component, other: &Component) -> Result<(), Error> {
        log_hook!("swap(component={component:?}, other={other:?})");
        Ok(())
    }

    fn custom_command(
        &self,
        number: i32,
        state: &ManifestState,
        component: &Component,
    ) -> Result<(), Error> {
        log_hook!("custom_command(number={number}, component={component:?}, state={state:?})");
        Ok(())
    }
}
