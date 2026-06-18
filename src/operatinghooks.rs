//! Dress Up operating hooks.
//!
use generic_array::ArrayLength;
use uuid::Uuid;

use crate::{component::Component, consts::SuitCommand, error::Error};

/// A trait to expose operating system functionality to the SUIT manifest parsing
///
/// A SUIT manifest contains a set of check and directives to verify the applicability of the
/// payload, retrieve the payload and install payload. Often this requires input from the operating
/// system.
pub trait OperatingHooks {
    /// The size of the intermediate buffer used during reads and writes with components.
    ///
    /// This determines the size of a stack-allocated buffer used. Conditions execution write in
    /// this buffer when content from a component is required for the condition. The Digest
    /// and the Content check use this buffer.
    type ReadWriteBufferSize: ArrayLength;

    /// Match the vendor ID from the manifest.
    ///
    /// Installations without multiple components can ignore the `component` parameter.
    fn match_vendor_id(&self, uuid: Uuid, component: &Component) -> Result<bool, Error>;

    /// Match the class ID from the manifest.
    ///
    /// Installations without multiple components can ignore the `component` parameter.
    fn match_class_id(&self, uuid: Uuid, component: &Component) -> Result<bool, Error>;

    /// Match the device ID from the manifest.
    ///
    /// Installations without multiple components can ignore the `component` parameter.
    fn match_device_id(&self, _uuid: Uuid, _component: &Component) -> Result<bool, Error> {
        Err(Error::UnsupportedCommand {
            command: SuitCommand::DeviceIdentifier.into(),
        })
    }

    /// Verify that the component slot index of the supplied component is valid
    ///
    /// Some components can have multiple slots to install into. This condition allows the
    /// to verify that the target slot is valid.
    fn match_component_slot(
        &self,
        _component: &Component,
        _component_slot: u64,
    ) -> Result<bool, Error> {
        Err(Error::UnsupportedCommand {
            command: SuitCommand::DeviceIdentifier.into(),
        })
    }

    /// Read the data from a component (with slot) into the supplied buffer.
    fn component_read(
        &self,
        component: &Component,
        slot: Option<u64>,
        offset: usize,
        bytes: &mut [u8],
    ) -> Result<(), Error>;

    /// Write the supplied data into the component (with slot).
    fn component_write(
        &self,
        component: &Component,
        slot: Option<u64>,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Error>;

    /// Get the size of the component installed.
    fn component_size(&self, component: &Component) -> Result<usize, Error>;

    /// Get the capacity of what can be installed in the component.
    fn component_capacity(&self, component: &Component) -> Result<usize, Error>;

    /// Check if the component exists on the system.
    fn has_component(&self, component: &Component) -> Result<(), Error> {
        self.component_capacity(component).map(|_| ())
    }

    #[cfg(not(feature = "integrated-payload"))]
    /// Retrieve the payload from the url and store it in the component.
    fn fetch(&self, _component: &Component, _slot: Option<u64>, _uri: &str) -> Result<(), Error> {
        Err(Error::UnsupportedCommand {
            command: SuitCommand::Fetch.into(),
        })
    }

    #[cfg(feature = "integrated-payload")]
    /// Store the integrated payload in the component.
    fn fetch(
        &self,
        _component: &Component,
        _slot: Option<u64>,
        _payload: &[u8],
    ) -> Result<(), Error> {
        Err(Error::UnsupportedCommand {
            command: SuitCommand::Fetch.into(),
        })
    }
}
