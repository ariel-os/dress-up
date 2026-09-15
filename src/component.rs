//! Implements component handling in the SUIT manifest.
use crate::cbor::SubCbor;
use crate::error::Error;
use heapless::string::String;
use itertools::Itertools;
use minicbor::bytes::ByteSlice;
use minicbor::decode::{ArrayIter, Decode, Decoder};

/// Represent the component index parameter in the SUIT manifest.
///
/// The parameter in a SUIT manifest can be set to a specific index, or by specifying 'true' as
/// parameter, all components can be referenced.
#[derive(Copy, Clone, PartialEq, Debug)]
enum ComponentIndex<'a> {
    /// Command sequence applies to all components.
    All,
    /// Command sequence applies to only to the component with this index.
    Index(u32),
    /// Command sequence applies to a set of components
    Set(&'a ByteSlice),
}

impl ComponentIndex<'_> {
    fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    fn in_set(&self, index: u32) -> bool {
        match self {
            ComponentIndex::All => true,
            ComponentIndex::Index(i) => *i == index,
            ComponentIndex::Set(arr) => Self::in_array(arr, index),
        }
    }

    /// Checks if the current component is in the array of components set as active. Returns false
    /// on a CBOR error
    fn in_array(arr: &ByteSlice, index: u32) -> bool {
        let mut dec = Decoder::new(arr);
        if let Ok(mut iter) = dec.array_iter::<u32>() {
            return iter.any(|i| i.is_ok_and(|i| i == index));
        }
        false
    }
}

/// Represents a single component in a manifest
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Component<'a> {
    cbor: &'a [u8],
}

impl<'a, C> Decode<'a, C> for Component<'a> {
    fn decode(d: &mut Decoder<'a>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let cbor = d.sub_cbor()?;
        Ok(Component { cbor })
    }
}

impl<'a> Component<'a> {
    /// Create a SUIT component from a byte slice.
    pub fn from_bytes(bytes: &'a impl AsRef<[u8]>) -> Component<'a> {
        Component {
            cbor: bytes.as_ref(),
        }
    }

    /// Combine the component into a string.
    #[allow(unstable_name_collisions)]
    pub fn as_string<const N: usize>(
        &self,
        s: &mut String<N>,
        separator: &str,
    ) -> Result<(), Error> {
        let mut decoder = Decoder::new(self.cbor);
        decoder
            .array_iter::<&ByteSlice>()?
            .map(|b| match b {
                Ok(b) => str::from_utf8(b).map_err(|e| Error::Utf8Error {
                    position: e.valid_up_to(),
                }),
                Err(e) => Err(e.into()),
            })
            .intersperse(Ok(separator))
            .try_for_each(|b| match b {
                Ok(b) => s.push_str(b).map_err(|_| Error::CapacityError),
                Err(e) => Err(e),
            })
    }

    /// returns an iterator over the individual segments of a component location.
    pub fn iter_segments(&self) -> Result<ComponentIdentifierIter<'a>, Error> {
        let decoder = Decoder::new(self.cbor);
        ComponentIdentifierIter::new(decoder)
    }
}

/// Iterator over the byte string components of a component identifier.
pub struct ComponentIdentifierIter<'a> {
    decoder: Decoder<'a>,
    remaining: u64,
}

impl<'a> ComponentIdentifierIter<'a> {
    pub(crate) fn new(mut decoder: Decoder<'a>) -> Result<Self, Error> {
        let Some(remaining) = decoder.array()? else {
            return Err(Error::UnexpectedIndefiniteLength { position: 0 });
        };
        Ok(Self { decoder, remaining })
    }
}

impl<'a> Iterator for ComponentIdentifierIter<'a> {
    type Item = Result<&'a [u8], Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(self.decoder.bytes().map_err(core::convert::Into::into))
    }
}

pub(crate) struct ComponentIter<'a, 'b> {
    array_iter: ArrayIter<'b, 'a, Component<'a>>,
}

impl<'a> ComponentIter<'a, '_> {
    pub(crate) fn new(decoder: &'a mut Decoder<'a>) -> Result<Self, Error> {
        let array_iter = decoder.array_iter::<Component>()?;
        Ok(ComponentIter { array_iter })
    }
}

impl<'a> Iterator for ComponentIter<'a, '_> {
    type Item = Result<Component<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.array_iter
            .next()
            .map(|s| s.map_err(core::convert::Into::into))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ComponentInfo<'a> {
    pub(crate) component: Component<'a>,
    pub(crate) index: u32,
}

impl<'a> ComponentInfo<'a> {
    pub(crate) fn new(component: Component<'a>, index: u32) -> Self {
        Self { component, index }
    }

    pub(crate) fn component(&self) -> &'a Component<'_> {
        &self.component
    }

    pub(crate) fn in_applylist(&self, decoder: &mut Decoder) -> Result<bool, Error> {
        let position = decoder.position();
        match decoder.datatype()? {
            minicbor::data::Type::Bool => {
                if decoder.bool()? {
                    Ok(true)
                } else {
                    Err(Error::UnexpectedCbor { position })
                }
            }
            minicbor::data::Type::U8 | minicbor::data::Type::U16 | minicbor::data::Type::U32 => {
                Ok(decoder.u32()? == self.index)
            }
            minicbor::data::Type::Array => Ok(decoder
                .array_iter::<u32>()?
                .any(|x| x.is_ok_and(|i| i == self.index))),
            _ => Err(Error::UnexpectedCbor { position }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn decode_component() {
        let input = std::vec![0x81, 0x81, 0x41, 0x00]; // [[h'00']]

        let mut decoder = Decoder::new(&input);
        let len = decoder.array().unwrap();
        assert_eq!(len, Some(1));
        let component = decoder.decode::<Component>().unwrap();
        assert_eq!(component.cbor, std::vec!(0x81, 0x41, 0x00));
        assert_eq!(decoder.position(), input.len());
    }

    #[test]
    fn iter_components() {
        let input = std::vec![0x82, 0x81, 0x41, 0x01, 0x81, 0x41, 0x02];
        let mut decoder = Decoder::new(&input);
        let mut components = ComponentIter::new(&mut decoder).unwrap();
        let component = components.next().unwrap().unwrap();
        assert_eq!(component.cbor, std::vec!(0x81, 0x41, 0x01));
        let component = components.next().unwrap().unwrap();
        assert_eq!(component.cbor, std::vec!(0x81, 0x41, 0x02));
    }

    #[test]
    fn component_utf8() {
        let input = std::vec![0x81, 0x82, 0x41, 0x61, 0x41, 0x62];
        let mut decoder = Decoder::new(&input);
        let mut components = ComponentIter::new(&mut decoder).unwrap();
        let component = components.next().unwrap().unwrap();
        let mut s: String<3> = String::new();
        let res = component.as_string(&mut s, "/");
        assert!(res.is_ok());
        assert_eq!(s.as_str(), "a/b");
        let mut s: String<2> = String::new();
        let res = component.as_string(&mut s, "/");
        assert!(matches!(res, Err(Error::CapacityError)));
    }

    #[test]
    fn component_identifier_iter() {
        let input = std::vec![0x81, 0x82, 0x41, 0x61, 0x41, 0x62];
        let mut decoder = Decoder::new(&input);
        let mut components = ComponentIter::new(&mut decoder).unwrap();
        let component = components.next().unwrap().unwrap();
        let mut iter = component.iter_segments().unwrap();
        assert_eq!(&[0x61], iter.next().unwrap().unwrap());
        assert_eq!(&[0x62], iter.next().unwrap().unwrap());
        assert_eq!(None, iter.next());
    }
}
