use crate::error::Error;
use heapless::string::String;
use itertools::Itertools;
use minicbor::bytes::ByteSlice;
use minicbor::decode::{ArrayIter, Decode, Decoder};

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum ComponentIndex {
    All,
    Index(u32),
}

impl ComponentIndex {
    fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Component<'a> {
    cbor: &'a [u8],
}

impl<'a, C> Decode<'a, C> for Component<'a> {
    fn decode(d: &mut Decoder<'a>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let start = d.position();
        d.skip()?;
        let end = d.position();
        let input = d.input();
        Ok(Component {
            cbor: &input[start..end],
        })
    }
}

impl<'a> Component<'a> {

    pub fn from_bytes(bytes: &'a [u8]) ->Component<'a> {
        Component {
            cbor: bytes
        }
    }

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
                Ok(b) => str::from_utf8(b).map_err(|e| Error::Utf8Error(e.valid_up_to())),
                Err(e) => Err(e.into()),
            })
            .intersperse(Ok(separator))
            .try_for_each(|b| match b {
                Ok(b) => s.push_str(b).map_err(|_| Error::CapacityError),
                Err(e) => Err(e),
            })
    }
}

pub(crate) struct ComponentIter<'a, 'b> {
    array_iter: ArrayIter<'b, 'a, Component<'a>>,
}

impl<'a, 'b> ComponentIter<'a, 'b> {
    pub(crate) fn new(decoder: &'a mut Decoder<'a>) -> Result<Self, Error> {
        let array_iter = decoder.array_iter::<Component>()?;
        Ok(ComponentIter { array_iter })
    }
}

impl<'a, 'b> Iterator for ComponentIter<'a, 'b> {
    type Item = Result<Component<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.array_iter.next().map(|s| s.map_err(|e| e.into()))
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

    pub(crate) fn in_applylist(
        &self,
        decoder: &mut Decoder,
    ) -> Result<bool, Error> {
        match decoder.datatype()? {
            minicbor::data::Type::Bool => {
                if decoder.bool()? {
                    Ok(true)
                } else {
                    Err(Error::UnexpectedCbor(decoder.position()))
                }
            }
            minicbor::data::Type::U8 | minicbor::data::Type::U16 | minicbor::data::Type::U32 => {
                Ok(decoder.u32()? == self.index)
            }
            minicbor::data::Type::Array => Ok(decoder
                .array_iter::<u32>()?
                .any(|x| x.is_ok_and(|i| i == self.index))),
            _ => Err(Error::UnexpectedCbor(decoder.position())),
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
}
