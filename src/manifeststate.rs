use crate::component::Component;
use crate::consts::SuitParameter;
use crate::digest::SuitDigest;
use crate::error::Error;
use minicbor::bytes::{ByteArray, ByteSlice};
use minicbor::decode::{Decode, Decoder};
use uuid::Uuid;

#[derive(Default, Clone, Debug, PartialEq)]
pub struct ManifestState<'a> {
    pub(crate) component_index: Option<Component<'a>>,
    pub(crate) content: Option<&'a ByteSlice>,
    pub(crate) vendor_id: Option<Uuid>,
    pub(crate) class_id: Option<Uuid>,
    pub(crate) device_id: Option<Uuid>,
    pub(crate) image_digest: Option<SuitDigest<'a>>,
    pub(crate) component_slot: Option<u64>,
    pub(crate) image_size: Option<usize>,
    pub(crate) uri: Option<&'a str>,
}

impl<'a> ManifestState<'a> {
    pub(crate) fn set_component_index(&mut self, component: Component<'a>) {
        self.component_index = Some(component);
    }

    pub(crate) fn set_content(&mut self, content: &'a ByteSlice) {
        self.content = Some(content);
    }

    pub(crate) fn content_from_cbor(&mut self, decoder: &mut Decoder<'a>) -> Result<(), Error> {
        self.set_content(decoder.decode()?);
        Ok(())
    }


    pub(crate) fn set_vendor_id(&mut self, vendor: Uuid) {
        self.vendor_id = Some(vendor);
    }

    pub(crate) fn vendor_id_from_cbor(&mut self, decoder: &mut Decoder) -> Result<(), Error> {
        let uuid: ByteArray<16> = ByteArray::decode(decoder, &mut ())?;
        let uuid = Uuid::from_bytes(*uuid);
        self.set_vendor_id(uuid);
        Ok(())
    }

    pub(crate) fn set_class_id(&mut self, class: Uuid) {
        self.class_id = Some(class);
    }

    pub(crate) fn class_id_from_cbor(&mut self, decoder: &mut Decoder) -> Result<(), Error> {
        let uuid: ByteArray<16> = ByteArray::decode(decoder, &mut ())?;
        let uuid = Uuid::from_bytes(*uuid);
        self.set_class_id(uuid);
        Ok(())
    }

    pub(crate) fn set_device_id(&mut self, device: Uuid) {
        self.device_id = Some(device);
    }

    pub(crate) fn device_id_from_cbor(&mut self, decoder: &mut Decoder) -> Result<(), Error> {
        let uuid: ByteArray<16> = ByteArray::decode(decoder, &mut ())?;
        let uuid = Uuid::from_bytes(*uuid);
        self.set_vendor_id(uuid);
        Ok(())
    }

    pub(crate) fn set_image_digest(&mut self, digest: SuitDigest<'a>) {
        self.image_digest = Some(digest);
    }

    pub(crate) fn image_digest_from_cbor(&mut self, decoder: &mut Decoder<'a>) -> Result<(), Error> {
        let bytes = decoder.bytes()?;
        let mut inner = Decoder::new(bytes);
        let digest = SuitDigest::decode(&mut inner, &mut ())?;
        self.set_image_digest(digest);
        Ok(())
    }

    pub(crate) fn component_slot(&mut self, component_slot: u64) {
        self.component_slot = Some(component_slot);
    }

    pub(crate) fn component_slot_from_cbor(&mut self, decoder: &mut Decoder) -> Result<(), Error> {
        let slot = decoder.u64()?;
        self.component_slot(slot);
        Ok(())
    }

    pub(crate) fn set_image_size(&mut self, size: usize) {
        self.image_size = Some(size);
    }

    pub(crate) fn image_size_from_cbor(&mut self, decoder: &mut Decoder) -> Result<(), Error> {
        let size = decoder.u64()?;
        let size: usize = size
            .try_into()
            .map_err(|_| Error::UnexpectedCbor(decoder.position()))?;
        self.set_image_size(size);
        Ok(())
    }

    pub(crate) fn set_uri(&mut self, uri: &'a str) {
        self.uri = Some(uri);
    }

    pub(crate) fn uri_from_cbor(&mut self, decoder: &mut Decoder<'a>) -> Result<(), Error> {
        let uri = decoder.str()?;
        self.set_uri(uri);
        Ok(())
    }

    pub(crate) fn update_parameter(&mut self, decoder: &mut Decoder<'a>) -> Result<(), Error> {
        let length = decoder.map()?;
        let length = length.ok_or(Error::UnexpectedIndefiniteLength(decoder.position()))?;
        for _ in 0..length {
            let param: SuitParameter = decoder.i32()?.try_into()?;
            match param {
                SuitParameter::VendorId => self.vendor_id_from_cbor(decoder)?,
                SuitParameter::ClassId => self.class_id_from_cbor(decoder)?,
                SuitParameter::ImageDigest => self.image_digest_from_cbor(decoder)?,
                SuitParameter::ComponentSlot => self.component_slot_from_cbor(decoder)?,
                SuitParameter::ImageSize => self.image_size_from_cbor(decoder)?,
                SuitParameter::Uri => self.uri_from_cbor(decoder)?,
                SuitParameter::SourceComponent => todo!(),
                SuitParameter::DeviceId => self.device_id_from_cbor(decoder)?,
                param => return Err(Error::UnsupportedParameter(param.into())),
            };
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn empty() {
        let input = std::vec![0xA0];
        let mut params = ManifestState::default();
        let mut decoder = Decoder::new(&input);
        params.update_parameter(&mut decoder).unwrap();
        assert_eq!(params, ManifestState::default());
    }

    #[test]
    fn unsupported() {
        let input = std::vec![0xA1, 0x00, 0x00];
        let mut params = ManifestState::default();
        let mut decoder = Decoder::new(&input);
        let err = params.update_parameter(&mut decoder);
        assert_eq!(err.unwrap_err(), Error::UnsupportedParameter(0));
    }

    #[test]
    fn vendor_id() {
        let input = std::vec![
            0xA1, 0x01, 0x50, 0xE2, 0xFA, 0xD0, 0x35, 0xB7, 0xB9, 0x40, 0x1F, 0xB3, 0x7C, 0x03,
            0x0E, 0x0B, 0x95, 0x48, 0x1F
        ];
        let uuid = Uuid::parse_str("e2fad035-b7b9-401f-b37c-030e0b95481f").unwrap();
        let mut params = ManifestState::default();
        let mut decoder = Decoder::new(&input);
        params.update_parameter(&mut decoder).unwrap();
        assert_eq!(params.vendor_id.unwrap(), uuid);
    }

    #[test]
    fn class_id() {
        let input = std::vec![
            0xA1, 0x02, 0x50, 0xE3, 0xFB, 0xD0, 0x35, 0xB7, 0xB9, 0x40, 0x1F, 0xB3, 0x7C, 0x03,
            0x0E, 0x0B, 0x95, 0x48, 0x1F
        ];
        let uuid = Uuid::parse_str("e3fbd035-b7b9-401f-b37c-030e0b95481f").unwrap();
        let mut params = ManifestState::default();
        let mut decoder = Decoder::new(&input);
        params.update_parameter(&mut decoder).unwrap();
        assert_eq!(params.class_id.unwrap(), uuid);
    }

    #[test]
    fn image_digest() {
        use crate::digest::SuitDigestAlgorithm;
        let input = std::vec![
            0xA1, 0x03, 0x58, 0x24, 0x82, 0x2F, 0x58, 0x20, 0x01, 0xBA, 0x47, 0x19, 0xC8, 0x0B, 0x6F, 0xE9,
            0x11, 0xB0, 0x91, 0xA7, 0xC0, 0x51, 0x24, 0xB6, 0x4E, 0xEE, 0xCE, 0x96, 0x4E, 0x09,
            0xC0, 0x58, 0xEF, 0x8F, 0x98, 0x05, 0xDA, 0xCA, 0x54, 0x6B
        ];
        let hash: &[u8] = &std::vec![
            0x01, 0xba, 0x47, 0x19, 0xc8, 0x0b, 0x6f, 0xe9, 0x11, 0xb0, 0x91, 0xa7, 0xc0, 0x51,
            0x24, 0xb6, 0x4e, 0xee, 0xce, 0x96, 0x4e, 0x09, 0xc0, 0x58, 0xef, 0x8f, 0x98, 0x05,
            0xda, 0xca, 0x54, 0x6b
        ];
        let digest = SuitDigest::new(SuitDigestAlgorithm::Sha256, hash.into());

        let mut params = ManifestState::default();
        let mut decoder = Decoder::new(&input);
        params.update_parameter(&mut decoder).unwrap();

        assert_eq!(params.image_digest.unwrap(), digest);
    }

    #[test]
    fn uri() {
        let uri = "coap://example.com";
        let input = std::vec![
            0xA1, 0x15, 0x72, 0x63, 0x6F, 0x61, 0x70, 0x3A, 0x2F, 0x2F, 0x65, 0x78, 0x61, 0x6D,
            0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D
        ];
        let mut params = ManifestState::default();
        let mut decoder = Decoder::new(&input);
        params.update_parameter(&mut decoder).unwrap();

        assert_eq!(params.uri.unwrap(), uri);
    }

    #[test]
    fn multiple() {
        use crate::digest::SuitDigestAlgorithm;
        let input = std::vec![
            0xA4, 0x01, 0x50, 0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF, 0xBE, 0x9D, 0xE6,
            0x63, 0xE4, 0xD4, 0x1F, 0xFE, 0x02, 0x50, 0x14, 0x92, 0xAF, 0x14, 0x25, 0x69, 0x5E,
            0x48, 0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45, 0x03, 0x58, 0x24, 0x82, 0x2F,
            0x58, 0x20, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
            0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0E, 0x19, 0x87, 0xD0
        ];
        let vendor_id = Uuid::parse_str("fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe").unwrap();
        let class_id = Uuid::parse_str("1492af14-2569-5e48-bf42-9b2d51f2ab45").unwrap();
        let hash: &[u8] = &std::vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10
        ];
        let digest = SuitDigest::new(SuitDigestAlgorithm::Sha256, hash.into());
        let size = 34768;
        let mut params = ManifestState::default();
        let mut decoder = Decoder::new(&input);
        params.update_parameter(&mut decoder).unwrap();
        assert_eq!(params.image_size.unwrap(), size);
        assert_eq!(params.vendor_id.unwrap(), vendor_id);
        assert_eq!(params.class_id.unwrap(), class_id);
        assert_eq!(params.image_digest.unwrap(), digest);
    }
}
