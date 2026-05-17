//! SUIT report handling and generation
use minicbor::Decode;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReportingPolicy {
    policy: u8,
}

#[allow(unused)]
impl ReportingPolicy {
    pub(crate) fn new(policy: u8) -> ReportingPolicy {
        ReportingPolicy { policy }
    }

    pub(crate) fn send_record_on_success(&self) -> bool {
        self.policy & 0x01 > 0
    }

    pub(crate) fn send_record_on_failure(&self) -> bool {
        self.policy & 0x02 > 0
    }

    pub(crate) fn add_sysinfo_on_success(&self) -> bool {
        self.policy & 0x04 > 0
    }

    pub(crate) fn add_sysinfo_on_failure(&self) -> bool {
        self.policy & 0x08 > 0
    }
}

impl<'b, C> Decode<'b, C> for ReportingPolicy {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let policy = d.u8()?;
        if policy > 15 {
            return Err(minicbor::decode::Error::type_mismatch(
                minicbor::data::Type::U8,
            ));
        }
        Ok(ReportingPolicy::new(policy))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn empty() {
        let policy = ReportingPolicy::new(0u8);
        assert!(!policy.send_record_on_success());
        assert!(!policy.send_record_on_failure());
        assert!(!policy.add_sysinfo_on_success());
        assert!(!policy.add_sysinfo_on_failure());
    }

    #[test]
    fn all() {
        let policy = ReportingPolicy::new(15u8);
        assert!(policy.send_record_on_success());
        assert!(policy.send_record_on_failure());
        assert!(policy.add_sysinfo_on_success());
        assert!(policy.add_sysinfo_on_failure());
    }

    #[test]
    fn not_a_report_policy() {
        let input = std::vec![0x20];
        let mut decoder = minicbor::Decoder::new(&input);
        let res = decoder.decode::<ReportingPolicy>().unwrap_err();
        assert!(res.is_type_mismatch());
    }
}
