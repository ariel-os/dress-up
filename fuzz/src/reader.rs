pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Never fails; returns 0 when exhausted so short inputs stay valid.
    pub fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.u8(), self.u8()])
    }

    /// Returns exactly `n` bytes, zero-padded if the input is too short.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.u8());
        }
        out
    }

    /// Pick one of `n` variants.
    pub fn choice(&mut self, n: u8) -> u8 {
        self.u8() % n
    }

    /// Consume a bit-flag.
    pub fn flag(&mut self) -> bool {
        self.u8() & 1 == 1
    }

    pub fn remaining(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
}
