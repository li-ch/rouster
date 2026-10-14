//! Checked little helpers over byte slices for the BGP wire codec.
//!
//! Everything that reads a length or count field goes through [`Reader`]'s
//! checked `take` — the A19 lesson (never trust counts): a declared length
//! is only ever accepted when the remaining buffer actually holds it.

/// A cursor over a received message body. Every read is bounds-checked;
/// there is no panicking indexing anywhere in the codec.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// True when exactly `n` bytes are left (framing exactness checks).
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.remaining() {
            None
        } else {
            let s = &self.buf[self.pos..self.pos + n];
            self.pos += n;
            Some(s)
        }
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Rest of the buffer.
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
}

/// Appends big-endian integers to an encode buffer (the BGP wire is
/// network byte order throughout).
pub fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Lowercase hex of a byte slice — RFC 7606 §6's "entire malformed
/// UPDATE message" in the debug log line.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
pub(crate) fn unhex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    cleaned
        .as_bytes()
        .chunks(2)
        .map(|p| {
            u8::from_str_radix(std::str::from_utf8(p).expect("hex digit"), 16)
                .expect("valid hex pair")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_take_respects_bounds() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.take(2), Some(&[1, 2][..]));
        assert_eq!(r.take(2), None, "only one byte left");
        assert_eq!(r.take(1), Some(&[3][..]));
        assert!(r.is_empty());
    }

    #[test]
    fn reader_integers() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(r.u8(), Some(1));
        assert_eq!(r.u16(), Some(0x0203));
        assert_eq!(r.u16(), None, "one byte short of a u16");
    }
}
