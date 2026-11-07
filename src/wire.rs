use crate::error::{Error, Result};

#[inline]
pub fn put_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

#[inline]
pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

#[inline]
pub fn put_bool(buf: &mut Vec<u8>, v: bool) {
    buf.push(u8::from(v));
}

#[inline]
pub fn put_bytes(buf: &mut Vec<u8>, s: &[u8]) {
    put_u32(buf, s.len() as u32);
    buf.extend_from_slice(s);
}

#[inline]
pub fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_bytes(buf, s.as_bytes());
}

pub fn put_namelist<S: AsRef<str>>(buf: &mut Vec<u8>, names: &[S]) {
    let len: usize = names.iter().map(|n| n.as_ref().len()).sum::<usize>()
        + names.len().saturating_sub(1);
    put_u32(buf, len as u32);
    for (i, n) in names.iter().enumerate() {
        if i != 0 {
            buf.push(b',');
        }
        buf.extend_from_slice(n.as_ref().as_bytes());
    }
}

/// SSH mpint of an unsigned big-endian integer (including the length prefix).
pub fn put_mpint(buf: &mut Vec<u8>, bytes: &[u8]) {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    let digits = &bytes[i..];
    if digits.is_empty() {
        put_u32(buf, 0);
        return;
    }
    let need_zero = digits[0] & 0x80 != 0;
    put_u32(buf, (digits.len() + usize::from(need_zero)) as u32);
    if need_zero {
        buf.push(0);
    }
    buf.extend_from_slice(digits);
}

pub struct Parser<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Parser<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    pub fn offset(&self) -> usize {
        self.off
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.off)
    }

    pub fn u8(&mut self) -> Result<u8> {
        let v = *self
            .buf
            .get(self.off)
            .ok_or(Error::protocol("truncated u8"))?;
        self.off += 1;
        Ok(v)
    }

    pub fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    pub fn str(&mut self) -> Result<&'a str> {
        std::str::from_utf8(self.bytes()?).map_err(|_| Error::protocol("non-utf8 string"))
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .off
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or(Error::protocol("truncated field"))?;
        let s = &self.buf[self.off..end];
        self.off = end;
        Ok(s)
    }
}

/// Iterate a comma separated name-list without allocating.
pub fn names(list: &str) -> impl Iterator<Item = &str> {
    list.split(',').filter(|s| !s.is_empty())
}

pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpint_encoding() {
        let mut b = Vec::new();
        put_mpint(&mut b, &[0x80, 0x00]);
        assert_eq!(b, vec![0, 0, 0, 3, 0, 0x80, 0x00]);
        b.clear();
        put_mpint(&mut b, &[0x00, 0x00, 0x01, 0x02]);
        assert_eq!(b, vec![0, 0, 0, 2, 0x01, 0x02]);
        b.clear();
        put_mpint(&mut b, &[0, 0, 0]);
        assert_eq!(b, vec![0, 0, 0, 0]);
    }

    #[test]
    fn namelist_and_b64() {
        let mut b = Vec::new();
        put_namelist(&mut b, &["a", "bc"]);
        assert_eq!(b, b"\0\0\0\x04a,bc");
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(b64_encode(b"hel"), "aGVs");
    }

    #[test]
    fn parser_rejects_overflow() {
        let mut p = Parser::new(&[0xff, 0xff, 0xff, 0xff, 1]);
        assert!(p.bytes().is_err());
    }
}
