use crate::error::{Error, Result};

pub fn put_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn put_bool(buf: &mut Vec<u8>, v: bool) {
    buf.push(u8::from(v));
}

pub fn put_bytes(buf: &mut Vec<u8>, s: &[u8]) {
    put_u32(buf, s.len() as u32);
    buf.extend_from_slice(s);
}

pub fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_bytes(buf, s.as_bytes());
}

pub fn put_namelist(buf: &mut Vec<u8>, names: &[&str]) {
    let mut joined = String::new();
    for (i, n) in names.iter().enumerate() {
        if i != 0 {
            joined.push(',');
        }
        joined.push_str(n);
    }
    put_str(buf, &joined);
}

pub fn encode_mpint(bytes: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    if i == bytes.len() {
        let mut out = Vec::with_capacity(5);
        put_u32(&mut out, 1);
        out.push(0);
        return out;
    }
    let need_zero = bytes[i] & 0x80 != 0;
    let data_len = bytes.len() - i + usize::from(need_zero);
    let mut out = Vec::with_capacity(4 + data_len);
    put_u32(&mut out, data_len as u32);
    if need_zero {
        out.push(0);
    }
    out.extend_from_slice(&bytes[i..]);
    out
}

pub struct Parser<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Parser<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.off)
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.off..]
    }

    pub fn u8(&mut self) -> Result<u8> {
        if self.off >= self.buf.len() {
            return Err(Error::protocol("truncated u8"));
        }
        let v = self.buf[self.off];
        self.off += 1;
        Ok(v)
    }

    pub fn u32(&mut self) -> Result<u32> {
        if self.off + 4 > self.buf.len() {
            return Err(Error::protocol("truncated u32"));
        }
        let v = u32::from_be_bytes(self.buf[self.off..self.off + 4].try_into().unwrap());
        self.off += 4;
        Ok(v)
    }

    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if self.off + n > self.buf.len() {
            return Err(Error::protocol("truncated string"));
        }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }

    pub fn str(&mut self) -> Result<&'a str> {
        let b = self.bytes()?;
        std::str::from_utf8(b).map_err(|_| Error::protocol("non-utf8 string"))
    }

    pub fn namelist(&mut self) -> Result<Vec<&'a str>> {
        let s = self.str()?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        Ok(s.split(',').collect())
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        if self.off + n > self.buf.len() {
            return Err(Error::protocol("truncated skip"));
        }
        self.off += n;
        Ok(())
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.off + n > self.buf.len() {
            return Err(Error::protocol("truncated take"));
        }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }
}

pub fn split_namelist(s: &str) -> Vec<&str> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split(',').collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpint_high_bit() {
        let e = encode_mpint(&[0x80, 0x00]);
        assert_eq!(e, vec![0, 0, 0, 3, 0, 0x80, 0x00]);
    }

    #[test]
    fn mpint_strips_leading_zeros() {
        let e = encode_mpint(&[0x00, 0x00, 0x01, 0x02]);
        assert_eq!(e, vec![0, 0, 0, 2, 0x01, 0x02]);
    }

    #[test]
    fn mpint_zero() {
        let e = encode_mpint(&[0, 0, 0]);
        assert_eq!(e, vec![0, 0, 0, 1, 0]);
    }
}
