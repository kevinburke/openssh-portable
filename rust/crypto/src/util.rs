use core::ffi::c_int;
use core::slice;

pub(crate) const SSHBUF_MAX_BIGNUM: usize = 16_384 / 8;

pub(crate) fn read_array<const N: usize>(ptr: *const u8, len: usize) -> Option<[u8; N]> {
    if ptr.is_null() || len != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(unsafe { slice::from_raw_parts(ptr, N) });
    Some(out)
}

pub(crate) fn read_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

pub(crate) fn slice_ptr(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        core::ptr::null()
    } else {
        bytes.as_ptr()
    }
}

pub(crate) struct SshWireReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> SshWireReader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub(crate) fn consumed(&self) -> usize {
        self.offset
    }

    pub(crate) fn input_len(&self) -> usize {
        self.input.len()
    }

    pub(crate) fn get_u32(&mut self) -> Option<u32> {
        let bytes = self.input.get(self.offset..self.offset + 4)?;
        self.offset += 4;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    pub(crate) fn get_u64(&mut self) -> Option<u64> {
        let bytes = self.input.get(self.offset..self.offset + 8)?;
        self.offset += 8;
        Some(u64::from_be_bytes(bytes.try_into().ok()?))
    }

    pub(crate) fn get_string(&mut self) -> Option<&'a [u8]> {
        let (_, bytes) = self.get_string_with_offset()?;
        Some(bytes)
    }

    pub(crate) fn get_string_with_offset(&mut self) -> Option<(usize, &'a [u8])> {
        let len = usize::try_from(self.get_u32()?).ok()?;
        let offset = self.offset;
        let bytes = self.input.get(offset..offset + len)?;
        self.offset += len;
        Some((offset, bytes))
    }

    pub(crate) fn get_cstring(&mut self) -> Option<&'a [u8]> {
        let bytes = self.get_string()?;
        match bytes.iter().position(|byte| *byte == 0) {
            Some(pos) if pos + 1 != bytes.len() => None,
            Some(pos) => Some(&bytes[..pos]),
            None => Some(bytes),
        }
    }

    pub(crate) fn get_mpint(&mut self) -> Option<&'a [u8]> {
        let bytes = self.get_string()?;
        if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
            return None;
        }
        if bytes.len() > SSHBUF_MAX_BIGNUM + 1
            || (bytes.len() == SSHBUF_MAX_BIGNUM + 1 && bytes[0] != 0)
        {
            return None;
        }
        let first_nonzero = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
        Some(&bytes[first_nonzero..])
    }
}

pub(crate) fn write_prefix(out: *mut u8, out_len: usize, bytes: &[u8]) -> c_int {
    if out.is_null() || out_len < bytes.len() {
        return -1;
    }
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    out[..bytes.len()].copy_from_slice(bytes);
    0
}
