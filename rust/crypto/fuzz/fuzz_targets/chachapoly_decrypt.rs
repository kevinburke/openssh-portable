#![no_main]

use std::ptr;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_crypto::{
    ossh_rust_chachapoly_crypt, ossh_rust_chachapoly_free,
    ossh_rust_chachapoly_get_length, ossh_rust_chachapoly_new,
};

const CHACHAPOLY_KEY_LEN: usize = 64;
const CHACHAPOLY_TAG_LEN: usize = 16;
const MAX_PAYLOAD_LEN: usize = 4096;

#[derive(Arbitrary, Debug)]
struct Input {
    key: [u8; CHACHAPOLY_KEY_LEN],
    seqnr: u32,
    payload: Vec<u8>,
    tamper: bool,
    tamper_index: u16,
}

fn slice_ptr(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    }
}

fuzz_target!(|input: Input| {
    let payload_len = input.payload.len().min(MAX_PAYLOAD_LEN);
    let payload = &input.payload[..payload_len];

    let ctx = ossh_rust_chachapoly_new(input.key.as_ptr(), input.key.len());
    assert!(!ctx.is_null());

    let mut packet = vec![0u8; 4 + payload.len()];
    packet[..4].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    packet[4..].copy_from_slice(payload);

    let mut enc = vec![0u8; packet.len() + CHACHAPOLY_TAG_LEN];
    assert_eq!(
        ossh_rust_chachapoly_crypt(
            ctx,
            input.seqnr,
            enc.as_mut_ptr(),
            enc.len(),
            packet.as_ptr(),
            packet.len(),
            payload.len() as u32,
            4,
            CHACHAPOLY_TAG_LEN as u32,
            1,
        ),
        0
    );

    let mut plen = 0u32;
    assert_eq!(
        ossh_rust_chachapoly_get_length(ctx, &mut plen, input.seqnr, enc.as_ptr(), 4),
        0
    );
    assert_eq!(plen, payload.len() as u32);

    if input.tamper && !enc.is_empty() {
        let idx = usize::from(input.tamper_index) % enc.len();
        enc[idx] ^= 0x40;
    }

    let mut dec = vec![0u8; enc.len()];
    let rc = ossh_rust_chachapoly_crypt(
        ctx,
        input.seqnr,
        dec.as_mut_ptr(),
        dec.len(),
        slice_ptr(&enc),
        enc.len(),
        payload.len() as u32,
        4,
        CHACHAPOLY_TAG_LEN as u32,
        0,
    );

    if input.tamper {
        assert_ne!(rc, 0);
    } else {
        assert_eq!(rc, 0);
        assert_eq!(&dec[..packet.len()], packet.as_slice());
    }

    ossh_rust_chachapoly_free(ctx);
});
