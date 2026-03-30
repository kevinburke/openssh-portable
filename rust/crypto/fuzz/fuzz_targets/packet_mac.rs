#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_crypto::{
    ossh_rust_mac_check, ossh_rust_mac_compute, ossh_rust_mac_free, ossh_rust_mac_init,
    ossh_rust_mac_start,
};

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    alg_index: u8,
    truncated: bool,
    seqno: u32,
    key: Vec<u8>,
    data: Vec<u8>,
    flip_first_byte: bool,
}

fn alg_from_index(index: u8) -> i32 {
    match index % 5 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        _ => 4,
    }
}

fuzz_target!(|input: Input| {
    let alg = alg_from_index(input.alg_index);
    let truncate_bits = if input.truncated { 96 } else { 0 };
    let ctx = ossh_rust_mac_start(alg, truncate_bits);
    if ctx.is_null() {
        return;
    }

    let key = if input.key.is_empty() { &[0u8][..] } else { &input.key[..] };
    if ossh_rust_mac_init(ctx, key.as_ptr(), key.len()) != 0 {
        ossh_rust_mac_free(ctx);
        return;
    }

    let mut out = [0u8; 64];
    if ossh_rust_mac_compute(
        ctx,
        input.seqno,
        input.data.as_ptr(),
        input.data.len(),
        out.as_mut_ptr(),
        out.len(),
    ) != 0
    {
        ossh_rust_mac_free(ctx);
        return;
    }

    let mac_len = if truncate_bits == 0 {
        match alg {
            0 => 16,
            1 => 20,
            2 => 32,
            3 => 48,
            _ => 64,
        }
    } else {
        12
    };

    let mut their_mac = out[..mac_len].to_vec();
    let expected = if input.flip_first_byte && !their_mac.is_empty() {
        their_mac[0] ^= 1;
        1
    } else {
        0
    };

    let rc = ossh_rust_mac_check(
        ctx,
        input.seqno,
        input.data.as_ptr(),
        input.data.len(),
        their_mac.as_ptr(),
        their_mac.len(),
    );
    assert_eq!(rc, expected);
    ossh_rust_mac_free(ctx);
});
