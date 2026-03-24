#![no_main]

use std::ptr;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_crypto::{
    ossh_rust_ed25519_public_from_seed, ossh_rust_ed25519_sign,
    ossh_rust_ed25519_verify,
};

const ED25519_SEED_LEN: usize = 32;
const ED25519_PUBLIC_LEN: usize = 32;
const ED25519_SECRET_LEN: usize = 64;
const ED25519_SIG_LEN: usize = 64;
const MAX_MSG_LEN: usize = 4096;

#[derive(Arbitrary, Debug)]
struct Input {
    seed: [u8; ED25519_SEED_LEN],
    msg: Vec<u8>,
    mutate_sig: bool,
    mutate_sig_index: u16,
    mutate_pk: bool,
    mutate_pk_index: u16,
    short_sig: u8,
    short_pk: u8,
}

fn slice_ptr(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    }
}

fuzz_target!(|input: Input| {
    let msg_len = input.msg.len().min(MAX_MSG_LEN);
    let msg = &input.msg[..msg_len];

    let mut public_key = [0u8; ED25519_PUBLIC_LEN];
    assert_eq!(
        ossh_rust_ed25519_public_from_seed(
            input.seed.as_ptr(),
            input.seed.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
        ),
        0
    );

    let mut secret_key = [0u8; ED25519_SECRET_LEN];
    secret_key[..ED25519_SEED_LEN].copy_from_slice(&input.seed);
    secret_key[ED25519_SEED_LEN..].copy_from_slice(&public_key);

    let mut signature = [0u8; ED25519_SIG_LEN];
    assert_eq!(
        ossh_rust_ed25519_sign(
            signature.as_mut_ptr(),
            signature.len(),
            slice_ptr(msg),
            msg.len(),
            secret_key.as_ptr(),
            secret_key.len(),
        ),
        0
    );

    let mut sig_buf = signature.to_vec();
    let mut pk_buf = public_key.to_vec();
    if input.mutate_sig {
        let idx = usize::from(input.mutate_sig_index) % sig_buf.len();
        sig_buf[idx] ^= 0x80;
    }
    if input.mutate_pk {
        let idx = usize::from(input.mutate_pk_index) % pk_buf.len();
        pk_buf[idx] ^= 0x80;
    }

    let sig_len = if input.short_sig == 0 {
        sig_buf.len()
    } else {
        usize::from(input.short_sig) % sig_buf.len()
    };
    let pk_len = if input.short_pk == 0 {
        pk_buf.len()
    } else {
        usize::from(input.short_pk) % pk_buf.len()
    };

    let rc = ossh_rust_ed25519_verify(
        slice_ptr(&sig_buf[..sig_len]),
        sig_len,
        slice_ptr(msg),
        msg.len(),
        slice_ptr(&pk_buf[..pk_len]),
        pk_len,
    );

    if sig_len == ED25519_SIG_LEN && pk_len == ED25519_PUBLIC_LEN {
        if !input.mutate_sig && !input.mutate_pk {
            assert_eq!(rc, 0);
        } else {
            assert_ne!(rc, 0);
        }
    }
});
