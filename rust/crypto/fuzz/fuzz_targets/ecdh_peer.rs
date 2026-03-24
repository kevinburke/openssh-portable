#![no_main]

use std::ptr;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_crypto::{ossh_rust_ecdh_keypair, ossh_rust_ecdh_shared_secret};

const OSSH_RUST_ECDH_NISTP256: i32 = 1;
const OSSH_RUST_ECDH_NISTP384: i32 = 2;
const OSSH_RUST_ECDH_NISTP521: i32 = 3;
const MAX_PUBLIC_LEN: usize = 133;

#[derive(Arbitrary, Debug)]
struct Input {
    curve_selector: u8,
    use_valid_peer: bool,
    mutate_peer: bool,
    mutate_peer_index: u16,
    arbitrary_peer: Vec<u8>,
    short_peer: u8,
}

fn curve_params(selector: u8) -> Option<(i32, usize, usize, usize)> {
    match selector % 5 {
        0 => Some((OSSH_RUST_ECDH_NISTP256, 32, 65, 32)),
        1 => Some((OSSH_RUST_ECDH_NISTP384, 48, 97, 48)),
        2 => Some((OSSH_RUST_ECDH_NISTP521, 66, 133, 66)),
        _ => None,
    }
}

fn slice_ptr(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    }
}

fuzz_target!(|input: Input| {
    let Some((curve_id, secret_len, public_len, shared_len)) =
        curve_params(input.curve_selector)
    else {
        let mut out = [0u8; 66];
        assert_eq!(
            ossh_rust_ecdh_shared_secret(
                99,
                out.as_ptr(),
                0,
                out.as_ptr(),
                0,
                out.as_mut_ptr(),
                out.len(),
            ),
            -1
        );
        return;
    };

    let mut local_secret = vec![0u8; secret_len];
    let mut local_public = vec![0u8; public_len];
    assert_eq!(
        ossh_rust_ecdh_keypair(
            curve_id,
            local_secret.as_mut_ptr(),
            local_secret.len(),
            local_public.as_mut_ptr(),
            local_public.len(),
        ),
        0
    );

    let mut peer_public = if input.use_valid_peer {
        let mut peer_secret = vec![0u8; secret_len];
        let mut peer_public = vec![0u8; public_len];
        assert_eq!(
            ossh_rust_ecdh_keypair(
                curve_id,
                peer_secret.as_mut_ptr(),
                peer_secret.len(),
                peer_public.as_mut_ptr(),
                peer_public.len(),
            ),
            0
        );
        peer_public
    } else {
        let mut peer = input.arbitrary_peer;
        peer.truncate(MAX_PUBLIC_LEN);
        peer
    };

    if input.mutate_peer && !peer_public.is_empty() {
        let idx = usize::from(input.mutate_peer_index) % peer_public.len();
        peer_public[idx] ^= 0x01;
    }

    let peer_len = if input.use_valid_peer && input.short_peer == 0 {
        public_len
    } else {
        usize::from(input.short_peer) % (peer_public.len().saturating_add(1))
    };
    let peer_view = &peer_public[..peer_len.min(peer_public.len())];

    let mut shared = vec![0u8; shared_len];
    let rc = ossh_rust_ecdh_shared_secret(
        curve_id,
        local_secret.as_ptr(),
        local_secret.len(),
        slice_ptr(peer_view),
        peer_view.len(),
        shared.as_mut_ptr(),
        shared.len(),
    );

    if input.use_valid_peer && !input.mutate_peer && peer_view.len() == public_len {
        assert_eq!(rc, 0);
    } else {
        assert!(rc == 0 || rc == -1);
    }
});
