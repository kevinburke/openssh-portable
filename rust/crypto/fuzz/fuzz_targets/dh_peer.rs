#![no_main]

use std::ptr;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_crypto::{
    ossh_rust_dh_export_public, ossh_rust_dh_free, ossh_rust_dh_generate_key, ossh_rust_dh_group_new,
    ossh_rust_dh_public_len, ossh_rust_dh_shared_secret,
};

const OSSH_RUST_DH_GROUP14: i32 = 14;
const MAX_PEER_LEN: usize = 512;

#[derive(Arbitrary, Debug)]
struct Input {
    use_valid_peer: bool,
    mutate_peer: bool,
    mutate_peer_index: u16,
    arbitrary_peer: Vec<u8>,
    short_peer: u16,
    need_bits: u16,
}

fn slice_ptr(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    }
}

fuzz_target!(|input: Input| {
    let local = ossh_rust_dh_group_new(OSSH_RUST_DH_GROUP14);
    assert!(!local.is_null());
    let need_bits = usize::from(input.need_bits.max(1));
    assert_eq!(ossh_rust_dh_generate_key(local, need_bits), 0);

    let public_len = ossh_rust_dh_public_len(local);
    assert!(public_len > 0);

    let mut peer_public = if input.use_valid_peer {
        let peer = ossh_rust_dh_group_new(OSSH_RUST_DH_GROUP14);
        assert!(!peer.is_null());
        assert_eq!(ossh_rust_dh_generate_key(peer, need_bits), 0);
        let mut public = vec![0u8; public_len];
        assert_eq!(ossh_rust_dh_export_public(peer, public.as_mut_ptr(), public.len()), 0);
        ossh_rust_dh_free(peer);
        public
    } else {
        let mut public = input.arbitrary_peer;
        public.truncate(MAX_PEER_LEN);
        public
    };

    if input.mutate_peer && !peer_public.is_empty() {
        let idx = usize::from(input.mutate_peer_index) % peer_public.len();
        peer_public[idx] ^= 0x01;
    }

    let peer_len = if input.use_valid_peer && !input.mutate_peer && input.short_peer == 0 {
        public_len
    } else {
        usize::from(input.short_peer) % (peer_public.len().saturating_add(1))
    };
    let peer_view = &peer_public[..peer_len.min(peer_public.len())];

    let mut shared = vec![0u8; public_len];
    let rc = ossh_rust_dh_shared_secret(
        local,
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

    ossh_rust_dh_free(local);
});
