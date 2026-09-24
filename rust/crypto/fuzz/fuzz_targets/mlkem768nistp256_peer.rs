#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_crypto::{
    ossh_rust_mlkem768nistp256_dec, ossh_rust_mlkem768nistp256_enc,
    ossh_rust_mlkem768nistp256_keypair,
};

fuzz_target!(|data: &[u8]| {
    let mut client = [0u8; 1249];
    let mut secret = [0u8; 2400];
    let mut scalar = [0u8; 32];
    let mut server = [0u8; 1153];
    let mut shared = [0u8; 32];
    assert_eq!(
        ossh_rust_mlkem768nistp256_keypair(
            client.as_mut_ptr(),
            client.len(),
            secret.as_mut_ptr(),
            secret.len(),
            scalar.as_mut_ptr(),
            scalar.len(),
        ),
        0
    );
    assert_eq!(
        ossh_rust_mlkem768nistp256_enc(
            client.as_ptr(),
            client.len(),
            server.as_mut_ptr(),
            server.len(),
            shared.as_mut_ptr(),
            shared.len(),
        ),
        0
    );
    let mut recovered = [0u8; 32];
    assert_eq!(
        ossh_rust_mlkem768nistp256_dec(
            server.as_ptr(),
            server.len(),
            secret.as_ptr(),
            secret.len(),
            scalar.as_ptr(),
            scalar.len(),
            recovered.as_mut_ptr(),
            recovered.len(),
        ),
        0
    );
    assert_eq!(shared, recovered);

    // Mutate both the KEM and SEC1 point, and vary the wire length.
    let selector = data.first().copied().unwrap_or(0);
    let payload = data.get(1..).unwrap_or(&[]);
    if selector & 1 == 0 {
        for (out, input) in client.iter_mut().rev().zip(payload) {
            *out ^= input;
        }
        let len = if selector & 2 == 0 {
            client.len()
        } else {
            payload.len().min(client.len())
        };
        let rc = ossh_rust_mlkem768nistp256_enc(
            client.as_ptr(),
            len,
            server.as_mut_ptr(),
            server.len(),
            shared.as_mut_ptr(),
            shared.len(),
        );
        assert!(rc == 0 || rc == -1);
    } else {
        for (out, input) in server.iter_mut().rev().zip(payload) {
            *out ^= input;
        }
        let len = if selector & 2 == 0 {
            server.len()
        } else {
            payload.len().min(server.len())
        };
        let rc = ossh_rust_mlkem768nistp256_dec(
            server.as_ptr(),
            len,
            secret.as_ptr(),
            secret.len(),
            scalar.as_ptr(),
            scalar.len(),
            recovered.as_mut_ptr(),
            recovered.len(),
        );
        assert!(rc == 0 || rc == -1);
    }
});
