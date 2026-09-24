/* $OpenBSD$ */
/*
 * Copyright (c) 2026 The OpenSSH contributors
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA, OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef WITH_RUST_CRYPTO

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "crypto_api.h"
#include "rust-crypto.h"

int
crypto_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk)
{
	unsigned char seed[crypto_sign_ed25519_SEEDBYTES];
	int r;

	arc4random_buf(seed, sizeof(seed));
	r = crypto_sign_ed25519_seed_keypair(pk, sk, seed);
	explicit_bzero(seed, sizeof(seed));
	return r;
}

int
crypto_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
    const unsigned char *seed)
{
	memcpy(sk, seed, crypto_sign_ed25519_SEEDBYTES);
	if (ossh_rust_ed25519_public_from_seed(seed,
	    crypto_sign_ed25519_SEEDBYTES, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES) != 0) {
		explicit_bzero(sk, crypto_sign_ed25519_SECRETKEYBYTES);
		return -1;
	}
	memcpy(sk + crypto_sign_ed25519_SEEDBYTES, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);
	return 0;
}

int
crypto_sign_ed25519_detached(unsigned char *sig, unsigned long long *siglenp,
    const unsigned char *m, unsigned long long mlen, const unsigned char *sk)
{
	if (mlen > SIZE_MAX)
		return -1;
	if (ossh_rust_ed25519_sign(sig, crypto_sign_ed25519_BYTES, m,
	    (size_t)mlen, sk, crypto_sign_ed25519_SECRETKEYBYTES) != 0)
		return -1;
	if (siglenp != NULL)
		*siglenp = crypto_sign_ed25519_BYTES;
	return 0;
}

int
crypto_sign_ed25519_verify_detached(const unsigned char *sig,
    const unsigned char *m, unsigned long long mlen, const unsigned char *pk)
{
	if (mlen > SIZE_MAX)
		return -1;
	return ossh_rust_ed25519_verify(sig, crypto_sign_ed25519_BYTES,
	    m, (size_t)mlen, pk, crypto_sign_ed25519_PUBLICKEYBYTES);
}

#endif /* WITH_RUST_CRYPTO */
