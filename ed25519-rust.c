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

#include <limits.h>
#include <string.h>

#include "crypto_api.h"
#include "rust-crypto.h"

int
crypto_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk)
{
	arc4random_buf(sk, crypto_sign_ed25519_PUBLICKEYBYTES);
	if (ossh_rust_ed25519_public_from_seed(sk,
	    crypto_sign_ed25519_PUBLICKEYBYTES, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES) != 0)
		return -1;
	memcpy(sk + crypto_sign_ed25519_PUBLICKEYBYTES, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES);
	return 0;
}

int
crypto_sign_ed25519(unsigned char *sm, unsigned long long *smlen,
    const unsigned char *m, unsigned long long mlen, const unsigned char *sk)
{
	if (mlen > ULLONG_MAX - crypto_sign_ed25519_BYTES)
		return -1;
	if (ossh_rust_ed25519_sign(sm, crypto_sign_ed25519_BYTES, m, mlen,
	    sk, crypto_sign_ed25519_SECRETKEYBYTES) != 0)
		return -1;
	memmove(sm + crypto_sign_ed25519_BYTES, m, mlen);
	*smlen = mlen + crypto_sign_ed25519_BYTES;
	return 0;
}

int
crypto_sign_ed25519_open(unsigned char *m, unsigned long long *mlen,
    const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
	unsigned long long msglen;
	unsigned long long outlen = 0;

	if (smlen < crypto_sign_ed25519_BYTES)
		goto badsig;
	msglen = smlen - crypto_sign_ed25519_BYTES;
	outlen = *mlen;
	if (outlen < msglen)
		goto badsig;
	if (ossh_rust_ed25519_verify(sm, crypto_sign_ed25519_BYTES,
	    sm + crypto_sign_ed25519_BYTES, msglen, pk,
	    crypto_sign_ed25519_PUBLICKEYBYTES) != 0)
		goto badsig;

	memmove(m, sm + crypto_sign_ed25519_BYTES, msglen);
	*mlen = msglen;
	return 0;

badsig:
	*mlen = (unsigned long long)-1;
	if (m != NULL)
		memset(m, 0, outlen);
	return -1;
}

#endif /* WITH_RUST_CRYPTO */
