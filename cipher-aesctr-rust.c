/* $OpenBSD$ */
/*
 * Copyright (c) 2026 Kevin Burke
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef WITH_RUST_CRYPTO

#include <sys/types.h>

#include <string.h>

#include "cipher-aesctr.h"
#include "log.h"
#include "rust-crypto.h"

void
aesctr_keysetup(aesctr_ctx *x, const u8 *k, u32 kbits, u32 ivbits)
{
	static const u8 zero_iv[AES_BLOCK_SIZE];
	size_t key_len = kbits / 8;

	(void)ivbits;
	memset(x, 0, sizeof(*x));
	x->state = ossh_rust_aesctr_init(k, key_len, zero_iv, sizeof(zero_iv));
	if (x->state == NULL)
		fatal_f("Rust AES-CTR initialization failed");
	memcpy(x->ctr, zero_iv, sizeof(x->ctr));
}

void
aesctr_ivsetup(aesctr_ctx *x, const u8 *iv)
{
	if (ossh_rust_aesctr_set_iv(x->state, iv, AES_BLOCK_SIZE) != 0)
		fatal_f("Rust AES-CTR IV setup failed");
	memcpy(x->ctr, iv, AES_BLOCK_SIZE);
}

void
aesctr_encrypt_bytes(aesctr_ctx *x, const u8 *m, u8 *c, u32 bytes)
{
	if (ossh_rust_aesctr_crypt(x->state, m, c, bytes) != 0)
		fatal_f("Rust AES-CTR encrypt failed");
	if (ossh_rust_aesctr_get_iv(x->state, x->ctr, AES_BLOCK_SIZE) != 0)
		fatal_f("Rust AES-CTR IV readback failed");
}

void
aesctr_free(aesctr_ctx *x)
{
	if (x == NULL)
		return;
	ossh_rust_aesctr_free(x->state);
	explicit_bzero(x, sizeof(*x));
}

#endif /* WITH_RUST_CRYPTO */
