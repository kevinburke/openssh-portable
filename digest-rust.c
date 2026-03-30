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
#include <stdlib.h>
#include <string.h>

#include "ssherr.h"
#include "sshbuf.h"
#include "digest.h"
#include "rust-crypto.h"

typedef void md_init_fn(void *mdctx);
typedef void md_update_fn(void *mdctx, const uint8_t *m, size_t mlen);
typedef void md_final_fn(uint8_t[], void *mdctx);

enum ssh_digest_backend {
	SSH_DIGEST_BACKEND_LIBC = 0,
	SSH_DIGEST_BACKEND_RUST
};

struct ssh_digest_ctx {
	int alg;
	enum ssh_digest_backend backend;
	union {
		MD5_CTX md5;
		SHA1_CTX sha1;
		void *rust;
	} state;
};

struct ssh_digest {
	int id;
	const char *name;
	size_t block_len;
	size_t digest_len;
	enum ssh_digest_backend backend;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
static const struct ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		SSH_DIGEST_BACKEND_RUST,
		0,
		NULL,
		NULL,
		NULL
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		SSH_DIGEST_BACKEND_RUST,
		0,
		NULL,
		NULL,
		NULL
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		SSH_DIGEST_BACKEND_RUST,
		0,
		NULL,
		NULL,
		NULL
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		SSH_DIGEST_BACKEND_RUST,
		0,
		NULL,
		NULL,
		NULL
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		SSH_DIGEST_BACKEND_RUST,
		0,
		NULL,
		NULL,
		NULL
	}
};

static const struct ssh_digest *
ssh_digest_by_alg(int alg)
{
	if (alg < 0 || alg >= SSH_DIGEST_MAX)
		return NULL;
	if (digests[alg].id != alg)
		return NULL;
	return &digests[alg];
}

int
ssh_digest_alg_by_name(const char *name)
{
	int alg;

	for (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		if (strcasecmp(name, digests[alg].name) == 0)
			return digests[alg].id;
	}
	return -1;
}

const char *
ssh_digest_alg_name(int alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	return digest == NULL ? NULL : digest->name;
}

size_t
ssh_digest_bytes(int alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	return digest == NULL ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(struct ssh_digest_ctx *ctx)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	return digest == NULL ? 0 : digest->block_len;
}

struct ssh_digest_ctx *
ssh_digest_start(int alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	struct ssh_digest_ctx *ret;

	if (digest == NULL || (ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	ret->alg = alg;
	ret->backend = digest->backend;
	switch (digest->backend) {
	case SSH_DIGEST_BACKEND_LIBC:
		digest->md_init(&ret->state);
		return ret;
	case SSH_DIGEST_BACKEND_RUST:
		if ((ret->state.rust = ossh_rust_digest_start(alg)) == NULL) {
			free(ret);
			return NULL;
		}
		return ret;
	}
	free(ret);
	return NULL;
}

int
ssh_digest_copy_state(struct ssh_digest_ctx *from, struct ssh_digest_ctx *to)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(from->alg);
	void *copy;

	if (digest == NULL || from->alg != to->alg ||
	    from->backend != to->backend)
		return SSH_ERR_INVALID_ARGUMENT;
	switch (digest->backend) {
	case SSH_DIGEST_BACKEND_LIBC:
		memcpy(&to->state, &from->state, digest->ctx_len);
		return 0;
	case SSH_DIGEST_BACKEND_RUST:
		if ((copy = ossh_rust_digest_copy(from->state.rust)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		ossh_rust_digest_free(to->state.rust);
		to->state.rust = copy;
		return 0;
	}
	return SSH_ERR_INTERNAL_ERROR;
}

int
ssh_digest_update(struct ssh_digest_ctx *ctx, const void *m, size_t mlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	if (digest == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	switch (digest->backend) {
	case SSH_DIGEST_BACKEND_LIBC:
		digest->md_update(&ctx->state, m, mlen);
		return 0;
	case SSH_DIGEST_BACKEND_RUST:
		return ossh_rust_digest_update(ctx->state.rust, m, mlen) == 0 ?
		    0 : SSH_ERR_INTERNAL_ERROR;
	}
	return SSH_ERR_INTERNAL_ERROR;
}

int
ssh_digest_update_buffer(struct ssh_digest_ctx *ctx, const struct sshbuf *b)
{
	return ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

int
ssh_digest_final(struct ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	if (digest == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (dlen > UINT_MAX)
		return SSH_ERR_INVALID_ARGUMENT;
	if (dlen < digest->digest_len)
		return SSH_ERR_INVALID_ARGUMENT;
	switch (digest->backend) {
	case SSH_DIGEST_BACKEND_LIBC:
		digest->md_final(d, &ctx->state);
		return 0;
	case SSH_DIGEST_BACKEND_RUST:
		return ossh_rust_digest_final(ctx->state.rust, d, dlen) == 0 ?
		    0 : SSH_ERR_INTERNAL_ERROR;
	}
	return SSH_ERR_INTERNAL_ERROR;
}

void
ssh_digest_free(struct ssh_digest_ctx *ctx)
{
	if (ctx == NULL)
		return;
	if (ctx->backend == SSH_DIGEST_BACKEND_RUST)
		ossh_rust_digest_free(ctx->state.rust);
	freezero(ctx, sizeof(*ctx));
}

int
ssh_digest_memory(int alg, const void *m, size_t mlen, u_char *d, size_t dlen)
{
	struct ssh_digest_ctx *ctx = ssh_digest_start(alg);
	int ret = 0;

	if (ctx == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	return ret;
}

int
ssh_digest_buffer(int alg, const struct sshbuf *b, u_char *d, size_t dlen)
{
	return ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}

#endif /* WITH_RUST_CRYPTO */
