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
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef WITH_RUST_CRYPTO

#include <sys/types.h>

#include <stdio.h>
#include <signal.h>
#include <string.h>

#include "kex.h"
#include "log.h"
#include "rust-crypto.h"
#include "sshbuf.h"
#include "ssherr.h"

static int
rust_dh_group_id_from_kex_type(u_int kex_type)
{
	switch (kex_type) {
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
		return OSSH_RUST_DH_GROUP14;
	default:
		return -1;
	}
}

static void
rust_dh_cleanup(struct kex *kex)
{
	if (kex->dh != NULL) {
		ossh_rust_dh_free(kex->dh);
		kex->dh = NULL;
	}
}

int
kex_dh_keygen(struct kex *kex)
{
	int group_id;

	if ((group_id = rust_dh_group_id_from_kex_type(kex->kex_type)) == -1)
		return SSH_ERR_INVALID_ARGUMENT;
	rust_dh_cleanup(kex);
	if ((kex->dh = ossh_rust_dh_group_new(group_id)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (ossh_rust_dh_generate_key(kex->dh, kex->we_need * 8) != 0) {
		rust_dh_cleanup(kex);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	return 0;
}

int
kex_dh_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char *public_key = NULL;
	size_t public_key_len;
	int r;

	if ((r = kex_dh_keygen(kex)) != 0)
		return r;
	if ((public_key_len = ossh_rust_dh_public_len(kex->dh)) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((public_key = calloc(1, public_key_len)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (ossh_rust_dh_export_public(kex->dh, public_key, public_key_len) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_bignum2_bytes(buf, public_key, public_key_len)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;
	kex->client_pub = buf;
	buf = NULL;
	r = 0;
 out:
	freezero(public_key, public_key_len);
	if (r != 0)
		rust_dh_cleanup(kex);
	sshbuf_free(buf);
	return r;
}

static int
rust_dh_shared_secret(const struct kex *kex, const struct sshbuf *peer_blob,
    struct sshbuf **shared_secretp)
{
	struct sshbuf *shared_secret = NULL;
	u_char *shared = NULL;
	size_t shared_len;
	int r;

	*shared_secretp = NULL;
	if (kex->dh == NULL || sshbuf_len(peer_blob) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((shared_len = ossh_rust_dh_public_len(kex->dh)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((shared = calloc(1, shared_len)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (ossh_rust_dh_shared_secret(kex->dh, sshbuf_ptr(peer_blob),
	    sshbuf_len(peer_blob), shared, shared_len) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}
	if ((r = sshbuf_put_bignum2_bytes(shared_secret, shared, shared_len)) != 0)
		goto out;
	*shared_secretp = shared_secret;
	shared_secret = NULL;
	r = 0;
 out:
	freezero(shared, shared_len);
	sshbuf_free(shared_secret);
	return r;
}

int
kex_dh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	struct sshbuf *server_blob = NULL, *shared_secret = NULL;
	u_char *public_key = NULL;
	size_t public_key_len;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;
	if ((r = kex_dh_keygen(kex)) != 0)
		goto out;
	if ((public_key_len = ossh_rust_dh_public_len(kex->dh)) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((public_key = calloc(1, public_key_len)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (ossh_rust_dh_export_public(kex->dh, public_key, public_key_len) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_bignum2_bytes(server_blob, public_key,
	    public_key_len)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;
	if ((r = rust_dh_shared_secret(kex, client_blob, &shared_secret)) != 0)
		goto out;
	*server_blobp = server_blob;
	*shared_secretp = shared_secret;
	server_blob = NULL;
	shared_secret = NULL;
	r = 0;
 out:
	rust_dh_cleanup(kex);
	freezero(public_key, public_key_len);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	return r;
}

int
kex_dh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	int r;

	*shared_secretp = NULL;
	r = rust_dh_shared_secret(kex, server_blob, shared_secretp);
	rust_dh_cleanup(kex);
	return r;
}

#endif /* WITH_RUST_CRYPTO */
