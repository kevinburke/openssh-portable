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
#include <string.h>
#include <signal.h>

#include "kex.h"
#include "log.h"
#include "rust-crypto.h"
#include "sshbuf.h"
#include "ssherr.h"

struct rust_ecdh_params {
	size_t secret_len;
	size_t public_len;
	size_t shared_len;
};

static int
rust_ecdh_params_for_curve(int curve_id, struct rust_ecdh_params *params)
{
	switch (curve_id) {
	case OSSH_RUST_ECDH_NISTP256:
		params->secret_len = 32;
		params->public_len = 65;
		params->shared_len = 32;
		return 0;
	case OSSH_RUST_ECDH_NISTP384:
		params->secret_len = 48;
		params->public_len = 97;
		params->shared_len = 48;
		return 0;
	case OSSH_RUST_ECDH_NISTP521:
		params->secret_len = 66;
		params->public_len = 133;
		params->shared_len = 66;
		return 0;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
}

int
kex_ecdh_keypair(struct kex *kex)
{
	struct rust_ecdh_client_key *client_key = NULL;
	struct rust_ecdh_params params;
	struct sshbuf *buf = NULL;
	u_char *public_key = NULL;
	int r;

	if ((r = rust_ecdh_params_for_curve(kex->ec_nid, &params)) != 0)
		goto out;
	if ((client_key = calloc(1, sizeof(*client_key))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	client_key->curve_id = kex->ec_nid;
	client_key->secret_len = params.secret_len;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(buf, params.public_len, &public_key)) != 0)
		goto out;
	if (ossh_rust_ecdh_keypair(kex->ec_nid,
	    client_key->secret, params.secret_len,
	    public_key, params.public_len) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key ecdh:", public_key, params.public_len);
#endif
	kex->ec_client_key = client_key;
	kex->ec_group = NULL;
	kex->client_pub = buf;
	client_key = NULL;
	buf = NULL;
	r = 0;
 out:
	if (client_key != NULL)
		freezero(client_key, sizeof(*client_key));
	sshbuf_free(buf);
	return r;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	struct rust_ecdh_params params;
	struct sshbuf *server_blob = NULL, *shared_secret = NULL;
	const u_char *client_pub;
	u_char *server_pub, server_secret[RUST_ECDH_MAX_SECRET_LEN];
	u_char shared[RUST_ECDH_MAX_SECRET_LEN];
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;
	explicit_bzero(server_secret, sizeof(server_secret));
	explicit_bzero(shared, sizeof(shared));

	if ((r = rust_ecdh_params_for_curve(kex->ec_nid, &params)) != 0)
		goto out;
	if (sshbuf_len(client_blob) != params.public_len) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	client_pub = sshbuf_ptr(client_blob);

	if ((server_blob = sshbuf_new()) == NULL ||
	    (shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(server_blob, params.public_len, &server_pub)) != 0)
		goto out;
	if (ossh_rust_ecdh_keypair(kex->ec_nid,
	    server_secret, params.secret_len,
	    server_pub, params.public_len) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (ossh_rust_ecdh_shared_secret(kex->ec_nid,
	    server_secret, params.secret_len,
	    client_pub, params.public_len,
	    shared, params.shared_len) != 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("server public key ecdh:", server_pub, params.public_len);
	dump_digest("shared secret ecdh:", shared, params.shared_len);
#endif
	if ((r = sshbuf_put_bignum2_bytes(shared_secret,
	    shared, params.shared_len)) != 0)
		goto out;
	*server_blobp = server_blob;
	*shared_secretp = shared_secret;
	server_blob = NULL;
	shared_secret = NULL;
	r = 0;
 out:
	explicit_bzero(server_secret, sizeof(server_secret));
	explicit_bzero(shared, sizeof(shared));
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	return r;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	struct rust_ecdh_client_key *client_key;
	struct rust_ecdh_params params;
	struct sshbuf *shared_secret = NULL;
	const u_char *server_pub;
	u_char shared[RUST_ECDH_MAX_SECRET_LEN];
	int r;

	*shared_secretp = NULL;
	explicit_bzero(shared, sizeof(shared));

	client_key = (struct rust_ecdh_client_key *)kex->ec_client_key;
	if (client_key == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((r = rust_ecdh_params_for_curve(client_key->curve_id, &params)) != 0)
		goto out;
	if (client_key->secret_len != params.secret_len ||
	    sshbuf_len(server_blob) != params.public_len) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	server_pub = sshbuf_ptr(server_blob);
	if ((shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (ossh_rust_ecdh_shared_secret(client_key->curve_id,
	    client_key->secret, client_key->secret_len,
	    server_pub, params.public_len,
	    shared, params.shared_len) != 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("server public key ecdh:", server_pub, params.public_len);
	dump_digest("shared secret ecdh:", shared, params.shared_len);
#endif
	if ((r = sshbuf_put_bignum2_bytes(shared_secret,
	    shared, params.shared_len)) != 0)
		goto out;
	*shared_secretp = shared_secret;
	shared_secret = NULL;
	r = 0;
 out:
	explicit_bzero(shared, sizeof(shared));
	freezero(kex->ec_client_key, sizeof(struct rust_ecdh_client_key));
	kex->ec_client_key = NULL;
	kex->ec_group = NULL;
	sshbuf_free(shared_secret);
	return r;
}

#endif /* WITH_RUST_CRYPTO */
