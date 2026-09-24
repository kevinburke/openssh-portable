/* $OpenBSD$ */
/*
 * Copyright (c) 2023 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <endian.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "log.h"

#include "crypto_api.h"

#ifdef WITH_RUST_CRYPTO

#include "rust-crypto.h"

/* Uncompressed SEC1 P-256 point; the shared ECDH secret is 32 bytes. */
#define NISTP256_PUBLICKEYBYTES 65

int
kex_kem_mlkem768ecdh_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	struct rust_ecdh_client_key *client_key = NULL;
	u_char *cp = NULL;
	size_t need;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (kex->ec_nid != OSSH_RUST_ECDH_NISTP256 ||
	    kex->hash_alg != SSH_DIGEST_SHA256)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((client_key = calloc(1, sizeof(*client_key))) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	client_key->curve_id = kex->ec_nid;
	client_key->secret_len = 32;
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	need = crypto_kem_mlkem768_PUBLICKEYBYTES + NISTP256_PUBLICKEYBYTES;
	if ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		goto out;
	if (ossh_rust_mlkem768nistp256_keypair(cp, need, kex->mlkem768_client_key,
	    sizeof(kex->mlkem768_client_key), client_key->secret,
	    client_key->secret_len) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	r = 0;
	kex->ec_client_key = client_key;
	kex->ec_group = NULL;
	client_key = NULL;
	kex->client_pub = buf;
	buf = NULL;
 out:
	if (client_key != NULL) {
		freezero(client_key, sizeof(*client_key));
		explicit_bzero(kex->mlkem768_client_key,
		    sizeof(kex->mlkem768_client_key));
	}
	sshbuf_free(buf);
	return r;
}

int
kex_kem_mlkem768ecdh_enc(struct kex *kex,
   const struct sshbuf *client_blob, struct sshbuf **server_blobp,
   struct sshbuf **shared_secretp)
{
	struct sshbuf *server_blob = NULL;
	struct sshbuf *shared_secret = NULL;
	u_char *server_blob_ptr = NULL;
	u_char shared_hash[SSH_DIGEST_MAX_LENGTH];
	size_t server_blob_len, shared_hash_len;
	int r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = NULL;
	*shared_secretp = NULL;
	server_blob_len = crypto_kem_mlkem768_CIPHERTEXTBYTES +
	    NISTP256_PUBLICKEYBYTES;
	shared_hash_len = ssh_digest_bytes(kex->hash_alg);
	if (kex->ec_nid != OSSH_RUST_ECDH_NISTP256 ||
	    kex->hash_alg != SSH_DIGEST_SHA256 ||
	    sshbuf_len(client_blob) != crypto_kem_mlkem768_PUBLICKEYBYTES +
	    NISTP256_PUBLICKEYBYTES ||
	    shared_hash_len != crypto_kem_mlkem768_BYTES) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	if ((server_blob = sshbuf_new()) == NULL ||
	    (shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(server_blob, server_blob_len, &server_blob_ptr)) != 0)
		goto out;
	if (ossh_rust_mlkem768nistp256_enc(sshbuf_ptr(client_blob),
	    sshbuf_len(client_blob), server_blob_ptr, server_blob_len,
	    shared_hash, shared_hash_len) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	if ((r = sshbuf_put_string(shared_secret, shared_hash, shared_hash_len)) != 0)
		goto out;
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = shared_secret;
	server_blob = NULL;
	shared_secret = NULL;
 out:
	explicit_bzero(shared_hash, sizeof(shared_hash));
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	return r;
}

int
kex_kem_mlkem768ecdh_dec(struct kex *kex,
    const struct sshbuf *server_blob, struct sshbuf **shared_secretp)
{
	struct sshbuf *shared_secret = NULL;
	struct rust_ecdh_client_key *client_key = kex->ec_client_key;
	u_char shared_hash[SSH_DIGEST_MAX_LENGTH];
	size_t shared_hash_len, server_blob_len;
	int r = SSH_ERR_INTERNAL_ERROR;

	*shared_secretp = NULL;
	server_blob_len = crypto_kem_mlkem768_CIPHERTEXTBYTES +
	    NISTP256_PUBLICKEYBYTES;
	shared_hash_len = ssh_digest_bytes(kex->hash_alg);
	if (client_key == NULL ||
	    client_key->curve_id != OSSH_RUST_ECDH_NISTP256 ||
	    client_key->secret_len != 32 ||
	    kex->hash_alg != SSH_DIGEST_SHA256 ||
	    sshbuf_len(server_blob) != server_blob_len ||
	    shared_hash_len != crypto_kem_mlkem768_BYTES) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	if ((shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (ossh_rust_mlkem768nistp256_dec(sshbuf_ptr(server_blob),
	    sshbuf_len(server_blob), kex->mlkem768_client_key,
	    sizeof(kex->mlkem768_client_key), client_key->secret,
	    client_key->secret_len, shared_hash, shared_hash_len) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	if ((r = sshbuf_put_string(shared_secret, shared_hash, shared_hash_len)) != 0)
		goto out;
	r = 0;
	*shared_secretp = shared_secret;
	shared_secret = NULL;
 out:
	if (client_key != NULL)
		freezero(client_key, sizeof(*client_key));
	kex->ec_client_key = NULL;
	kex->ec_group = NULL;
	explicit_bzero(kex->mlkem768_client_key,
	    sizeof(kex->mlkem768_client_key));
	explicit_bzero(shared_hash, sizeof(shared_hash));
	sshbuf_free(shared_secret);
	return r;
}

#endif /* WITH_RUST_CRYPTO */
