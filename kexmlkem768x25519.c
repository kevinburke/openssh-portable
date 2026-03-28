/* $OpenBSD: kexmlkem768x25519.c,v 1.3 2026/06/14 03:59:34 djm Exp $ */
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

int
kex_kem_mlkem768x25519_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char *cp = NULL;
	size_t need;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_mlkem768_PUBLICKEYBYTES + CURVE25519_SIZE;
	if ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		goto out;
	if (ossh_rust_mlkem768x25519_keypair(cp, need, kex->mlkem768_client_key,
	    sizeof(kex->mlkem768_client_key), kex->c25519_client_key,
	    sizeof(kex->c25519_client_key)) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    crypto_kem_mlkem768_PUBLICKEYBYTES);
	dump_digest("client public key c25519:",
	    cp + crypto_kem_mlkem768_PUBLICKEYBYTES, CURVE25519_SIZE);
#endif
	r = 0;
	kex->client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	return r;
}

int
kex_kem_mlkem768x25519_enc(struct kex *kex,
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
	server_blob_len = crypto_kem_mlkem768_CIPHERTEXTBYTES + CURVE25519_SIZE;
	shared_hash_len = ssh_digest_bytes(kex->hash_alg);
	if (sshbuf_len(client_blob) != crypto_kem_mlkem768_PUBLICKEYBYTES +
	    CURVE25519_SIZE || shared_hash_len != crypto_kem_mlkem768_BYTES) {
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
	if (ossh_rust_mlkem768x25519_enc(sshbuf_ptr(client_blob),
	    sshbuf_len(client_blob), server_blob_ptr, server_blob_len,
	    shared_hash, shared_hash_len) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	if ((r = sshbuf_put_string(shared_secret, shared_hash, shared_hash_len)) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", server_blob_ptr,
	    crypto_kem_mlkem768_CIPHERTEXTBYTES);
	dump_digest("server public key 25519:",
	    server_blob_ptr + crypto_kem_mlkem768_CIPHERTEXTBYTES,
	    CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(shared_secret),
	    sshbuf_len(shared_secret));
#endif
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
kex_kem_mlkem768x25519_dec(struct kex *kex,
    const struct sshbuf *server_blob, struct sshbuf **shared_secretp)
{
	struct sshbuf *shared_secret = NULL;
	u_char shared_hash[SSH_DIGEST_MAX_LENGTH];
	size_t shared_hash_len, server_blob_len;
	int r = SSH_ERR_INTERNAL_ERROR;

	*shared_secretp = NULL;
	server_blob_len = crypto_kem_mlkem768_CIPHERTEXTBYTES + CURVE25519_SIZE;
	shared_hash_len = ssh_digest_bytes(kex->hash_alg);
	if (sshbuf_len(server_blob) != server_blob_len ||
	    shared_hash_len != crypto_kem_mlkem768_BYTES) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	if ((shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (ossh_rust_mlkem768x25519_dec(sshbuf_ptr(server_blob),
	    sshbuf_len(server_blob), kex->mlkem768_client_key,
	    sizeof(kex->mlkem768_client_key), kex->c25519_client_key,
	    sizeof(kex->c25519_client_key), shared_hash, shared_hash_len) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	if ((r = sshbuf_put_string(shared_secret, shared_hash, shared_hash_len)) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", sshbuf_ptr(server_blob),
	    crypto_kem_mlkem768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:",
	    (const u_char *)sshbuf_ptr(server_blob) +
	    crypto_kem_mlkem768_CIPHERTEXTBYTES, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(shared_secret),
	    sshbuf_len(shared_secret));
#endif
	r = 0;
	*shared_secretp = shared_secret;
	shared_secret = NULL;
 out:
	explicit_bzero(shared_hash, sizeof(shared_hash));
	sshbuf_free(shared_secret);
	return r;
}

#elif defined(USE_MLKEM768X25519)

int
kex_kem_mlkem768x25519_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char *cp = NULL;
	size_t need;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	if ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		goto out;
	if (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_key) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	cp += MLKEM768_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_key, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	return r;
}

int
kex_kem_mlkem768x25519_enc(struct kex *kex,
   const struct sshbuf *client_blob, struct sshbuf **server_blobp,
   struct sshbuf **shared_secretp)
{
	struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	const u_char *client_pub;
	u_char server_pub[CURVE25519_SIZE], server_key[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	int r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	if (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + MLKEM768_PUBLICKEYBYTES,
	    CURVE25519_SIZE);
#endif

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* generate and encrypt KEM key with client key */
	if (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* generate ECDH key pair, store server pubkey after ciphertext */
	kexc25519_keygen(server_key, server_pub);
	if ((r = sshbuf_put(buf, shared_secret, sizeof(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, sizeof(ct))) != 0 ||
	    (r = sshbuf_put(server_blob, server_pub, sizeof(server_pub))) != 0)
		goto out;
	/* append ECDH shared key */
	client_pub += MLKEM768_PUBLICKEYBYTES;
	if ((r = kexc25519_shared_key_ext(server_key, client_pub, buf, 1)) < 0)
		goto out;
	if ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, sizeof(hash))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ct, sizeof(ct));
	dump_digest("server kem key:", shared_secret, sizeof(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	if ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = NULL;
	buf = NULL;
 out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(server_key, sizeof(server_key));
	explicit_bzero(shared_secret, sizeof(shared_secret));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	return r;
}

int
kex_kem_mlkem768x25519_dec(struct kex *kex,
    const struct sshbuf *server_blob, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	u_char shared_secret[MLKEM768_BYTES];
	const u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	int r;

	*shared_secretp = NULL;

	need = MLKEM768_CIPHERTEXTBYTES + CURVE25519_SIZE;
	if (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	if (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_key) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((r = sshbuf_put(buf, shared_secret, sizeof(shared_secret))) != 0)
		goto out;
	if ((r = kexc25519_shared_key_ext(kex->c25519_client_key, server_pub,
	    buf, 1)) < 0)
		goto out;
	if ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, sizeof(hash))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, sizeof(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	if ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = NULL;
 out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(shared_secret, sizeof(shared_secret));
	sshbuf_free(buf);
	return r;
}
#else /* !WITH_RUST_CRYPTO && !USE_MLKEM768X25519 */
int
kex_kem_mlkem768x25519_keypair(struct kex *kex)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_kem_mlkem768x25519_enc(struct kex *kex,
   const struct sshbuf *client_blob, struct sshbuf **server_blobp,
   struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_kem_mlkem768x25519_dec(struct kex *kex,
    const struct sshbuf *server_blob, struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* WITH_RUST_CRYPTO || USE_MLKEM768X25519 */
