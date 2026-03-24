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

#include <stdlib.h>
#include <string.h>

#include "digest.h"
#include "rust-crypto.h"
#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

static size_t
rust_ecdsa_scalar_len(int nid)
{
	switch (nid) {
	case NID_X9_62_prime256v1:
		return 32;
	case NID_secp384r1:
		return 48;
	case NID_secp521r1:
		return 66;
	default:
		return 0;
	}
}

static size_t
rust_ecdsa_public_len(int nid)
{
	size_t scalar_len = rust_ecdsa_scalar_len(nid);

	return scalar_len == 0 ? 0 : 1 + 2 * scalar_len;
}

static size_t
rust_ecdsa_signature_len(int nid)
{
	size_t scalar_len = rust_ecdsa_scalar_len(nid);

	return scalar_len == 0 ? 0 : 2 * scalar_len;
}

static int
rust_ecdsa_export_public_bytes(const struct sshkey *key, u_char *public_key,
    size_t public_key_len)
{
	if (key->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (ossh_rust_ecdsa_export_public(key->pkey,
	    public_key, public_key_len) != 0)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

static int
rust_ecdsa_export_private_bytes(const struct sshkey *key, u_char *private_key,
    size_t private_key_len)
{
	if (key->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (ossh_rust_ecdsa_export_private(key->pkey,
	    private_key, private_key_len) != 0)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

static int
rust_ecdsa_digest(int nid, const u_char *data, size_t datalen, u_char *digest,
    size_t digest_len)
{
	int hash_alg;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(nid)) == -1)
		return SSH_ERR_INTERNAL_ERROR;
	return ssh_digest_memory(hash_alg, data, datalen, digest, digest_len);
}

static int
rust_ecdsa_sig_from_sshbuf(struct sshbuf *sigbuf, int nid, u_char *sig,
    size_t siglen)
{
	const u_char *r_ptr, *s_ptr;
	size_t r_len, s_len, scalar_len;
	int ret;

	if ((scalar_len = rust_ecdsa_scalar_len(nid)) == 0 ||
	    siglen != rust_ecdsa_signature_len(nid))
		return SSH_ERR_INVALID_ARGUMENT;
	memset(sig, 0, siglen);
	if ((ret = sshbuf_get_bignum2_bytes_direct(sigbuf, &r_ptr, &r_len)) != 0 ||
	    (ret = sshbuf_get_bignum2_bytes_direct(sigbuf, &s_ptr, &s_len)) != 0)
		return SSH_ERR_INVALID_FORMAT;
	if (r_len > scalar_len || s_len > scalar_len)
		return SSH_ERR_INVALID_FORMAT;
	memcpy(sig + (scalar_len - r_len), r_ptr, r_len);
	memcpy(sig + scalar_len + (scalar_len - s_len), s_ptr, s_len);
	if (sshbuf_len(sigbuf) != 0)
		return SSH_ERR_UNEXPECTED_TRAILING_DATA;
	return 0;
}

static int
rust_ecdsa_encode_store_sig_bytes(const struct sshkey *key, const u_char *sig,
    size_t siglen, u_char **sigp, size_t *lenp)
{
	struct sshbuf *b = NULL, *bb = NULL;
	size_t scalar_len, len;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;
	if ((scalar_len = rust_ecdsa_scalar_len(key->ecdsa_nid)) == 0 ||
	    siglen != rust_ecdsa_signature_len(key->ecdsa_nid))
		return SSH_ERR_INVALID_ARGUMENT;
	if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_bignum2_bytes(bb, sig, scalar_len)) != 0 ||
	    (ret = sshbuf_put_bignum2_bytes(bb, sig + scalar_len,
	    scalar_len)) != 0 ||
	    (ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(bb);
	sshbuf_free(b);
	return ret;
}

static u_int
ssh_ecdsa_size(const struct sshkey *key)
{
	return sshkey_curve_nid_to_bits(key->ecdsa_nid);
}

static void
ssh_ecdsa_cleanup(struct sshkey *k)
{
	ossh_rust_ecdsa_free(k->pkey);
	k->pkey = NULL;
}

static int
ssh_ecdsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a->pkey == NULL || b->pkey == NULL)
		return 0;
	return ossh_rust_ecdsa_equal_public(a->pkey, b->pkey) == 1;
}

static int
ssh_ecdsa_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	u_char public_key[133];
	size_t public_key_len;
	int r;

	if ((public_key_len = rust_ecdsa_public_len(key->ecdsa_nid)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = rust_ecdsa_export_public_bytes(key,
	    public_key, public_key_len)) != 0)
		goto out;
	if ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(key->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_string(b, public_key, public_key_len)) != 0)
		goto out;
	r = 0;
 out:
	explicit_bzero(public_key, sizeof(public_key));
	return r;
}

static int
ssh_ecdsa_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	u_char private_key[66];
	size_t private_key_len;
	int r;

	if (!sshkey_is_cert(key)) {
		if ((r = ssh_ecdsa_serialize_public(key, b, opts)) != 0)
			return r;
	}
	if ((private_key_len = rust_ecdsa_scalar_len(key->ecdsa_nid)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = rust_ecdsa_export_private_bytes(key,
	    private_key, private_key_len)) != 0)
		goto out;
	r = sshbuf_put_bignum2_bytes(b, private_key, private_key_len);
 out:
	explicit_bzero(private_key, sizeof(private_key));
	return r;
}

static int
ssh_ecdsa_generate(struct sshkey *k, int bits)
{
	if ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		return SSH_ERR_KEY_LENGTH;
	ossh_rust_ecdsa_free(k->pkey);
	if ((k->pkey = ossh_rust_ecdsa_generate(k->ecdsa_nid)) == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

static int
ssh_ecdsa_copy_public(const struct sshkey *from, struct sshkey *to)
{
	to->ecdsa_nid = from->ecdsa_nid;
	ossh_rust_ecdsa_free(to->pkey);
	if ((to->pkey = ossh_rust_ecdsa_copy_public(from->pkey)) == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

static int
ssh_ecdsa_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	const u_char *public_key;
	size_t public_key_len;
	char *curve = NULL;
	void *rust_key = NULL;
	int r;

	if ((key->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshbuf_get_cstring(b, &curve, NULL)) != 0)
		goto out;
	if (key->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		goto out;
	}
	if ((r = sshbuf_get_string_direct(b, &public_key, &public_key_len)) != 0)
		goto out;
	if ((rust_key = ossh_rust_ecdsa_from_public(key->ecdsa_nid,
	    public_key, public_key_len)) == NULL) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}
	ossh_rust_ecdsa_free(key->pkey);
	key->pkey = rust_key;
	rust_key = NULL;
	r = 0;
 out:
	ossh_rust_ecdsa_free(rust_key);
	free(curve);
	return r;
}

static int
ssh_ecdsa_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	const u_char *exponent;
	u_char public_key[133], private_key[66];
	size_t exponent_len, public_key_len, private_key_len;
	void *rust_key = NULL;
	int r;

	if (!sshkey_is_cert(key)) {
		if ((r = ssh_ecdsa_deserialize_public(ktype, b, key)) != 0)
			return r;
	}
	if ((private_key_len = rust_ecdsa_scalar_len(key->ecdsa_nid)) == 0 ||
	    (public_key_len = rust_ecdsa_public_len(key->ecdsa_nid)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshbuf_get_bignum2_bytes_direct(b, &exponent, &exponent_len)) != 0)
		return SSH_ERR_INVALID_FORMAT;
	if (exponent_len > private_key_len)
		return SSH_ERR_INVALID_FORMAT;
	memset(private_key, 0, sizeof(private_key));
	memcpy(private_key + (private_key_len - exponent_len), exponent, exponent_len);
	if ((r = rust_ecdsa_export_public_bytes(key,
	    public_key, public_key_len)) != 0)
		goto out;
	if ((rust_key = ossh_rust_ecdsa_from_private(key->ecdsa_nid,
	    public_key, public_key_len, private_key, private_key_len)) == NULL) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ossh_rust_ecdsa_free(key->pkey);
	key->pkey = rust_key;
	rust_key = NULL;
	r = 0;
 out:
	explicit_bzero(public_key, sizeof(public_key));
	explicit_bzero(private_key, sizeof(private_key));
	ossh_rust_ecdsa_free(rust_key);
	return r;
}

static int
ssh_ecdsa_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t dlen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	u_char digest[64], sig[132];
	size_t digest_len, sig_len;
	int r;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;
	if (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((digest_len = ssh_digest_bytes(
	    sshkey_ec_nid_to_hash_alg(key->ecdsa_nid))) == 0 ||
	    (sig_len = rust_ecdsa_signature_len(key->ecdsa_nid)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((r = rust_ecdsa_digest(key->ecdsa_nid, data, dlen,
	    digest, digest_len)) != 0)
		goto out;
	if (ossh_rust_ecdsa_sign_prehashed(key->pkey, digest, digest_len,
	    sig, sig_len) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	r = rust_ecdsa_encode_store_sig_bytes(key, sig, sig_len, sigp, lenp);
 out:
	explicit_bzero(digest, sizeof(digest));
	explicit_bzero(sig, sizeof(sig));
	return r;
}

static int
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	struct sshbuf *b = NULL, *sigbuf = NULL;
	u_char digest[64], raw_sig[132];
	size_t digest_len, raw_sig_len;
	char *ktype = NULL;
	int r, valid;

	if (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((digest_len = ssh_digest_bytes(
	    sshkey_ec_nid_to_hash_alg(key->ecdsa_nid))) == 0 ||
	    (raw_sig_len = rust_ecdsa_signature_len(key->ecdsa_nid)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if ((r = rust_ecdsa_sig_from_sshbuf(sigbuf, key->ecdsa_nid,
	    raw_sig, raw_sig_len)) != 0)
		goto out;
	if ((r = rust_ecdsa_digest(key->ecdsa_nid, data, dlen,
	    digest, digest_len)) != 0)
		goto out;
	valid = ossh_rust_ecdsa_verify_prehashed(key->pkey,
	    digest, digest_len, raw_sig, raw_sig_len);
	if (valid == 0)
		r = 0;
	else if (valid == 1)
		r = SSH_ERR_SIGNATURE_INVALID;
	else
		r = SSH_ERR_LIBCRYPTO_ERROR;
 out:
	explicit_bzero(digest, sizeof(digest));
	explicit_bzero(raw_sig, sizeof(raw_sig));
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	free(ktype);
	return r;
}

const struct sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .serialize_public = */ ssh_ecdsa_serialize_public,
	/* .deserialize_public = */ ssh_ecdsa_deserialize_public,
	/* .serialize_private = */ ssh_ecdsa_serialize_private,
	/* .deserialize_private = */ ssh_ecdsa_deserialize_private,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_public,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

const struct sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_RUST_CRYPTO */
