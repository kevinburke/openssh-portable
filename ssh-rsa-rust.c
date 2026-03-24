/* $OpenBSD$ */

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
rust_rsa_component_len(const struct sshkey *key, int component)
{
	if (key == NULL || key->pkey == NULL)
		return 0;
	return ossh_rust_rsa_component_len(key->pkey, component);
}

static int
rust_rsa_export_component_bytes(const struct sshkey *key, int component,
    u_char **bufp, size_t *lenp)
{
	u_char *buf = NULL;
	size_t len;

	if (bufp != NULL)
		*bufp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if ((len = rust_rsa_component_len(key, component)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((buf = calloc(1, len)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (ossh_rust_rsa_export_component(key->pkey, component, buf, len) != 0) {
		freezero(buf, len);
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (bufp != NULL)
		*bufp = buf;
	else
		freezero(buf, len);
	if (lenp != NULL)
		*lenp = len;
	return 0;
}

static u_int
ssh_rsa_size(const struct sshkey *k)
{
	if (k == NULL || k->pkey == NULL)
		return 0;
	return ossh_rust_rsa_bits(k->pkey);
}

static void
ssh_rsa_cleanup(struct sshkey *k)
{
	ossh_rust_rsa_free(k->pkey);
	k->pkey = NULL;
}

static int
ssh_rsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a == NULL || b == NULL || a->pkey == NULL || b->pkey == NULL)
		return 0;
	return ossh_rust_rsa_equal_public(a->pkey, b->pkey) == 1;
}

static int
ssh_rsa_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	u_char *rsa_n = NULL, *rsa_e = NULL;
	size_t rsa_n_len = 0, rsa_e_len = 0;
	int r;

	if ((r = rust_rsa_export_component_bytes(key, OSSH_RUST_RSA_COMPONENT_N,
	    &rsa_n, &rsa_n_len)) != 0 ||
	    (r = rust_rsa_export_component_bytes(key, OSSH_RUST_RSA_COMPONENT_E,
	    &rsa_e, &rsa_e_len)) != 0)
		goto out;
	if ((r = sshbuf_put_bignum2_bytes(b, rsa_e, rsa_e_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(b, rsa_n, rsa_n_len)) != 0)
		goto out;
	r = 0;
 out:
	freezero(rsa_n, rsa_n_len);
	freezero(rsa_e, rsa_e_len);
	return r;
}

static int
ssh_rsa_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	u_char *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
	u_char *rsa_iqmp = NULL, *rsa_p = NULL, *rsa_q = NULL;
	size_t rsa_n_len = 0, rsa_e_len = 0, rsa_d_len = 0;
	size_t rsa_iqmp_len = 0, rsa_p_len = 0, rsa_q_len = 0;
	int r;

	if (!sshkey_is_cert(key)) {
		if ((r = rust_rsa_export_component_bytes(key,
		    OSSH_RUST_RSA_COMPONENT_N, &rsa_n, &rsa_n_len)) != 0 ||
		    (r = rust_rsa_export_component_bytes(key,
		    OSSH_RUST_RSA_COMPONENT_E, &rsa_e, &rsa_e_len)) != 0)
			goto out;
		if ((r = sshbuf_put_bignum2_bytes(b, rsa_n, rsa_n_len)) != 0 ||
		    (r = sshbuf_put_bignum2_bytes(b, rsa_e, rsa_e_len)) != 0)
			goto out;
	}
	if ((r = rust_rsa_export_component_bytes(key, OSSH_RUST_RSA_COMPONENT_D,
	    &rsa_d, &rsa_d_len)) != 0 ||
	    (r = rust_rsa_export_component_bytes(key, OSSH_RUST_RSA_COMPONENT_IQMP,
	    &rsa_iqmp, &rsa_iqmp_len)) != 0 ||
	    (r = rust_rsa_export_component_bytes(key, OSSH_RUST_RSA_COMPONENT_P,
	    &rsa_p, &rsa_p_len)) != 0 ||
	    (r = rust_rsa_export_component_bytes(key, OSSH_RUST_RSA_COMPONENT_Q,
	    &rsa_q, &rsa_q_len)) != 0)
		goto out;
	if ((r = sshbuf_put_bignum2_bytes(b, rsa_d, rsa_d_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(b, rsa_iqmp, rsa_iqmp_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(b, rsa_p, rsa_p_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(b, rsa_q, rsa_q_len)) != 0)
		goto out;
	r = 0;
 out:
	freezero(rsa_n, rsa_n_len);
	freezero(rsa_e, rsa_e_len);
	freezero(rsa_d, rsa_d_len);
	freezero(rsa_iqmp, rsa_iqmp_len);
	freezero(rsa_p, rsa_p_len);
	freezero(rsa_q, rsa_q_len);
	return r;
}

static int
ssh_rsa_generate(struct sshkey *k, int bits)
{
	if (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		return SSH_ERR_KEY_LENGTH;
	ossh_rust_rsa_free(k->pkey);
	if ((k->pkey = ossh_rust_rsa_generate(bits)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	return 0;
}

static int
ssh_rsa_copy_public(const struct sshkey *from, struct sshkey *to)
{
	void *copy;

	if (from == NULL || from->pkey == NULL || to == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((copy = ossh_rust_rsa_copy_public(from->pkey)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	ossh_rust_rsa_free(to->pkey);
	to->pkey = copy;
	return 0;
}

static int
ssh_rsa_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	size_t consumed = 0;
	void *rust_key;

	if ((rust_key = ossh_rust_rsa_parse_public_blob(sshbuf_ptr(b),
	    sshbuf_len(b), &consumed)) == NULL)
		return SSH_ERR_INVALID_FORMAT;
	if (sshbuf_consume(b, consumed) != 0) {
		ossh_rust_rsa_free(rust_key);
		return SSH_ERR_INTERNAL_ERROR;
	}
	ossh_rust_rsa_free(key->pkey);
	key->pkey = rust_key;
	return sshkey_check_rsa_length(key, 0);
}

static int
ssh_rsa_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	const u_char *rsa_n = NULL, *rsa_e = NULL;
	const u_char *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	u_char *cert_n = NULL, *cert_e = NULL;
	size_t rsa_n_len = 0, rsa_e_len = 0;
	size_t rsa_d_len, rsa_iqmp_len, rsa_p_len, rsa_q_len;
	void *rust_key = NULL;
	int r;

	if (sshkey_is_cert(key)) {
		if ((r = rust_rsa_export_component_bytes(key,
		    OSSH_RUST_RSA_COMPONENT_N, &cert_n, &rsa_n_len)) != 0 ||
		    (r = rust_rsa_export_component_bytes(key,
		    OSSH_RUST_RSA_COMPONENT_E, &cert_e, &rsa_e_len)) != 0)
			goto out;
		rsa_n = cert_n;
		rsa_e = cert_e;
	} else {
		if ((r = sshbuf_get_bignum2_bytes_direct(b, &rsa_n, &rsa_n_len)) != 0 ||
		    (r = sshbuf_get_bignum2_bytes_direct(b, &rsa_e, &rsa_e_len)) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	if ((r = sshbuf_get_bignum2_bytes_direct(b, &rsa_d, &rsa_d_len)) != 0 ||
	    (r = sshbuf_get_bignum2_bytes_direct(b, &rsa_iqmp, &rsa_iqmp_len)) != 0 ||
	    (r = sshbuf_get_bignum2_bytes_direct(b, &rsa_p, &rsa_p_len)) != 0 ||
	    (r = sshbuf_get_bignum2_bytes_direct(b, &rsa_q, &rsa_q_len)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((rust_key = ossh_rust_rsa_from_private(rsa_n, rsa_n_len,
	    rsa_e, rsa_e_len, rsa_d, rsa_d_len, rsa_iqmp, rsa_iqmp_len,
	    rsa_p, rsa_p_len, rsa_q, rsa_q_len)) == NULL) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ossh_rust_rsa_free(key->pkey);
	key->pkey = rust_key;
	rust_key = NULL;
	r = sshkey_check_rsa_length(key, 0);
 out:
	ossh_rust_rsa_free(rust_key);
	freezero(cert_n, rsa_n_len);
	freezero(cert_e, rsa_e_len);
	return r;
}

const char *
ssh_rsa_hash_alg_ident(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		return "ssh-rsa";
	case SSH_DIGEST_SHA256:
		return "rsa-sha2-256";
	case SSH_DIGEST_SHA512:
		return "rsa-sha2-512";
	}
	return NULL;
}

static int
rsa_hash_id_from_ident(const char *ident)
{
	if (strcmp(ident, "ssh-rsa") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(ident, "rsa-sha2-256") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(ident, "rsa-sha2-512") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

int
ssh_rsa_hash_id_from_keyname(const char *alg)
{
	int r;

	if ((r = rsa_hash_id_from_ident(alg)) != -1)
		return r;
	if (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

int
ssh_rsa_encode_store_sig(int hash_alg, const u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	struct sshbuf *b = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
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
	sshbuf_free(b);
	return ret;
}

static int
ssh_rsa_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sig = NULL;
	size_t digest_len, modlen;
	int hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg == NULL || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);
	if (key == NULL || key->pkey == NULL || hash_alg == -1 ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((modlen = rust_rsa_component_len(key, OSSH_RUST_RSA_COMPONENT_N)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if (ssh_rsa_size(key) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;
	if ((digest_len = ssh_digest_bytes(hash_alg)) == 0 ||
	    ssh_digest_memory(hash_alg, data, datalen, digest, digest_len) != 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((sig = calloc(1, modlen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (ossh_rust_rsa_sign_prehashed(key->pkey, hash_alg, digest, digest_len,
	    sig, modlen) != 0) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, modlen, sigp, lenp)) != 0)
		goto out;
	ret = 0;
 out:
	freezero(sig, modlen);
	explicit_bzero(digest, sizeof(digest));
	return ret;
}

static int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	char *sigtype = NULL;
	int hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, digest_len;
	struct sshbuf *b = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = NULL;

	if (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if (ssh_rsa_size(key) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		if ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			goto out;
		}
	}
	if (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if ((modlen = rust_rsa_component_len(key, OSSH_RUST_RSA_COMPONENT_N)) == 0) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (len > modlen) {
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		goto out;
	} else if (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		if ((sigblob = realloc(sigblob, modlen)) == NULL) {
			sigblob = osigblob;
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}
	if ((digest_len = ssh_digest_bytes(hash_alg)) == 0 ||
	    ssh_digest_memory(hash_alg, data, dlen, digest, digest_len) != 0) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	switch (ossh_rust_rsa_verify_prehashed(key->pkey, hash_alg, digest,
	    digest_len, sigblob, len)) {
	case 1:
		ret = 0;
		break;
	case 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		break;
	default:
		ret = SSH_ERR_INVALID_ARGUMENT;
		break;
	}
 out:
	freezero(sigblob, len);
	free(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, sizeof(digest));
	return ret;
}

static const struct sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_size,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_private,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_public,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

const struct sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

#endif /* WITH_RUST_CRYPTO */
