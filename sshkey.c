/* $OpenBSD: sshkey.c,v 1.163 2026/06/29 01:58:29 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Alexander von Gernler.  All rights reserved.
 * Copyright (c) 2010,2011 Damien Miller.  All rights reserved.
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
#include <sys/mman.h>
#include <netinet/in.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#endif

#include "crypto_api.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <time.h>
#include <util.h>

#include "ssh2.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "cipher.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "match.h"
#include "ssh-sk.h"
#include "ssh-pkcs11.h"

#include "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(sizeof(MARK_BEGIN) - 1)
#define MARK_END_LEN		(sizeof(MARK_END) - 1)
#define KDFNAME			"bcrypt"
#define AUTH_MAGIC		"openssh-key-v1"
#define SALT_LEN		16
#define DEFAULT_CIPHERNAME	"aes256-ctr"
#define	DEFAULT_ROUNDS		24

/*
 * Constants relating to "shielding" support; protection of keys expected
 * to remain in memory for long durations
 */
#define SSHKEY_SHIELD_PREKEY_LEN	(16 * 1024)
#define SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
#define SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512

static int sshkey_from_blob_internal(struct sshbuf *buf,
    struct sshkey **keyp, int allow_cert);
static int peek_ecdsa_type_nid(const char *name, size_t len, int *nid);
static int sshkey_ecdsa_deserialize_public_noec(const char *ktype,
    struct sshbuf *b, struct sshkey *key);

/* Supported key types */
extern const struct sshkey_impl sshkey_ed25519_impl;
extern const struct sshkey_impl sshkey_ed25519_cert_impl;
extern const struct sshkey_impl sshkey_ed25519_sk_impl;
extern const struct sshkey_impl sshkey_ed25519_sk_cert_impl;
#ifdef USE_MLDSA
extern const struct sshkey_impl sshkey_mldsa44_ed25519_impl;
extern const struct sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
#endif /* USE_MLDSA */
#if (defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)) || \
    defined(WITH_RUST_CRYPTO)
extern const struct sshkey_impl sshkey_ecdsa_nistp256_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp384_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
# if defined(WITH_RUST_CRYPTO) || defined(OPENSSL_HAS_NISTP521)
extern const struct sshkey_impl sshkey_ecdsa_nistp521_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
# endif /* WITH_RUST_CRYPTO || OPENSSL_HAS_NISTP521 */
# if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC) && defined(ENABLE_SK)
extern const struct sshkey_impl sshkey_ecdsa_sk_impl;
extern const struct sshkey_impl sshkey_ecdsa_sk_cert_impl;
extern const struct sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
extern const struct sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* WITH_OPENSSL && OPENSSL_HAS_ECC && ENABLE_SK */
#endif /* WITH_OPENSSL && OPENSSL_HAS_ECC || WITH_RUST_CRYPTO */
#if defined(WITH_OPENSSL) || defined(WITH_RUST_CRYPTO)
extern const struct sshkey_impl sshkey_rsa_impl;
extern const struct sshkey_impl sshkey_rsa_cert_impl;
extern const struct sshkey_impl sshkey_rsa_sha256_impl;
extern const struct sshkey_impl sshkey_rsa_sha256_cert_impl;
extern const struct sshkey_impl sshkey_rsa_sha512_impl;
extern const struct sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL || WITH_RUST_CRYPTO */

const struct sshkey_impl * const keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#ifdef ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#endif
#ifdef USE_MLDSA
	&sshkey_mldsa44_ed25519_impl,
	&sshkey_mldsa44_ed25519_cert_impl,
#endif /* USE_MLDSA */
#if (defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)) || \
    defined(WITH_RUST_CRYPTO)
	&sshkey_ecdsa_nistp256_impl,
	&sshkey_ecdsa_nistp256_cert_impl,
	&sshkey_ecdsa_nistp384_impl,
	&sshkey_ecdsa_nistp384_cert_impl,
# if defined(WITH_RUST_CRYPTO) || defined(OPENSSL_HAS_NISTP521)
	&sshkey_ecdsa_nistp521_impl,
	&sshkey_ecdsa_nistp521_cert_impl,
# endif /* WITH_RUST_CRYPTO || OPENSSL_HAS_NISTP521 */
# if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC) && defined(ENABLE_SK)
	&sshkey_ecdsa_sk_impl,
	&sshkey_ecdsa_sk_cert_impl,
	&sshkey_ecdsa_sk_webauthn_impl,
	&sshkey_ecdsa_sk_webauthn_cert_impl,
# endif /* WITH_OPENSSL && OPENSSL_HAS_ECC && ENABLE_SK */
#endif
#if defined(WITH_OPENSSL) || defined(WITH_RUST_CRYPTO)
	&sshkey_rsa_impl,
	&sshkey_rsa_cert_impl,
	&sshkey_rsa_sha256_impl,
	&sshkey_rsa_sha256_cert_impl,
	&sshkey_rsa_sha512_impl,
	&sshkey_rsa_sha512_cert_impl,
#endif /* WITH_OPENSSL || WITH_RUST_CRYPTO */
	NULL
};

#ifdef WITH_RUST_CRYPTO
static size_t
keyimpl_nentries(void)
{
	size_t i;

	for (i = 0; keyimpls[i] != NULL; i++)
		;
	return i;
}
#define OSSH_RUST_NO_IMPL_INDEX (-1)
#endif /* WITH_RUST_CRYPTO */

static const struct sshkey_impl *
sshkey_impl_from_type(int type)
{
	size_t idx = 0;

#ifdef WITH_RUST_CRYPTO
	if (ossh_rust_sshkey_impl_index_from_type(type,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &idx) == 0)
		return keyimpls[idx];
#endif
	for (idx = 0; keyimpls[idx] != NULL; idx++) {
		if (keyimpls[idx]->type == type)
			return keyimpls[idx];
	}
	return NULL;
}

static const struct sshkey_impl *
sshkey_impl_from_type_nid(int type, int nid)
{
	size_t idx = 0;

#ifdef WITH_RUST_CRYPTO
	if (ossh_rust_sshkey_impl_index_from_type_nid(type, nid,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &idx) == 0)
		return keyimpls[idx];
#endif
	for (idx = 0; keyimpls[idx] != NULL; idx++) {
		if (keyimpls[idx]->type == type &&
		    (keyimpls[idx]->nid == 0 || keyimpls[idx]->nid == nid))
			return keyimpls[idx];
	}
	return NULL;
}

static const struct sshkey_impl *
sshkey_impl_from_key(const struct sshkey *k)
{
	if (k == NULL)
		return NULL;
	return sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

const char *
sshkey_type(const struct sshkey *k)
{
#ifdef WITH_RUST_CRYPTO
	const char *name = NULL;
#endif
	const struct sshkey_impl *impl;

#ifdef WITH_RUST_CRYPTO
	if (k != NULL &&
	    ossh_rust_sshkey_impl_name_from_type_nid(k->type, k->ecdsa_nid, 1,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &name) == 0 && name != NULL)
		return name;
#endif
	if ((impl = sshkey_impl_from_key(k)) == NULL)
		return "unknown";
	return impl->shortname;
}

static const char *
sshkey_ssh_name_from_type_nid(int type, int nid)
{
#ifdef WITH_RUST_CRYPTO
	const char *name = NULL;
#endif
	const struct sshkey_impl *impl;

#ifdef WITH_RUST_CRYPTO
	if (ossh_rust_sshkey_impl_name_from_type_nid(type, nid, 0,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &name) == 0 && name != NULL)
		return name;
#endif
	if ((impl = sshkey_impl_from_type_nid(type, nid)) == NULL)
		return "ssh-unknown";
	return impl->name;
}

int
sshkey_type_is_cert(int type)
{
#ifdef WITH_RUST_CRYPTO
	int ret;

	if (ossh_rust_sshkey_type_is_cert(type, &ret) == 0)
		return ret;
#endif
	switch (type) {
	case KEY_RSA_CERT:
	case KEY_ECDSA_CERT:
	case KEY_ECDSA_SK_CERT:
	case KEY_ED25519_CERT:
	case KEY_ED25519_SK_CERT:
		return 1;
	default:
		return 0;
	}
}

const char *
sshkey_ssh_name(const struct sshkey *k)
{
	return sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

const char *
sshkey_ssh_name_plain(const struct sshkey *k)
{
	return sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

static int
type_from_name(const char *name, int allow_short)
{
	int i;
	int nid = -1, type;
	const struct sshkey_impl *impl;

#ifdef WITH_RUST_CRYPTO
	if (ossh_rust_sshkey_type_from_name((const u_char *)name,
	    name == NULL ? 0 : strlen(name),
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), allow_short, &type) == 0)
		return type;
#endif

	type = peek_ecdsa_type_nid(name, strlen(name), &nid);
	if (type != KEY_UNSPEC)
		return type;

	for (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		if (impl->name != NULL && strcmp(name, impl->name) == 0)
			return impl->type;
		/* Only allow shortname matches for plain key types */
		if (allow_short && !impl->cert && impl->shortname != NULL &&
		    strcasecmp(impl->shortname, name) == 0)
			return impl->type;
	}
	return KEY_UNSPEC;
}

int
sshkey_type_from_name(const char *name)
{
	return type_from_name(name, 0);
}

int
sshkey_type_from_shortname(const char *name)
{
	return type_from_name(name, 1);
}

static int
key_type_is_ecdsa_variant(int type)
{
	switch (type) {
	case KEY_ECDSA:
	case KEY_ECDSA_CERT:
	case KEY_ECDSA_SK:
	case KEY_ECDSA_SK_CERT:
		return 1;
	}
	return 0;
}

static int
peek_ecdsa_type_nid(const char *name, size_t len, int *nid)
{
	if (len == strlen("ecdsa-sha2-nistp256") &&
	    memcmp(name, "ecdsa-sha2-nistp256", len) == 0) {
		*nid = NID_X9_62_prime256v1;
		return KEY_ECDSA;
	}
	if (len == strlen("ecdsa-sha2-nistp384") &&
	    memcmp(name, "ecdsa-sha2-nistp384", len) == 0) {
		*nid = NID_secp384r1;
		return KEY_ECDSA;
	}
#if defined(OPENSSL_HAS_NISTP521) || defined(WITH_RUST_CRYPTO)
	if (len == strlen("ecdsa-sha2-nistp521") &&
	    memcmp(name, "ecdsa-sha2-nistp521", len) == 0) {
		*nid = NID_secp521r1;
		return KEY_ECDSA;
	}
#endif
	if (len == strlen("ecdsa-sha2-nistp256-cert-v01@openssh.com") &&
	    memcmp(name, "ecdsa-sha2-nistp256-cert-v01@openssh.com",
	    len) == 0) {
		*nid = NID_X9_62_prime256v1;
		return KEY_ECDSA_CERT;
	}
	if (len == strlen("ecdsa-sha2-nistp384-cert-v01@openssh.com") &&
	    memcmp(name, "ecdsa-sha2-nistp384-cert-v01@openssh.com",
	    len) == 0) {
		*nid = NID_secp384r1;
		return KEY_ECDSA_CERT;
	}
#if defined(OPENSSL_HAS_NISTP521) || defined(WITH_RUST_CRYPTO)
	if (len == strlen("ecdsa-sha2-nistp521-cert-v01@openssh.com") &&
	    memcmp(name, "ecdsa-sha2-nistp521-cert-v01@openssh.com",
	    len) == 0) {
		*nid = NID_secp521r1;
		return KEY_ECDSA_CERT;
	}
#endif
	return KEY_UNSPEC;
}

int
sshkey_ecdsa_nid_from_name(const char *name)
{
#ifdef WITH_RUST_CRYPTO
	int nid;

	if (ossh_rust_sshkey_ecdsa_nid_from_name((const u_char *)name,
	    name == NULL ? 0 : strlen(name),
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &nid) == 0)
		return nid;
	return -1;
#else
	int i;
	int nid = -1, type;

	type = peek_ecdsa_type_nid(name, strlen(name), &nid);
	if (key_type_is_ecdsa_variant(type))
		return nid;

	for (i = 0; keyimpls[i] != NULL; i++) {
		if (!key_type_is_ecdsa_variant(keyimpls[i]->type))
			continue;
		if (keyimpls[i]->name != NULL &&
		    strcmp(name, keyimpls[i]->name) == 0)
			return keyimpls[i]->nid;
	}
	return -1;
#endif
}

int
sshkey_match_keyname_to_sigalgs(const char *keyname, const char *sigalgs)
{
#ifndef WITH_RUST_CRYPTO
	int ktype;
#endif
#ifdef WITH_RUST_CRYPTO
	int match_kind;

	if (sigalgs == NULL || *sigalgs == '\0' ||
	    ossh_rust_sshkey_sigalg_match_plan((const u_char *)keyname,
	    keyname == NULL ? 0 : strlen(keyname),
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &match_kind) != 0)
		return 0;
	switch (match_kind) {
	case 1:
		return match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	case 2:
		return match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	case 3:
		return match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	case 4:
		return match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	default:
		return match_pattern_list(keyname, sigalgs, 0) == 1;
	}
#else

	if (sigalgs == NULL || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == KEY_UNSPEC)
		return 0;
	else if (ktype == KEY_RSA) {
		return match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} else if (ktype == KEY_RSA_CERT) {
		return match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} else if (ktype == KEY_ECDSA_SK) {
		return match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} else if (ktype == KEY_ECDSA_SK_CERT) {
		return match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} else
		return match_pattern_list(keyname, sigalgs, 0) == 1;
#endif
}

char *
sshkey_alg_list(int certs_only, int plain_only, int include_sigonly, char sep)
{
	char *ret = NULL;
#ifdef WITH_RUST_CRYPTO
	size_t len = 0;
	size_t nentries = 0;
#else
	size_t i;
	const struct sshkey_impl *impl;
	char sep_str[2] = {sep, '\0'};
#endif

#ifdef WITH_RUST_CRYPTO
	for (nentries = 0; keyimpls[nentries] != NULL; nentries++)
		;
	if (ossh_rust_sshkey_alg_list_len(certs_only, plain_only,
	    include_sigonly, (u_char)sep,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    nentries, &len) != 0 || len == 0)
		return NULL;
	if ((ret = malloc(len + 1)) == NULL)
		return NULL;
	if (ossh_rust_sshkey_alg_list_write(certs_only, plain_only,
	    include_sigonly, (u_char)sep,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    nentries, (u_char *)ret, len) != 0) {
		free(ret);
		return NULL;
	}
	ret[len] = '\0';
	return ret;
#else
	for (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		if (impl->name == NULL)
			continue;
		if (!include_sigonly && impl->sigonly)
			continue;
		if ((certs_only && !impl->cert) || (plain_only && impl->cert))
			continue;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	return ret;
#endif /* WITH_RUST_CRYPTO */
}

int
sshkey_names_valid2(const char *names, int allow_wildcard, int plain_only)
{
	char *s, *cp, *p;
#ifdef WITH_RUST_CRYPTO
	int valid = 0;
#else
	const struct sshkey_impl *impl;
	int i, type;
#endif

	if (names == NULL || strcmp(names, "") == 0)
		return 0;
	if ((s = cp = strdup(names)) == NULL)
		return 0;
	for ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
#ifdef WITH_RUST_CRYPTO
		if (ossh_rust_sshkey_names_valid_include((const u_char *)p,
		    strlen(p), allow_wildcard, plain_only,
		    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
		    keyimpl_nentries(), &valid) != 0 || !valid) {
			free(s);
			return 0;
		}
		continue;
#else
		type = sshkey_type_from_name(p);
		if (type == KEY_UNSPEC) {
			if (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = NULL;
				for (i = 0; keyimpls[i] != NULL; i++) {
					if (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						break;
					}
				}
				if (impl != NULL)
					continue;
			}
			free(s);
			return 0;
		} else if (plain_only && sshkey_type_is_cert(type)) {
			free(s);
			return 0;
		}
#endif /* WITH_RUST_CRYPTO */
	}
	free(s);
	return 1;
}

u_int
sshkey_size(const struct sshkey *k)
{
	const struct sshkey_impl *impl;

	if ((impl = sshkey_impl_from_key(k)) == NULL)
		return 0;
	if (impl->funcs->size != NULL)
		return impl->funcs->size(k);
	return impl->keybits;
}

static int
sshkey_type_is_valid_ca(int type)
{
#ifdef WITH_RUST_CRYPTO
	int ret;

	if (ossh_rust_sshkey_type_is_valid_ca(type,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &ret) == 0)
		return ret;
	return 0;
#else
	const struct sshkey_impl *impl;

	if (type == KEY_ECDSA)
		return 1;
	if ((impl = sshkey_impl_from_type(type)) == NULL)
		return 0;
	/* All non-certificate types may act as CAs */
	return !impl->cert;
#endif
}

int
sshkey_is_cert(const struct sshkey *k)
{
	if (k == NULL)
		return 0;
	return sshkey_type_is_cert(k->type);
}

int
sshkey_is_sk(const struct sshkey *k)
{
#ifdef WITH_RUST_CRYPTO
	int ret;
#endif

	if (k == NULL)
		return 0;
#ifdef WITH_RUST_CRYPTO
	if (ossh_rust_sshkey_type_is_sk(k->type, &ret) == 0)
		return ret;
	return 0;
#else
	switch (sshkey_type_plain(k->type)) {
	case KEY_ECDSA_SK:
	case KEY_ED25519_SK:
		return 1;
	default:
		return 0;
	}
#endif
}

/* Return the cert-less equivalent to a certified key type */
int
sshkey_type_plain(int type)
{
#ifdef WITH_RUST_CRYPTO
	int ret;

	if (ossh_rust_sshkey_type_plain(type, &ret) == 0)
		return ret;
	fatal_f("Rust sshkey plain-type lookup failed for type %d", type);
#else
	switch (type) {
	case KEY_RSA_CERT:
		return KEY_RSA;
	case KEY_ECDSA_CERT:
		return KEY_ECDSA;
	case KEY_ECDSA_SK_CERT:
		return KEY_ECDSA_SK;
	case KEY_ED25519_CERT:
		return KEY_ED25519;
	case KEY_MLDSA44_ED25519_CERT:
		return KEY_MLDSA44_ED25519;
	case KEY_ED25519_SK_CERT:
		return KEY_ED25519_SK;
	default:
		return type;
	}
#endif
}

/* Return the cert equivalent to a plain key type */
static int
sshkey_type_certified(int type)
{
#ifdef WITH_RUST_CRYPTO
	int ret;

	if (ossh_rust_sshkey_type_certified(type, &ret) == 0)
		return ret;
	fatal_f("Rust sshkey certified-type lookup failed for type %d", type);
#else
	switch (type) {
	case KEY_RSA:
		return KEY_RSA_CERT;
	case KEY_ECDSA:
		return KEY_ECDSA_CERT;
	case KEY_ECDSA_SK:
		return KEY_ECDSA_SK_CERT;
	case KEY_ED25519:
		return KEY_ED25519_CERT;
	case KEY_MLDSA44_ED25519:
		return KEY_MLDSA44_ED25519_CERT;
	case KEY_ED25519_SK:
		return KEY_ED25519_SK_CERT;
	default:
		return -1;
	}
#endif
}

#ifdef WITH_OPENSSL
static const EVP_MD *
ssh_digest_to_md(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		return EVP_sha1();
	case SSH_DIGEST_SHA256:
		return EVP_sha256();
	case SSH_DIGEST_SHA384:
		return EVP_sha384();
	case SSH_DIGEST_SHA512:
		return EVP_sha512();
	}
	return NULL;
}

int
sshkey_pkey_digest_sign(EVP_PKEY *pkey, int hash_alg, u_char **sigp,
    size_t *lenp, const u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = NULL;
	u_char *sig = NULL;
	int ret;
	size_t slen;
	const EVP_MD *evpmd;

	*sigp = NULL;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	if (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((sig = malloc(slen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_DigestSignInit(ctx, NULL, evpmd, NULL, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = NULL;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	free(sig);
	return ret;
}

int
sshkey_pkey_digest_verify(EVP_PKEY *pkey, int hash_alg, const u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;
	const EVP_MD *evpmd;

	if ((evpmd = ssh_digest_to_md(hash_alg)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((ctx = EVP_MD_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (EVP_DigestVerifyInit(ctx, NULL, evpmd, NULL, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	switch (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	case 1:
		ret = 0;
		break;
	case 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		break;
	default:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		break;
	}

 out:
	EVP_MD_CTX_free(ctx);
	return ret;
}

#endif /* WITH_OPENSSL */

/* XXX: these are really begging for a table-driven approach */
int
sshkey_curve_name_to_nid(const char *name)
{
#ifdef WITH_RUST_CRYPTO
	int nid;

	if (name == NULL)
		return -1;
	if (ossh_rust_sshkey_curve_name_to_nid((const u_char *)name,
	    strlen(name), &nid) == 0)
		return nid;
	return -1;
#else
	if (strcmp(name, "nistp256") == 0)
		return NID_X9_62_prime256v1;
	else if (strcmp(name, "nistp384") == 0)
		return NID_secp384r1;
# if defined(OPENSSL_HAS_NISTP521) || defined(WITH_RUST_CRYPTO)
	else if (strcmp(name, "nistp521") == 0)
		return NID_secp521r1;
# endif /* OPENSSL_HAS_NISTP521 || WITH_RUST_CRYPTO */
	else
		return -1;
#endif /* WITH_RUST_CRYPTO */
}

u_int
sshkey_curve_nid_to_bits(int nid)
{
#ifdef WITH_RUST_CRYPTO
	int bits;

	if (ossh_rust_sshkey_curve_nid_to_bits(nid, &bits) == 0)
		return bits;
	return 0;
#else
	switch (nid) {
	case NID_X9_62_prime256v1:
		return 256;
	case NID_secp384r1:
		return 384;
# if defined(OPENSSL_HAS_NISTP521) || defined(WITH_RUST_CRYPTO)
	case NID_secp521r1:
		return 521;
# endif /* OPENSSL_HAS_NISTP521 || WITH_RUST_CRYPTO */
	default:
		return 0;
	}
#endif /* WITH_RUST_CRYPTO */
}

int
sshkey_ecdsa_bits_to_nid(int bits)
{
#ifdef WITH_RUST_CRYPTO
	int nid;

	if (ossh_rust_sshkey_ecdsa_bits_to_nid(bits, &nid) == 0)
		return nid;
	return -1;
#else
	switch (bits) {
	case 256:
		return NID_X9_62_prime256v1;
	case 384:
		return NID_secp384r1;
# if defined(OPENSSL_HAS_NISTP521) || defined(WITH_RUST_CRYPTO)
	case 521:
		return NID_secp521r1;
# endif /* OPENSSL_HAS_NISTP521 || WITH_RUST_CRYPTO */
	default:
		return -1;
	}
#endif /* WITH_RUST_CRYPTO */
}

const char *
sshkey_curve_nid_to_name(int nid)
{
#ifdef WITH_RUST_CRYPTO
	return ossh_rust_sshkey_curve_nid_to_name(nid);
#else
	switch (nid) {
	case NID_X9_62_prime256v1:
		return "nistp256";
	case NID_secp384r1:
		return "nistp384";
# if defined(OPENSSL_HAS_NISTP521) || defined(WITH_RUST_CRYPTO)
	case NID_secp521r1:
		return "nistp521";
# endif /* OPENSSL_HAS_NISTP521 || WITH_RUST_CRYPTO */
	default:
		return NULL;
	}
#endif /* WITH_RUST_CRYPTO */
}

int
sshkey_ec_nid_to_hash_alg(int nid)
{
	int kbits = sshkey_curve_nid_to_bits(nid);

	if (kbits <= 0)
		return -1;

	/* RFC5656 section 6.2.1 */
	if (kbits <= 256)
		return SSH_DIGEST_SHA256;
	else if (kbits <= 384)
		return SSH_DIGEST_SHA384;
	else
		return SSH_DIGEST_SHA512;
}

static void
cert_free(struct sshkey_cert *cert)
{
	u_int i;

	if (cert == NULL)
		return;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	free(cert->key_id);
	for (i = 0; i < cert->nprincipals; i++)
		free(cert->principals[i]);
	free(cert->principals);
	sshkey_free(cert->signature_key);
	free(cert->signature_type);
	freezero(cert, sizeof(*cert));
}

static struct sshkey_cert *
cert_new(void)
{
	struct sshkey_cert *cert;

	if ((cert = calloc(1, sizeof(*cert))) == NULL)
		return NULL;
	if ((cert->certblob = sshbuf_new()) == NULL ||
	    (cert->critical = sshbuf_new()) == NULL ||
	    (cert->extensions = sshbuf_new()) == NULL) {
		cert_free(cert);
		return NULL;
	}
	cert->key_id = NULL;
	cert->principals = NULL;
	cert->signature_key = NULL;
	cert->signature_type = NULL;
	return cert;
}

struct sshkey *
sshkey_new(int type)
{
	struct sshkey *k;
	const struct sshkey_impl *impl = NULL;
#ifdef WITH_RUST_CRYPTO
	int can_new = 0, is_cert = 0;
	int impl_index = OSSH_RUST_NO_IMPL_INDEX;
#endif

#ifdef WITH_RUST_CRYPTO
	if (ossh_rust_sshkey_new_plan(type,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &can_new, &impl_index, &is_cert) != 0 ||
	    !can_new)
		return NULL;
	if (impl_index != OSSH_RUST_NO_IMPL_INDEX)
		impl = keyimpls[impl_index];
#else
	if (type != KEY_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == NULL) {
		if (!(key_type_is_ecdsa_variant(type) &&
		    sshkey_type_plain(type) == KEY_ECDSA))
			return NULL;
	}
#endif

	/* All non-certificate types may act as CAs */
	if ((k = calloc(1, sizeof(*k))) == NULL)
		return NULL;
	k->type = type;
	k->ecdsa_nid = -1;
	if (impl != NULL && impl->funcs->alloc != NULL) {
		if (impl->funcs->alloc(k) != 0) {
			free(k);
			return NULL;
		}
	}
#ifndef WITH_RUST_CRYPTO
	if (sshkey_is_cert(k)) {
#else
	if (is_cert) {
#endif
		if ((k->cert = cert_new()) == NULL) {
			sshkey_free(k);
			return NULL;
		}
	}

	return k;
}

static int
sshkey_ecdsa_deserialize_public_noec(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;
	const u_char *point;
	size_t point_len;
	char *curve = NULL;

	if ((key->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshbuf_get_cstring(b, &curve, NULL)) != 0)
		goto out;
	if (key->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		goto out;
	}
	if ((r = sshbuf_get_string_direct(b, &point, &point_len)) != 0)
		goto out;
	if (point_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	r = 0;
 out:
	free(curve);
	return r;
}

/* Frees common FIDO fields */
void
sshkey_sk_cleanup(struct sshkey *k)
{
	free(k->sk_application);
	sshbuf_free(k->sk_key_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = NULL;
	k->sk_key_handle = k->sk_reserved = NULL;
}

#if defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#elif defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#else
# define PREKEY_MMAP_FLAG	0
#endif

static int
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#if defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = NULL;
	if ((prekey = mmap(NULL, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		return SSH_ERR_SYSTEM_ERROR;
#if defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(void)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#else
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	return 0;
}

static void
sshkey_prekey_free(void *prekey, size_t len)
{
#if defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	if (prekey == NULL)
		return;
	munmap(prekey, len);
#else
	free(prekey);
#endif /* HAVE_MMAP et al */
}

static void
sshkey_free_contents(struct sshkey *k)
{
	const struct sshkey_impl *impl;
#ifdef WITH_RUST_CRYPTO
	int has_cert = 0, impl_index = OSSH_RUST_NO_IMPL_INDEX;
#endif

	if (k == NULL)
		return;
	if ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_key_free(k);
#ifdef WITH_RUST_CRYPTO
	impl = NULL;
	if (ossh_rust_sshkey_free_contents_plan(k->type,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &has_cert, &impl_index) != 0)
		fatal_f("Rust sshkey free-contents planning failed for type %d",
		    k->type);
	if (impl_index != OSSH_RUST_NO_IMPL_INDEX)
		impl = keyimpls[impl_index];
	if (impl != NULL && impl->funcs->cleanup != NULL)
		impl->funcs->cleanup(k);
	if (has_cert)
		cert_free(k->cert);
#else
	if ((impl = sshkey_impl_from_type(k->type)) != NULL &&
	    impl->funcs->cleanup != NULL)
		impl->funcs->cleanup(k);
	if (sshkey_type_is_cert(k->type))
		cert_free(k->cert);
#endif
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

void
sshkey_free(struct sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, sizeof(*k));
}

static int
cert_compare(struct sshkey_cert *a, struct sshkey_cert *b)
{
	if (a == NULL && b == NULL)
		return 1;
	if (a == NULL || b == NULL)
		return 0;
	if (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		return 0;
	if (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		return 0;
	return 1;
}

/* Compares FIDO-specific pubkey fields only */
int
sshkey_sk_fields_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a->sk_application == NULL || b->sk_application == NULL)
		return 0;
	if (strcmp(a->sk_application, b->sk_application) != 0)
		return 0;
	return 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
int
sshkey_equal_public(const struct sshkey *a, const struct sshkey *b)
{
#ifdef WITH_RUST_CRYPTO
	int comparable = 0, dispatch_type = KEY_UNSPEC;
#endif
	const struct sshkey_impl *impl;

	if (a == NULL || b == NULL)
		return 0;
#ifdef WITH_RUST_CRYPTO
	if (ossh_rust_sshkey_equal_public_plan(a->type, b->type,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &comparable, &dispatch_type) != 0)
		return 0;
	if (!comparable)
		return 0;
	if ((impl = sshkey_impl_from_type(dispatch_type)) == NULL)
		return 0;
#else
	if (sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		return 0;
	if ((impl = sshkey_impl_from_type(a->type)) == NULL)
		return 0;
#endif
	return impl->funcs->equal(a, b);
}

int
sshkey_equal(const struct sshkey *a, const struct sshkey *b)
{
	const struct sshkey_impl *impl;
#ifdef WITH_RUST_CRYPTO
	int compare_cert = 0, dispatch_type = KEY_UNSPEC;
#endif

	if (a == NULL || b == NULL)
		return 0;
#ifdef WITH_RUST_CRYPTO
	if (ossh_rust_sshkey_equal_plan(a->type, b->type,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &compare_cert, &dispatch_type) != 0)
		return 0;
	if ((impl = sshkey_impl_from_type(dispatch_type)) == NULL)
		return 0;
	if (compare_cert) {
#else
	if (a->type != b->type)
		return 0;
	if (sshkey_is_cert(a)) {
#endif
		if (!cert_compare(a->cert, b->cert))
			return 0;
	}
#ifndef WITH_RUST_CRYPTO
	if ((impl = sshkey_impl_from_type(a->type)) == NULL)
		return 0;
#endif
	return impl->funcs->equal(a, b);
}


/* Serialise common FIDO key parts */
int
sshkey_serialize_sk(const struct sshkey *key, struct sshbuf *b)
{
	int r;

	if ((r = sshbuf_put_cstring(b, key->sk_application)) != 0)
		return r;

	return 0;
}

static int
to_blob_buf(const struct sshkey *key, struct sshbuf *b, int force_plain,
  enum sshkey_serialize_rep opts)
{
	int type, ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_RUST_CRYPTO
	int use_cert_blob = 0;
#endif
	const char *typename;
	const struct sshkey_impl *impl;

	if (key == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

#ifdef WITH_RUST_CRYPTO
	ret = ossh_rust_sshkey_serialize_plan(key->type, force_plain,
	    key->cert != NULL, key->cert == NULL ? 0 : sshbuf_len(key->cert->certblob),
	    &type, &use_cert_blob);
	if (ret != 0)
		return ret;
	if (use_cert_blob) {
		if ((ret = sshbuf_putb(b, key->cert->certblob)) != 0)
			return ret;
		return 0;
	}
#else
	type = force_plain ? sshkey_type_plain(key->type) : key->type;

	if (sshkey_type_is_cert(type)) {
		if (key->cert == NULL)
			return SSH_ERR_EXPECTED_CERT;
		if (sshbuf_len(key->cert->certblob) == 0)
			return SSH_ERR_KEY_LACKS_CERTBLOB;
		/* Use the existing blob */
		if ((ret = sshbuf_putb(b, key->cert->certblob)) != 0)
			return ret;
		return 0;
	}
#endif
	if ((impl = sshkey_impl_from_type(type)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, key->ecdsa_nid);
	if ((ret = sshbuf_put_cstring(b, typename)) != 0)
		return ret;
	return impl->funcs->serialize_public(key, b, opts);
}

int
sshkey_putb(const struct sshkey *key, struct sshbuf *b)
{
	return to_blob_buf(key, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

static int
sshkey_puts_opts_internal(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts, int force_plain)
{
	struct sshbuf *tmp;
	int r;

	if ((tmp = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(key, tmp, force_plain, opts);
	if (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	return r;
}

int
sshkey_puts(const struct sshkey *key, struct sshbuf *b)
{
	return sshkey_puts_opts_internal(key, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

int
sshkey_putb_plain(const struct sshkey *key, struct sshbuf *b)
{
	return to_blob_buf(key, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

int
sshkey_puts_plain(const struct sshkey *key, struct sshbuf *b)
{
	return sshkey_puts_opts_internal(key, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

static int
to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp, int force_plain,
    enum sshkey_serialize_rep opts)
{
	int ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (blobp != NULL)
		*blobp = NULL;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((ret = to_blob_buf(key, b, force_plain, opts)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (lenp != NULL)
		*lenp = len;
	if (blobp != NULL) {
		if ((*blobp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	return ret;
}

int
sshkey_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp)
{
	return to_blob(key, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

int
sshkey_plain_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp)
{
	return to_blob(key, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

int
sshkey_fingerprint_raw(const struct sshkey *k, int dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = NULL, *ret = NULL;
	size_t blob_len = 0;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (retp != NULL)
		*retp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		goto out;
	if ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
	/* success */
	if (retp != NULL) {
		*retp = ret;
		ret = NULL;
	}
	if (lenp != NULL)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	free(ret);
	if (blob != NULL)
		freezero(blob, blob_len);
	return r;
}

static char *
fingerprint_b64(const char *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	char *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	if (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == NULL)
		return NULL;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	if (dgst_raw_len == 0)
		return ret;
	if (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		return NULL;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	return ret;
}

static char *
fingerprint_hex(const char *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	char *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	if (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == NULL)
		return NULL;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	for (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, sizeof(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	return retval;
}

static char *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	char vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	char consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	char *retval;

	rounds = (dgst_raw_len / 2) + 1;
	if ((retval = calloc(rounds, 6)) == NULL)
		return NULL;
	retval[j++] = 'x';
	for (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		if ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			if ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} else {
			idx0 = seed % 6;
			idx1 = 16;
			idx2 = seed / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	return retval;
}

/*
 * Draw an ASCII-Art representing the fingerprint so human brain can
 * profit from its built-in pattern recognition ability.
 * This technique is called "random art" and can be found in some
 * scientific publications like this original paper:
 *
 * "Hash Visualization: a New Technique to improve Real-World Security",
 * Perrig A. and Song D., 1999, International Workshop on Cryptographic
 * Techniques and E-Commerce (CrypTEC '99)
 * sparrow.ece.cmu.edu/~adrian/projects/validation/validation.pdf
 *
 * The subject came up in a talk by Dan Kaminsky, too.
 *
 * If you see the picture is different, the key is different.
 * If the picture looks the same, you still know nothing.
 *
 * The algorithm used here is a worm crawling over a discrete plane,
 * leaving a trace (augmenting the field) everywhere it goes.
 * Movement is taken from dgst_raw 2bit-wise.  Bumping into walls
 * makes the respective movement vector be ignored for this turn.
 * Graphs are not unambiguous, because circles in graphs can be
 * walked in either direction.
 */

/*
 * Field sizes for the random art.  Have to be odd, so the starting point
 * can be in the exact middle of the picture, and FLDBASE should be >=8 .
 * Else pictures would be too dense, and drawing the frame would
 * fail, too, because the key type would not fit in anymore.
 */
#define	FLDBASE		8
#define	FLDSIZE_Y	(FLDBASE + 1)
#define	FLDSIZE_X	(FLDBASE * 2 + 1)
static char *
fingerprint_randomart(const char *alg, u_char *dgst_raw, size_t dgst_raw_len,
    const struct sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	char	*augmentation_string = " .o+=*BOX@%&#/^SE";
	char	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	int	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	if ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == NULL)
		return NULL;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * sizeof(char));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	for (i = 0; i < dgst_raw_len; i++) {
		int input;
		/* each byte conveys four 2-bit move commands */
		input = dgst_raw[i];
		for (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (input & 0x1) ? 1 : -1;
			y += (input & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			if (field[x][y] < len - 2)
				field[x][y]++;
			input = input >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, sizeof(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	if (r < 0 || r > (int)sizeof(title))
		r = snprintf(title, sizeof(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, sizeof(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	for (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	for (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	for (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		for (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	for (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	for (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	return retval;
}

char *
sshkey_fingerprint(const struct sshkey *k, int dgst_alg,
    enum sshkey_fp_rep dgst_rep)
{
	char *retval = NULL;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	if (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		return NULL;
	switch (dgst_rep) {
	case SSH_FP_DEFAULT:
		if (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} else {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		break;
	case SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		break;
	default:
		freezero(dgst_raw, dgst_raw_len);
		return NULL;
	}
	freezero(dgst_raw, dgst_raw_len);
	return retval;
}

static int
peek_type_nid(const char *s, size_t l, int *nid)
{
	const struct sshkey_impl *impl;
	int i;

	if ((i = peek_ecdsa_type_nid(s, l, nid)) != KEY_UNSPEC)
		return i;

	for (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		if (impl->name == NULL || strlen(impl->name) != l)
			continue;
		if (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			if (key_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			return impl->type;
		}
	}
	return KEY_UNSPEC;
}

/* XXX this can now be made const char * */
int
sshkey_read(struct sshkey *ret, char **cpp)
{
	struct sshkey *k;
	char *cp;
	char *blob_ktype = NULL;
#ifndef WITH_RUST_CRYPTO
	char *blobcopy;
#endif
	size_t space;
	int r, type, curve_nid = -1;
	struct sshbuf *blob;
	struct sshbuf *blob_copy = NULL;
#ifdef WITH_RUST_CRYPTO
	struct ossh_rust_public_line_parse parsed;
	size_t cp_len, blob_len;
	u_char *blobp;
#endif

	if (ret == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (ret->type != KEY_UNSPEC && sshkey_impl_from_type(ret->type) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
#ifdef WITH_RUST_CRYPTO
	cp_len = strlen(cp);
	if (ossh_rust_public_line_parse((const u_char *)cp, cp_len, &parsed) != 0)
		return SSH_ERR_INVALID_FORMAT;
	space = parsed.key_type_len;
#else
	space = strcspn(cp, " \t");
	if (space == strlen(cp))
		return SSH_ERR_INVALID_FORMAT;
#endif
	if ((type = peek_type_nid(cp, space, &curve_nid)) == KEY_UNSPEC)
		return SSH_ERR_INVALID_FORMAT;
#if !defined(OPENSSL_HAS_ECC) && !defined(WITH_RUST_CRYPTO)
	if (key_type_is_ecdsa_variant(type))
		return SSH_ERR_INVALID_FORMAT;
#endif

	/* skip whitespace */
#ifdef WITH_RUST_CRYPTO
	if (parsed.key_blob_offset >= cp_len)
		return SSH_ERR_INVALID_FORMAT;
#else
	for (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	if (*cp == '\0')
		return SSH_ERR_INVALID_FORMAT;
#endif
	if (ret->type != KEY_UNSPEC && ret->type != type)
		return SSH_ERR_KEY_TYPE_MISMATCH;
	if ((blob = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
#ifdef WITH_RUST_CRYPTO
	if ((blob_len = ossh_rust_public_blob_decode_len(
	    (const u_char *)cp + parsed.key_blob_offset,
	    parsed.key_blob_len)) == 0) {
		sshbuf_free(blob);
		return SSH_ERR_INVALID_FORMAT;
	}
	if ((r = sshbuf_reserve(blob, blob_len, &blobp)) != 0) {
		sshbuf_free(blob);
		return r;
	}
	if (ossh_rust_public_blob_decode_write((const u_char *)cp +
	    parsed.key_blob_offset, parsed.key_blob_len, blobp, blob_len) != 0) {
		sshbuf_free(blob);
		return SSH_ERR_INVALID_FORMAT;
	}
#else
	space = strcspn(cp, " \t");
	if ((blobcopy = strndup(cp, space)) == NULL) {
		sshbuf_free(blob);
		return SSH_ERR_ALLOC_FAIL;
	}
	if ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		free(blobcopy);
		sshbuf_free(blob);
		return r;
	}
	free(blobcopy);
#endif
	if (key_type_is_ecdsa_variant(type)) {
		if ((blob_copy = sshbuf_fromb(blob)) == NULL) {
			sshbuf_free(blob);
			return SSH_ERR_ALLOC_FAIL;
		}
		if ((r = sshbuf_get_cstring(blob_copy, &blob_ktype, NULL)) != 0) {
			sshbuf_free(blob_copy);
			sshbuf_free(blob);
			return SSH_ERR_INVALID_FORMAT;
		}
		if (sshkey_ecdsa_nid_from_name(blob_ktype) != curve_nid) {
			sshbuf_free(blob_copy);
			sshbuf_free(blob);
			free(blob_ktype);
			return SSH_ERR_EC_CURVE_MISMATCH;
		}
		sshbuf_free(blob_copy);
		blob_copy = NULL;
		free(blob_ktype);
		blob_ktype = NULL;
	}
	if ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		free(blob_ktype);
		sshbuf_free(blob_copy);
		return r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
#ifdef WITH_RUST_CRYPTO
	cp += parsed.comment_offset;
#else
	for (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
#endif

	/* ensure type of blob matches type at start of line */
	if (k->type != type) {
		sshkey_free(k);
		return SSH_ERR_KEY_TYPE_MISMATCH;
	}
	if (key_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		return SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, sizeof(*k));

	/* success */
	*cpp = cp;
	return 0;
}

int
sshkey_to_base64(const struct sshkey *key, char **b64p)
{
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	char *uu = NULL;

	if (b64p != NULL)
		*b64p = NULL;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_putb(key, b)) != 0)
		goto out;
	if ((uu = sshbuf_dtob64_string(b, 0)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* Success */
	if (b64p != NULL) {
		*b64p = uu;
		uu = NULL;
	}
	r = 0;
 out:
	sshbuf_free(b);
	free(uu);
	return r;
}

int
sshkey_format_text(const struct sshkey *key, struct sshbuf *b)
{
	int r = SSH_ERR_INTERNAL_ERROR;
	char *uu = NULL;

	if ((r = sshkey_to_base64(key, &uu)) != 0)
		goto out;
	if ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(key), uu)) != 0)
		goto out;
	r = 0;
 out:
	free(uu);
	return r;
}

int
sshkey_write(const struct sshkey *key, FILE *f)
{
	struct sshbuf *b = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_format_text(key, b)) != 0)
		goto out;
	if (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		if (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		goto out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	return r;
}

const char *
sshkey_cert_type(const struct sshkey *k)
{
	switch (k->cert->type) {
	case SSH2_CERT_TYPE_USER:
		return "user";
	case SSH2_CERT_TYPE_HOST:
		return "host";
	default:
		return "unknown";
	}
}

int
sshkey_check_rsa_length(const struct sshkey *k, int min_size)
{
#if defined(WITH_OPENSSL) || defined(WITH_RUST_CRYPTO)
	int nbits;

	if (k == NULL ||
	    (k->type != KEY_RSA && k->type != KEY_RSA_CERT))
		return 0;
# ifdef WITH_OPENSSL
	if (k->pkey == NULL)
		return 0;
	nbits = EVP_PKEY_bits(k->pkey);
# else
	nbits = sshkey_size(k);
# endif
	if (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		return SSH_ERR_KEY_LENGTH;
#endif /* WITH_OPENSSL || WITH_RUST_CRYPTO */
	return 0;
}

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)
int
sshkey_ecdsa_key_to_nid(const EC_KEY *k)
{
	const EC_GROUP *g;
	int nid;

	if (k == NULL || (g = EC_KEY_get0_group(k)) == NULL)
		return -1;
	if ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		return -1;
	return nid;
}

int
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	return sshkey_ecdsa_key_to_nid(EVP_PKEY_get0_EC_KEY(pkey));
}
#endif /* defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC) */

int
sshkey_generate(int type, u_int bits, struct sshkey **keyp)
{
	struct sshkey *k;
	int ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_RUST_CRYPTO
	int new_type = KEY_UNSPEC;
#endif
	const struct sshkey_impl *impl;

	if (keyp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	*keyp = NULL;
#ifdef WITH_RUST_CRYPTO
	ret = ossh_rust_sshkey_generate_plan(type,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &new_type);
	if (ret != 0)
		return ret;
	if ((impl = sshkey_impl_from_type(new_type)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
#else
	if (sshkey_type_is_cert(type))
		return SSH_ERR_INVALID_ARGUMENT;
	if ((impl = sshkey_impl_from_type(type)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
#endif
	if (impl->funcs->generate == NULL)
		return SSH_ERR_FEATURE_UNSUPPORTED;
	if ((k = sshkey_new(KEY_UNSPEC)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	k->type =
#ifdef WITH_RUST_CRYPTO
	    new_type;
#else
	    type;
#endif
	if ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		return ret;
	}
	/* success */
	*keyp = k;
	return 0;
}

int
sshkey_cert_copy(const struct sshkey *from_key, struct sshkey *to_key)
{
	u_int i;
	const struct sshkey_cert *from;
	struct sshkey_cert *to;
	int r = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_RUST_CRYPTO
	int copy_signature_key = 0;
#endif

	if (to_key == NULL || (from = from_key->cert) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
#ifdef WITH_RUST_CRYPTO
	if ((r = ossh_rust_sshkey_cert_copy_plan(1,
	    from->signature_key != NULL, from->nprincipals,
	    &copy_signature_key)) != 0)
		return r;
#else
	if (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS)
		return SSH_ERR_INVALID_ARGUMENT;
#endif

	if ((to = cert_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		goto out;

	to->serial = from->serial;
	to->type = from->type;
	if (from->key_id == NULL)
		to->key_id = NULL;
	else if ((to->key_id = strdup(from->key_id)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	if (
#ifdef WITH_RUST_CRYPTO
	    !copy_signature_key
#else
	    from->signature_key == NULL
#endif
	    )
		to->signature_key = NULL;
	else if ((r = sshkey_from_private(from->signature_key,
	    &to->signature_key)) != 0)
		goto out;
	if (from->signature_type != NULL &&
	    (to->signature_type = strdup(from->signature_type)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (from->nprincipals > 0) {
		if ((to->principals = calloc(from->nprincipals,
		    sizeof(*to->principals))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		for (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			if (to->principals[i] == NULL) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_key->cert);
	to_key->cert = to;
	to = NULL;
	r = 0;
 out:
	cert_free(to);
	return r;
}

int
sshkey_copy_public_sk(const struct sshkey *from, struct sshkey *to)
{
#ifdef WITH_RUST_CRYPTO
	int r;

	if ((r = ossh_rust_sshkey_copy_public_sk_plan(
	    from->sk_application != NULL)) != 0)
		return r;
#endif
	/* Append security-key application string */
	if ((to->sk_application = strdup(from->sk_application)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	return 0;
}

int
sshkey_from_private(const struct sshkey *k, struct sshkey **pkp)
{
	struct sshkey *n = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_RUST_CRYPTO
	int new_type = KEY_UNSPEC, copy_cert = 0;
#endif
	const struct sshkey_impl *impl;

	*pkp = NULL;
	if (k == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
#ifdef WITH_RUST_CRYPTO
	r = ossh_rust_sshkey_from_private_plan(k->type, k->ecdsa_nid,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &new_type, &copy_cert);
	if (r != 0)
		return r;
	if ((impl = sshkey_impl_from_key(k)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	if ((n = sshkey_new(new_type)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
#else
	if ((impl = sshkey_impl_from_key(k)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	if ((n = sshkey_new(k->type)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
#endif
	if ((r = impl->funcs->copy_public(k, n)) != 0)
		goto out;
	if (
#ifdef WITH_RUST_CRYPTO
	    copy_cert
#else
	    sshkey_is_cert(k)
#endif
	    && (r = sshkey_cert_copy(k, n)) != 0)
		goto out;
	/* success */
	*pkp = n;
	n = NULL;
	r = 0;
 out:
	sshkey_free(n);
	return r;
}

int
sshkey_is_shielded(struct sshkey *k)
{
	return k != NULL && k->shielded_private != NULL;
}

int
sshkey_shield_private(struct sshkey *k)
{
	struct sshbuf *prvbuf = NULL;
	u_char *prekey = NULL, *enc = NULL, keyiv[SSH_DIGEST_MAX_LENGTH];
	struct sshcipher_ctx *cctx = NULL;
	const struct sshcipher *cipher;
	size_t i, enclen = 0;
	struct sshkey *kswap = NULL, tmp;
	int r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	if ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	if ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		goto out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	if ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	if ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		goto out;

	/* Serialise and encrypt the private key using the ephemeral key */
	if ((prvbuf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		goto out;
	if ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		goto out;
	/* pad to cipher blocksize */
	i = 0;
	while (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		if ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			goto out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	if ((enc = malloc(enclen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	if ((r = sshkey_from_private(k, &kswap)) != 0)
		goto out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = NULL; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, sizeof(keyiv));
	explicit_bzero(&tmp, sizeof(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	return r;
}

/* Check deterministic padding after private key */
static int
private2_check_padding(struct sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	int r;

	i = 0;
	while (sshbuf_len(decrypted)) {
		if ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			goto out;
		if (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, sizeof(pad));
	explicit_bzero(&i, sizeof(i));
	return r;
}

int
sshkey_unshield_private(struct sshkey *k)
{
	struct sshbuf *prvbuf = NULL;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	struct sshcipher_ctx *cctx = NULL;
	const struct sshcipher *cipher;
	struct sshkey *kswap = NULL, tmp;
	int r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	if (!sshkey_is_shielded(k))
		return 0; /* nothing to do */

	if ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* check size of shielded key blob */
	if (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Calculate the ephemeral key from the prekey */
	if ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
	if ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	if ((prvbuf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		goto out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	if ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	if ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		goto out;

	if ((r = private2_check_padding(prvbuf)) != 0)
		goto out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, sizeof(keyiv));
	explicit_bzero(&tmp, sizeof(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	return r;
}

static int
cert_parse(struct sshbuf *b, struct sshkey *key, struct sshbuf *certbuf)
{
	struct sshbuf *principals = NULL, *crit = NULL;
	struct sshbuf *exts = NULL, *ca = NULL;
#ifdef WITH_RUST_CRYPTO
	struct ossh_rust_cert_body_parse parsed;
	const u_char *blob, *sig;
	size_t blob_len, signed_len = 0, slen = 0;
#else
	u_char *sig = NULL;
	size_t signed_len = 0, slen = 0, kidlen = 0;
#endif
	int ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	if ((ret = sshbuf_putb(key->cert->certblob, certbuf)) != 0)
		return ret;

#ifdef WITH_RUST_CRYPTO
	blob = sshbuf_ptr(b);
	blob_len = sshbuf_len(b);

	if (ossh_rust_cert_parse_body(blob, blob_len, &parsed) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((ret = sshbuf_consume(b, parsed.total_consumed)) != 0)
		goto out;

	if ((key->cert->key_id = malloc(parsed.key_id_len + 1)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(key->cert->key_id, blob + parsed.key_id_offset, parsed.key_id_len);
	key->cert->key_id[parsed.key_id_len] = '\0';
	key->cert->serial = parsed.serial;
	key->cert->type = parsed.cert_type;
	key->cert->valid_after = parsed.valid_after;
	key->cert->valid_before = parsed.valid_before;
	signed_len = sshbuf_len(key->cert->certblob) - blob_len +
	    parsed.signed_consumed;
	sig = blob + parsed.signature_offset;
	slen = parsed.signature_len;

	if ((principals = sshbuf_from(blob + parsed.principals_offset,
	    parsed.principals_len)) == NULL ||
	    (crit = sshbuf_from(blob + parsed.critical_offset,
	    parsed.critical_len)) == NULL ||
	    (exts = sshbuf_from(blob + parsed.extensions_offset,
	    parsed.extensions_len)) == NULL ||
	    (ca = sshbuf_from(blob + parsed.ca_key_offset,
	    parsed.ca_key_len)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
#else
	/* Parse body of certificate up to signature */
	if ((ret = sshbuf_get_u64(b, &key->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &key->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &key->cert->key_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &key->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &key->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, NULL, NULL)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(key->cert->certblob) - sshbuf_len(b);

	if ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
#endif

	if (key->cert->type != SSH2_CERT_TYPE_USER &&
	    key->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_KEY_CERT_UNKNOWN_TYPE;
		goto out;
	}

	/* Parse principals section */
	while (sshbuf_len(principals) > 0) {
		char *principal = NULL;
		char **oprincipals = NULL;

		if (key->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if ((ret = sshbuf_get_cstring(principals, &principal,
		    NULL)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		oprincipals = key->cert->principals;
		key->cert->principals = recallocarray(key->cert->principals,
		    key->cert->nprincipals, key->cert->nprincipals + 1,
		    sizeof(*key->cert->principals));
		if (key->cert->principals == NULL) {
			free(principal);
			key->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		key->cert->principals[key->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	if ((ret = sshbuf_putb(key->cert->critical, crit)) != 0 ||
	    (exts != NULL &&
	    (ret = sshbuf_putb(key->cert->extensions, exts)) != 0))
		goto out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	while (sshbuf_len(crit) != 0) {
		if ((ret = sshbuf_get_string_direct(crit, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, NULL, NULL)) != 0) {
			sshbuf_reset(key->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	while (exts != NULL && sshbuf_len(exts) != 0) {
		if ((ret = sshbuf_get_string_direct(exts, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, NULL, NULL)) != 0) {
			sshbuf_reset(key->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* Parse CA key and check signature */
	if (sshkey_from_blob_internal(ca, &key->cert->signature_key, 0) != 0) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}
	if (!sshkey_type_is_valid_ca(key->cert->signature_key->type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}
	if ((ret = sshkey_verify(key->cert->signature_key, sig, slen,
	    sshbuf_ptr(key->cert->certblob), signed_len, NULL, 0, NULL)) != 0)
		goto out;
	if ((ret = sshkey_get_sigtype(sig, slen,
	    &key->cert->signature_type)) != 0)
		goto out;

	/* Success */
	ret = 0;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
#ifndef WITH_RUST_CRYPTO
	free(sig);
#endif
	return ret;
}

int
sshkey_deserialize_sk(struct sshbuf *b, struct sshkey *key)
{
	/* Parse additional security-key application string */
	if (sshbuf_get_cstring(b, &key->sk_application, NULL) != 0)
		return SSH_ERR_INVALID_FORMAT;
	return 0;
}

static int
sshkey_from_blob_internal(struct sshbuf *b, struct sshkey **keyp,
    int allow_cert)
{
	int type, ret = SSH_ERR_INTERNAL_ERROR;
	char *ktype = NULL;
	struct sshkey *key = NULL;
	struct sshbuf *copy = NULL, *namebuf = NULL;
	const struct sshkey_impl *impl;
#ifdef WITH_RUST_CRYPTO
	int impl_index = OSSH_RUST_NO_IMPL_INDEX, use_noec_fallback = 0;
#endif

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	if (keyp != NULL)
		*keyp = NULL;
	if ((namebuf = sshbuf_fromb(b)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (sshbuf_get_cstring(namebuf, &ktype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	sshbuf_free(namebuf);
	namebuf = NULL;

#ifdef WITH_RUST_CRYPTO
	ret = ossh_rust_sshkey_from_blob_plan((const u_char *)ktype,
	    strlen(ktype), allow_cert,
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &type, &impl_index, &use_noec_fallback);
	if (ret != 0)
		goto out;
	impl = impl_index == OSSH_RUST_NO_IMPL_INDEX ? NULL : keyimpls[impl_index];
#else
	type = sshkey_type_from_name(ktype);
	if (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}
	impl = sshkey_impl_from_type(type);
	if (impl == NULL && !(key_type_is_ecdsa_variant(type) &&
	    sshkey_type_plain(type) == KEY_ECDSA)) {
		ret = SSH_ERR_KEY_TYPE_UNKNOWN;
		goto out;
	}
#endif
	if (sshkey_type_is_cert(type)) {
		if ((copy = sshbuf_new()) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((ret = sshbuf_putb(copy, b)) != 0)
			goto out;
	}
	if ((ret = sshbuf_skip_string(b)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((key = sshkey_new(type)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		if (sshbuf_get_string_direct(b, NULL, NULL) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	if (impl != NULL)
		ret = impl->funcs->deserialize_public(ktype, b, key);
#ifdef WITH_RUST_CRYPTO
	else if (use_noec_fallback)
		ret = sshkey_ecdsa_deserialize_public_noec(ktype, b, key);
#else
	else
		ret = sshkey_ecdsa_deserialize_public_noec(ktype, b, key);
#endif
	if (ret != 0)
		goto out;

	/* Parse certificate potion */
	if (sshkey_is_cert(key) && (ret = cert_parse(b, key, copy)) != 0)
		goto out;

	if (key != NULL && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ret = 0;
	if (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}
 out:
	sshbuf_free(namebuf);
	sshbuf_free(copy);
	sshkey_free(key);
	free(ktype);
	return ret;
}

int
sshkey_from_blob(const u_char *blob, size_t blen, struct sshkey **keyp)
{
	struct sshbuf *b;
	int r;

	if ((b = sshbuf_from(blob, blen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1);
	sshbuf_free(b);
	return r;
}

int
sshkey_fromb(struct sshbuf *b, struct sshkey **keyp)
{
	return sshkey_from_blob_internal(b, keyp, 1);
}

int
sshkey_froms(struct sshbuf *buf, struct sshkey **keyp)
{
	struct sshbuf *b;
	int r;

	if ((r = sshbuf_froms(buf, &b)) != 0)
		return r;
	r = sshkey_from_blob_internal(b, keyp, 1);
	sshbuf_free(b);
	return r;
}

int
sshkey_get_sigtype(const u_char *sig, size_t siglen, char **sigtypep)
{
	int r;
	struct sshbuf *b = NULL;
	char *sigtype = NULL;

	if (sigtypep != NULL)
		*sigtypep = NULL;
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_get_cstring(b, &sigtype, NULL)) != 0)
		goto out;
	/* success */
	if (sigtypep != NULL) {
		*sigtypep = sigtype;
		sigtype = NULL;
	}
	r = 0;
 out:
	free(sigtype);
	sshbuf_free(b);
	return r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
int
sshkey_check_cert_sigtype(const struct sshkey *key, const char *allowed)
{
	if (key == NULL || allowed == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!sshkey_type_is_cert(key->type))
		return 0;
	if (key->cert == NULL || key->cert->signature_type == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (match_pattern_list(key->cert->signature_type, allowed, 0) != 1)
		return SSH_ERR_SIGN_ALG_UNSUPPORTED;
	return 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
const char *
sshkey_sigalg_by_name(const char *name)
{
	const struct sshkey_impl *impl;
	int i;

#ifdef WITH_RUST_CRYPTO
	const char *sigalg = NULL;

	if (name != NULL &&
	    ossh_rust_sshkey_sigalg_by_name((const u_char *)name, strlen(name),
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &sigalg) == 0 && sigalg != NULL)
		return sigalg;
#endif /* WITH_RUST_CRYPTO */

	for (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		if (strcmp(impl->name, name) != 0)
			continue;
		if (impl->sigalg != NULL)
			return impl->sigalg;
		if (!impl->cert)
			return impl->name;
		return sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	return NULL;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
int
sshkey_check_sigtype(const u_char *sig, size_t siglen,
    const char *requested_alg)
{
	const char *expected_alg;
	char *sigtype = NULL;
	int r;

	if (requested_alg == NULL)
		return 0;
	if ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		return r;
	r = strcmp(expected_alg, sigtype) == 0;
	free(sigtype);
	return r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
sshkey_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	int was_shielded = sshkey_is_shielded(key);
	int r2, r = SSH_ERR_INTERNAL_ERROR;
	const struct sshkey_impl *impl;

	if (sigp != NULL)
		*sigp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if (datalen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((impl = sshkey_impl_from_key(key)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	if ((r = sshkey_unshield_private(key)) != 0)
		return r;
	if (sshkey_is_sk(key)) {
		r = sshsk_sign(sk_provider, key, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} else if ((key->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(key, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} else {
		if (impl->funcs->sign == NULL)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		else {
			r = impl->funcs->sign(key, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	if (was_shielded && (r2 = sshkey_shield_private(key)) != 0)
		return r2;
	return r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
int
sshkey_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	const struct sshkey_impl *impl;

	if (detailsp != NULL)
		*detailsp = NULL;
	if (siglen == 0 || dlen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((impl = sshkey_impl_from_key(key)) == NULL)
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	return impl->funcs->verify(key, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
int
sshkey_to_certified(struct sshkey *k)
{
	int newtype;

	if ((newtype = sshkey_type_certified(k->type)) == -1)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((k->cert = cert_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	return 0;
}

/* Convert a certificate to its raw key equivalent */
int
sshkey_drop_cert(struct sshkey *k)
{
	if (!sshkey_type_is_cert(k->type))
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = NULL;
	k->type = sshkey_type_plain(k->type);
	return 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
int
sshkey_certify_custom(struct sshkey *k, struct sshkey *ca, const char *alg,
    const char *sk_provider, const char *sk_pin,
    sshkey_certify_signer *signer, void *signer_ctx)
{
	const struct sshkey_impl *impl;
	struct sshbuf *principals = NULL;
	u_char *ca_blob = NULL, *sig_blob = NULL, nonce[32];
	size_t i, ca_len, sig_len;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *cert = NULL;
	char *sigtype = NULL;

	if (k == NULL || k->cert == NULL ||
	    k->cert->certblob == NULL || ca == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!sshkey_is_cert(k))
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	if (!sshkey_type_is_valid_ca(ca->type))
		return SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
	if ((impl = sshkey_impl_from_key(k)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	if (alg == NULL)
		alg = k->cert->signature_type;
	else if (k->cert->signature_type != NULL &&
	    strcmp(alg, k->cert->signature_type) != 0)
		return SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	if (alg == NULL && ca->type == KEY_RSA)
		alg = "rsa-sha2-512";

	if ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		return SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	if ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		goto out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, sizeof(nonce));
	if ((ret = sshbuf_put_string(cert, nonce, sizeof(nonce))) != 0)
		goto out;

	/* Public key next */
	if ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		goto out;

	/* Then remaining cert fields */
	if ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->key_id)) != 0)
		goto out;

	if ((principals = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	for (i = 0; i < k->cert->nprincipals; i++) {
		if ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			goto out;
	}
	if ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, NULL, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		goto out;

	/* Sign the whole mess */
	if ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		goto out;
	/* Check and update signature_type against what was actually used */
	if ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		goto out;
	if (alg != NULL && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		goto out;
	}
	if (k->cert->signature_type == NULL) {
		k->cert->signature_type = sigtype;
		sigtype = NULL;
	}
	/* Append signature and we are done */
	if ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		goto out;
	ret = 0;
 out:
	if (ret != 0)
		sshbuf_reset(cert);
	free(sig_blob);
	free(ca_blob);
	free(sigtype);
	sshbuf_free(principals);
	return ret;
}

static int
default_key_sign(struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin,
    u_int compat, void *ctx)
{
	if (ctx != NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	return sshkey_sign(key, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

int
sshkey_certify(struct sshkey *k, struct sshkey *ca, const char *alg,
    const char *sk_provider, const char *sk_pin)
{
	return sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_key_sign, NULL);
}

int
sshkey_cert_check_authority(const struct sshkey *k,
    int want_host, int wildcard_pattern, uint64_t verify_time,
    const char *name, const char **reason)
{
	u_int i, principal_matches;

	if (reason == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if (want_host) {
		if (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			return SSH_ERR_KEY_CERT_INVALID;
		}
	} else {
		if (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			return SSH_ERR_KEY_CERT_INVALID;
		}
	}
	if (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if (name == NULL)
		return 0; /* principal matching not requested */

	principal_matches = 0;
	for (i = 0; i < k->cert->nprincipals; i++) {
		if (wildcard_pattern) {
			if (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				break;
			}
		} else if (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			break;
		}
	}
	if (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	return 0;
}

int
sshkey_cert_check_authority_now(const struct sshkey *k,
    int want_host, int wildcard_pattern, const char *name,
    const char **reason)
{
	time_t now;

	if ((now = time(NULL)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	return sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

int
sshkey_cert_check_host(const struct sshkey *key, const char *host,
    const char *ca_sign_algorithms, const char **reason)
{
	int r;

	if ((r = sshkey_cert_check_authority_now(key, 1, 1, host, reason)) != 0)
		return r;
	if (sshbuf_len(key->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	if (ca_sign_algorithms != NULL &&
	    (r = sshkey_check_cert_sigtype(key, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		return SSH_ERR_KEY_CERT_INVALID;
	}
	return 0;
}

size_t
sshkey_format_cert_validity(const struct sshkey_cert *cert, char *s, size_t l)
{
	char from[32], to[32], ret[128];

	*from = *to = '\0';
	if (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		return strlcpy(s, "forever", l);

	if (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, sizeof(from));
	if (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, sizeof(to));

	if (cert->valid_after == 0)
		snprintf(ret, sizeof(ret), "before %s", to);
	else if (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, sizeof(ret), "after %s", from);
	else
		snprintf(ret, sizeof(ret), "from %s to %s", from, to);

	return strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
int
sshkey_serialize_private_sk(const struct sshkey *key, struct sshbuf *b)
{
	int r;

	if ((r = sshbuf_put_cstring(b, key->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, key->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, key->sk_key_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, key->sk_reserved)) != 0)
		return r;

	return 0;
}

static int
sshkey_private_serialize_opt(struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	int r = SSH_ERR_INTERNAL_ERROR;
	int was_shielded = sshkey_is_shielded(key);
	struct sshbuf *b = NULL;
	const struct sshkey_impl *impl;
#ifdef WITH_RUST_CRYPTO
	int impl_index = OSSH_RUST_NO_IMPL_INDEX;
#endif

	if (key == NULL)
		return SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_RUST_CRYPTO
	r = ossh_rust_sshkey_private_serialize_plan(key->type, key->ecdsa_nid,
	    key->cert != NULL, key->cert == NULL ? 0 : sshbuf_len(key->cert->certblob),
	    (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &impl_index);
	if (r == -1)
		return SSH_ERR_INTERNAL_ERROR;
	if (r != 0)
		return r;
	impl = keyimpls[impl_index];
#else
	if ((impl = sshkey_impl_from_key(key)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;
#endif
	if ((r = sshkey_unshield_private(key)) != 0)
		return r;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put_cstring(b, sshkey_ssh_name(key))) != 0)
		goto out;
#ifndef WITH_RUST_CRYPTO
	if (sshkey_is_cert(key)) {
		if (key->cert == NULL ||
		    sshbuf_len(key->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
	}
#endif
	if (sshkey_is_cert(key)) {
		if ((r = sshbuf_put_stringb(b, key->cert->certblob)) != 0)
			goto out;
	}
	if ((r = impl->funcs->serialize_private(key, b, opts)) != 0)
		goto out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	if (was_shielded)
		r = sshkey_shield_private(key);
	if (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	return r;
}

int
sshkey_private_serialize(struct sshkey *key, struct sshbuf *b)
{
	return sshkey_private_serialize_opt(key, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
int
sshkey_private_deserialize_sk(struct sshbuf *buf, struct sshkey *k)
{
	int r;

	if ((k->sk_key_handle = sshbuf_new()) == NULL ||
	    (k->sk_reserved = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_get_cstring(buf, &k->sk_application, NULL)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_key_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		return r;

	return 0;
}

int
sshkey_private_deserialize(struct sshbuf *buf, struct sshkey **kp)
{
	const struct sshkey_impl *impl;
	char *tname = NULL;
	char *expect_sk_application = NULL;
	u_char *expect_ed25519_pk = NULL;
	struct sshkey *k = NULL;
	int type, r = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_RUST_CRYPTO
	int is_cert = 0, impl_index = OSSH_RUST_NO_IMPL_INDEX,
	    expected_cert_nid = -1;
#endif

	if (kp != NULL)
		*kp = NULL;
	if ((r = sshbuf_get_cstring(buf, &tname, NULL)) != 0)
		goto out;
#ifdef WITH_RUST_CRYPTO
	r = ossh_rust_sshkey_private_deserialize_plan((const u_char *)tname,
	    strlen(tname), (const struct ossh_rust_sshkey_impl * const *)keyimpls,
	    keyimpl_nentries(), &type, &is_cert, &impl_index,
	    &expected_cert_nid);
	if (r != 0)
		goto out;
	if (is_cert) {
#else
	type = sshkey_type_from_name(tname);
	if (sshkey_type_is_cert(type)) {
#endif
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		if ((r = sshkey_froms(buf, &k)) != 0)
			goto out;
		if (k->type != type) {
			r = SSH_ERR_KEY_CERT_MISMATCH;
			goto out;
		}
		/* For ECDSA keys, the group must match too */
		if (k->type == KEY_ECDSA &&
		    k->ecdsa_nid !=
#ifdef WITH_RUST_CRYPTO
		    expected_cert_nid
#else
		    sshkey_ecdsa_nid_from_name(tname)
#endif
		    ) {
			r = SSH_ERR_KEY_CERT_MISMATCH;
			goto out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = NULL;
		k->ed25519_pk = NULL;
	} else {
		if ((k = sshkey_new(type)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
	}
#ifdef WITH_RUST_CRYPTO
	impl = impl_index == OSSH_RUST_NO_IMPL_INDEX ? NULL : keyimpls[impl_index];
#else
	if ((impl = sshkey_impl_from_type(type)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
#endif
	if (impl == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		goto out;

	if ((expect_sk_application != NULL && (k->sk_application == NULL ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != NULL && (k->ed25519_pk == NULL ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}
	/* success */
	r = 0;
	if (kp != NULL) {
		*kp = k;
		k = NULL;
	}
 out:
	free(tname);
	sshkey_free(k);
	free(expect_sk_application);
	free(expect_ed25519_pk);
	return r;
}

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)
int
sshkey_ec_validate_public(const EC_GROUP *group, const EC_POINT *public)
{
	EC_POINT *nq = NULL;
	BIGNUM *order = NULL, *cofactor = NULL;
	int ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	if (EC_POINT_is_at_infinity(group, public))
		goto out;

	if ((cofactor = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_GROUP_get_cofactor(group, cofactor, NULL) != 1)
		goto out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	if (!BN_is_one(cofactor)) {
		if ((order = BN_new()) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if (EC_GROUP_get_order(group, order, NULL) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		if ((nq = EC_POINT_new(group)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if (EC_POINT_mul(group, nq, NULL, public, order, NULL) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		if (EC_POINT_is_at_infinity(group, nq) != 1)
			goto out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	return ret;
}

int
sshkey_ec_validate_private(const EC_KEY *key)
{
	BIGNUM *order = NULL, *tmp = NULL;
	int ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	if ((order = BN_new()) == NULL || (tmp = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* log2(private) > log2(order)/2 */
	if (EC_GROUP_get_order(EC_KEY_get0_group(key), order, NULL) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_num_bits(EC_KEY_get0_private_key(key)) <=
	    BN_num_bits(order) / 2)
		goto out;

	/* private < order - 1 */
	if (!BN_sub(tmp, order, BN_value_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_cmp(EC_KEY_get0_private_key(key), tmp) >= 0)
		goto out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	return ret;
}

void
sshkey_dump_ec_point(const EC_GROUP *group, const EC_POINT *point)
{
	BIGNUM *x = NULL, *y = NULL;

	if (point == NULL) {
		fputs("point=(NULL)\n", stderr);
		return;
	}
	if ((x = BN_new()) == NULL || (y = BN_new()) == NULL) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		goto out;
	}
	if (EC_POINT_get_affine_coordinates(group, point, x, y, NULL) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		goto out;
	}
	fputs("x=", stderr);
	BN_print_fp(stderr, x);
	fputs("\ny=", stderr);
	BN_print_fp(stderr, y);
	fputs("\n", stderr);
 out:
	BN_clear_free(x);
	BN_clear_free(y);
}

void
sshkey_dump_ec_key(const EC_KEY *key)
{
	const BIGNUM *exponent;

	sshkey_dump_ec_point(EC_KEY_get0_group(key),
	    EC_KEY_get0_public_key(key));
	fputs("exponent=", stderr);
	if ((exponent = EC_KEY_get0_private_key(key)) == NULL)
		fputs("(NULL)", stderr);
	else
		BN_print_fp(stderr, EC_KEY_get0_private_key(key));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL && OPENSSL_HAS_ECC */

static int
sshkey_private_to_blob2(struct sshkey *prv, struct sshbuf *blob,
    const char *passphrase, const char *comment, const char *ciphername,
    int rounds)
{
	u_char *cp, *key = NULL, *pubkeyblob = NULL;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshcipher_ctx *ciphercontext = NULL;
	const struct sshcipher *cipher;
	const char *kdfname = KDFNAME;
	struct sshbuf *encoded = NULL, *encrypted = NULL, *kdf = NULL;

	if (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	if (passphrase == NULL || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} else if (ciphername == NULL)
		ciphername = DEFAULT_CIPHERNAME;
	if ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	if ((kdf = sshbuf_new()) == NULL ||
	    (encoded = sshbuf_new()) == NULL ||
	    (encrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	if ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		if (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			goto out;
	} else if (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	if ((r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 1)) != 0)
		goto out;

	if ((r = sshbuf_put(encoded, AUTH_MAGIC, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		goto out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	if ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		goto out;

	/* append private key and comment*/
	if ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		goto out;

	/* padding */
	i = 0;
	while (sshbuf_len(encrypted) % blocksize) {
		if ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			goto out;
	}

	/* length in destination buffer */
	if ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		goto out;

	/* encrypt */
	if ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		goto out;
	if ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		goto out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	if ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		goto out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, sizeof(salt));
	if (key != NULL)
		freezero(key, keylen + ivlen);
	if (pubkeyblob != NULL)
		freezero(pubkeyblob, pubkeylen);
	return r;
}

static int
private2_uudecode(struct sshbuf *blob, struct sshbuf **decodedp)
{
#ifdef WITH_RUST_CRYPTO
	size_t decoded_len;
	u_char *dp;
	int r;
	struct sshbuf *decoded = NULL;

	if (blob == NULL || decodedp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	*decodedp = NULL;

	if ((decoded = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((decoded_len = ossh_rust_private2_decode_len(sshbuf_ptr(blob),
	    sshbuf_len(blob))) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((r = sshbuf_reserve(decoded, decoded_len, &dp)) != 0)
		goto out;
	if (ossh_rust_private2_decode_write(sshbuf_ptr(blob), sshbuf_len(blob),
	    dp, decoded_len) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	*decodedp = decoded;
	decoded = NULL;
	r = 0;
 out:
	sshbuf_free(decoded);
	return r;
#else
	const u_char *cp;
	size_t encoded_len;
	int r;
	u_char last;
	struct sshbuf *encoded = NULL, *decoded = NULL;

	if (blob == NULL || decodedp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	*decodedp = NULL;

	if ((encoded = sshbuf_new()) == NULL ||
	    (decoded = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	if (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	while (encoded_len > 0) {
		if (*cp != '\n' && *cp != '\r') {
			if ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				goto out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		if (last == '\n') {
			if (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				if ((r = sshbuf_put_u8(encoded, 0)) != 0)
					goto out;
				break;
			}
		}
	}
	if (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decode base64 */
	if ((r = sshbuf_b64tod(decoded, (char *)sshbuf_ptr(encoded))) != 0)
		goto out;

	/* check magic */
	if (sshbuf_len(decoded) < sizeof(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, sizeof(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	*decodedp = decoded;
	decoded = NULL;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	return r;
#endif
}

static int
private2_decrypt(struct sshbuf *decoded, const char *passphrase,
    struct sshbuf **decryptedp, struct sshkey **pubkeyp)
{
#ifdef WITH_RUST_CRYPTO
	struct ossh_rust_private2_header_parse parsed;
	const u_char *blob;
	const char *ciphername;
	const struct sshcipher *cipher = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	struct sshbuf *decrypted = NULL;
	struct sshcipher_ctx *ciphercontext = NULL;
	struct sshkey *pubkey = NULL;
	u_char *key = NULL, *salt = NULL, *dp;
	u_int blocksize, rounds, encrypted_len, check1, check2;

	if (decoded == NULL || decryptedp == NULL || pubkeyp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = NULL;
	*pubkeyp = NULL;

	if ((decrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (ossh_rust_private2_parse_header(sshbuf_ptr(decoded),
	    sshbuf_len(decoded), &parsed) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	blob = sshbuf_ptr(decoded);
	ciphername = (const char *)(blob + parsed.ciphername_offset);
	encrypted_len = parsed.encrypted_len;

	if ((r = sshkey_from_blob(blob + parsed.public_key_offset,
	    parsed.public_key_len, &pubkey)) != 0)
		goto out;

	if ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	if (parsed.kdf_kind != OSSH_RUST_PRIVATE2_KDF_NONE &&
	    parsed.kdf_kind != OSSH_RUST_PRIVATE2_KDF_BCRYPT) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	if (parsed.kdf_kind == OSSH_RUST_PRIVATE2_KDF_NONE &&
	    strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((passphrase == NULL || strlen(passphrase) == 0) &&
	    parsed.kdf_kind != OSSH_RUST_PRIVATE2_KDF_NONE) {
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}

	blocksize = cipher_blocksize(cipher);
	if (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	if ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (parsed.kdf_kind == OSSH_RUST_PRIVATE2_KDF_BCRYPT) {
		slen = parsed.bcrypt_salt_len;
		rounds = parsed.bcrypt_rounds;
		if ((salt = malloc(slen)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(salt, blob + parsed.bcrypt_salt_offset, slen);
		if (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	if (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < parsed.encrypted_offset + encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(decoded) != parsed.encrypted_offset + encrypted_len + authlen) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 0)) != 0)
		goto out;
	if ((r = cipher_crypt(ciphercontext, 0, dp,
	    blob + parsed.encrypted_offset, encrypted_len, 0, authlen)) != 0) {
		if (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	if ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		goto out;
	if (check1 != check2) {
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}

	*decryptedp = decrypted;
	decrypted = NULL;
	*pubkeyp = pubkey;
	pubkey = NULL;
	r = 0;
 out:
	cipher_free(ciphercontext);
	sshkey_free(pubkey);
	if (salt != NULL) {
		explicit_bzero(salt, slen);
		free(salt);
	}
	if (key != NULL) {
		explicit_bzero(key, keylen + ivlen);
		free(key);
	}
	sshbuf_free(decrypted);
	return r;
#else
	char *ciphername = NULL, *kdfname = NULL;
	const struct sshcipher *cipher = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	struct sshbuf *kdf = NULL, *decrypted = NULL;
	struct sshcipher_ctx *ciphercontext = NULL;
	struct sshkey *pubkey = NULL;
	u_char *key = NULL, *salt = NULL, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	if (decoded == NULL || decryptedp == NULL || pubkeyp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = NULL;
	*pubkeyp = NULL;

	if ((decrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* parse public portion of key */
	if ((r = sshbuf_consume(decoded, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, NULL)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	if (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		goto out;

	if ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	if (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	if (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((passphrase == NULL || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	if (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	if ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (strcmp(kdfname, "bcrypt") == 0) {
		if ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			goto out;
		if (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	if (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decrypt private portion of key */
	if ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 0)) != 0)
		goto out;
	if ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		if (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	if ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		goto out;
	/* there should be no trailing data */
	if (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* check check bytes */
	if ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		goto out;
	if (check1 != check2) {
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = NULL;
	*pubkeyp = pubkey;
	pubkey = NULL;
	r = 0;
 out:
	cipher_free(ciphercontext);
	free(ciphername);
	free(kdfname);
	sshkey_free(pubkey);
	if (salt != NULL) {
		explicit_bzero(salt, slen);
		free(salt);
	}
	if (key != NULL) {
		explicit_bzero(key, keylen + ivlen);
		free(key);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	return r;
#endif
}

#ifdef WITH_RUST_CRYPTO
static int
sshkey_rust_private2_copy_comment(const u_char *decrypted_start,
    size_t decrypted_len, const struct ossh_rust_private2_plaintext_parse *parsed,
    char **commentp)
{
	char *comment;

	if (commentp != NULL)
		*commentp = NULL;
	if (parsed->comment_offset + 4 + parsed->comment_len > decrypted_len)
		return SSH_ERR_INVALID_FORMAT;
	if ((comment = calloc(1, parsed->comment_len + 1)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	memcpy(comment, decrypted_start + parsed->comment_offset + 4,
	    parsed->comment_len);
	if (commentp != NULL)
		*commentp = comment;
	else
		free(comment);
	return 0;
}

static int
sshkey_rust_private2_deserialize(const u_char *decrypted_start,
    size_t decrypted_len, const struct ossh_rust_private2_plaintext_parse *parsed,
    struct sshkey **kp, char **commentp)
{
	struct sshkey *k = NULL;
	char *comment = NULL;
	u_char derived_pk[ED25519_PK_SZ];
	u_char ecdsa_public[133], ecdsa_private[66];
	u_char *rsa_n = NULL, *rsa_e = NULL;
	size_t rsa_n_len = 0, rsa_e_len = 0;
	size_t ecdsa_public_len = 0, ecdsa_private_len = 0;
	void *rust_key = NULL;
	const u_char *pk, *sk, *private_key;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (kp != NULL)
		*kp = NULL;
	if (commentp != NULL)
		*commentp = NULL;
	memset(derived_pk, 0, sizeof(derived_pk));
	memset(ecdsa_public, 0, sizeof(ecdsa_public));
	memset(ecdsa_private, 0, sizeof(ecdsa_private));

	if ((r = sshkey_rust_private2_copy_comment(decrypted_start, decrypted_len,
	    parsed, &comment)) != 0)
		goto out;
	if (parsed->is_cert != 0) {
		if (parsed->cert_offset + parsed->cert_len > decrypted_len) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if ((r = sshkey_from_blob(decrypted_start + parsed->cert_offset,
		    parsed->cert_len, &k)) != 0)
			goto out;
	}
	switch (parsed->key_kind) {
	case OSSH_RUST_PRIVATE2_KEY_ED25519:
		if (parsed->part1_len != ED25519_PK_SZ ||
		    parsed->part2_len != ED25519_SK_SZ ||
		    parsed->part1_offset + parsed->part1_len > decrypted_len ||
		    parsed->part2_offset + parsed->part2_len > decrypted_len) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		pk = decrypted_start + parsed->part1_offset;
		sk = decrypted_start + parsed->part2_offset;
		if (ossh_rust_ed25519_public_from_seed(sk, 32, derived_pk,
		    sizeof(derived_pk)) != 0 ||
		    timingsafe_bcmp(pk, derived_pk, ED25519_PK_SZ) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if (parsed->is_cert != 0) {
			if (k == NULL || k->type != KEY_ED25519_CERT ||
			    k->ed25519_pk == NULL ||
			    timingsafe_bcmp(pk, k->ed25519_pk,
			    ED25519_PK_SZ) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
		} else {
			if ((k = sshkey_new(KEY_ED25519)) == NULL) {
				r = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
			if ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == NULL) {
				r = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
			memcpy(k->ed25519_pk, pk, ED25519_PK_SZ);
		}
		if ((k->ed25519_sk = malloc(ED25519_SK_SZ)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(k->ed25519_sk, sk, ED25519_SK_SZ);
		break;
	case OSSH_RUST_PRIVATE2_KEY_ECDSA:
		if ((ecdsa_private_len = sshkey_curve_nid_to_bits(parsed->curve_nid)) == 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ecdsa_private_len = (ecdsa_private_len + 7) / 8;
		if ((ecdsa_public_len = 1 + 2 * ecdsa_private_len) > sizeof(ecdsa_public) ||
		    ecdsa_private_len > sizeof(ecdsa_private) ||
		    parsed->part2_offset + parsed->part2_len > decrypted_len ||
		    parsed->part2_len > ecdsa_private_len) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if (parsed->is_cert != 0) {
			if (k == NULL || sshkey_type_plain(k->type) != KEY_ECDSA ||
			    k->ecdsa_nid != parsed->curve_nid ||
			    ossh_rust_ecdsa_export_public(k->pkey,
			    ecdsa_public, ecdsa_public_len) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
		} else {
			if (parsed->part1_offset + parsed->part1_len > decrypted_len ||
			    parsed->part1_len != ecdsa_public_len) {
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			memcpy(ecdsa_public, decrypted_start + parsed->part1_offset,
			    ecdsa_public_len);
			if ((k = sshkey_new(KEY_ECDSA)) == NULL) {
				r = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
			k->ecdsa_nid = parsed->curve_nid;
		}
		private_key = decrypted_start + parsed->part2_offset;
		memcpy(ecdsa_private + (ecdsa_private_len - parsed->part2_len),
		    private_key, parsed->part2_len);
		if ((rust_key = ossh_rust_ecdsa_from_private(parsed->curve_nid,
		    ecdsa_public, ecdsa_public_len, ecdsa_private,
		    ecdsa_private_len)) == NULL) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ossh_rust_ecdsa_free(k->pkey);
		k->pkey = rust_key;
		rust_key = NULL;
		break;
	case OSSH_RUST_PRIVATE2_KEY_RSA:
		if (parsed->is_cert != 0) {
			if (k == NULL || sshkey_type_plain(k->type) != KEY_RSA ||
			    (rsa_n_len = ossh_rust_rsa_component_len(k->pkey,
			    OSSH_RUST_RSA_COMPONENT_N)) == 0 ||
			    (rsa_e_len = ossh_rust_rsa_component_len(k->pkey,
			    OSSH_RUST_RSA_COMPONENT_E)) == 0 ||
			    (rsa_n = calloc(1, rsa_n_len)) == NULL ||
			    (rsa_e = calloc(1, rsa_e_len)) == NULL ||
			    ossh_rust_rsa_export_component(k->pkey,
			    OSSH_RUST_RSA_COMPONENT_N, rsa_n, rsa_n_len) != 0 ||
			    ossh_rust_rsa_export_component(k->pkey,
			    OSSH_RUST_RSA_COMPONENT_E, rsa_e, rsa_e_len) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
		} else {
			if (parsed->part1_offset + parsed->part1_len > decrypted_len ||
			    parsed->part2_offset + parsed->part2_len > decrypted_len) {
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			rsa_n = calloc(1, parsed->part1_len);
			rsa_e = calloc(1, parsed->part2_len);
			if (rsa_n == NULL || rsa_e == NULL) {
				r = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
			memcpy(rsa_n, decrypted_start + parsed->part1_offset,
			    parsed->part1_len);
			memcpy(rsa_e, decrypted_start + parsed->part2_offset,
			    parsed->part2_len);
			rsa_n_len = parsed->part1_len;
			rsa_e_len = parsed->part2_len;
			if ((k = sshkey_new(KEY_RSA)) == NULL) {
				r = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
		}
		if (parsed->part3_offset + parsed->part3_len > decrypted_len ||
		    parsed->part4_offset + parsed->part4_len > decrypted_len ||
		    parsed->part5_offset + parsed->part5_len > decrypted_len ||
		    parsed->part6_offset + parsed->part6_len > decrypted_len) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if ((rust_key = ossh_rust_rsa_from_private(rsa_n, rsa_n_len,
		    rsa_e, rsa_e_len, decrypted_start + parsed->part3_offset,
		    parsed->part3_len, decrypted_start + parsed->part4_offset,
		    parsed->part4_len, decrypted_start + parsed->part5_offset,
		    parsed->part5_len, decrypted_start + parsed->part6_offset,
		    parsed->part6_len)) == NULL) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ossh_rust_rsa_free(k->pkey);
		k->pkey = rust_key;
		rust_key = NULL;
		if ((r = sshkey_check_rsa_length(k, 0)) != 0)
			goto out;
		break;
	default:
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	r = 0;
	if (kp != NULL) {
		*kp = k;
		k = NULL;
	}
	if (commentp != NULL) {
		*commentp = comment;
		comment = NULL;
	}
 out:
	explicit_bzero(derived_pk, sizeof(derived_pk));
	explicit_bzero(ecdsa_public, sizeof(ecdsa_public));
	explicit_bzero(ecdsa_private, sizeof(ecdsa_private));
	freezero(rsa_n, rsa_n_len);
	freezero(rsa_e, rsa_e_len);
	free(comment);
	sshkey_free(k);
	if (rust_key != NULL) {
		if (parsed->key_kind == OSSH_RUST_PRIVATE2_KEY_ECDSA)
			ossh_rust_ecdsa_free(rust_key);
		else if (parsed->key_kind == OSSH_RUST_PRIVATE2_KEY_RSA)
			ossh_rust_rsa_free(rust_key);
	}
	return r;
}
#endif

static int
sshkey_parse_private2(struct sshbuf *blob, int type, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	char *comment = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *decoded = NULL, *decrypted = NULL;
	struct sshkey *k = NULL, *pubkey = NULL;
#ifdef WITH_RUST_CRYPTO
	struct ossh_rust_private2_plaintext_parse parsed;
	const u_char *decrypted_start = NULL;
	size_t decrypted_len = 0;
#endif

	if (keyp != NULL)
		*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	/* Undo base64 encoding and decrypt the private section */
	if ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		goto out;

	if (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

#ifdef WITH_RUST_CRYPTO
	decrypted_start = sshbuf_ptr(decrypted);
	decrypted_len = sshbuf_len(decrypted);
	if (ossh_rust_private2_parse_plaintext(decrypted_start, decrypted_len,
	    &parsed) == 0) {
		r = sshkey_rust_private2_deserialize(decrypted_start, decrypted_len,
		    &parsed, &k, &comment);
		if (r != 0)
			goto out;
	}
#endif

	/* Load the private key and comment */
	if (k == NULL &&
	    ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, NULL)) != 0 ||
	    (r = private2_check_padding(decrypted)) != 0))
		goto out;

	/* Check that the public key in the envelope matches the private key */
	if (!sshkey_equal_public(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* success */
	r = 0;
	if (keyp != NULL) {
		*keyp = k;
		k = NULL;
	}
	if (commentp != NULL) {
		*commentp = comment;
		comment = NULL;
	}
 out:
	free(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	return r;
}

static int
sshkey_parse_private2_pubkey(struct sshbuf *blob, int type,
    struct sshkey **keyp)
{
#ifdef WITH_RUST_CRYPTO
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *decoded = NULL;
	struct sshkey *pubkey = NULL;
	struct ossh_rust_private2_header_parse parsed;
	const u_char *cp;

	if (keyp != NULL)
		*keyp = NULL;

	if ((r = private2_uudecode(blob, &decoded)) != 0)
		goto out;
	if (ossh_rust_private2_parse_header(sshbuf_ptr(decoded),
	    sshbuf_len(decoded), &parsed) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	cp = sshbuf_ptr(decoded);
	if ((r = sshkey_from_blob(cp + parsed.public_key_offset,
	    parsed.public_key_len, &pubkey)) != 0)
		goto out;

	if (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	r = 0;
	if (keyp != NULL) {
		*keyp = pubkey;
		pubkey = NULL;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	return r;
#else
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *decoded = NULL;
	struct sshkey *pubkey = NULL;
	u_int nkeys = 0;

	if (keyp != NULL)
		*keyp = NULL;

	if ((r = private2_uudecode(blob, &decoded)) != 0)
		goto out;
	/* parse public key from unencrypted envelope */
	if ((r = sshbuf_consume(decoded, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	if (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Parse the public key */
	if ((r = sshkey_froms(decoded, &pubkey)) != 0)
		goto out;

	if (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	/* success */
	r = 0;
	if (keyp != NULL) {
		*keyp = pubkey;
		pubkey = NULL;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	return r;
#endif
}

#if defined(WITH_OPENSSL) || defined(WITH_RUST_CRYPTO)
/* convert SSH v2 key to PEM or PKCS#8 format */
static int
sshkey_private_to_blob_pem_pkcs8(struct sshkey *key, struct sshbuf *buf,
    int format, const char *_passphrase, const char *comment)
{
#ifdef WITH_RUST_CRYPTO
	struct sshbuf *blob;
	size_t pem_len;
	int r;
	(void)comment;

	if (_passphrase != NULL && *_passphrase != '\0')
		return SSH_ERR_INVALID_FORMAT;
	if ((blob = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	switch (key->type) {
	case KEY_ECDSA:
		pem_len = ossh_rust_ecdsa_private_pem_len(key->pkey, format);
		if (pem_len == 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if ((r = sshbuf_reserve(blob, pem_len, NULL)) != 0)
			goto out;
		if (ossh_rust_ecdsa_private_pem_write(key->pkey, format,
		    sshbuf_mutable_ptr(blob), pem_len) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		break;
	case KEY_RSA:
		pem_len = ossh_rust_rsa_private_pem_len(key->pkey, format);
		if (pem_len == 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if ((r = sshbuf_reserve(blob, pem_len, NULL)) != 0)
			goto out;
		if (ossh_rust_rsa_private_pem_write(key->pkey, format,
		    sshbuf_mutable_ptr(blob), pem_len) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		break;
	default:
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	r = sshbuf_putb(buf, blob);
 out:
	sshbuf_free(blob);
	return r;
#else
	int was_shielded = sshkey_is_shielded(key);
	int success, r;
	int blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : NULL;
	const EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : NULL;
	char *bptr;
	BIO *bio = NULL;
	struct sshbuf *blob;
	EVP_PKEY *pkey = NULL;

	if (len > 0 && len <= 4)
		return SSH_ERR_PASSPHRASE_TOO_SHORT;
	if ((blob = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_unshield_private(key)) != 0)
		goto out;

	switch (key->type) {
#ifdef OPENSSL_HAS_ECC
	case KEY_ECDSA:
		if (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivateKey(bio,
			    EVP_PKEY_get0_EC_KEY(key->pkey),
			    cipher, passphrase, len, NULL, NULL);
		} else {
			pkey = key->pkey;
			EVP_PKEY_up_ref(key->pkey);
			success = 1;
		}
		break;
#endif
	case KEY_RSA:
		if (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivateKey(bio,
			    EVP_PKEY_get0_RSA(key->pkey),
			    cipher, passphrase, len, NULL, NULL);
		} else {
			pkey = key->pkey;
			EVP_PKEY_up_ref(key->pkey);
			success = 1;
		}
		break;
#ifdef OPENSSL_HAS_ED25519
	case KEY_ED25519:
		if (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		} else {
			pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,
			    NULL, key->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != NULL;
		}
		break;
#endif
	default:
		success = 0;
		break;
	}
	if (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (format == SSHKEY_PRIVATE_PKCS8) {
		if ((success = PEM_write_bio_PrivateKey(bio, pkey, cipher,
		    passphrase, len, NULL, NULL)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
	if ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((r = sshbuf_put(blob, bptr, blen)) != 0)
		goto out;
	r = 0;
 out:
	if (was_shielded)
		r = sshkey_shield_private(key);
	if (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	return r;
#endif /* WITH_RUST_CRYPTO */
}
#endif /* WITH_OPENSSL || WITH_RUST_CRYPTO */

/* Serialise "key" to buffer "blob" */
int
sshkey_private_to_fileblob(struct sshkey *key, struct sshbuf *blob,
    const char *passphrase, const char *comment,
    int format, const char *openssh_format_cipher, int openssh_format_rounds)
{
	switch (key->type) {
#ifdef WITH_OPENSSL
	case KEY_ECDSA:
	case KEY_RSA:
	case KEY_ED25519:
		break;
#elif defined(WITH_RUST_CRYPTO)
	case KEY_ECDSA:
	case KEY_RSA:
	case KEY_ED25519:
		break; /* see below */
#else /* WITH_OPENSSL */
	case KEY_ED25519:
#endif /* WITH_OPENSSL */
	case KEY_ED25519_SK:
#ifdef WITH_OPENSSL
	case KEY_ECDSA_SK:
#endif /* WITH_OPENSSL */
	case KEY_MLDSA44_ED25519:
		return sshkey_private_to_blob2(key, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	switch (format) {
	case SSHKEY_PRIVATE_OPENSSH:
		return sshkey_private_to_blob2(key, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	case SSHKEY_PRIVATE_PEM:
	case SSHKEY_PRIVATE_PKCS8:
		return sshkey_private_to_blob_pem_pkcs8(key, blob,
		    format, passphrase, comment);
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
#elif defined(WITH_RUST_CRYPTO)
	switch (format) {
	case SSHKEY_PRIVATE_OPENSSH:
		return sshkey_private_to_blob2(key, blob, passphrase, comment,
		    openssh_format_cipher, openssh_format_rounds);
	case SSHKEY_PRIVATE_PEM:
	case SSHKEY_PRIVATE_PKCS8:
		return sshkey_private_to_blob_pem_pkcs8(key, blob,
		    format, passphrase, comment);
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
static int
translate_libcrypto_error(unsigned long pem_err)
{
	int pem_reason = ERR_GET_REASON(pem_err);

	switch (ERR_GET_LIB(pem_err)) {
	case ERR_LIB_PEM:
		switch (pem_reason) {
		case PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		case PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		case PEM_R_BAD_DECRYPT:
#endif
			return SSH_ERR_KEY_WRONG_PASSPHRASE;
		default:
			return SSH_ERR_INVALID_FORMAT;
		}
	case ERR_LIB_EVP:
		switch (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		case EVP_R_BAD_DECRYPT:
			return SSH_ERR_KEY_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		case EVP_R_BN_DECODE_ERROR:
#endif
		case EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_KEY_DECODE_ERROR
		case EVP_R_PRIVATE_KEY_DECODE_ERROR:
#endif
			return SSH_ERR_INVALID_FORMAT;
		default:
			return SSH_ERR_LIBCRYPTO_ERROR;
		}
	case ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	case ERR_LIB_OSSL_DECODER:
#endif
		return SSH_ERR_INVALID_FORMAT;
	}
	return SSH_ERR_LIBCRYPTO_ERROR;
}

static void
clear_libcrypto_errors(void)
{
	while (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
static int
convert_libcrypto_error(void)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	if (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_KEY_WRONG_PASSPHRASE)
		return SSH_ERR_KEY_WRONG_PASSPHRASE;
	return translate_libcrypto_error(ERR_peek_last_error());
}

static int
pem_passphrase_cb(char *buf, int size, int rwflag, void *u)
{
	char *p = (char *)u;
	size_t len;

	if (p == NULL || (len = strlen(p)) == 0)
		return -1;
	if (size < 0 || len > (size_t)size)
		return -1;
	memcpy(buf, p, len);
	return (int)len;
}

static int
sshkey_parse_private_pem_fileblob(struct sshbuf *blob, int type,
    const char *passphrase, struct sshkey **keyp)
{
	EVP_PKEY *pk = NULL;
	struct sshkey *prv = NULL;
	BIO *bio = NULL;
	int r;
	RSA *rsa = NULL;
	EC_KEY *ecdsa = NULL;

	if (keyp != NULL)
		*keyp = NULL;

	if ((bio = BIO_new(BIO_s_mem())) == NULL || sshbuf_len(blob) > INT_MAX)
		return SSH_ERR_ALLOC_FAIL;
	if (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (int)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	clear_libcrypto_errors();
	if ((pk = PEM_read_bio_PrivateKey(bio, NULL, pem_passphrase_cb,
	    (char *)passphrase)) == NULL) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		if (passphrase != NULL && *passphrase != '\0')
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		else
			r = convert_libcrypto_error();
		goto out;
	}
	if (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == KEY_UNSPEC || type == KEY_RSA)) {
		if ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((rsa = EVP_PKEY_get1_RSA(pk)) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		prv->type = KEY_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		if (RSA_blinding_on(rsa, NULL) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		if ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			goto out;
#ifdef OPENSSL_HAS_ECC
	} else if (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == KEY_UNSPEC || type == KEY_ECDSA)) {
		if ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_KEY(pk)) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		prv->type = KEY_ECDSA;
		if (sshkey_curve_nid_to_name(prv->ecdsa_nid) == NULL ||
		    sshkey_ec_validate_public(EC_KEY_get0_group(ecdsa),
		    EC_KEY_get0_public_key(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		if (prv != NULL && prv->pkey != NULL)
			sshkey_dump_ec_key(EVP_PKEY_get0_EC_KEY(prv->pkey));
#endif
#endif /* OPENSSL_HAS_ECC */
#ifdef OPENSSL_HAS_ED25519
	} else if (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == KEY_UNSPEC || type == KEY_ED25519)) {
		size_t len;

		if ((prv = sshkey_new(KEY_UNSPEC)) == NULL ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == NULL ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		prv->type = KEY_ED25519;
		len = ED25519_PK_SZ;
		if (!EVP_PKEY_get_raw_public_key(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		if (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		if (!EVP_PKEY_get_raw_private_key(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		if (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} else {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	r = 0;
	if (keyp != NULL) {
		*keyp = prv;
		prv = NULL;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
#ifdef OPENSSL_HAS_ECC
	EC_KEY_free(ecdsa);
#endif
	sshkey_free(prv);
	return r;
}
#endif /* WITH_OPENSSL */

#ifdef WITH_RUST_CRYPTO
static int
sshkey_parse_private_pem_fileblob_rust(struct sshbuf *blob, int type,
    const char *passphrase, struct sshkey **keyp)
{
	struct sshkey *prv = NULL;
	int r = SSH_ERR_INVALID_FORMAT;
	int parse_status, saw_wrong_passphrase = 0;
	size_t passphrase_len = passphrase != NULL ? strlen(passphrase) : 0;

	if (keyp != NULL)
		*keyp = NULL;
	if (type == KEY_UNSPEC || type == KEY_ECDSA) {
		if ((prv = sshkey_new(KEY_UNSPEC)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		parse_status = OSSH_RUST_PARSE_STATUS_INVALID_FORMAT;
		prv->pkey = ossh_rust_ecdsa_parse_private_pem_passphrase(
		    sshbuf_ptr(blob), sshbuf_len(blob), (const uint8_t *)passphrase,
		    passphrase_len, &parse_status);
		if (prv->pkey != NULL) {
			prv->type = KEY_ECDSA;
			prv->ecdsa_nid = ossh_rust_ecdsa_curve_nid(prv->pkey);
			if (sshkey_curve_nid_to_name(prv->ecdsa_nid) == NULL)
				goto out;
			if (keyp != NULL) {
				*keyp = prv;
				prv = NULL;
			}
			return 0;
		}
		if (parse_status == OSSH_RUST_PARSE_STATUS_WRONG_PASSPHRASE)
			saw_wrong_passphrase = 1;
		sshkey_free(prv);
		prv = NULL;
	}
	if (type == KEY_UNSPEC || type == KEY_RSA) {
		if ((prv = sshkey_new(KEY_UNSPEC)) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		parse_status = OSSH_RUST_PARSE_STATUS_INVALID_FORMAT;
		prv->pkey = ossh_rust_rsa_parse_private_pem_passphrase(
		    sshbuf_ptr(blob), sshbuf_len(blob), (const uint8_t *)passphrase,
		    passphrase_len, &parse_status);
		if (prv->pkey != NULL) {
			prv->type = KEY_RSA;
			if ((r = sshkey_check_rsa_length(prv, 0)) != 0)
				goto out;
			if (keyp != NULL) {
				*keyp = prv;
				prv = NULL;
			}
			return 0;
		}
		if (parse_status == OSSH_RUST_PARSE_STATUS_WRONG_PASSPHRASE)
			saw_wrong_passphrase = 1;
	}
	if (saw_wrong_passphrase)
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
 out:
	sshkey_free(prv);
	return r;
}
#endif /* WITH_RUST_CRYPTO */

int
sshkey_parse_private_fileblob_type(struct sshbuf *blob, int type,
    const char *passphrase, struct sshkey **keyp, char **commentp)
{
	int r = SSH_ERR_INTERNAL_ERROR;

	if (keyp != NULL)
		*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	if (r != SSH_ERR_INVALID_FORMAT)
		return r;
#ifdef WITH_OPENSSL
	return sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#elif defined(WITH_RUST_CRYPTO)
	return sshkey_parse_private_pem_fileblob_rust(blob, type,
	    passphrase, keyp);
#else
	return SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

int
sshkey_parse_private_fileblob(struct sshbuf *buffer, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	if (keyp != NULL)
		*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	return sshkey_parse_private_fileblob_type(buffer, KEY_UNSPEC,
	    passphrase, keyp, commentp);
}

void
sshkey_sig_details_free(struct sshkey_sig_details *details)
{
	freezero(details, sizeof(*details));
}

int
sshkey_parse_pubkey_from_private_fileblob_type(struct sshbuf *blob, int type,
    struct sshkey **pubkeyp)
{
	int r = SSH_ERR_INTERNAL_ERROR;

	if (pubkeyp != NULL)
		*pubkeyp = NULL;
	/* only new-format private keys bundle a public key inside */
	if ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		return r;
	return 0;
}
