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

#if defined(WITH_RUST_CRYPTO) && !defined(WITH_OPENSSL)

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "compat.h"
#include "digest.h"
#include "dispatch.h"
#include "dh.h"
#include "kex.h"
#include "log.h"
#include "misc.h"
#include "packet.h"
#include "rust-crypto.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"

static int input_kex_dh_gex_group(int, uint32_t, struct ssh *);
static int input_kex_dh_gex_reply(int, uint32_t, struct ssh *);
static int input_kex_dh_gex_request(int, uint32_t, struct ssh *);
static int input_kex_dh_gex_init(int, uint32_t, struct ssh *);

static u_int
rust_dh_estimate(int bits)
{
	if (bits <= 112)
		return 2048;
	if (bits <= 128)
		return 3072;
	if (bits <= 192)
		return 7680;
	return 8192;
}

static int
rust_dh_group_id_from_gex_request(u_int min, u_int wantbits, u_int max)
{
	struct {
		u_int bits;
		int group_id;
	} groups[] = {
		{ 2048, OSSH_RUST_DH_GROUP14 },
		{ 4096, OSSH_RUST_DH_GROUP16 },
		{ 8192, OSSH_RUST_DH_GROUP18 },
	};
	u_int best = 0;
	size_t i;
	int best_group_id = -1;

	for (i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
		if (groups[i].bits < min || groups[i].bits > max)
			continue;
		if ((groups[i].bits > wantbits && groups[i].bits < best) ||
		    (groups[i].bits > best && best < wantbits)) {
			best = groups[i].bits;
			best_group_id = groups[i].group_id;
		}
	}
	return best_group_id;
}

static int
rust_mpint_bits(const u_char *d, size_t len)
{
	u_int i;

	if (len == 0)
		return 0;
	for (i = 0; i < 8; i++) {
		if ((d[0] & (0x80 >> i)) != 0)
			return (int)((len - 1) * 8 + 8 - i);
	}
	return 0;
}

static int
rust_count_set_bits(const u_char *d, size_t len)
{
	size_t i;
	int bits_set = 0;

	for (i = 0; i < len; i++)
		bits_set += __builtin_popcount((unsigned int)d[i]);
	return bits_set;
}

static void
rust_dh_cleanup(struct kex *kex)
{
	if (kex->dh != NULL) {
		ossh_rust_dh_free(kex->dh);
		kex->dh = NULL;
	}
}

static int
sshpkt_put_bignum2_bytes_rust(struct ssh *ssh, const u_char *v, size_t len)
{
	struct sshbuf *b = NULL;
	int r;

	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put_bignum2_bytes(b, v, len)) != 0 ||
	    (r = sshpkt_put(ssh, sshbuf_ptr(b), sshbuf_len(b))) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(b);
	return r;
}

static int
sshbuf_put_bignum2_bytes_rust(struct sshbuf *buf, const u_char *v, size_t len)
{
	return sshbuf_put_bignum2_bytes(buf, v, len);
}

static int
rust_dh_export_modulus(const struct kex *kex, u_char **outp, size_t *out_lenp)
{
	u_char *out = NULL;
	size_t out_len;

	*outp = NULL;
	*out_lenp = 0;
	if ((out_len = ossh_rust_dh_modulus_len(kex->dh)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((out = calloc(1, out_len)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (ossh_rust_dh_export_modulus(kex->dh, out, out_len) != 0) {
		freezero(out, out_len);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	*outp = out;
	*out_lenp = out_len;
	return 0;
}

static int
rust_dh_export_generator(const struct kex *kex, u_char **outp, size_t *out_lenp)
{
	u_char *out = NULL;
	size_t out_len;

	*outp = NULL;
	*out_lenp = 0;
	if ((out_len = ossh_rust_dh_generator_len(kex->dh)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((out = calloc(1, out_len)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (ossh_rust_dh_export_generator(kex->dh, out, out_len) != 0) {
		freezero(out, out_len);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	*outp = out;
	*out_lenp = out_len;
	return 0;
}

static int
rust_dh_export_public(const struct kex *kex, u_char **outp, size_t *out_lenp)
{
	u_char *out = NULL;
	size_t out_len;

	*outp = NULL;
	*out_lenp = 0;
	if ((out_len = ossh_rust_dh_public_len(kex->dh)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((out = calloc(1, out_len)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (ossh_rust_dh_export_public(kex->dh, out, out_len) != 0) {
		freezero(out, out_len);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	*outp = out;
	*out_lenp = out_len;
	return 0;
}

static int
rust_dh_shared_secret(const struct kex *kex, const u_char *peer_public,
    size_t peer_public_len, struct sshbuf **shared_secretp)
{
	struct sshbuf *shared_secret = NULL;
	u_char *shared = NULL;
	size_t shared_len, modulus_len;
	int r;

	*shared_secretp = NULL;
	if (kex->dh == NULL || peer_public_len == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((shared_len = ossh_rust_dh_public_len(kex->dh)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((modulus_len = ossh_rust_dh_modulus_len(kex->dh)) == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((shared = calloc(1, shared_len)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((shared_secret = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	debug2("bits set: %d/%d", rust_count_set_bits(peer_public, peer_public_len),
	    (int)(modulus_len * 8));
	if (ossh_rust_dh_shared_secret(kex->dh, peer_public, peer_public_len,
	    shared, shared_len) != 0) {
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

static int
kexgex_hash_rust(
    int hash_alg,
    const struct sshbuf *client_version,
    const struct sshbuf *server_version,
    const struct sshbuf *client_kexinit,
    const struct sshbuf *server_kexinit,
    const struct sshbuf *server_host_key_blob,
    int min, int wantbits, int max,
    const u_char *prime, size_t prime_len,
    const u_char *gen, size_t gen_len,
    const u_char *client_dh_pub, size_t client_dh_pub_len,
    const u_char *server_dh_pub, size_t server_dh_pub_len,
    const u_char *shared_secret, size_t secretlen,
    u_char *hash, size_t *hashlen)
{
	struct sshbuf *b;
	int r;

	if (*hashlen < ssh_digest_bytes(SSH_DIGEST_SHA1))
		return SSH_ERR_INVALID_ARGUMENT;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_key_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2_bytes_rust(b, prime, prime_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes_rust(b, gen, gen_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes_rust(b, client_dh_pub,
	    client_dh_pub_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes_rust(b, server_dh_pub,
	    server_dh_pub_len)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		return r;
	}
	if (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
	return 0;
}

int
kexgex_client(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	int r;
	u_int nbits;

	nbits = rust_dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	if (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		return r;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_GROUP,
	    &input_kex_dh_gex_group);
	return 0;
}

static int
input_kex_dh_gex_group(int type, uint32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	const u_char *p = NULL, *g = NULL;
	u_char *client_pub = NULL;
	size_t p_len = 0, g_len = 0, client_pub_len = 0;
	int r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_GROUP, &kex_protocol_error);

	if ((r = sshpkt_get_bignum2_bytes_direct(ssh, &p, &p_len)) != 0 ||
	    (r = sshpkt_get_bignum2_bytes_direct(ssh, &g, &g_len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	if ((bits = rust_mpint_bits(p, p_len)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		goto out;
	}
	rust_dh_cleanup(kex);
	if ((kex->dh = ossh_rust_dh_group_from_params(g, g_len, p, p_len)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (ossh_rust_dh_generate_key(kex->dh, kex->we_need * 8) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	sshbuf_free(kex->client_pub);
	kex->client_pub = NULL;
	if ((r = rust_dh_export_public(kex, &client_pub, &client_pub_len)) != 0)
		goto out;
	if ((kex->client_pub = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put(kex->client_pub, client_pub, client_pub_len)) != 0)
		goto out;
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2_bytes_rust(ssh, client_pub,
	    client_pub_len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_REPLY, &input_kex_dh_gex_reply);
	r = 0;
 out:
	freezero(client_pub, client_pub_len);
	if (r != 0)
		rust_dh_cleanup(kex);
	return r;
}

static int
input_kex_dh_gex_reply(int type, uint32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *tmp = NULL, *server_host_key_blob = NULL;
	struct sshkey *server_host_key = NULL;
	const u_char *dh_server_pub = NULL;
	u_char *dh_p = NULL, *dh_g = NULL;
	u_char *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t dh_server_pub_len = 0, dh_p_len = 0, dh_g_len = 0;
	size_t slen, hashlen;
	int r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_REPLY, &kex_protocol_error);

	if ((r = sshpkt_getb_froms(ssh, &server_host_key_blob)) != 0)
		goto out;
	if ((tmp = sshbuf_fromb(server_host_key_blob)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_fromb(tmp, &server_host_key)) != 0 ||
	    (r = kex_verify_host_key(ssh, server_host_key)) != 0)
		goto out;
	if ((r = sshpkt_get_bignum2_bytes_direct(ssh, &dh_server_pub,
	    &dh_server_pub_len)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	if ((r = rust_dh_shared_secret(kex, dh_server_pub, dh_server_pub_len,
	    &shared_secret)) != 0 ||
	    (r = rust_dh_export_modulus(kex, &dh_p, &dh_p_len)) != 0 ||
	    (r = rust_dh_export_generator(kex, &dh_g, &dh_g_len)) != 0)
		goto out;
	if (kex->client_pub == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	hashlen = sizeof(hash);
	if ((r = kexgex_hash_rust(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_key_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_p_len, dh_g, dh_g_len,
	    sshbuf_ptr(kex->client_pub), sshbuf_len(kex->client_pub),
	    dh_server_pub, dh_server_pub_len,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		goto out;

	if ((r = sshkey_verify(server_host_key, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, NULL)) != 0)
		goto out;
	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		goto out;
	if ((kex->flags & KEX_INITIAL) != 0) {
		if (kex->initial_hostkey != NULL || kex->initial_sig != NULL) {
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
		if ((kex->initial_sig = sshbuf_new()) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			goto out;
		kex->initial_hostkey = server_host_key;
		server_host_key = NULL;
	}
	r = 0;
 out:
	explicit_bzero(hash, sizeof(hash));
	rust_dh_cleanup(kex);
	sshkey_free(server_host_key);
	sshbuf_free(tmp);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_key_blob);
	free(signature);
	freezero(dh_p, dh_p_len);
	freezero(dh_g, dh_g_len);
	return r;
}

int
kexgex_server(struct ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_REQUEST,
	    &input_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	return 0;
}

static int
input_kex_dh_gex_request(int type, uint32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	u_char *dh_p = NULL, *dh_g = NULL;
	size_t dh_p_len = 0, dh_g_len = 0;
	int group_id, r;
	u_int min = 0, max = 0, nbits = 0;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	if ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);
	if (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		goto out;
	}

	rust_dh_cleanup(kex);
	group_id = rust_dh_group_id_from_gex_request(min, nbits, max);
	if (group_id == -1) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		goto out;
	}
	if ((kex->dh = ossh_rust_dh_group_new(group_id)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = rust_dh_export_modulus(kex, &dh_p, &dh_p_len)) != 0 ||
	    (r = rust_dh_export_generator(kex, &dh_g, &dh_g_len)) != 0)
		goto out;
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2_bytes_rust(ssh, dh_p, dh_p_len)) != 0 ||
	    (r = sshpkt_put_bignum2_bytes_rust(ssh, dh_g, dh_g_len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;
	if (ossh_rust_dh_generate_key(kex->dh, kex->we_need * 8) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_INIT, &input_kex_dh_gex_init);
	r = 0;
 out:
	if (r != 0)
		rust_dh_cleanup(kex);
	freezero(dh_p, dh_p_len);
	freezero(dh_g, dh_g_len);
	return r;
}

static int
input_kex_dh_gex_init(int type, uint32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *server_host_key_blob = NULL;
	struct sshkey *server_host_public = NULL, *server_host_private = NULL;
	const u_char *dh_client_pub = NULL;
	u_char *dh_p = NULL, *dh_g = NULL, *pub_key = NULL;
	u_char *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t dh_client_pub_len = 0, dh_p_len = 0, dh_g_len = 0, pub_key_len = 0;
	size_t slen, hashlen;
	int r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_INIT, &kex_protocol_error);

	if ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		goto out;
	if ((r = sshpkt_get_bignum2_bytes_direct(ssh, &dh_client_pub,
	    &dh_client_pub_len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	if ((r = rust_dh_shared_secret(kex, dh_client_pub, dh_client_pub_len,
	    &shared_secret)) != 0)
		goto out;
	if ((server_host_key_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_putb(server_host_public, server_host_key_blob)) != 0 ||
	    (r = rust_dh_export_public(kex, &pub_key, &pub_key_len)) != 0 ||
	    (r = rust_dh_export_modulus(kex, &dh_p, &dh_p_len)) != 0 ||
	    (r = rust_dh_export_generator(kex, &dh_g, &dh_g_len)) != 0)
		goto out;

	hashlen = sizeof(hash);
	if ((r = kexgex_hash_rust(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_key_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_p_len, dh_g, dh_g_len,
	    dh_client_pub, dh_client_pub_len,
	    pub_key, pub_key_len,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		goto out;
	if ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		goto out;
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_key_blob)) != 0 ||
	    (r = sshpkt_put_bignum2_bytes_rust(ssh, pub_key, pub_key_len)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;
	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		goto out;
	if (kex->initial_hostkey == NULL &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		goto out;
	r = 0;
 out:
	explicit_bzero(hash, sizeof(hash));
	rust_dh_cleanup(kex);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_key_blob);
	free(signature);
	freezero(dh_p, dh_p_len);
	freezero(dh_g, dh_g_len);
	freezero(pub_key, pub_key_len);
	return r;
}

#endif /* WITH_RUST_CRYPTO && !WITH_OPENSSL */
