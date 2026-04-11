/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"

#include "ssherr.h"
#include "ssh_api.h"
#include "sshbuf.h"
#include "packet.h"
#include "myproposal.h"
#include "digest.h"
#include "dh.h"
#include "log.h"

#ifdef WITH_RUST_CRYPTO
#include "rust-crypto.h"
#endif

void kex_tests(void);
static int do_debug = 0;

static int
do_send_and_receive(struct ssh *from, struct ssh *to)
{
	u_char type;
	size_t len;
	const u_char *buf;
	int r;

	for (;;) {
		if ((r = ssh_packet_next(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			return r;
		}
		if (type != 0)
			return 0;
		buf = ssh_output_ptr(from, &len);
		if (do_debug)
			printf("%zu", len);
		if (len == 0)
			return 0;
		if ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_input_append(to, buf, len)) != 0)
			return r;
	}
}

static void
run_kex(struct ssh *client, struct ssh *server)
{
	int r = 0;

	while (!server->kex->done || !client->kex->done) {
		if (do_debug)
			printf(" S:");
		if ((r = do_send_and_receive(server, client)))
			break;
		if (do_debug)
			printf(" C:");
		if ((r = do_send_and_receive(client, server)))
			break;
	}
	if (do_debug)
		printf("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

static void
do_kex_with_key(char *kex, char *cipher, char *mac,
    struct sshkey *key, int keytype, int bits)
{
	struct ssh *client = NULL, *server = NULL, *server2 = NULL;
	struct sshkey *private, *public;
	struct sshbuf *state;
	struct kex_params kex_params;
	char *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	char *keyname = NULL;

	if (key != NULL) {
		private = key;
		keytype = key->type;
	} else {
		TEST_START("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, bits, &private), 0);
		TEST_DONE();
	}

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(private, &public), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	memcpy(kex_params.proposal, myproposal, sizeof(myproposal));
	if (kex != NULL)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	if (cipher != NULL) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	if (mac != NULL) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(private));
	ASSERT_PTR_NE(keyname, NULL);
	kex_params.proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, NULL);
	ASSERT_PTR_NE(server, NULL);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, private), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, public), 0);
	TEST_DONE();

	TEST_START("kex");
	run_kex(client, server);
	TEST_DONE();

	TEST_START("rekeying client");
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server);
	TEST_DONE();

	TEST_START("rekeying server");
	ASSERT_INT_EQ(kex_send_kexinit(server), 0);
	run_kex(client, server);
	TEST_DONE();

	TEST_START("ssh_packet_get_state");
	state = sshbuf_new();
	ASSERT_PTR_NE(state, NULL);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = NULL;
	ASSERT_INT_EQ(ssh_init(&server2, 1, NULL), 0);
	ASSERT_PTR_NE(server2, NULL);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, private), 0);
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, NULL);
	/* XXX we need to set the callbacks */
#ifdef WITH_OPENSSL
	server2->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	server2->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	server2->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
#ifdef OPENSSL_HAS_ECC
	server2->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
#if defined(WITH_RUST_CRYPTO) && !defined(WITH_OPENSSL)
	server2->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	server2->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	server2->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#endif /* WITH_RUST_CRYPTO && !WITH_OPENSSL */
	server2->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	server2->kex->load_host_public_key = server->kex->load_host_public_key;
	server2->kex->load_host_private_key = server->kex->load_host_private_key;
	server2->kex->sign = server->kex->sign;
	TEST_DONE();

	TEST_START("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	run_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server2);
	TEST_DONE();

	TEST_START("cleanup");
	if (key == NULL)
		sshkey_free(private);
	sshkey_free(public);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	free(keyname);
	TEST_DONE();
}

static void
do_kex(char *kex)
{
	struct sshkey *key = NULL;
	char name[256];

	if (test_is_benchmark()) {
		snprintf(name, sizeof(name), "generate %s", kex);
		TEST_START(name);
		ASSERT_INT_EQ(sshkey_generate(KEY_ED25519, 0, &key), 0);
		TEST_DONE();
		snprintf(name, sizeof(name), "KEX %s", kex);
		BENCH_START(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_key(kex, "aes128-ctr", "hmac-sha2-256", key,
		    KEY_ED25519, 256);
		BENCH_FINISH("kex");
		sshkey_free(key);
		return;
	}

#ifdef WITH_OPENSSL
	do_kex_with_key(kex, NULL, NULL, NULL, KEY_RSA, 2048);
# ifdef OPENSSL_HAS_ECC
	do_kex_with_key(kex, NULL, NULL, NULL, KEY_ECDSA, 256);
# endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
	do_kex_with_key(kex, NULL, NULL, NULL, KEY_ED25519, 256);
}

#ifdef WITH_RUST_CRYPTO
static void
rust_dh_substep_benchmarks(void)
{
	struct sshbuf *client_version = NULL, *server_version = NULL;
	struct sshbuf *client_kexinit = NULL, *server_kexinit = NULL;
	struct sshbuf *server_host_key_blob = NULL, *b = NULL;
	void *client = NULL, *server = NULL, *group = NULL;
	u_char *modulus = NULL, *generator = NULL, *client_pub = NULL, *server_pub = NULL;
	u_char *shared = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	size_t modulus_len, generator_len, public_len, digest_len;

	client = ossh_rust_dh_group_new(OSSH_RUST_DH_GROUP14);
	server = ossh_rust_dh_group_new(OSSH_RUST_DH_GROUP14);
	ASSERT_PTR_NE(client, NULL);
	ASSERT_PTR_NE(server, NULL);
	ASSERT_INT_EQ(ossh_rust_dh_generate_key(client, 256), 0);
	ASSERT_INT_EQ(ossh_rust_dh_generate_key(server, 256), 0);

	modulus_len = ossh_rust_dh_modulus_len(client);
	generator_len = ossh_rust_dh_generator_len(client);
	public_len = ossh_rust_dh_public_len(client);
	ASSERT_SIZE_T_NE(modulus_len, 0);
	ASSERT_SIZE_T_NE(generator_len, 0);
	ASSERT_SIZE_T_NE(public_len, 0);

	modulus = calloc(1, modulus_len);
	generator = calloc(1, generator_len);
	client_pub = calloc(1, public_len);
	server_pub = calloc(1, public_len);
	shared = calloc(1, public_len);
	ASSERT_PTR_NE(modulus, NULL);
	ASSERT_PTR_NE(generator, NULL);
	ASSERT_PTR_NE(client_pub, NULL);
	ASSERT_PTR_NE(server_pub, NULL);
	ASSERT_PTR_NE(shared, NULL);
	ASSERT_INT_EQ(ossh_rust_dh_export_modulus(client, modulus, modulus_len), 0);
	ASSERT_INT_EQ(ossh_rust_dh_export_generator(client, generator, generator_len), 0);
	ASSERT_INT_EQ(ossh_rust_dh_export_public(client, client_pub, public_len), 0);
	ASSERT_INT_EQ(ossh_rust_dh_export_public(server, server_pub, public_len), 0);
	ASSERT_INT_EQ(ossh_rust_dh_shared_secret(client, server_pub, public_len,
	    shared, public_len), 0);

	client_version = sshbuf_new();
	server_version = sshbuf_new();
	client_kexinit = sshbuf_new();
	server_kexinit = sshbuf_new();
	server_host_key_blob = sshbuf_new();
	ASSERT_PTR_NE(client_version, NULL);
	ASSERT_PTR_NE(server_version, NULL);
	ASSERT_PTR_NE(client_kexinit, NULL);
	ASSERT_PTR_NE(server_kexinit, NULL);
	ASSERT_PTR_NE(server_host_key_blob, NULL);
	ASSERT_INT_EQ(sshbuf_put(client_version, "SSH-2.0-test-client",
	    sizeof("SSH-2.0-test-client") - 1), 0);
	ASSERT_INT_EQ(sshbuf_put(server_version, "SSH-2.0-test-server",
	    sizeof("SSH-2.0-test-server") - 1), 0);
	ASSERT_INT_EQ(sshbuf_put(client_kexinit, "client-kexinit-payload",
	    sizeof("client-kexinit-payload") - 1), 0);
	ASSERT_INT_EQ(sshbuf_put(server_kexinit, "server-kexinit-payload",
	    sizeof("server-kexinit-payload") - 1), 0);
	ASSERT_INT_EQ(sshbuf_put(server_host_key_blob, "server-host-key-blob",
	    sizeof("server-host-key-blob") - 1), 0);

	BENCH_START("Rust DH group14 keygen");
		group = ossh_rust_dh_group_new(OSSH_RUST_DH_GROUP14);
		ASSERT_PTR_NE(group, NULL);
		ASSERT_INT_EQ(ossh_rust_dh_generate_key(group, 256), 0);
		ossh_rust_dh_free(group);
	BENCH_FINISH("ops");

	BENCH_START("Rust DH group14 shared secret");
		ASSERT_INT_EQ(ossh_rust_dh_shared_secret(client, server_pub,
		    public_len, shared, public_len), 0);
	BENCH_FINISH("ops");

	BENCH_START("Rust DH group14 from params");
		group = ossh_rust_dh_group_from_params(generator, generator_len,
		    modulus, modulus_len);
		ASSERT_PTR_NE(group, NULL);
		ossh_rust_dh_free(group);
	BENCH_FINISH("ops");

	BENCH_START("Rust DH group14 export trio");
		ASSERT_INT_EQ(ossh_rust_dh_export_public(client, client_pub,
		    public_len), 0);
		ASSERT_INT_EQ(ossh_rust_dh_export_modulus(client, modulus,
		    modulus_len), 0);
		ASSERT_INT_EQ(ossh_rust_dh_export_generator(client, generator,
		    generator_len), 0);
	BENCH_FINISH("ops");

	BENCH_START("Rust DH-GEX hash build");
		b = sshbuf_new();
		ASSERT_PTR_NE(b, NULL);
		ASSERT_INT_EQ(sshbuf_put_stringb(b, client_version), 0);
		ASSERT_INT_EQ(sshbuf_put_stringb(b, server_version), 0);
		ASSERT_INT_EQ(sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1), 0);
		ASSERT_INT_EQ(sshbuf_put_u8(b, SSH2_MSG_KEXINIT), 0);
		ASSERT_INT_EQ(sshbuf_putb(b, client_kexinit), 0);
		ASSERT_INT_EQ(sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1), 0);
		ASSERT_INT_EQ(sshbuf_put_u8(b, SSH2_MSG_KEXINIT), 0);
		ASSERT_INT_EQ(sshbuf_putb(b, server_kexinit), 0);
		ASSERT_INT_EQ(sshbuf_put_stringb(b, server_host_key_blob), 0);
		ASSERT_INT_EQ(sshbuf_put_u32(b, DH_GRP_MIN), 0);
		ASSERT_INT_EQ(sshbuf_put_u32(b, 3072), 0);
		ASSERT_INT_EQ(sshbuf_put_u32(b, DH_GRP_MAX), 0);
		ASSERT_INT_EQ(sshbuf_put_bignum2_bytes(b, modulus, modulus_len), 0);
		ASSERT_INT_EQ(sshbuf_put_bignum2_bytes(b, generator, generator_len), 0);
		ASSERT_INT_EQ(sshbuf_put_bignum2_bytes(b, client_pub, public_len), 0);
		ASSERT_INT_EQ(sshbuf_put_bignum2_bytes(b, server_pub, public_len), 0);
		ASSERT_INT_EQ(sshbuf_put(b, shared, public_len), 0);
		digest_len = sizeof(digest);
		ASSERT_INT_EQ(ssh_digest_buffer(SSH_DIGEST_SHA256, b, digest,
		    digest_len), 0);
		sshbuf_free(b);
	BENCH_FINISH("ops");

	ossh_rust_dh_free(client);
	ossh_rust_dh_free(server);
	sshbuf_free(client_version);
	sshbuf_free(server_version);
	sshbuf_free(client_kexinit);
	sshbuf_free(server_kexinit);
	sshbuf_free(server_host_key_blob);
	freezero(modulus, modulus_len);
	freezero(generator, generator_len);
	freezero(client_pub, public_len);
	freezero(server_pub, public_len);
	freezero(shared, public_len);
}
#endif

void
kex_tests(void)
{
	do_kex("curve25519-sha256");
#ifdef WITH_OPENSSL
#ifdef OPENSSL_HAS_ECC
	do_kex("ecdh-sha2-nistp256");
	do_kex("ecdh-sha2-nistp384");
	do_kex("ecdh-sha2-nistp521");
#endif /* OPENSSL_HAS_ECC */
	do_kex("diffie-hellman-group-exchange-sha256");
	do_kex("diffie-hellman-group-exchange-sha1");
	do_kex("diffie-hellman-group14-sha1");
	do_kex("diffie-hellman-group1-sha1");
	if (test_is_benchmark()) {
		do_kex("diffie-hellman-group14-sha256");
		do_kex("diffie-hellman-group16-sha512");
		do_kex("diffie-hellman-group18-sha512");
	}
# ifdef USE_MLKEM768X25519
	do_kex("mlkem768x25519-sha256");
# endif /* USE_MLKEM768X25519 */
# ifdef USE_SNTRUP761X25519
	do_kex("sntrup761x25519-sha512");
# endif /* USE_SNTRUP761X25519 */
#endif /* WITH_OPENSSL */
#if defined(WITH_RUST_CRYPTO) && !defined(WITH_OPENSSL)
	do_kex("ecdh-sha2-nistp256");
	do_kex("ecdh-sha2-nistp384");
	do_kex("ecdh-sha2-nistp521");
	do_kex("diffie-hellman-group-exchange-sha256");
	do_kex("diffie-hellman-group-exchange-sha1");
	do_kex("diffie-hellman-group14-sha1");
	do_kex("diffie-hellman-group14-sha256");
	do_kex("diffie-hellman-group16-sha512");
	do_kex("diffie-hellman-group18-sha512");
# ifdef USE_MLKEM768X25519
	do_kex("mlkem768x25519-sha256");
# endif /* USE_MLKEM768X25519 */
# ifdef USE_SNTRUP761X25519
	do_kex("sntrup761x25519-sha512");
# endif /* USE_SNTRUP761X25519 */
#endif /* WITH_RUST_CRYPTO && !WITH_OPENSSL */
#ifdef WITH_RUST_CRYPTO
	if (test_is_benchmark())
		rust_dh_substep_benchmarks();
#endif
}
