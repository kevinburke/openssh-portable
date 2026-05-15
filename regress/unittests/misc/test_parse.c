/* 	$OpenBSD: test_parse.c,v 1.3 2025/06/12 10:09:39 dtucker Exp $ */
/*
 * Regress test for misc user/host/URI parsing functions.
 *
 * Placed in the public domain.
 */

#include "includes.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"

#include "log.h"
#include "misc.h"
#include "ssh.h"
#include "readconf.h"
#include "xmalloc.h"

void test_parse(void);

static void
free_forward(struct Forward *fwd)
{
	free(fwd->listen_host);
	free(fwd->listen_path);
	free(fwd->connect_host);
	free(fwd->connect_path);
	memset(fwd, 0, sizeof(*fwd));
}

static void
free_jump_options(Options *o)
{
	free(o->proxy_command);
	free(o->jump_user);
	free(o->jump_host);
	free(o->jump_extra);
	memset(o, 0, sizeof(*o));
}

void
test_parse(void)
{
	int port;
	char *user, *host, *path;

	TEST_START("misc_parse_user_host_path");
	user = host = path = NULL;
	ASSERT_INT_EQ(parse_user_host_path("someuser@some.host:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(path, "some/path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv4_path");
	user = host = path = NULL;
	ASSERT_INT_EQ(parse_user_host_path("someuser@1.22.33.144:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_path");
	user = host = path = NULL;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_nopath");
	user = host = path = NULL;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, ".");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv6_path");
	user = host = path = NULL;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[::1]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(path, "some/path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_empty_user_host_path");
	user = host = path = NULL;
	ASSERT_INT_EQ(parse_user_host_path("@some.host:some/path",
	    &user, &host, &path), 0);
	ASSERT_PTR_EQ(user, NULL);
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(path, "some/path");
	free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_user_host_path_rejects_local_path");
	ASSERT_INT_EQ(parse_user_host_path("some/host:path",
	    &user, &host, &path), -1);
	TEST_DONE();

	TEST_START("misc_parse_uri");
	user = host = path = NULL;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &port, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(port, 22);
	ASSERT_STRING_EQ(path, "some/path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_uri_encoded_and_params");
	user = host = path = NULL;
	ASSERT_INT_EQ(parse_uri("ssh",
	    "ssh://someuser;ignored@some.host:2222/some%20path",
	    &user, &host, &port, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(port, 2222);
	ASSERT_STRING_EQ(path, "some path");
	free(user); free(host); free(path);
	TEST_DONE();

	TEST_START("misc_parse_uri_rejects_empty_user");
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://@some.host:22/path",
	    &user, &host, &port, &path), -1);
	TEST_DONE();

	TEST_START("readconf_parse_forward_local_tcp");
	{
		struct Forward fwd;
		memset(&fwd, 0, sizeof(fwd));
		ASSERT_INT_EQ(parse_forward(&fwd, "8080:dest.example:80", 0, 0), 3);
		ASSERT_PTR_EQ(fwd.listen_host, NULL);
		ASSERT_INT_EQ(fwd.listen_port, 8080);
		ASSERT_PTR_EQ(fwd.listen_path, NULL);
		ASSERT_STRING_EQ(fwd.connect_host, "dest.example");
		ASSERT_INT_EQ(fwd.connect_port, 80);
		ASSERT_PTR_EQ(fwd.connect_path, NULL);
		free_forward(&fwd);
	}
	TEST_DONE();

	TEST_START("readconf_parse_forward_dynamic_with_listen_host");
	{
		struct Forward fwd;
		memset(&fwd, 0, sizeof(fwd));
		ASSERT_INT_EQ(parse_forward(&fwd, "[host:name]:8080", 1, 0), 2);
		ASSERT_STRING_EQ(fwd.listen_host, "host:name");
		ASSERT_INT_EQ(fwd.listen_port, 8080);
		ASSERT_PTR_EQ(fwd.listen_path, NULL);
		ASSERT_STRING_EQ(fwd.connect_host, "socks");
		ASSERT_INT_EQ(fwd.connect_port, 0);
		ASSERT_PTR_EQ(fwd.connect_path, NULL);
		free_forward(&fwd);
	}
	TEST_DONE();

	TEST_START("readconf_parse_forward_streamlocal");
	{
		struct Forward fwd;
		memset(&fwd, 0, sizeof(fwd));
		ASSERT_INT_EQ(parse_forward(&fwd,
		    "/tmp/listen.sock:/tmp/connect.sock", 0, 0), 2);
		ASSERT_PTR_EQ(fwd.listen_host, NULL);
		ASSERT_INT_EQ(fwd.listen_port, PORT_STREAMLOCAL);
		ASSERT_STRING_EQ(fwd.listen_path, "/tmp/listen.sock");
		ASSERT_PTR_EQ(fwd.connect_host, NULL);
		ASSERT_INT_EQ(fwd.connect_port, PORT_STREAMLOCAL);
		ASSERT_STRING_EQ(fwd.connect_path, "/tmp/connect.sock");
		free_forward(&fwd);
	}
	TEST_DONE();

	TEST_START("readconf_parse_forward_rejects_bad_brackets");
	{
		struct Forward fwd;
		memset(&fwd, 0, sizeof(fwd));
		ASSERT_INT_EQ(parse_forward(&fwd,
		    "[host]x:8080:dest.example:80", 0, 0), 0);
		free_forward(&fwd);
	}
	TEST_DONE();

	TEST_START("readconf_process_localforward_keeps_long_target");
	{
		Options o;
		char target[301], *line = NULL;
		int active = 1;

		memset(target, 'a', sizeof(target) - 1);
		target[sizeof(target) - 1] = '\0';
		initialize_options(&o);
		xasprintf(&line, "LocalForward 8080 %s:80", target);
		ASSERT_INT_EQ(process_config_line(&o, NULL, "host", "host",
		    "", line, "test", 1, &active, 0), 0);
		ASSERT_INT_EQ(o.num_local_forwards, 1);
		ASSERT_INT_EQ(o.local_forwards[0].listen_port, 8080);
		ASSERT_STRING_EQ(o.local_forwards[0].connect_host, target);
		ASSERT_INT_EQ(o.local_forwards[0].connect_port, 80);
		free(line);
		free_options(&o);
	}
	TEST_DONE();

	TEST_START("readconf_process_localforward_dedupes");
	{
		Options o;
		char line[] = "LocalForward 8080 dest.example:80";
		char line2[] = "LocalForward 8080 dest.example:80";
		int active = 1;

		initialize_options(&o);
		ASSERT_INT_EQ(process_config_line(&o, NULL, "host", "host",
		    "", line, "test", 1, &active, 0), 0);
		ASSERT_INT_EQ(process_config_line(&o, NULL, "host", "host",
		    "", line2, "test", 2, &active, 0), 0);
		ASSERT_INT_EQ(o.num_local_forwards, 1);
		free_options(&o);
	}
	TEST_DONE();

	TEST_START("readconf_process_inactive_localforward_discards");
	{
		Options o;
		char line[] = "LocalForward 8080 dest.example:80";
		int active = 0;

		initialize_options(&o);
		ASSERT_INT_EQ(process_config_line(&o, NULL, "host", "host",
		    "", line, "test", 1, &active, 0), 0);
		ASSERT_INT_EQ(o.num_local_forwards, 0);
		free_options(&o);
	}
	TEST_DONE();

	TEST_START("readconf_parse_jump_chain");
	{
		Options o;
		memset(&o, 0, sizeof(o));
		ASSERT_INT_EQ(parse_jump("jumpa,ssh://user@jumpb:2200", &o, 1, 1), 0);
		ASSERT_STRING_EQ(o.jump_user, "user");
		ASSERT_STRING_EQ(o.jump_host, "jumpb");
		ASSERT_INT_EQ(o.jump_port, 2200);
		ASSERT_STRING_EQ(o.jump_extra, "jumpa");
		ASSERT_STRING_EQ(o.proxy_command, "none");
		free_jump_options(&o);
	}
	TEST_DONE();

	TEST_START("readconf_parse_jump_none");
	{
		Options o;
		memset(&o, 0, sizeof(o));
		ASSERT_INT_EQ(parse_jump("NoNe", &o, 1, 1), 0);
		ASSERT_STRING_EQ(o.jump_host, "none");
		ASSERT_INT_EQ(o.jump_port, 0);
		ASSERT_PTR_EQ(o.jump_user, NULL);
		ASSERT_PTR_EQ(o.jump_extra, NULL);
		free_jump_options(&o);
	}
	TEST_DONE();

	TEST_START("readconf_parse_jump_rejects_bad_chain");
	{
		Options o;
		memset(&o, 0, sizeof(o));
		ASSERT_INT_EQ(parse_jump("jumpa,,jumpb", &o, 1, 1), -1);
		free_jump_options(&o);
	}
	TEST_DONE();

	TEST_START("misc_valid_permit_basic");
	ASSERT_INT_EQ(valid_permit("dest.example:80", 0), 0);
	ASSERT_INT_EQ(valid_permit("[host:name]:smtp", 0), 0);
	ASSERT_INT_EQ(valid_permit("*:*", 0), 0);
	ASSERT_INT_EQ(valid_permit("8080", 1), 0);
	TEST_DONE();

	TEST_START("misc_valid_permit_rejects_bad_forms");
	ASSERT_INT_EQ(valid_permit("dest.example", 0), -1);
	ASSERT_INT_EQ(valid_permit("host:", 0), -1);
	ASSERT_INT_EQ(valid_permit("[]:22", 0), -1);
	ASSERT_INT_EQ(valid_permit("[host]x:22", 0), -1);
	ASSERT_INT_EQ(valid_permit("host:0", 0), -1);
	TEST_DONE();
}
