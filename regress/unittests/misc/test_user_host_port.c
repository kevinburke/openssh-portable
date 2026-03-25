/*
 * Regress test for misc parse_user_host_port().
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

void test_user_host_port(void);

void
test_user_host_port(void)
{
	char *user = NULL, *host = NULL;
	int port = -2;

	TEST_START("parse_user_host_port host only");
	ASSERT_INT_EQ(parse_user_host_port("host", &user, &host, &port), 0);
	ASSERT_PTR_EQ(user, NULL);
	ASSERT_STRING_EQ(host, "host");
	ASSERT_INT_EQ(port, -1);
	free(host);
	TEST_DONE();

	TEST_START("parse_user_host_port user host port");
	user = host = NULL;
	port = -2;
	ASSERT_INT_EQ(parse_user_host_port("user@host:2222", &user, &host, &port), 0);
	ASSERT_STRING_EQ(user, "user");
	ASSERT_STRING_EQ(host, "host");
	ASSERT_INT_EQ(port, 2222);
	free(user);
	free(host);
	TEST_DONE();

	TEST_START("parse_user_host_port bracketed ipv6");
	user = host = NULL;
	port = -2;
	ASSERT_INT_EQ(parse_user_host_port("user@[::1]:22", &user, &host, &port), 0);
	ASSERT_STRING_EQ(user, "user");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_INT_EQ(port, 22);
	free(user);
	free(host);
	TEST_DONE();

	TEST_START("parse_user_host_port syntax-only");
	ASSERT_INT_EQ(parse_user_host_port("host:1234", NULL, NULL, NULL), 0);
	TEST_DONE();

	TEST_START("parse_user_host_port rejects empty user");
	ASSERT_INT_EQ(parse_user_host_port("@host", &user, &host, &port), -1);
	TEST_DONE();

	TEST_START("parse_user_host_port rejects empty port");
	ASSERT_INT_EQ(parse_user_host_port("host:", &user, &host, &port), -1);
	TEST_DONE();

	TEST_START("parse_user_host_port rejects slash");
	ASSERT_INT_EQ(parse_user_host_port("host/path", &user, &host, &port), -1);
	TEST_DONE();

	TEST_START("parse_user_host_port rejects malformed bracket host");
	ASSERT_INT_EQ(parse_user_host_port("[::1", &user, &host, &port), -1);
	ASSERT_INT_EQ(parse_user_host_port("[]:22", &user, &host, &port), -1);
	TEST_DONE();
}
