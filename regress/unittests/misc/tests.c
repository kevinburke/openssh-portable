/* 	$OpenBSD: tests.c,v 1.13 2025/09/04 00:34:17 djm Exp $ */
/*
 * Regress test for misc helper functions.
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
#include "xmalloc.h"

void test_parse(void);
void test_convtime(void);
void test_expand(void);
void test_argv(void);
void test_strdelim(void);
void test_hpdelim(void);
void test_user_host_port(void);
void test_ptimeout(void);
void test_xextendf(void);
void test_misc(void);

void
tests(void)
{
	test_parse();
	test_convtime();
	test_expand();
	test_argv();
	test_strdelim();
	test_hpdelim();
	test_user_host_port();
	test_ptimeout();
	test_xextendf();
	test_misc();
}

void
benchmarks(void)
{
	char *s, *user, *host, *type;
	int i, port, secs;
	const char *errstr;

	BENCH_START("a2port numeric x1024");
		for (i = 0; i < 1024; i++) {
			port = a2port("65535");
			if (port != 65535)
				abort();
		}
	BENCH_FINISH("batch");

	BENCH_START("a2port service");
		port = a2port("smtp");
		if (port != 25)
			abort();
	BENCH_FINISH("parse");

	BENCH_START("convtime");
		if (convtime("1w2d3h4m5s") != 788645)
			abort();
	BENCH_FINISH("parse");

	BENCH_START("convtime double fractional");
		if (convtime_double("1m.5s") != 60.5)
			abort();
	BENCH_FINISH("parse");

	BENCH_START("parse ipqos");
		if (parse_ipqos("af21") != 72)
			abort();
	BENCH_FINISH("parse");

	BENCH_START("valid domain");
		s = xstrdup("EXAMPLE.COM.");
		errstr = NULL;
		if (!valid_domain(s, 1, &errstr))
			abort();
		free(s);
	BENCH_FINISH("parse");

	BENCH_START("parse user host port");
		user = host = NULL;
		port = -1;
		if (parse_user_host_port("user@[host.example]:2222",
		    &user, &host, &port) != 0 || port != 2222)
			abort();
		free(user);
		free(host);
	BENCH_FINISH("parse");

	BENCH_START("parse pattern interval");
		type = NULL;
		secs = -1;
		if (parse_pattern_interval("session:command=1m",
		    &type, &secs) != 0 || secs != 60)
			abort();
		free(type);
	BENCH_FINISH("parse");
}
