/* $OpenBSD$ */

#include "includes.h"

#ifdef WITH_RUST_CRYPTO

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include "log.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"
#include "rust-crypto.h"

struct chachapoly_ctx {
	void	*state;
};

struct chachapoly_ctx *
chachapoly_new(const u_char *key, u_int keylen)
{
	struct chachapoly_ctx *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return NULL;
	ctx->state = ossh_rust_chachapoly_new(key, keylen);
	if (ctx->state == NULL) {
		freezero(ctx, sizeof(*ctx));
		return NULL;
	}
	return ctx;
}

void
chachapoly_free(struct chachapoly_ctx *cpctx)
{
	if (cpctx == NULL)
		return;
	ossh_rust_chachapoly_free(cpctx->state);
	cpctx->state = NULL;
	freezero(cpctx, sizeof(*cpctx));
}

int
chachapoly_crypt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
	size_t src_len, dest_len;
	int r;

	src_len = (size_t)aadlen + len + (do_encrypt ? 0 : authlen);
	dest_len = (size_t)aadlen + len + authlen;
	r = ossh_rust_chachapoly_crypt(ctx->state, seqnr, dest, dest_len,
	    src, src_len, len, aadlen, authlen, do_encrypt);
	if (r == 0)
		return 0;
	if (r == 1)
		return SSH_ERR_MAC_INVALID;
	return SSH_ERR_INTERNAL_ERROR;
}

int
chachapoly_get_length(struct chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
	uint32_t plen = 0;

	if (ossh_rust_chachapoly_get_length(ctx->state, &plen, seqnr,
	    cp, len) != 0)
		return SSH_ERR_INTERNAL_ERROR;
	*plenp = plen;
	return 0;
}

#endif /* WITH_RUST_CRYPTO */
