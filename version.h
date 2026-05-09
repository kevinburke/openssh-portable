/* $OpenBSD: version.h,v 1.110 2026/08/10 23:27:30 djm Exp $ */

#define SSH_VERSION	"OpenSSH_10.5"

#define SSH_PORTABLE	"p1"
#define SSH_RELEASE_BASE	SSH_VERSION SSH_PORTABLE
/*
 * Keep the base OpenSSH release string stable for compatibility matching and
 * peer heuristics. Expose the Rust backend release separately for version
 * reporting and the default banner addendum.
 */
#define SSH_VERSION_ADDENDUM	"rust-crypto-v0.1.5"
#define SSH_RELEASE	SSH_RELEASE_BASE " " SSH_VERSION_ADDENDUM
