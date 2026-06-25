// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0
//
// Interop PAC verifier: parse a Go-minted PAC with the reference MIT krb5
// implementation and verify its Server signature (service key) and KDC
// signature (krbtgt key), plus the PAC_CLIENT_INFO name and authtime. Args:
//   pacverify <serverkey_hex> <kdckey_hex> <pac_hex> <authtime_unix> <principal>
// Exits 0 only if parse + full verify succeed.
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// h2b decodes hex into b, bounded by max. Oversized input is truncated; that
// can only make a later krb5_pac_parse fail (never a false pass), which is the
// safe failure direction for a fixture.
static int h2b(const char *h, unsigned char *b, int max) {
	int n = strlen(h) / 2;
	if (n > max) n = max;
	for (int i = 0; i < n; i++) sscanf(h + 2 * i, "%2hhx", &b[i]);
	return n;
}

static int fail(krb5_context ctx, const char *what, krb5_error_code e) {
	const char *msg = krb5_get_error_message(ctx, e);
	fprintf(stderr, "%s FAILED: %s\n", what, msg);
	krb5_free_error_message(ctx, msg);
	return 1;
}

int main(int argc, char **argv) {
	if (argc != 6) {
		fprintf(stderr, "usage: %s serverkey_hex kdckey_hex pac_hex authtime principal\n", argv[0]);
		return 2;
	}
	unsigned char sk[64], kk[64];
	static unsigned char pacb[65536];
	int skn = h2b(argv[1], sk, sizeof sk);
	int kkn = h2b(argv[2], kk, sizeof kk);
	int pn = h2b(argv[3], pacb, sizeof pacb);
	long authtime = atol(argv[4]);

	krb5_context ctx;
	if (krb5_init_context(&ctx)) {
		fprintf(stderr, "krb5_init_context failed\n");
		return 2;
	}

	krb5_pac pac;
	krb5_error_code e = krb5_pac_parse(ctx, pacb, pn, &pac);
	if (e) {
		int rc = fail(ctx, "krb5_pac_parse", e);
		krb5_free_context(ctx);
		return rc;
	}

	krb5_keyblock server, privsvr;
	memset(&server, 0, sizeof server);
	memset(&privsvr, 0, sizeof privsvr);
	server.enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	server.length = (unsigned int)skn;
	server.contents = sk;
	privsvr.enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
	privsvr.length = (unsigned int)kkn;
	privsvr.contents = kk;

	krb5_principal princ;
	if (krb5_parse_name(ctx, argv[5], &princ)) {
		fprintf(stderr, "krb5_parse_name(%s) failed\n", argv[5]);
		krb5_pac_free(ctx, pac);
		krb5_free_context(ctx);
		return 2;
	}

	e = krb5_pac_verify(ctx, pac, (krb5_timestamp)authtime, princ, &server, &privsvr);
	krb5_free_principal(ctx, princ);
	krb5_pac_free(ctx, pac);
	if (e) {
		int rc = fail(ctx, "krb5_pac_verify", e);
		krb5_free_context(ctx);
		return rc;
	}
	krb5_free_context(ctx);
	printf("krb5_pac_verify OK (signatures + client name + authtime)\n");
	return 0;
}
