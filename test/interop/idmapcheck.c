// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0
//
// Interop id-map checker: map a Go-minted PAC's SIDs to POSIX IDs with the
// reference SSSD library (libsss_idmap), using SSSD's default ldap_id_mapping
// configuration. Proves the synthetic SIDs are consumable by a real SSSD
// id-mapping domain. Args:
//   idmapcheck <domain_sid> <sid> [<sid> ...]
// Exits 0 only if every SID maps to a POSIX ID.
#include <sss_idmap.h>
#include <stdio.h>

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: %s domain_sid sid [sid ...]\n", argv[0]);
		return 2;
	}
	const char *dom = argv[1];

	struct sss_idmap_ctx *ctx = NULL;
	if (sss_idmap_init(NULL, NULL, NULL, &ctx) != IDMAP_SUCCESS) {
		fprintf(stderr, "sss_idmap_init failed\n");
		return 2;
	}
	// SSSD ldap_id_mapping defaults (hardcoded valid values; these setters
	// cannot fail for them, so the return codes are intentionally ignored).
	(void)sss_idmap_ctx_set_lower(ctx, 200000);
	(void)sss_idmap_ctx_set_upper(ctx, 2000200000);
	(void)sss_idmap_ctx_set_rangesize(ctx, 200000);

	id_t slice = 0;
	struct sss_idmap_range range;
	enum idmap_error_code e = sss_idmap_calculate_range(ctx, dom, &slice, &range);
	if (e != IDMAP_SUCCESS) {
		fprintf(stderr, "sss_idmap_calculate_range failed: %d\n", e);
		return 2;
	}
	e = sss_idmap_add_auto_domain_ex(ctx, "exdom", dom, &range, NULL, 0, false, NULL, NULL);
	if (e != IDMAP_SUCCESS) {
		fprintf(stderr, "sss_idmap_add_auto_domain_ex failed: %d\n", e);
		return 2;
	}

	int failed = 0;
	for (int i = 2; i < argc; i++) {
		uint32_t id = 0;
		e = sss_idmap_sid_to_unix(ctx, argv[i], &id);
		if (e == IDMAP_SUCCESS) {
			printf("  %s -> POSIX id %u\n", argv[i], id);
		} else {
			fprintf(stderr, "  %s -> UNMAPPABLE (sss_idmap error %d)\n", argv[i], e);
			failed = 1;
		}
	}
	if (failed) {
		fprintf(stderr, "sss_idmap: one or more SIDs are not mappable\n");
		return 1;
	}
	printf("sss_idmap OK (all PAC SIDs map to POSIX IDs)\n");
	return 0;
}
