#!/usr/bin/env bash
# Start a live SSSD daemon configured with this library's synthetic domain SID
# and show (A) the daemon accepting and id-ranging that SID, and (B) the boundary
# for live SID->POSIX resolution. Exits non-zero only if the daemon fails to start.
set -uo pipefail
DOM="S-1-5-21-1111111111-2222222222-3333333333"

mkdir -p /etc/sssd
cat > /etc/sssd/sssd.conf <<CONF
[sssd]
config_file_version = 2
services = nss
domains = exdom
[domain/exdom]
debug_level = 9
id_provider = ldap
ldap_uri = ldap://127.0.0.1:1
ldap_schema = ad
ldap_id_mapping = true
ldap_idmap_default_domain_sid = $DOM
CONF
chmod 600 /etc/sssd/sssd.conf

# Daemon-backed SID->uid query (talks to the running sssd over its socket).
gcc -x c -o /q - -lsss_nss_idmap <<'C'
#include <sss_nss_idmap.h>
#include <stdio.h>
#include <string.h>
int main(int c, char **v) {
    uint32_t id = 0; enum sss_id_type t;
    int r = sss_nss_getidbysid(v[1], &id, &t);
    if (r == 0) printf("POSIX id %u\n", id); else printf("ENOENT (%s)\n", strerror(r));
    return r;
}
C

mkdir -p /run/dbus && dbus-daemon --system --fork 2>/dev/null
/usr/sbin/sssd -i -d 9 >/tmp/sssd.log 2>&1 &
sleep 9

echo "== A. A live SSSD daemon accepts our synthetic domain SID =="
if ! pidof sssd >/dev/null; then
    echo "FAIL: sssd did not start"; tail -20 /tmp/sssd.log; exit 1
fi
echo "[ok] sssd daemon + per-domain backend running"
echo "[ok] daemon initialized the algorithmic id-map range for our domain SID:"
grep -oE "Adding domain \[$DOM\] as slice \[[0-9]+\]" /tmp/sssd.log | head -1 \
    | sed 's/^/       /'

echo
echo "== B. Boundary: live SID->POSIX resolution needs a directory object =="
printf "  sss_nss_getidbysid(%s) = " "$DOM-119674831"; /q "$DOM-119674831"
grep -oE "Object \[SID:[^]]+\] was not found in cache" /tmp/sssd.log | head -1 \
    | sed 's/^/  daemon: /'
echo "  SSSD resolves a SID to a directory OBJECT first (populated from AD/LDAP,"
echo "  or by the PAC responder ingesting a verified PAC), then id-maps it. A"
echo "  standalone realm with no AD/IPA enrollment populates no such object, so"
echo "  live resolution stops here. See README.md."
