#!/usr/bin/env bash
# AD deployment demo. Provisions a real Samba AD DC, exports a service key,
# mints an end user a ticket with this library using that key, and has a real
# Apache mod_auth_gssapi service accept it for the user's HTTP login — the user
# never contacting the KDC. Exits 0 only if the SPNEGO login succeeds as the user.
set -euo pipefail

REALM=EXAMPLE.COM
SPN_HOST=web.example.com
USER=alice
KT=/etc/krb5.keytab.svc

echo "==> [1/5] provisioning a real Active Directory domain (Samba AD DC)"
rm -f /etc/krb5.conf
# The sysvol NT-ACL step fails on container overlayfs (no xattr support) and
# returns non-zero, but the directory DB is fully provisioned — which is all this
# demo needs (key export + Kerberos). Tolerate it, then verify the DB exists.
samba-tool domain provision --realm="$REALM" --domain=EXAMPLE \
  --server-role=dc --use-rfc2307 --adminpass='Passw0rd!2026' >/tmp/prov.log 2>&1 || true
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  echo "    provision failed:"; tail -15 /tmp/prov.log; exit 1
fi
echo "    domain $REALM provisioned"

echo "==> [2/5] creating the end user '$USER' and a service account (AES keys)"
samba-tool user create "$USER" 'Alice!2026pw' >/dev/null 2>&1
samba-tool user create webservice 'WebSvc!2026pw' >/dev/null 2>&1
samba-tool spn add "HTTP/$SPN_HOST" webservice >/dev/null 2>&1
ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null 2>&1 <<LDIF
dn: CN=webservice,CN=Users,DC=example,DC=com
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 24
LDIF
samba-tool user setpassword webservice --newpassword='WebSvc!2026pwAES' >/dev/null 2>&1
samba-tool domain exportkeytab "$KT" --principal="HTTP/$SPN_HOST" >/dev/null 2>&1
chmod a+r "$KT"  # Apache (www-data) must read the service keytab to acquire creds
DOMSID=$(ldbsearch -H /var/lib/samba/private/sam.ldb '(sAMAccountName=alice)' objectSid 2>/dev/null | sed -n 's/objectSid: //p')
echo "    exported HTTP/$SPN_HOST service key (AES256); $USER SID = $DOMSID"

echo "==> [3/5] starting a real SPNEGO service (Apache mod_auth_gssapi)"
echo "127.0.0.1 $SPN_HOST" >> /etc/hosts
cat > /etc/krb5.conf <<KRB
[libdefaults]
  default_realm = $REALM
  dns_lookup_kdc = false
  dns_canonicalize_hostname = false
  rdns = false
[realms]
  $REALM = { }
KRB
a2enmod auth_gssapi cgid >/dev/null 2>&1
cat > /etc/apache2/conf-available/spnego.conf <<APACHE
ServerName $SPN_HOST
<Location /whoami>
  AuthType GSSAPI
  AuthName "Active Directory SPNEGO"
  GssapiCredStore keytab:$KT
  GssapiAllowedMech krb5
  Require valid-user
</Location>
ScriptAlias /whoami /usr/lib/cgi-bin/whoami
APACHE
a2enconf spnego >/dev/null 2>&1
mkdir -p /usr/lib/cgi-bin
cat > /usr/lib/cgi-bin/whoami <<'CGI'
#!/bin/sh
printf 'Content-Type: text/plain\n\n'
printf 'Authenticated to the Kerberos backend as: %s\n' "$REMOTE_USER"
CGI
chmod +x /usr/lib/cgi-bin/whoami
apache2ctl start >/dev/null 2>&1
sleep 2

echo "==> [4/5] minting $USER a ticket with this library, using the AD-exported key"
admint -keytab "$KT" -realm "$REALM" -service HTTP -host "$SPN_HOST" -client "$USER" \
  -ccache /tmp/$USER.ccache 2>&1 | sed 's/^/    /'

echo "==> [5/5] the end user logs in to the SPNEGO service (curl --negotiate, no KDC)"
BODY=$(KRB5CCNAME=FILE:/tmp/$USER.ccache curl -s --negotiate -u : "http://$SPN_HOST/whoami")
CODE=$(KRB5CCNAME=FILE:/tmp/$USER.ccache curl -s -o /dev/null -w '%{http_code}' --negotiate -u : "http://$SPN_HOST/whoami")
echo "    HTTP $CODE — $BODY"
if [ "$CODE" = "200" ] && echo "$BODY" | grep -q "$USER@$REALM"; then
  echo "==> AD DEMO PASSED (real Apache SPNEGO authenticated $USER from a library-minted ticket)"
else
  echo "==> AD DEMO FAILED — diagnostics:"
  KRB5CCNAME=FILE:/tmp/$USER.ccache curl -sv --negotiate -u : "http://$SPN_HOST/whoami" 2>&1 | grep -iE '> Authorization: Negotiate|< HTTP|< WWW-Authenticate' | head
  echo "--- ccache ---"; KRB5CCNAME=FILE:/tmp/$USER.ccache klist 2>&1 | tail -3
  echo "--- apache error.log ---"; tail -6 /var/log/apache2/error.log 2>/dev/null
  exit 1
fi
