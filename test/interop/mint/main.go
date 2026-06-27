// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

// Command mint is an interop fixture: it generates a service keytab, mints a
// Kerberos service ticket (carrying a signed synthetic PAC) for that service
// using this library's DirectMinter, and writes the resulting GSSAPI
// initial-context (AP-REQ) token plus a PAC-verify bundle (the PAC bytes and
// the two signing keys). A real MIT krb5 GSSAPI acceptor validates the token,
// and krb5_pac_verify checks the PAC — proving Go-minted credentials
// interoperate with the reference C implementation at both layers.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hstern/krb5/crypto"
	"github.com/hstern/krb5/iana/adtype"
	"github.com/hstern/krb5/iana/etypeID"
	"github.com/hstern/krb5/iana/keyusage"
	"github.com/hstern/krb5/iana/nametype"
	"github.com/hstern/krb5/keytab"
	"github.com/hstern/krb5/messages"
	"github.com/hstern/krb5/pac"
	"github.com/hstern/krb5/types"
	"github.com/hstern/x/encoding/asn1"

	kerb "github.com/hstern/go-oauth2-kerberos-exchange"
)

func main() {
	var (
		keytabPath = flag.String("keytab", "/tmp/interop.keytab", "path to write the shared service keytab")
		tokenPath  = flag.String("token", "/tmp/interop.token.b64", "path to write the base64 GSSAPI AP-REQ token")
		ccachePath = flag.String("ccache", "", "if set, write the service ticket as an MIT ccache here")
		bundlePath = flag.String("bundle", "", "if set, write a PAC-verify bundle (PAC + signing keys) here")
		realm      = flag.String("realm", "EXAMPLE.COM", "Kerberos realm")
		service    = flag.String("service", "HTTP", "target service component")
		host       = flag.String("host", "interop.example.com", "target host component")
		client     = flag.String("client", "alice", "client principal name")
		password   = flag.String("password", "interop-secret", "password used to derive the service key in the keytab")
		domainSID  = flag.String("domain-sid", "S-1-5-21-1111111111-2222222222-3333333333", "synthetic domain SID for the PAC")
	)
	flag.Parse()

	// 1. Build a keytab holding the service key AND a krbtgt key (for the PAC KDC
	//    signature). The same file is read by both this minter and the C acceptor.
	kt := keytab.New()
	now := time.Now()
	// Both the service key (encrypts the ticket) and the krbtgt key (signs the
	// PAC KDC signature) live in the keytab; AddEntry derives each from the
	// password and both this minter and the acceptor read the stored key.
	for _, pn := range []string{*service + "/" + *host, "krbtgt/" + *realm} {
		if err := kt.AddEntry(pn, *realm, *password, now, 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
			log.Fatalf("keytab AddEntry %q: %v", pn, err)
		}
	}
	ktf, err := os.Create(*keytabPath)
	if err != nil {
		log.Fatalf("create keytab: %v", err)
	}
	if _, err := kt.Write(ktf); err != nil {
		log.Fatalf("write keytab: %v", err)
	}
	_ = ktf.Close()

	// 2. Mint a service ticket for the SPN, carrying a signed synthetic PAC.
	ks := kerb.NewKeytabSource(kt, *realm)
	pac, err := kerb.NewSyntheticPACBuilder(*domainSID)
	if err != nil {
		log.Fatalf("pac builder: %v", err)
	}
	authTime := now.Add(-30 * time.Second)
	minter := kerb.NewDirectMinter(ks, *realm).WithPACBuilder(pac)
	mt, err := minter.Mint(
		kerb.ServicePrincipal{Service: *service, Host: *host, Realm: *realm},
		kerb.MintOptions{
			ClientName:  types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{*client}},
			ClientRealm: *realm,
			Identity:    kerb.Identity{Subject: *client, Claims: json.RawMessage(`{"groups":["mail-users","staff"]}`), Expiry: now.Add(time.Hour)},
			AuthTime:    authTime,
			EndTime:     now.Add(5 * time.Minute),
		},
	)
	if err != nil {
		log.Fatalf("mint: %v", err)
	}

	// 3. Emit the GSSAPI initial-context (AP-REQ) token.
	token, err := kerb.MarshalAPReqToken(mt)
	if err != nil {
		log.Fatalf("marshal AP-REQ token: %v", err)
	}
	if err := os.WriteFile(*tokenPath, []byte(base64.StdEncoding.EncodeToString(token)), 0o600); err != nil {
		log.Fatalf("write token: %v", err)
	}

	// 3b. Optionally emit the service ticket as an MIT ccache (the holder-of-key
	//     output) so a client can drive a full GSSAPI exchange from it.
	if *ccachePath != "" {
		cred, err := mt.Credential(kerb.OutputCCache)
		if err != nil {
			log.Fatalf("ccache credential: %v", err)
		}
		cc, err := cred.CCache()
		if err != nil {
			log.Fatalf("marshal ccache: %v", err)
		}
		if err := os.WriteFile(*ccachePath, cc, 0o600); err != nil {
			log.Fatalf("write ccache: %v", err)
		}
	}

	// 4. Optionally emit a PAC-verify bundle: the PAC bytes plus the service key
	//    (Server signature) and the krbtgt key (KDC signature), which the
	//    reference krb5_pac_verify needs.
	if *bundlePath != "" {
		writeBundle(*bundlePath, kt, mt, *service, *host, *realm, *client, authTime)
	}

	log.Printf("minted: keytab=%s token=%s spn=%s/%s@%s client=%s", *keytabPath, *tokenPath, *service, *host, *realm, *client)
}

// writeBundle decrypts the minted ticket, extracts the embedded PAC, and writes
// the PAC bytes plus both signing keys (KEY=hex lines) for the C PAC verifier.
func writeBundle(path string, kt *keytab.Keytab, mt kerb.MintedTicket, service, host, realm, client string, authTime time.Time) {
	svc, _, err := kt.GetEncryptionKey(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{service, host}}, realm, 0, etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		log.Fatalf("service key: %v", err)
	}
	tgt, _, err := kt.GetEncryptionKey(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"krbtgt", realm}}, realm, 0, etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		log.Fatalf("krbtgt key: %v", err)
	}
	plain, err := crypto.DecryptMessage(mt.Ticket.EncPart.Cipher, svc, keyusage.KDC_REP_TICKET)
	if err != nil {
		log.Fatalf("decrypt EncPart: %v", err)
	}
	pacBytes := extractPAC(plain)
	userSID, groupSIDs := pacSIDs(pacBytes, svc)
	bundle := fmt.Sprintf("PAC=%s\nSERVERKEY=%s\nKDCKEY=%s\nAUTHTIME=%d\nCLIENT=%s@%s\nUSERSID=%s\nGROUPSIDS=%s\n",
		hex.EncodeToString(pacBytes),
		hex.EncodeToString(svc.KeyValue), hex.EncodeToString(tgt.KeyValue),
		authTime.UTC().Unix(), client, realm,
		userSID, strings.Join(groupSIDs, ","))
	if err := os.WriteFile(path, []byte(bundle), 0o600); err != nil {
		log.Fatalf("write bundle: %v", err)
	}
}

// pacSIDs parses the PAC's KERB_VALIDATION_INFO and returns the user's full SID
// and the group SIDs, as the reference sss_idmap library would see them.
func pacSIDs(pacBytes []byte, key types.EncryptionKey) (string, []string) {
	var pt pac.PACType
	if err := pt.Unmarshal(pacBytes); err != nil {
		log.Fatalf("PAC unmarshal: %v", err)
	}
	if err := pt.ProcessPACInfoBuffers(key, log.New(io.Discard, "", 0)); err != nil {
		log.Fatalf("PAC process: %v", err)
	}
	kvi := pt.KerbValidationInfo
	return fmt.Sprintf("%s-%d", kvi.LogonDomainID.String(), kvi.UserID), kvi.GetGroupMembershipSIDs()
}

// extractPAC pulls the AD-WIN2K-PAC bytes out of a decrypted EncTicketPart's
// AD-IF-RELEVANT authorization-data.
func extractPAC(encTicketPart []byte) []byte {
	var etp messages.EncTicketPart
	if err := etp.Unmarshal(encTicketPart); err != nil {
		log.Fatalf("unmarshal EncTicketPart: %v", err)
	}
	for _, e := range etp.AuthorizationData {
		if e.ADType != adtype.ADIfRelevant {
			continue
		}
		var inner types.AuthorizationData
		if _, err := asn1.Unmarshal(e.ADData, &inner); err != nil {
			log.Fatalf("unmarshal AD-IF-RELEVANT: %v", err)
		}
		for _, ie := range inner {
			if ie.ADType == adtype.ADWin2KPAC {
				return ie.ADData
			}
		}
	}
	log.Fatal("no AD-WIN2K-PAC in the minted ticket")
	return nil
}
