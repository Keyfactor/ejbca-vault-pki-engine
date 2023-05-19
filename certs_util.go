package ejbca_vault_pki_engine

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Keyfactor/ejbca-go-client-sdk/api/ejbca"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/net/idna"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	labelRegex    = `([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])`
	hostnameRegex = regexp.MustCompile(`^(\*\.)?(` + labelRegex + `\.)*` + labelRegex + `\.?$`)
)

func revokeCert(sc *storageContext, serialNumber string) (*logical.Response, error) {
	// Revoke the certificate
	client, err := sc.getClient()
	if err != nil {
		return nil, err
	}

	// Get the certificate
	parsedBundle, err := sc.Cert().fetchCertBundleBySerial(serialNumber)
	if err != nil {
		return nil, err
	}

	execute, _, err := client.V1CertificateApi.RevokeCertificate(sc.Context, parsedBundle.Certificate.Issuer.String(), serialNumber).Reason("CESSATION_OF_OPERATION").Execute()
	if err != nil {
		return nil, client.createErrorFromEjbcaErr(sc.Backend, "failed to revoke certificate with serial number "+serialNumber, err)
	}

	sc.Backend.Logger().Info("revoked certificate with serial number " + *execute.SerialNumber)

	path := "certs/" + normalizeSerial(serialNumber)

	//remove the certificate from vault.
	err = sc.Cert().deleteCert(path)
	if err != nil {
		return nil, err
	}

	bundle, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, err
	}

	revokedEntry := &revokedCertEntry{
		Certificate:       bundle.Certificate,
		SerialNumber:      bundle.SerialNumber,
		RevocationTime:    execute.RevocationDate.Unix(),
		RevocationTimeUTC: execute.RevocationDate.UTC(),
	}

	err = sc.Cert().putRevokedCertEntry(revokedEntry)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"revocation_time":         execute.RevocationDate.Unix(),
			"revocation_time_rfc3339": execute.RevocationDate.UTC().Format(time.RFC3339Nano),
			"state":                   "revoked",
		},
	}, nil
}

// =================== Issue/Sign Response Builder ===================

type issueSignResponseBuilder struct {
	storageContext *storageContext
	helper         *issueSignHelper

	privateKeyType string
	privateKey     certutil.PrivateKeyType
}

func (b *issueSignResponseBuilder) Config(sc *storageContext, path string, data *framework.FieldData) *issueSignResponseBuilder {
	b.storageContext = sc

	b.helper = &issueSignHelper{}
	b.helper.Init(b.storageContext, path, data)

	return b
}

// IssueCertificate creates a new certificate and private key according to the role configuration
// and signs it using the configured CA.
func (b *issueSignResponseBuilder) IssueCertificate() (*logical.Response, error) {
	err := b.helper.SetRole()
	if err != nil {
		return nil, err
	}

	// Issue methods create the private key and CSR according to the role configuration
	csr, err := b.helper.CreateCsr()
	if err != nil {
		return nil, err
	}

	csrRestResponse, err := b.signCsr(csr)
	if err != nil {
		return nil, err
	}

	return b.helper.SerializeCertificateResponse(csrRestResponse)
}

// SignCertificate signs the provided CSR using the configured CA.
func (b *issueSignResponseBuilder) SignCertificate() (*logical.Response, error) {
	err := b.helper.SetRole()
	if err != nil {
		return nil, err
	}

	csr, err := b.helper.GetCsr()
	if err != nil {
		return nil, err
	}

	csrRestResponse, err := b.signCsr(csr)
	if err != nil {
		return nil, err
	}

	return b.helper.SerializeCertificateResponse(csrRestResponse)
}

// signCsr signs the provided CSR using the EJBCA Go Client SDK library.
func (b *issueSignResponseBuilder) signCsr(csr *x509.CertificateRequest) (*ejbca.CertificateRestResponse, error) {
	endEntityName := "vault_engine-" + generateRandomString(16)
	endEntityPassword := generateRandomString(16)

	enrollConfig := ejbca.EnrollCertificateRestRequest{
		Username: &endEntityName,
		Password: &endEntityPassword,
	}

	enrollConfig.SetCertificateRequest(deserializeCsr(csr))
	enrollConfig.SetCertificateAuthorityName(b.helper.getCaName())
	enrollConfig.SetCertificateProfileName(b.helper.getCertificateProfileName())
	enrollConfig.SetEndEntityProfileName(b.helper.getEndEntityProfileName())
	enrollConfig.SetIncludeChain(b.helper.includeChain())
	enrollConfig.SetAccountBindingId(b.helper.getAccountBindingId())

	client, err := b.storageContext.getClient()
	if err != nil {
		return nil, err
	}

	enrollResponse, _, err := client.V1CertificateApi.EnrollPkcs10Certificate(b.storageContext.Context).EnrollCertificateRestRequest(enrollConfig).Execute()
	if err != nil {
		return nil, client.createErrorFromEjbcaErr(b.storageContext.Backend, "error enrolling certificate with EJBCA. verify that the certificate profile name, end entity profile name, and certificate authority name are appropriate for the certificate request.", err)
	}

	return enrollResponse, nil
}

// ======================= Signing Helpers =======================

type issueSignHelper struct {
	storageContext   *storageContext
	path             string
	data             *framework.FieldData
	role             *roleEntry
	privateKeyHelper *privateKeyHelper
}

func (i *issueSignHelper) Init(sc *storageContext, path string, data *framework.FieldData) {
	i.storageContext = sc
	i.path = path
	i.data = data

	i.privateKeyHelper = &privateKeyHelper{}
}

func (i *issueSignHelper) SerializeCertificateResponse(enrollResponse *ejbca.CertificateRestResponse) (*logical.Response, error) {
	data := map[string]interface{}{}

	caParsedBundle, err := i.storageContext.CA().fetchCaBundle(i.getCaName())
	if err != nil {
		return nil, err
	}

	caBundle, err := caParsedBundle.ToCertBundle()
	if err != nil {
		return nil, err
	}

	var certBytes []byte

	if enrollResponse.GetResponseFormat() == "PEM" {
		// Extract the certificate from the PEM string
		block, _ := pem.Decode([]byte(enrollResponse.GetCertificate()))
		if block == nil {
			return nil, errors.New("failed to parse certificate PEM")
		}
		certBytes = block.Bytes
	} else if enrollResponse.GetResponseFormat() == "DER" {
		// Depending on how the EJBCA API was called, the certificate will either be single b64 encoded or double b64 encoded
		// Try to decode the certificate twice, but don't exit if we fail here. The certificate is decoded later which
		// will give more insight into the failure.
		bytes := []byte(enrollResponse.GetCertificate())
		for i := 0; i < 2; i++ {
			var tempBytes []byte
			tempBytes, err = base64.StdEncoding.DecodeString(string(bytes))
			if err == nil {
				bytes = tempBytes
			}
		}
		certBytes = append(certBytes, bytes...)
	} else {
		return nil, errors.New("ejbca returned unknown certificate format: " + enrollResponse.GetResponseFormat())
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	certBundle := certutil.CertBundle{
		Certificate:    enrollResponse.GetCertificate(),
		IssuingCA:      caBundle.Certificate,
		CAChain:        caBundle.CAChain,
		SerialNumber:   enrollResponse.GetSerialNumber(),
		PrivateKeyType: i.privateKeyHelper.GetPrivateKeyType(),
		PrivateKey:     i.privateKeyHelper.GetPrivateKeyPemString(),
	}

	data["expiration"] = cert.NotAfter.Unix()
	data["serial_number"] = enrollResponse.GetSerialNumber()

	switch i.getCertFormat() {
	case "pem":
		data["certificate"] = enrollResponse.GetCertificate()
		data["issuing_ca"] = caBundle.Certificate
		data["ca_chain"] = caBundle.CAChain

		if !i.isCsrEnroll() {
			data["private_key"] = i.privateKeyHelper.GetPrivateKeyPemString()
			data["private_key_type"] = i.privateKeyHelper.GetPrivateKeyType()
		}
	case "pem_bundle":
		data["certificate"] = certBundle.ToPEMBundle()
		data["issuing_ca"] = caBundle.Certificate
		data["ca_chain"] = caBundle.CAChain
		if !i.isCsrEnroll() {
			data["private_key"] = i.privateKeyHelper.GetPrivateKeyPemString()
			data["private_key_type"] = i.privateKeyHelper.GetPrivateKeyType()
		}
	case "der":
		var derChain []string

		for _, cert := range caParsedBundle.CAChain {
			derChain = append(derChain, base64.StdEncoding.EncodeToString(cert.Bytes))
		}

		data["certificate"] = base64.StdEncoding.EncodeToString(cert.Raw)
		data["issuing_ca"] = base64.StdEncoding.EncodeToString(caParsedBundle.Certificate.Raw)
		data["ca_chain"] = derChain

		if !i.isCsrEnroll() {
			data["private_key"] = i.privateKeyHelper.GetPrivateKeyDerString()
			data["private_key_type"] = i.privateKeyHelper.GetPrivateKeyType()
		}
	}

	// If we created the CSR, we need to return the private key
	if !i.isCsrEnroll() {
		data["private_key_type"] = i.privateKeyHelper.GetPrivateKeyType()
		switch i.getPrivateKeyFormat() {
		case "pem":
			data["private_key"] = i.privateKeyHelper.GetPrivateKeyPemString()
		case "der":
			data["private_key"] = i.privateKeyHelper.GetPrivateKeyDerString()
		case "pkcs8":
			if i.getCertFormat() == "der" {
				data["private_key"] = i.privateKeyHelper.GetPKCS8PrivateKey(false)
			} else {
				data["private_key"] = i.privateKeyHelper.GetPKCS8PrivateKey(true)
			}
		}
	}

	var resp *logical.Response
	switch {
	case i.role.GenerateLease == nil:
		return nil, fmt.Errorf("generate lease in role is nil")
	case !*i.role.GenerateLease:
		// If lease generation is disabled do not populate `Secret` field in
		// the response
		resp = &logical.Response{
			Data: data,
		}
	default:
		resp = i.storageContext.Backend.Secret(SecretCertsEjbcaType).Response(
			data,
			map[string]interface{}{
				"serial_number": enrollResponse.GetSerialNumber(),
			})
		resp.Secret.TTL = cert.NotAfter.Sub(time.Now())
	}

	if !i.role.NoStore {
		// Store the certificate
		entry := &certEntry{
			Certificate:    certBundle.ToPEMBundle(),
			SerialNumber:   certBundle.SerialNumber,
			PrivateKeyType: certBundle.PrivateKeyType,
			PrivateKey:     certBundle.PrivateKey,
			IssuerName:     i.getCaName(),
		}
		err = i.storageContext.Cert().putCertEntry(entry)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (i *issueSignHelper) SetRole() error {
	var err error
	role := &roleEntry{}
	roleRequired := true

	if i.isSignVerbatim() {
		roleRequired = false
	}

	var roleName string
	r, ok := i.data.GetOk("role")
	if ok {
		roleName = r.(string)
	}

	if roleName != "" {
		// Get the role
		role, err = i.storageContext.Role().getRole(roleName)
		if err != nil {
			return err
		}
		if role == nil && (roleRequired || roleName != "") {
			return fmt.Errorf("unknown role: %s", roleName)
		}
	}

	if i.isSignVerbatim() {
		role.AllowLocalhost = true
		role.AllowAnyName = true
		role.AllowIPSANs = true
		role.AllowWildcardCertificates = new(bool)
		role.EnforceHostnames = false
		role.KeyType = "any"
		role.UseCSRCommonName = true
		role.UseCSRSANs = true
		role.AllowedOtherSANs = []string{"*"}
		role.AllowedSerialNumbers = []string{"*"}
		role.AllowedURISANs = []string{"*"}
		role.AllowedUserIDs = []string{"*"}
		role.CNValidations = []string{"disabled"}
		role.GenerateLease = new(bool)
		role.KeyUsage = i.data.Get("key_usage").([]string)
		role.ExtKeyUsage = i.data.Get("ext_key_usage").([]string)
		role.ExtKeyUsageOIDs = i.data.Get("ext_key_usage_oids").([]string)
		role.SignatureBits = i.data.Get("signature_bits").(int)
		role.UsePSS = i.data.Get("use_pss").(bool)
	}

	i.role = role
	return nil
}

// ===============================
// === Data/Path Interpreters ====
// ===============================

func (i *issueSignHelper) isSignVerbatim() bool {
	// The following paths are considered sign-verbatim:
	// - sign-verbatim(/:role_name)
	// - issuer/:issuer_ref/sign-verbatim(/:role_name)

	return strings.HasPrefix(i.path, "sign-verbatim/") || (strings.HasPrefix(i.path, "issuer/") && strings.Contains(i.path, "/sign-verbatim/"))
}

func (i *issueSignHelper) getCaName() string {
	if strings.HasPrefix(i.path, "sign-verbatim/") || strings.HasPrefix(i.path, "sign/") || strings.HasPrefix(i.path, "issue/") {
		return i.role.Issuer
	}

	// If the path is:
	// - issuer/:issuer_ref/sign/:role_name
	// - issuer/:issuer_ref/issue/:role_name
	// - issuer/:issuer_ref/sign-verbatim(/:role_name)
	// , we want to pull the issuer from the path
	if strings.HasPrefix(i.path, "issuer") {
		issuer, ok := i.data.GetOk(issuerRefParam)
		if !ok {
			return ""
		}

		return issuer.(string)
	}

	// If the path is any of the legacy paths (sign, issue, sign-verbatim), we
	// want to use the issuer from the role
	return i.role.Issuer
}

func (i *issueSignHelper) getCertFormat() string {
	format, ok := i.data.GetOk("format")
	if !ok {
		return "pem"
	}

	return format.(string)
}

func (i *issueSignHelper) isCsrEnroll() bool {
	// If the path is:
	// - sign/:role_name
	// - issuer/:issuer_ref/sign/:role_name
	// - sign-verbatim(/:role_name)
	// - issuer/:issuer_ref/sign-verbatim(/:role_name)
	// , it is a CSR enrollment
	if strings.HasPrefix(i.path, "sign/") ||
		(strings.HasPrefix(i.path, "issuer/") && strings.Contains(i.path, "sign/")) ||
		strings.HasPrefix(i.path, "sign-verbatim/") ||
		(strings.HasPrefix(i.path, "sign-verbatim/") && strings.Contains(i.path, "sign-verbatim")) {
		return true
	}

	return false
}

func (i *issueSignHelper) getCertificateProfileName() string {
	return i.role.CertificateProfileName
}

func (i *issueSignHelper) getEndEntityProfileName() string {
	return i.role.EndEntityProfileName
}

func (i *issueSignHelper) getAccountBindingId() string {
	// If an account binding ID was specified on the role, use that
	if i.role.AccountBindingId != "" {
		return i.role.AccountBindingId
	}

	// Otherwise, use the account binding ID from the request
	accountId, ok := i.data.GetOk("account_id")
	if !ok {
		return ""
	}
	return accountId.(string)
}

func (i *issueSignHelper) includeChain() bool {
	// The 'remove_roots_from_chain' contains a boolean value that indicates whether
	// the root certificate should be included in the chain.

	format, ok := i.data.GetOk("remove_roots_from_chain")
	if !ok {
		return true
	}

	return !format.(bool)
}

func (i *issueSignHelper) getPrivateKeyFormat() string {
	format, ok := i.data.GetOk("private_key_format")
	if !ok {
		return "der"
	}

	return format.(string)
}

// ====================
// === CSR Handling ===
// ====================

func (i *issueSignHelper) getSubject() (pkix.Name, error) {
	cn, ok := i.data.GetOk("common_name")
	if !ok && i.role.RequireCN {
		return pkix.Name{}, fmt.Errorf("common_name is required")
	}

	return pkix.Name{
		Country:            i.role.Country,
		Organization:       i.role.Organization,
		OrganizationalUnit: i.role.OU,
		Locality:           i.role.Locality,
		Province:           i.role.Province,
		StreetAddress:      i.role.StreetAddress,
		PostalCode:         i.role.PostalCode,
		CommonName:         cn.(string),
	}, nil
}

func (i *issueSignHelper) getDnsNames() ([]string, error) {
	// TODO validate DNS names against role
	var dnsNames []string

	if altNames := i.data.Get("alt_names").(string); len(altNames) > 0 {
		for _, name := range strutil.ParseDedupAndSortStrings(altNames, ",") {
			// If the name contains an @, it's an email address and is handled by getEmailAddresses
			if !strings.Contains(name, "@") {
				// Only add to dnsNames if it's actually a DNS name but
				// convert idn first
				p := idna.New(
					idna.StrictDomainName(true),
					idna.VerifyDNSLength(true),
				)
				converted, err := p.ToASCII(name)
				if err != nil {
					return nil, errutil.UserError{Err: err.Error()}
				}
				if hostnameRegex.MatchString(converted) {
					dnsNames = append(dnsNames, converted)
				}
			}
		}
	}

	return dnsNames, nil
}

func (i *issueSignHelper) getEmailAddresses() ([]string, error) {
	var emails []string

	if altNames := i.data.Get("alt_names").(string); len(altNames) > 0 {
		for _, name := range strutil.ParseDedupAndSortStrings(altNames, ",") {
			// If the name contains an @, it's an email address
			if strings.Contains(name, "@") {
				emails = append(emails, name)
			}
		}
	}

	return emails, nil
}

func (i *issueSignHelper) getIpAddresses() ([]net.IP, error) {
	var result []net.IP

	if ipAlt := i.data.Get("ip_sans").([]string); len(ipAlt) > 0 {
		if !i.role.AllowIPSANs {
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"IP Subject Alternative Names are not allowed in this role, but was provided %s", ipAlt)}
		}
		for _, v := range ipAlt {
			parsedIP := net.ParseIP(v)
			if parsedIP == nil {
				return nil, errutil.UserError{Err: fmt.Sprintf("the value %q is not a valid IP address", v)}
			}
			result = append(result, parsedIP)
		}
	}

	return result, nil
}

func (i *issueSignHelper) getUriNames() ([]*url.URL, error) {
	var URIs []*url.URL

	if uriAlt := i.data.Get("uri_sans").([]string); len(uriAlt) > 0 {
		if len(i.role.AllowedURISANs) == 0 {
			return nil, errutil.UserError{
				Err: "URI Subject Alternative Names are not allowed in this role, but were provided via the API",
			}
		}

		for _, uri := range uriAlt {
			// TODO validate URI SAN against role

			parsedURI, err := url.Parse(uri)
			if parsedURI == nil || err != nil {
				return nil, errutil.UserError{
					Err: fmt.Sprintf(
						"the provided URI Subject Alternative Name %q is not a valid URI", uri),
				}
			}

			URIs = append(URIs, parsedURI)
		}
	}

	return URIs, nil
}

func (i *issueSignHelper) getOtherSANs() (map[string][]string, error) {
	result := map[string][]string{}

	if sans := i.data.Get("other_sans").([]string); len(sans) > 0 {
		for _, other := range sans {
			splitOther := strings.SplitN(other, ";", 2)
			if len(splitOther) != 2 {
				return nil, fmt.Errorf("expected a semicolon in other SAN %q", other)
			}
			splitType := strings.SplitN(splitOther[1], ":", 2)
			if len(splitType) != 2 {
				return nil, fmt.Errorf("expected a colon in other SAN %q", other)
			}
			switch {
			case strings.EqualFold(splitType[0], "utf8"):
			case strings.EqualFold(splitType[0], "utf-8"):
			default:
				return nil, fmt.Errorf("only utf8 other SANs are supported; found non-supported type in other SAN %q", other)
			}
			result[splitOther[0]] = append(result[splitOther[0]], splitType[1])
		}
	}

	return result, nil
}

func (i *issueSignHelper) CreateCsr() (*x509.CertificateRequest, error) {
	subject, err := i.getSubject()
	if err != nil {
		return nil, err
	}
	names, err := i.getDnsNames()
	if err != nil {
		return nil, err
	}
	emailAddresses, err := i.getEmailAddresses()
	if err != nil {
		return nil, err
	}
	ipAddresses, err := i.getIpAddresses()
	if err != nil {
		return nil, err
	}
	uriNames, err := i.getUriNames()
	if err != nil {
		return nil, err
	}
	otherSans, err := i.getOtherSANs()
	if err != nil {
		return nil, err
	}

	creationBundle := &certutil.CreationBundle{
		Params: &certutil.CreationParameters{
			Subject:        subject,
			DNSNames:       names,
			EmailAddresses: emailAddresses,
			IPAddresses:    ipAddresses,
			URIs:           uriNames,
			OtherSANs:      otherSans,
			IsCA:           false,
			KeyType:        i.role.KeyType,
			KeyBits:        i.role.KeyBits,
			UsePSS:         i.role.UsePSS,
		},
	}

	// Create the CSR. The private key is also generated here.
	csr, err := certutil.CreateCSRWithRandomSource(creationBundle, true, rand.Reader)
	if err != nil {
		return nil, err
	}

	// Initialize the private key helper for later key formatting
	i.privateKeyHelper.Init(csr)

	return csr.CSR, nil
}

func (i *issueSignHelper) GetCsr() (*x509.CertificateRequest, error) {
	csr, ok := i.data.GetOk("csr")
	if !ok {
		return nil, fmt.Errorf("csr is required")
	}

	pemBlock, _ := pem.Decode([]byte(csr.(string)))
	if pemBlock == nil {
		return nil, errutil.UserError{Err: "csr contains no data"}
	}
	parsedCsr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, errutil.UserError{Err: fmt.Sprintf("certificate request could not be parsed: %v", err)}
	}
	if parsedCsr.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm || parsedCsr.PublicKey == nil {
		return nil, errutil.UserError{Err: "Refusing to sign CSR with empty PublicKey. This usually means the SubjectPublicKeyInfo field has an OID not recognized by Go, such as 1.2.840.113549.1.1.10 for rsaPSS."}
	}

	if i.isSignVerbatim() {
		return parsedCsr, nil
	}

	err = i.validateCsr(parsedCsr)
	if err != nil {
		return nil, err
	}

	return parsedCsr, nil
}

func (i *issueSignHelper) validateCsr(csr *x509.CertificateRequest) error {
	var err error
	// This switch validates that the CSR key type matches the role and sets
	// the value in the actualKeyType/actualKeyBits values.
	actualKeyType := ""
	actualKeyBits := 0

	switch i.role.KeyType {
	case "rsa":
		// Verify that the key matches the role type
		if csr.PublicKeyAlgorithm != x509.RSA {
			return errutil.UserError{Err: fmt.Sprintf(
				"role requires keys of type %s",
				i.role.KeyType)}
		}

		pubKey, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errutil.UserError{Err: "could not parse CSR's public key"}
		}

		actualKeyType = "rsa"
		actualKeyBits = pubKey.N.BitLen()
	case "ec":
		// Verify that the key matches the role type
		if csr.PublicKeyAlgorithm != x509.ECDSA {
			return errutil.UserError{Err: fmt.Sprintf(
				"role requires keys of type %s",
				i.role.KeyType)}
		}
		pubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errutil.UserError{Err: "could not parse CSR's public key"}
		}

		actualKeyType = "ec"
		actualKeyBits = pubKey.Params().BitSize
	case "ed25519":
		// Verify that the key matches the role type
		if csr.PublicKeyAlgorithm != x509.Ed25519 {
			return errutil.UserError{Err: fmt.Sprintf(
				"role requires keys of type %s",
				i.role.KeyType)}
		}

		_, ok := csr.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errutil.UserError{Err: "could not parse CSR's public key"}
		}

		actualKeyType = "ed25519"
		actualKeyBits = 0
	case "any":
		// We need to compute the actual key type and key bits, to correctly
		// validate minimums and SignatureBits below.
		switch csr.PublicKeyAlgorithm {
		case x509.RSA:
			pubKey, ok := csr.PublicKey.(*rsa.PublicKey)
			if !ok {
				return errutil.UserError{Err: "could not parse CSR's public key"}
			}
			if pubKey.N.BitLen() < 2048 {
				return errutil.UserError{Err: "RSA keys < 2048 bits are unsafe and not supported"}
			}

			actualKeyType = "rsa"
			actualKeyBits = pubKey.N.BitLen()
		case x509.ECDSA:
			pubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return errutil.UserError{Err: "could not parse CSR's public key"}
			}

			actualKeyType = "ec"
			actualKeyBits = pubKey.Params().BitSize
		case x509.Ed25519:
			_, ok := csr.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errutil.UserError{Err: "could not parse CSR's public key"}
			}

			actualKeyType = "ed25519"
			actualKeyBits = 0
		default:
			return errutil.UserError{Err: "Unknown key type in CSR: " + csr.PublicKeyAlgorithm.String()}
		}
	default:
		return errutil.InternalError{Err: fmt.Sprintf("unsupported key type value: %s", i.role.KeyType)}
	}

	// Before validating key lengths, update our KeyBits/SignatureBits based
	// on the actual CSR key type.
	if i.role.KeyType == "any" {
		// We update the value of KeyBits and SignatureBits here (from the
		// role), using the specified key type. This allows us to convert
		// the default value (0) for SignatureBits and KeyBits to a
		// meaningful value.
		//
		// We ignore the role's original KeyBits value if the KeyType is any
		// as legacy (pre-1.10) roles had default values that made sense only
		// for RSA keys (key_bits=2048) and the older code paths ignored the role value
		// set for KeyBits when KeyType was set to any. This also enforces the
		// docs saying when key_type=any, we only enforce our specified minimums
		// for signing operations
		if i.role.KeyBits, i.role.SignatureBits, err = certutil.ValidateDefaultOrValueKeyTypeSignatureLength(
			actualKeyType, 0, i.role.SignatureBits); err != nil {
			return errutil.InternalError{Err: fmt.Sprintf("unknown internal error updating default values: %v", err)}
		}

		// We're using the KeyBits field as a minimum value below, and P-224 is safe
		// and a previously allowed value. However, the above call defaults
		// to P-256 as that's a saner default than P-224 (w.r.t. generation), so
		// override it here to allow 224 as the smallest size we permit.
		if actualKeyType == "ec" {
			i.role.KeyBits = 224
		}
	}

	// At this point, role.KeyBits and role.SignatureBits should both
	// be non-zero, for RSA and ECDSA keys. Validate the actualKeyBits based on
	// the role's values. If the KeyType was any, and KeyBits was set to 0,
	// KeyBits should be updated to 2048 unless some other value was chosen
	// explicitly.
	//
	// This validation needs to occur regardless of the role's key type, so
	// that we always validate both RSA and ECDSA key sizes.
	if actualKeyType == "rsa" {
		if actualKeyBits < i.role.KeyBits {
			return errutil.UserError{Err: fmt.Sprintf(
				"role requires a minimum of a %d-bit key, but CSR's key is %d bits",
				i.role.KeyBits, actualKeyBits)}
		}

		if actualKeyBits < 2048 {
			return errutil.UserError{Err: fmt.Sprintf(
				"Vault requires a minimum of a 2048-bit key, but CSR's key is %d bits",
				actualKeyBits)}
		}
	} else if actualKeyType == "ec" {
		if actualKeyBits < i.role.KeyBits {
			return errutil.UserError{Err: fmt.Sprintf(
				"role requires a minimum of a %d-bit key, but CSR's key is %d bits",
				i.role.KeyBits,
				actualKeyBits)}
		}
	}

	// TODO many other validations based on role

	return nil
}

// ======================= General Helpers =======================

func compileCertificatesToPemString(certificates []*x509.Certificate) (string, error) {
	var pemBuilder strings.Builder

	for _, certificate := range certificates {
		err := pem.Encode(&pemBuilder, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})
		if err != nil {
			return "", err
		}
	}

	return pemBuilder.String(), nil
}

func deserializeCsr(csr *x509.CertificateRequest) string {
	// PEM encode the CSR
	csrBytes := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csr.Raw,
	})

	return string(csrBytes)
}

func serializePemCert(cert string) (*x509.Certificate, error) {
	// Serialize the certificate
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

func normalizeSerial(serial string) string {
	return strings.Replace(strings.ToLower(serial), ":", "-", -1)
}

func denormalizeSerial(serial string) string {
	return strings.ReplaceAll(strings.ToLower(serial), "-", ":")
}
