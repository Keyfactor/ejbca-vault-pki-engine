/*
Copyright 2023 Keyfactor
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License.  You may obtain a
copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless
required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied. See the License for
thespecific language governing permissions and limitations under the
License.
*/
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
    logger := sc.Backend.Logger().Named("revokeCert")
    logger.Info("revoking certificate with serial number " + serialNumber)

	client, err := sc.getClient()
	if err != nil {
		return nil, err
	}

	// Get the certificate
	parsedBundle, err := sc.Cert().fetchCertBundleBySerial(serialNumber)
	if err != nil {
		return nil, err
	}

	renormSerialNumber := strings.ReplaceAll(denormalizeSerial(serialNumber), ":", "")

    logger.Debug("Calling EJBCA to revoke certificate with serial number " + renormSerialNumber)
	execute, _, err := client.V1CertificateApi.RevokeCertificate(sc.Context, parsedBundle.Certificate.Issuer.String(), renormSerialNumber).Reason("CESSATION_OF_OPERATION").Execute()
	if err != nil {
		return nil, client.createErrorFromEjbcaErr(sc.Backend, "failed to revoke certificate with serial number "+serialNumber, err)
	}

    logger.Debug("Certificate with serial number " + renormSerialNumber + " revoked successfully")

	//remove the certificate from vault.
	err = sc.Cert().deleteCert(serialNumber)
	if err != nil {
		return nil, err
	}

	bundle, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, err
	}

    logger.Trace("Creating revoked certificate entry")
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
    logger := b.storageContext.Backend.Logger().Named("issueSignResponseBuilder.IssueCertificate")
    logger.Debug("Issuing certificate")

    logger.Trace("Setting role for certificate issuance")
	err := b.helper.SetRole()
	if err != nil {
		return nil, err
	}

	// Issue methods create the private key and CSR according to the role configuration
    logger.Trace("Creating CSR")
	csr, err := b.helper.CreateCsr()
	if err != nil {
		return nil, err
	}

    logger.Trace("Signing CSR")
	csrRestResponse, err := b.signCsr(csr)
	if err != nil {
		return nil, err
	}

	return b.helper.SerializeCertificateResponse(csrRestResponse)
}

// SignCertificate signs the provided CSR using the configured CA.
func (b *issueSignResponseBuilder) SignCertificate() (*logical.Response, error) {
    logger := b.storageContext.Backend.Logger().Named("issueSignResponseBuilder.SignCertificate")
    logger.Debug("Signing certificate")

    logger.Trace("Setting role for certificate signing")
	err := b.helper.SetRole()
	if err != nil {
		return nil, err
	}

    logger.Trace("Getting CSR")
	csr, err := b.helper.GetCsr()
	if err != nil {
		return nil, err
	}

    logger.Trace("Signing CSR")
	csrRestResponse, err := b.signCsr(csr)
	if err != nil {
		return nil, err
	}

	return b.helper.SerializeCertificateResponse(csrRestResponse)
}

// signCsr signs the provided CSR using the EJBCA Go Client SDK library.
func (b *issueSignResponseBuilder) signCsr(csr *x509.CertificateRequest) (*ejbca.CertificateRestResponse, error) {
    logger := b.storageContext.Backend.Logger().Named("issueSignResponseBuilder.signCsr")
    logger.Debug("Signing CSR")

	endEntityPassword := generateRandomString(16)

	enrollConfig := ejbca.EnrollCertificateRestRequest{}
    enrollConfig.SetUsername(b.helper.getEndEntityName(csr))
    enrollConfig.SetPassword(endEntityPassword)

	// Configure the request using local state and the CSR
	enrollConfig.SetCertificateRequest(deserializeCsr(csr))
	enrollConfig.SetCertificateAuthorityName(b.helper.getCaName())
	enrollConfig.SetCertificateProfileName(b.helper.getCertificateProfileName())
	enrollConfig.SetEndEntityProfileName(b.helper.getEndEntityProfileName())
	enrollConfig.SetIncludeChain(b.helper.includeChain())
	enrollConfig.SetAccountBindingId(b.helper.getAccountBindingId())

    logger.Trace("EJBCA PKCS#10 Request CA name", "caName", b.helper.getCaName())
    logger.Trace("EJBCA PKCS#10 Request certificate profile name", "certificateProfileName", b.helper.getCertificateProfileName())
    logger.Trace("EJBCA PKCS#10 Request end entity profile name", "endEntityProfileName", b.helper.getEndEntityProfileName())
    logger.Trace("EJBCA PKCS#10 Request include chain", "includeChain", b.helper.includeChain())
    logger.Trace("EJBCA PKCS#10 Request account binding ID", "accountBindingId", b.helper.getAccountBindingId())

	// Retrieve the EJBCA client from the storage context
	client, err := b.storageContext.getClient()
	if err != nil {
		return nil, err
	}

	// Send the CSR to EJBCA to be signed
    logger.Trace("Enrolling certificate with EJBCA using PKCS#10 request")
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

func (i *issueSignHelper) getRoleName() string {
	var roleName string
	r, ok := i.data.GetOk("role")
	if ok {
		roleName = r.(string)
	}
	return roleName
}

func (i *issueSignHelper) Init(sc *storageContext, path string, data *framework.FieldData) {
	i.storageContext = sc
	i.path = path
	i.data = data

	i.privateKeyHelper = &privateKeyHelper{isInit: false}
}

func (i *issueSignHelper) SerializeCertificateResponse(enrollResponse *ejbca.CertificateRestResponse) (*logical.Response, error) {
    logger := i.storageContext.Backend.Logger().Named("issueSignHelper.SerializeCertificateResponse")
    logger.Debug("Serializing certificate response")

	data := map[string]interface{}{}
	var err error

	var certBytes []byte

	if enrollResponse.GetResponseFormat() == "PEM" {
        logger.Trace("EJBCA returned certificate in PEM format - serializing")
          
		// Extract the certificate from the PEM string
		block, _ := pem.Decode([]byte(enrollResponse.GetCertificate()))
		if block == nil {
			return nil, errors.New("failed to parse certificate PEM")
		}
		certBytes = block.Bytes
	} else if enrollResponse.GetResponseFormat() == "DER" {
        logger.Trace("EJBCA returned certificate in DER format - serializing")

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

    logger.Trace("Fetching CA bundle from storage to include in response")
	caParsedBundle, err := i.storageContext.CA().fetchCaBundle(i.getCaName())
	if err != nil {
		return nil, err
	}

	parsedCertBundle := certutil.ParsedCertBundle{
		CertificateBytes: cert.Raw,
		Certificate:      cert,
		CAChain:          caParsedBundle.GetFullChain(),
	}

	certBundle, err := parsedCertBundle.ToCertBundle()
	if err != nil {
		return nil, err
	}

    logger.Trace("Populating parsed cert bundle to response data")

	data["expiration"] = cert.NotAfter.Unix()
	data["serial_number"] = certBundle.SerialNumber

	switch i.getCertFormat() {
	case "pem":
		data["certificate"] = certBundle.Certificate
		data["issuing_ca"] = certBundle.CAChain[0]
		data["ca_chain"] = certBundle.CAChain
	case "pem_bundle":
		data["certificate"] = certBundle.ToPEMBundle()
		data["issuing_ca"] = certBundle.CAChain[0]
		data["ca_chain"] = certBundle.CAChain
	case "der":
		var derChain []string

		for _, block := range caParsedBundle.GetFullChain() {
			derChain = append(derChain, base64.StdEncoding.EncodeToString(block.Bytes))
		}

		data["certificate"] = base64.StdEncoding.EncodeToString(cert.Raw)
		data["issuing_ca"] = derChain[0]
		data["ca_chain"] = derChain
	}

	// If we created the CSR, we need to return the private key
	if !i.isCsrEnroll() {
        logger.Trace("Private key generated by EJBCA PKI engine - serializing", "privateKeyType", i.privateKeyHelper.GetPrivateKeyType())
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
		case "pem_bundle":
			data["private_key"] = i.privateKeyHelper.GetPrivateKeyPemString()
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
				"serial_number": certBundle.SerialNumber,
			})
		resp.Secret.TTL = time.Until(cert.NotAfter)
	}

	if !i.role.NoStore {
		// Store the certificate
		entry := &certEntry{
			Certificate:    certBundle.Certificate,
			SerialNumber:   certBundle.SerialNumber,
			PrivateKeyType: i.privateKeyHelper.GetPrivateKeyType(),
			PrivateKey:     i.privateKeyHelper.GetPrivateKeyPemString(),
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
    logger := i.storageContext.Backend.Logger().Named("issueSignHelper.SetRole")
    logger.Debug("Setting role")

	var err error
	roleRequired := true

	if i.isSignVerbatim() {
        roleRequired = false
	}

	var roleName string
	r, ok := i.data.GetOk("role")
	if ok {
		roleName = r.(string)
	}

    logger.Trace("Fetching role from storage", "roleName", roleName)
	role, err := i.storageContext.Role().getRole(roleName)
	if err != nil {
		return err
	}
	if role == nil && (roleRequired || roleName != "") {
		return fmt.Errorf("unknown role: %s", roleName)
	}

	if i.isSignVerbatim() {
	    logger.Trace("Sign verbatim - Won't validate CSR against role")
		role = &roleEntry{}
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

		_, _ = role.validate(i.storageContext)
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

    isSignVerbatim := strings.HasPrefix(i.path, "sign-verbatim") || (strings.HasPrefix(i.path, "issuer/") && strings.Contains(i.path, "/sign-verbatim"))
    i.storageContext.Backend.Logger().Named("issueSignHelper.isSignVerbatim").Debug("Checking if path is sign verbatim", "isSignVerbatim", isSignVerbatim)
    return isSignVerbatim
}

func (i *issueSignHelper) getCaName() string {
    logger := i.storageContext.Backend.Logger().Named("issueSignHelper.getCaName")

	if strings.HasPrefix(i.path, "sign-verbatim") || strings.HasPrefix(i.path, "sign/") || strings.HasPrefix(i.path, "issue/") {
	    logger.Trace("Using CA name (issuer) from role", "caName", i.role.Issuer)
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

        logger.Trace("Using CA name (issuer) from path", "caName", issuer.(string))
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
		strings.HasPrefix(i.path, "sign-verbatim") {
            i.storageContext.Backend.Logger().Named("issueSignHelper.isCsrEnroll").Trace("Determined path from request requires CSR enrollment (client-generated keys)")
            return true
	}

    i.storageContext.Backend.Logger().Named("issueSignHelper.isCsrEnroll").Trace("Determined path from request does not require CSR enrollment (EJBCA PKI engine will generate keys)")
	return false
}

func (i *issueSignHelper) getCertificateProfileName() string {
	return i.role.CertificateProfileName
}

func (i *issueSignHelper) getEndEntityProfileName() string {
	return i.role.EndEntityProfileName
}

// getEndEntityName determines the EJBCA end entity name based on the CSR and the defaultEndEntityName option.
func (i *issueSignHelper) getEndEntityName(csr *x509.CertificateRequest) string {
    logger := i.storageContext.Backend.Logger().Named("issueSignHelper.getEndEntityName")

	eeName := ""
	// 1. If the endEntityName option is set, determine the end entity name based on the option
	// 2. If the endEntityName option is not set, determine the end entity name based on the CSR

	// cn: Use the CommonName from the CertificateRequest's DN
	if i.role.EndEntityName == "cn" || i.role.EndEntityName == "" {
		if csr.Subject.CommonName != "" {
			eeName = csr.Subject.CommonName
			logger.Trace(fmt.Sprintf("Using CommonName from the CertificateRequest's DN as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	//* dns: Use the first DNSName from the CertificateRequest's DNSNames SANs
	if i.role.EndEntityName == "dns" || i.role.EndEntityName == "" {
		if len(csr.DNSNames) > 0 && csr.DNSNames[0] != "" {
			eeName = csr.DNSNames[0]
			logger.Trace(fmt.Sprintf("Using the first DNSName from the CertificateRequest's DNSNames SANs as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	//* uri: Use the first URI from the CertificateRequest's URI Sans
	if i.role.EndEntityName == "uri" || i.role.EndEntityName == "" {
		if len(csr.URIs) > 0 {
			eeName = csr.URIs[0].String()
			logger.Trace(fmt.Sprintf("Using the first URI from the CertificateRequest's URI Sans as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	//* ip: Use the first IPAddress from the CertificateRequest's IPAddresses SANs
	if i.role.EndEntityName == "ip" || i.role.EndEntityName == "" {
		if len(csr.IPAddresses) > 0 {
			eeName = csr.IPAddresses[0].String()
			logger.Trace(fmt.Sprintf("Using the first IPAddress from the CertificateRequest's IPAddresses SANs as the EJBCA end entity name: %q", eeName))
			return eeName
		}
	}

	// End of defaults; if the endEntityName option is set to anything but cn, dns, or uri, use the option as the end entity name
	if i.role.EndEntityName != "" && i.role.EndEntityName != "cn" && i.role.EndEntityName != "dns" && i.role.EndEntityName != "uri" {
		eeName = i.role.EndEntityName
		logger.Trace(fmt.Sprintf("Using the defaultEndEntityName as the EJBCA end entity name: %q", eeName))
		return eeName
	}

	// If we get here, we were unable to determine the end entity name
	logger.Error(fmt.Sprintf("the endEntityName option is set to %q, but no valid end entity name could be determined from the CertificateRequest", i.role.EndEntityName))

	return eeName
}

func (i *issueSignHelper) getAccountBindingId() string {
	// If an account binding ID was specified on the role, use that
	if i.role.AccountBindingId != "" {
		return i.role.AccountBindingId
	}

	// Otherwise, use the account binding ID from the request
	accountId, ok := i.data.GetOk("account_binding_id")
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
		return i.getCertFormat()
	}

	return format.(string)
}

// ====================
// === CSR Handling ===
// ====================

func (i *issueSignHelper) getSubject() (pkix.Name, error) {
	cnInterface := i.data.Get("common_name")

	cn, ok := cnInterface.(string)
	if !ok {
		return pkix.Name{}, fmt.Errorf("common_name is not a string")
	}

	if i.role.RequireCN && cn == "" {
		return pkix.Name{}, fmt.Errorf("common_name is required for role called %q", i.getRoleName())
	}

	return pkix.Name{
		Country:            i.role.Country,
		Organization:       i.role.Organization,
		OrganizationalUnit: i.role.OU,
		Locality:           i.role.Locality,
		Province:           i.role.Province,
		StreetAddress:      i.role.StreetAddress,
		PostalCode:         i.role.PostalCode,
		CommonName:         cn,
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
    logger := i.storageContext.Backend.Logger().Named("issueSignHelper.CreateCsr")
    logger.Debug("Creating CSR")

	subject, err := i.getSubject()
	if err != nil {
		return nil, err
	}
    logger.Trace("Subject for CSR", "subject", subject)

	names, err := i.getDnsNames()
	if err != nil {
		return nil, err
	}
    logger.Trace("DNS names for CSR", "names", names)

	emailAddresses, err := i.getEmailAddresses()
	if err != nil {
		return nil, err
	}
    logger.Trace("Email addresses for CSR", "emailAddresses", emailAddresses)

	ipAddresses, err := i.getIpAddresses()
	if err != nil {
		return nil, err
	}
    logger.Trace("IP addresses for CSR", "ipAddresses", ipAddresses)

	uriNames, err := i.getUriNames()
	if err != nil {
		return nil, err
	}
    logger.Trace("URI names for CSR", "uriNames", uriNames)

	otherSans, err := i.getOtherSANs()
	if err != nil {
		return nil, err
	}
    logger.Trace("Other SANs for CSR", "otherSans", otherSans)

    logger.Trace("Assembling CSR creation bundle")
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
    logger.Trace("Creating CSR with random source")
	csr, err := certutil.CreateCSRWithRandomSource(creationBundle, false, rand.Reader)
	if err != nil {
		return nil, err
	}

	// Initialize the private key helper for later key formatting
	i.privateKeyHelper.Init(csr)

	return csr.CSR, nil
}

func (i *issueSignHelper) GetCsr() (*x509.CertificateRequest, error) {
    logger := i.storageContext.Backend.Logger().Named("issueSignHelper.GetCsr")
    logger.Debug("Getting CSR from request data")

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
        logger.Trace("Sign verbatim - Skipping CSR validation")
		return parsedCsr, nil
	}

    logger.Trace("Validating CSR")
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
