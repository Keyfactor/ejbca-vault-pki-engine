package ejbca_vault_pki_engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

func TestPathIssueSign(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	err := testConfigCreate(t, b, reqStorage, map[string]interface{}{
		"client_cert":                 clientCert,
		"client_key":                  clientKey,
		"hostname":                    hostname,
		"default_ca":                  _defaultCaName,
		"default_end_entity_profile":  defaultEndEntityProfile,
		"default_certificate_profile": defaultCertificateProfile,
	})
	assert.NoError(t, err)

	maxTTL, _ := time.ParseDuration("1h")
	notBeforeDuration, _ := time.ParseDuration("15m")
	var issueSignRole = map[string]interface{}{
		"max_ttl":        int(maxTTL.Seconds()),
		"ttl":            int(notBeforeDuration.Seconds()),
		"key_type":       "rsa",
		"key_bits":       2048,
		"signature_bits": 256,
		"use_pss":        false,
	}

	err = testRoleCreate(t, b, reqStorage, issueSignRole)
	assert.NoError(t, err)

	t.Run("sign/:role_name", func(t *testing.T) {
		err = testSign(b, reqStorage, fmt.Sprintf("sign/%s", testRoleName))
		assert.NoError(t, err)
	})

	t.Run("issuer/:issuer_ref/sign/:role_name", func(t *testing.T) {
		err = testSign(b, reqStorage, fmt.Sprintf("issuer/%s/sign/%s", _defaultCaName, testRoleName))
		assert.NoError(t, err)
	})

	t.Run("sign-verbatim", func(t *testing.T) {
		err = testSign(b, reqStorage, fmt.Sprintf("sign-verbatim"))
		assert.NoError(t, err)
	})

	t.Run("sign-verbatim(/:role_name)", func(t *testing.T) {
		err = testSign(b, reqStorage, fmt.Sprintf("sign-verbatim/%s", testRoleName))
		assert.NoError(t, err)
	})

	t.Run("issue/:role_name", func(t *testing.T) {
		err = testIssue(b, reqStorage, fmt.Sprintf("issue/%s", testRoleName))
		assert.NoError(t, err)
	})

	t.Run("issuer/:issuer_ref/sign-verbatim(/:role_name)", func(t *testing.T) {
		err = testIssue(b, reqStorage, fmt.Sprintf("issuer/%s/issue/%s", _defaultCaName, testRoleName))
		assert.NoError(t, err)
	})
}

func testSign(b logical.Backend, s logical.Storage, path string) error {
	// Generate CSR
	csr, err := generateCSR("CN=EJBCAVaultTest_" + generateRandomString(16))
	if err != nil {
		return err
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Storage:   s,
		Data: map[string]interface{}{
			"csr": csr,
		},
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}

	return nil
}

func testIssue(b logical.Backend, s logical.Storage, path string) error {
	cn := "EJBCAVaultTest_" + generateRandomString(16)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Storage:   s,
		Data: map[string]interface{}{
			"common_name": cn,
			"alt_names":   "example.com",
		},
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}

	return nil
}

func generateCSR(subject string) (string, error) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj, err := parseSubjectDN(subject, false)
	if err != nil {
		return "", err
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	var csrBuf bytes.Buffer
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	err = pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return "", err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return "", err
	}

	if err = csr.CheckSignature(); err != nil {
		return "", errors.New("failed signature validation for CSR")
	}

	return csrBuf.String(), nil
}

// Function that turns subject string into pkix.Name
// EG "C=US,ST=California,L=San Francisco,O=HashiCorp,OU=Engineering,CN=example.com"
func parseSubjectDN(subject string, randomizeCn bool) (pkix.Name, error) {
	var name pkix.Name

	// Split the subject into its individual parts
	parts := strings.Split(subject, ",")

	for _, part := range parts {
		// Split the part into key and value
		keyValue := strings.SplitN(part, "=", 2)

		if len(keyValue) != 2 {
			return pkix.Name{}, asn1.SyntaxError{Msg: "malformed subject DN"}
		}

		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		// Map the key to the appropriate field in the pkix.Name struct
		switch key {
		case "C":
			name.Country = []string{value}
		case "ST":
			name.Province = []string{value}
		case "L":
			name.Locality = []string{value}
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "CN":
			if randomizeCn {
				value = fmt.Sprintf("%s-%s", value, generateRandomString(5))
			} else {
				name.CommonName = value
			}
		default:
			// Ignore any unknown keys
		}
	}

	return name, nil
}
