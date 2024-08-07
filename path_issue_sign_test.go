/*
Copyright © 2024 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ejbca

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
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathIssueSign(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	err := testConfigCreate(t, b, reqStorage, map[string]interface{}{
		"client_cert":                 clientCert,
		"client_key":                  clientKey,
		"ca_cert":                     caCert,
		"hostname":                    hostname,
		"default_ca":                  _defaultCaName,
		"default_end_entity_profile":  defaultEndEntityProfile,
		"default_certificate_profile": defaultCertificateProfile,
	})
	assert.NoError(t, err)

	maxTTL, _ := time.ParseDuration("1h")
	notBeforeDuration, _ := time.ParseDuration("15m")
	var issueSignRole = map[string]interface{}{
		"max_ttl":            int(maxTTL.Seconds()),
		"ttl":                int(notBeforeDuration.Seconds()),
		"key_type":           "rsa",
		"key_bits":           2048,
		"signature_bits":     256,
		"use_pss":            false,
		"require_cn":         false,
		"allow_bare_domains": true,
		"allow_subdomains":   true,
		"allowed_domains":    "example.com,EJBCAVaultTest.com",
	}

	err = testRoleCreate(t, b, reqStorage, issueSignRole)
	assert.NoError(t, err)

	t.Run("sign/:role_name", func(t *testing.T) {
		err = testSign(t, b, reqStorage, fmt.Sprintf("sign/%s", testRoleName))
		assert.NoError(t, err)
	})

	t.Run("issuer/:issuer_ref/sign/:role_name", func(t *testing.T) {
		err = testSign(t, b, reqStorage, fmt.Sprintf("issuer/%s/sign/%s", _defaultCaName, testRoleName))
		assert.NoError(t, err)
	})

	t.Run("sign-verbatim", func(t *testing.T) {
		err = testSign(t, b, reqStorage, "sign-verbatim")
		assert.NoError(t, err)
	})

	t.Run("sign-verbatim(/:role_name)", func(t *testing.T) {
		err = testSign(t, b, reqStorage, fmt.Sprintf("sign-verbatim/%s", testRoleName))
		assert.NoError(t, err)
	})

	t.Run("sign-verbatim", func(t *testing.T) {
		err = testSign(t, b, reqStorage, "sign-verbatim")
		assert.NoError(t, err)
	})

	t.Run("issue/:role_name", func(t *testing.T) {
		err = testIssue(t, b, reqStorage, fmt.Sprintf("issue/%s", testRoleName))
		assert.NoError(t, err)
	})

	t.Run("issuer/:issuer_ref/sign-verbatim(/:role_name)", func(t *testing.T) {
		err = testSign(t, b, reqStorage, fmt.Sprintf("issuer/%s/sign-verbatim/%s", _defaultCaName, testRoleName))
		assert.NoError(t, err)
	})

	t.Run("issuer/:issuer_ref/sign-verbatim", func(t *testing.T) {
		err = testSign(t, b, reqStorage, fmt.Sprintf("issuer/%s/sign-verbatim", _defaultCaName))
		assert.NoError(t, err)
	})
}

func testSign(t *testing.T, b logical.Backend, s logical.Storage, path string) error {
	// Generate CSR
	random, err := generateRandomString(16)
	require.NoError(t, err)
	subject := fmt.Sprintf("CN=%s.EJBCAVaultTest.com", random)
	csr, err := generateCSR(subject)
	if err != nil {
		return err
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Storage:   s,
		Data: map[string]interface{}{
			"csr":                csr,
			"format":             "pem",
			"private_key_format": "pkcs8",
		},
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}

	if logicalResponseIsEjbcaError(resp) {
		return errors.New("EJBCA returned an error")
	}

	t.Logf("resp.Data:\n%v", resp.Data)

	return testFetchCert(t, b, s, resp.Data["serial_number"].(string))
}

func testIssue(t *testing.T, b logical.Backend, s logical.Storage, path string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Storage:   s,
		Data: map[string]interface{}{
			"common_name": "example.com",
			"alt_names":   "example.com",
		},
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}

	if logicalResponseIsEjbcaError(resp) {
		return errors.New("EJBCA returned an error")
	}

	t.Logf("resp.Data:\n%v", resp.Data)

	return testFetchCert(t, b, s, resp.Data["serial_number"].(string))
}

func testFetchCert(t *testing.T, b logical.Backend, s logical.Storage, serial string) error {
	paths := []string{"", "/raw", "/raw/pem"}

	for _, path := range paths {
		path = "cert/" + serial + path
		t.Logf("Fetching %s", path)
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   s,
		})

		if err != nil {
			return err
		}

		if resp != nil && resp.IsError() {
			return resp.Error()
		}

		if logicalResponseIsEjbcaError(resp) {
			return errors.New("EJBCA returned an error")
		}

		t.Logf("resp.Data:\n%v", resp.Data)
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
				random, err := generateRandomString(5)
				if err != nil {
					return name, err
				}
				name.CommonName = fmt.Sprintf("%s-%s", value, random)
			} else {
				name.CommonName = value
			}
		default:
			// Ignore any unknown keys
		}
	}

	return name, nil
}
