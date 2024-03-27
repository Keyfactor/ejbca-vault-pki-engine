/*
Copyright 2024 Keyfactor
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
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestPathRevoke(t *testing.T) {
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
		"allow_bare_domains": true,
		"allow_subdomains":   true,
		"allowed_domains":    "example.com,EJBCAVaultTest.com",
	}

	err = testRoleCreate(t, b, reqStorage, issueSignRole)
	assert.NoError(t, err)

	cn := fmt.Sprintf("%s.EJBCAVaultTest.com", generateRandomString(16))

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("issue/%s", testRoleName),
		Storage:   reqStorage,
		Data: map[string]interface{}{
			"common_name": cn,
			"alt_names":   "example.com",
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	if resp == nil {
		t.Fatal("response is nil")
	}

	if resp.Data == nil {
		t.Fatal("response data is nil")
	}

	serialNumberInterface, ok := resp.Data["serial_number"]
	if !ok {
		t.Fatal("serial_number not found in response")
	}
	serialNumber := serialNumberInterface.(string)

	t.Run("revoke", func(t *testing.T) {
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "revoke",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"serial_number": serialNumber,
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.Data["revocation_time"])
	})
}

func TestPathRevokeWithPrivateKey(t *testing.T) {
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

	cn := fmt.Sprintf("%s.EJBCAVaultTest.com", generateRandomString(16))

	maxTTL, _ := time.ParseDuration("1h")
	notBeforeDuration, _ := time.ParseDuration("15m")
	var issueSignRole = map[string]interface{}{
		"max_ttl":            int(maxTTL.Seconds()),
		"ttl":                int(notBeforeDuration.Seconds()),
		"key_type":           "rsa",
		"key_bits":           2048,
		"signature_bits":     256,
		"use_pss":            false,
		"allow_bare_domains": true,
		"allow_subdomains":   true,
		"allowed_domains":    "example.com,EJBCAVaultTest.com",
	}

	err = testRoleCreate(t, b, reqStorage, issueSignRole)
	assert.NoError(t, err)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("issue/%s", testRoleName),
		Storage:   reqStorage,
		Data: map[string]interface{}{
			"common_name": cn,
			"alt_names":   "example.com",
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	if resp == nil {
		t.Fatal("response is nil")
	}

	if resp.Data == nil {
		t.Fatal("response data is nil")
	}

	serialNumberInterface, ok := resp.Data["serial_number"]
	if !ok {
		t.Fatal("serial_number not found in response")
	}
	serialNumber := serialNumberInterface.(string)
	privateKey := resp.Data["private_key"].(string)

	t.Run("revoke", func(t *testing.T) {
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "revoke-with-key",
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"serial_number": serialNumber,
				"private_key":   privateKey,
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.Data["revocation_time"])
	})
}
