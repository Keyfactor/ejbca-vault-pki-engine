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
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

const (
	testRoleName = "test-role"
)

func TestRole(t *testing.T) {
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
	var testRole = map[string]interface{}{
		"max_ttl":                            int(maxTTL.Seconds()),
		"ttl":                                int(notBeforeDuration.Seconds()),
		"allow_localhost":                    true,
		"allowed_domains":                    []string{"example.com", "example.org"},
		"allowed_domains_template":           false,
		"allow_bare_domains":                 true,
		"allow_subdomains":                   true,
		"allow_glob_domains":                 true,
		"allow_any_name":                     false,
		"allowed_uri_sans_template":          false,
		"enforce_hostnames":                  true,
		"allow_ip_sans":                      true,
		"allowed_uri_sans":                   []string{"urn:example"},
		"server_flag":                        true,
		"client_flag":                        false,
		"code_signing_flag":                  false,
		"email_protection_flag":              true,
		"key_type":                           "rsa",
		"key_bits":                           2048,
		"signature_bits":                     256,
		"use_pss":                            true,
		"use_csr_common_name":                true,
		"use_csr_sans":                       false,
		"key_usage":                          []string{"Digital Signature", "Key Encipherment"},
		"ext_key_usage":                      []string{"Server Auth", "Client Auth"},
		"ext_key_usage_oids":                 []string{"1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"},
		"ou":                                 []string{"Engineering"},
		"organization":                       []string{"Example Co."},
		"country":                            []string{"US"},
		"locality":                           []string{"San Francisco"},
		"province":                           []string{"California"},
		"street_address":                     []string{"123 Example St."},
		"postal_code":                        []string{"94101"},
		"no_store":                           true,
		"require_cn":                         true,
		"cn_validations":                     []string{"disabled"},
		"allowed_serial_numbers":             []string{"123456789"},
		"allowed_user_ids":                   []string{"userid1", "userid2"},
		"basic_constraints_valid_for_non_ca": true,
		"not_before_duration":                int(notBeforeDuration.Seconds()),
		"not_after":                          "2024-05-18T00:00:00Z",
		"issuer_ref":                         "ManagementCA",
		"end_entity_profile_name":            "End Entity Profile Name",
		"certificate_profile_name":           "Certificate Profile Name",
		"account_binding_id":                 "Account Binding ID",
	}

	t.Run("Test Create Role", func(t *testing.T) {
		err := testRoleCreate(t, b, reqStorage, testRole)

		assert.NoError(t, err)
	})

	t.Run("Test Read Role", func(t *testing.T) {
		err := testRoleRead(t, b, reqStorage, testRole)

		assert.NoError(t, err)
	})

	t.Run("Test Delete Role", func(t *testing.T) {
		err := testRoleDelete(t, b, reqStorage)

		assert.NoError(t, err)
	})
}

func testRoleCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      roleStoragePath + testRoleName,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testRoleRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      roleStoragePath + testRoleName,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp.IsError() {
		return resp.Error()
	}

	if resp == nil {
		return fmt.Errorf("resp is nil")
	}

	// Find the values in expected that are not in resp.Data
	diff := map[string]interface{}{}
	for k, _ := range expected {
		if _, ok := resp.Data[k]; !ok {
			diff[k] = nil
		}
	}

	if len(diff) > 0 {
		return fmt.Errorf("read data mismatch (unexpected keys: %v)", diff)
	}

	return nil
}

func testRoleDelete(t *testing.T, b logical.Backend, s logical.Storage) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      roleStoragePath + testRoleName,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}
