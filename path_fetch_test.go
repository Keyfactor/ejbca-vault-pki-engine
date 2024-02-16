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
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPathFetchCa(t *testing.T) {
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

	t.Run("Test /ca", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "ca")
		assert.NoError(t, err)
	})

	t.Run("Test ca/pem", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "ca/pem")
		assert.NoError(t, err)
	})

	t.Run("Test cert/ca", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "cert/ca")
		assert.NoError(t, err)
	})

	t.Run("Test cert/ca/raw", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "cert/ca/raw")
		assert.NoError(t, err)
	})

	t.Run("Test cert/ca/raw/pem", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "cert/ca/raw/pem")
		assert.NoError(t, err)
	})

	t.Run("Test ca_chain", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "ca_chain")
		assert.NoError(t, err)
	})

	t.Run("Test cert/ca_chain", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "cert/ca_chain")
		assert.NoError(t, err)
	})

	t.Run("Test issuer/:issuer_ref", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "issuer/"+_defaultCaName)
		assert.NoError(t, err)
	})

	t.Run("Test issuer/:issuer_ref/json", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "issuer/"+_defaultCaName+"/json")
		assert.NoError(t, err)
	})

	t.Run("Test issuer/:issuer_ref/der", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "issuer/"+_defaultCaName+"/der")
		assert.NoError(t, err)
	})

	t.Run("Test issuer/:issuer_ref/pem", func(t *testing.T) {
		err = testFetchCa(t, b, reqStorage, "issuer/"+_defaultCaName+"/pem")
		assert.NoError(t, err)
	})
}

func testFetchCa(t *testing.T, b logical.Backend, s logical.Storage, path string) error {
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

	t.Logf("resp.Data:\n%v", resp.Data)

	return nil
}
