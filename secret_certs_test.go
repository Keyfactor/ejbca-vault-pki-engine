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
	"encoding/pem"
	"errors"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchCertBundleBySerialNotFound(t *testing.T) {
	sc := newTestStorageContext(t)

	_, err := sc.Cert().fetchCertBundleBySerial("de:ad:be:ef")
	require.Error(t, err)

	// A missing serial must surface as a UserError (mapped to a clean client
	// response) rather than an InternalError (HTTP 500).
	var userErr errutil.UserError
	assert.True(t, errors.As(err, &userErr), "expected a UserError for a missing serial, got %T", err)
}

func TestLeaseSerialNumber(t *testing.T) {
	t.Run("nil secret returns empty", func(t *testing.T) {
		assert.Equal(t, "", leaseSerialNumber(nil))
	})

	t.Run("nil internal data returns empty", func(t *testing.T) {
		assert.Equal(t, "", leaseSerialNumber(&logical.Secret{}))
	})

	t.Run("string serial is returned", func(t *testing.T) {
		secret := &logical.Secret{
			InternalData: map[string]interface{}{"serial_number": "ab:cd:ef"},
		}
		assert.Equal(t, "ab:cd:ef", leaseSerialNumber(secret))
	})

	t.Run("non-string serial returns empty", func(t *testing.T) {
		secret := &logical.Secret{
			InternalData: map[string]interface{}{"serial_number": 1234},
		}
		assert.Equal(t, "", leaseSerialNumber(secret))
	})
}

func TestRevokeBuilderConfigFromSerial(t *testing.T) {
	t.Run("empty serial sets an error response", func(t *testing.T) {
		b := (&revokeBuilder{}).ConfigFromSerial(newTestStorageContext(t), "")
		require.NotNil(t, b.errorResponse)
		assert.True(t, b.errorResponse.IsError())
	})

	t.Run("unknown serial sets an error response", func(t *testing.T) {
		b := (&revokeBuilder{}).ConfigFromSerial(newTestStorageContext(t), "de:ad:be:ef")
		require.NotNil(t, b.errorResponse)
		assert.True(t, b.errorResponse.IsError())
	})

	t.Run("stored serial resolves issuer and serial independent of format", func(t *testing.T) {
		sc := newTestStorageContext(t)
		cert := makeTestCert(t, "Issuing CA")
		pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

		const serial = "01:02:03:04"
		require.NoError(t, sc.Cert().putCertEntry(&certEntry{
			Certificate:  pemCert,
			SerialNumber: serial,
		}))

		b := (&revokeBuilder{}).ConfigFromSerial(sc, serial)
		require.Nil(t, b.errorResponse)
		assert.Equal(t, cert.Issuer.String(), b.issuerDn)
		assert.NotEmpty(t, b.normalizedHexSerialNumber)
		// The normalized serial must not contain the colons used in storage.
		assert.NotContains(t, b.normalizedHexSerialNumber, ":")
	})
}
