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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestCert generates a minimal self-signed certificate for use in tests.
func makeTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestBuildCaEntry(t *testing.T) {
	t.Run("empty chain returns an error instead of panicking", func(t *testing.T) {
		entry, err := buildCaEntry(nil)
		require.Error(t, err)
		assert.Empty(t, entry.CaCertificate)
		assert.Empty(t, entry.CAChain)
	})

	t.Run("single certificate becomes the CA certificate with an empty chain", func(t *testing.T) {
		cert := makeTestCert(t, "Root CA")

		entry, err := buildCaEntry([]*x509.Certificate{cert})
		require.NoError(t, err)
		assert.Contains(t, entry.CaCertificate, "BEGIN CERTIFICATE")
		assert.Empty(t, entry.CAChain)
	})

	t.Run("multiple certificates split into CA certificate plus chain", func(t *testing.T) {
		issuing := makeTestCert(t, "Issuing CA")
		root := makeTestCert(t, "Root CA")

		entry, err := buildCaEntry([]*x509.Certificate{issuing, root})
		require.NoError(t, err)
		assert.Contains(t, entry.CaCertificate, "BEGIN CERTIFICATE")
		require.Len(t, entry.CAChain, 1)
		assert.Contains(t, entry.CAChain[0], "BEGIN CERTIFICATE")
		// The first certificate is the CA certificate; the remainder is the chain.
		assert.NotEqual(t, entry.CaCertificate, entry.CAChain[0])
	})
}
