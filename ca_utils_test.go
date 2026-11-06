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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStorageContext builds a storageContext backed by in-memory storage
// with a null logger, for unit tests that don't require a live EJBCA instance.
func newTestStorageContext(t *testing.T) *storageContext {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	require.NoError(t, err)

	be := b.(*ejbcaBackend)
	return be.makeStorageContext(context.Background(), config.StorageView)
}

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

func TestCaEntryIsFresh(t *testing.T) {
	ttl := time.Hour

	t.Run("recently fetched entry is fresh", func(t *testing.T) {
		entry := caEntry{FetchedAt: time.Now().Unix()}
		assert.True(t, caEntryIsFresh(entry, ttl))
	})

	t.Run("entry older than the TTL is stale", func(t *testing.T) {
		entry := caEntry{FetchedAt: time.Now().Add(-2 * time.Hour).Unix()}
		assert.False(t, caEntryIsFresh(entry, ttl))
	})

	t.Run("entry with no fetch timestamp is stale", func(t *testing.T) {
		assert.False(t, caEntryIsFresh(caEntry{}, ttl))
	})
}

func TestCaCacheTTL(t *testing.T) {
	t.Run("defaults when unconfigured", func(t *testing.T) {
		sc := newTestStorageContext(t)
		assert.Equal(t, defaultCaCacheDuration, sc.CA().caCacheTTL())
	})

	t.Run("defaults when the configured duration is zero", func(t *testing.T) {
		sc := newTestStorageContext(t)
		require.NoError(t, sc.Config().putConfig(&ejbcaConfig{
			Hostname:               "ejbca.example.com",
			CaCacheDurationSeconds: 0,
		}))
		assert.Equal(t, defaultCaCacheDuration, sc.CA().caCacheTTL())
	})

	t.Run("uses the configured duration when set", func(t *testing.T) {
		sc := newTestStorageContext(t)
		require.NoError(t, sc.Config().putConfig(&ejbcaConfig{
			Hostname:               "ejbca.example.com",
			CaCacheDurationSeconds: 7200,
		}))
		assert.Equal(t, 2*time.Hour, sc.CA().caCacheTTL())
	})
}

func TestCaResponseBuilderResolvesDefaultCA(t *testing.T) {
	t.Run("uses the configured default_ca", func(t *testing.T) {
		sc := newTestStorageContext(t)
		require.NoError(t, sc.Config().putConfig(&ejbcaConfig{
			Hostname:      "ejbca.example.com",
			DefaultCAName: "MyConfiguredCA",
		}))

		b := (&caResponseBuilder{}).Config(sc, "ca")
		assert.Equal(t, "MyConfiguredCA", b.caName)
	})

	t.Run("falls back to the built-in default when unconfigured", func(t *testing.T) {
		sc := newTestStorageContext(t)

		b := (&caResponseBuilder{}).Config(sc, "ca")
		assert.Equal(t, defaultCaName, b.caName)
	})

	t.Run("falls back to the built-in default when default_ca is empty", func(t *testing.T) {
		sc := newTestStorageContext(t)
		require.NoError(t, sc.Config().putConfig(&ejbcaConfig{
			Hostname: "ejbca.example.com",
		}))

		b := (&caResponseBuilder{}).Config(sc, "ca")
		assert.Equal(t, defaultCaName, b.caName)
	})
}
