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
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newValidationHelper builds an issueSignHelper wired to an in-memory backend
// with a null logger for the given role. It does not require a live EJBCA
// instance, so it can be used to unit test the request-validation logic in
// isolation.
func newValidationHelper(t *testing.T, role *roleEntry) *issueSignHelper {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	require.NoError(t, err)

	be := b.(*ejbcaBackend)
	sc := be.makeStorageContext(context.Background(), config.StorageView)

	return &issueSignHelper{
		storageContext: sc,
		role:           role,
	}
}

// mustParseURIs parses each raw URI string into a *url.URL, failing the test
// if any is invalid.
func mustParseURIs(t *testing.T, raw ...string) []*url.URL {
	t.Helper()

	uris := make([]*url.URL, 0, len(raw))
	for _, r := range raw {
		u, err := url.Parse(r)
		require.NoError(t, err, "failed to parse test URI %q", r)
		uris = append(uris, u)
	}
	return uris
}

func TestValidateURISANs(t *testing.T) {
	tests := []struct {
		name            string
		allowedURISANs  []string
		requestedURIs   []string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:           "no URIs requested is always allowed",
			allowedURISANs: nil,
			requestedURIs:  nil,
			wantErr:        false,
		},
		{
			name:           "no URIs requested is allowed even with restrictions",
			allowedURISANs: []string{"spiffe://example.com/*"},
			requestedURIs:  nil,
			wantErr:        false,
		},
		{
			// This is the core of the reported vulnerability: when the role
			// permits no URI SANs, a request containing any must be rejected.
			name:            "URI requested but role allows none is rejected",
			allowedURISANs:  nil,
			requestedURIs:   []string{"spiffe://example.com/workload"},
			wantErr:         true,
			wantErrContains: "not allowed in this role",
		},
		{
			// The previously-vulnerable path: role restricts URIs to a
			// pattern, but an arbitrary URI outside the pattern was accepted.
			name:            "URI not matching allowed pattern is rejected",
			allowedURISANs:  []string{"spiffe://example.com/*"},
			requestedURIs:   []string{"spiffe://evil.com/workload"},
			wantErr:         true,
			wantErrContains: "not allowed by this role",
		},
		{
			name:           "URI matching glob pattern is allowed",
			allowedURISANs: []string{"spiffe://example.com/*"},
			requestedURIs:  []string{"spiffe://example.com/workload"},
			wantErr:        false,
		},
		{
			name:           "URI matching exact pattern is allowed",
			allowedURISANs: []string{"spiffe://example.com/workload"},
			requestedURIs:  []string{"spiffe://example.com/workload"},
			wantErr:        false,
		},
		{
			name:           "wildcard pattern allows any URI",
			allowedURISANs: []string{"*"},
			requestedURIs:  []string{"https://anything.example/whatever"},
			wantErr:        false,
		},
		{
			name:            "one disallowed URI among several is rejected",
			allowedURISANs:  []string{"spiffe://example.com/*"},
			requestedURIs:   []string{"spiffe://example.com/a", "spiffe://evil.com/b"},
			wantErr:         true,
			wantErrContains: "spiffe://evil.com/b",
		},
		{
			name:           "all URIs among several match allowed patterns",
			allowedURISANs: []string{"spiffe://example.com/*", "https://svc.example.com/*"},
			requestedURIs:  []string{"spiffe://example.com/a", "https://svc.example.com/b"},
			wantErr:        false,
		},
		{
			name:           "empty allowed entries are ignored and non-empty still matches",
			allowedURISANs: []string{"", "spiffe://example.com/*"},
			requestedURIs:  []string{"spiffe://example.com/workload"},
			wantErr:        false,
		},
		{
			name:            "empty allowed entries do not permit arbitrary URIs",
			allowedURISANs:  []string{""},
			requestedURIs:   []string{"spiffe://evil.com/workload"},
			wantErr:         true,
			wantErrContains: "not allowed by this role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helper := newValidationHelper(t, &roleEntry{
				AllowedURISANs: tt.allowedURISANs,
			})

			csr := &x509.CertificateRequest{
				URIs: mustParseURIs(t, tt.requestedURIs...),
			}

			err := helper.validateURISANs(csr)

			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateNamesEnforcesURISANs ensures that the shared validateNames path
// (used by both the issue and sign flows) actually enforces the URI SAN
// restrictions, not just the domain restrictions. AllowAnyName is enabled so
// that domain validation is a no-op and the URI logic is exercised in
// isolation.
func TestValidateNamesEnforcesURISANs(t *testing.T) {
	t.Run("disallowed URI SAN is rejected even when any domain name is allowed", func(t *testing.T) {
		helper := newValidationHelper(t, &roleEntry{
			AllowAnyName:   true,
			AllowedURISANs: []string{"spiffe://example.com/*"},
		})

		csr := &x509.CertificateRequest{
			DNSNames: []string{"anything.example.org"},
			URIs:     mustParseURIs(t, "spiffe://evil.com/workload"),
		}

		err := helper.validateNames(csr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not allowed by this role")
	})

	t.Run("allowed URI SAN passes validateNames", func(t *testing.T) {
		helper := newValidationHelper(t, &roleEntry{
			AllowAnyName:   true,
			AllowedURISANs: []string{"spiffe://example.com/*"},
		})

		csr := &x509.CertificateRequest{
			DNSNames: []string{"anything.example.org"},
			URIs:     mustParseURIs(t, "spiffe://example.com/workload"),
		}

		err := helper.validateNames(csr)
		assert.NoError(t, err)
	})

	t.Run("URI SAN in submitted CSR is rejected when role allows none", func(t *testing.T) {
		helper := newValidationHelper(t, &roleEntry{
			AllowAnyName:   true,
			AllowedURISANs: nil,
		})

		csr := &x509.CertificateRequest{
			DNSNames: []string{"anything.example.org"},
			URIs:     mustParseURIs(t, "spiffe://example.com/workload"),
		}

		err := helper.validateNames(csr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not allowed in this role")
	})
}
