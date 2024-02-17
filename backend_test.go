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
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"os"
	"testing"
)

var (
	clientCert                = ""
	clientKey                 = ""
	caCert                    = ""
	hostname                  = os.Getenv("EJBCA_HOSTNAME")
	_defaultCaName            = os.Getenv("EJBCA_CA_NAME")
	defaultEndEntityProfile   = os.Getenv("EJBCA_END_ENTITY_PROFILE_NAME")
	defaultCertificateProfile = os.Getenv("EJBCA_CERTIFICATE_PROFILE_NAME")
)

func getTestBackend(tb testing.TB) (*ejbcaBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatalf("error creating backend: %v", err)
	}

	clientCertPath := os.Getenv("EJBCA_CLIENT_CERT_PATH")
	file, err := os.ReadFile(clientCertPath)
	if err != nil {
		tb.Fatalf("error reading client cert: %v", err)
	}
	clientCert = string(file)

	clientKeyPath := os.Getenv("EJBCA_CLIENT_KEY_PATH")
	file, err = os.ReadFile(clientKeyPath)
	if err != nil {
		tb.Fatalf("error reading client key: %v", err)
	}
	clientKey = string(file)

	caCertPath := os.Getenv("EJBCA_CA_CERT_PATH")
	file, err = os.ReadFile(caCertPath)
	if err != nil {
		tb.Fatalf("error reading ca cert: %v", err)
	}
	caCert = string(file)

	return b.(*ejbcaBackend), config.StorageView
}
