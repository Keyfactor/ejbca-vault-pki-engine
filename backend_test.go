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
	hostname                  = os.Getenv("EJBCA_HOSTNAME")
	_defaultCaName            = os.Getenv("EJBCA_DEFAULT_CA_NAME")
	defaultEndEntityProfile   = os.Getenv("EJBCA_DEFAULT_END_ENTITY_PROFILE")
	defaultCertificateProfile = os.Getenv("EJBCA_DEFAULT_CERTIFICATE_PROFILE")
)

func getTestBackend(tb testing.TB) (*ejbcaBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	clientCertPath := os.Getenv("EJBCA_CLIENT_CERT_PATH")
	file, err := os.ReadFile(clientCertPath)
	if err != nil {
		tb.Fatal(err)
	}
	clientCert = string(file)

	clientKeyPath := os.Getenv("EJBCA_CLIENT_CERT_KEY_PATH")
	file, err = os.ReadFile(clientKeyPath)
	if err != nil {
		tb.Fatal(err)
	}
	clientKey = string(file)

	return b.(*ejbcaBackend), config.StorageView
}
