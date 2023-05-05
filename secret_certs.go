package ejbca_vault_pki_engine

import (
	"context"
	"crypto/x509"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type ejbcaCertificate struct {
	Crt string `json:"crt"`
	Key string `json:"key"`
}

const SecretCertsEjbcaType = "ejbca_certificate"

func secretCerts(b *ejbcaBackend) *framework.Secret {
	return &framework.Secret{
		Type: SecretCertsEjbcaType,
		Fields: map[string]*framework.FieldSchema{
			"certificate": {
				Type:        framework.TypeString,
				Description: "The PEM-encoded concatenated certificate and\nissuing certificate authority",
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: "The PEM-encoded private key for the certificate",
			},
			"serial": {
				Type:        framework.TypeString,
				Description: "The serial number of the certificate, for handy\nreference",
			},
		},
		Revoke: b.secretCertsRevoke,
	}
}

func (b *ejbcaBackend) secretCertsRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if b.System().Tainted() {
		return nil, nil
	}

	if req.Secret == nil {
		return nil, fmt.Errorf("secret is nil in request")
	}

	serialInt, ok := req.Secret.InternalData["serial_number"]
	if !ok {
		return nil, fmt.Errorf("could not find serial in internal secret data")
	}

	sc := b.makeStorageContext(ctx, req.Storage)
	serial := serialInt.(string)

	certEntry, err := sc.Cert().fetchCertBySerial("certs/", serial)
	if err != nil {
		return nil, err
	}
	if certEntry == nil {
		// We can't write to revoked/ or update the CRL anyway because we don't have the cert,
		// and there's no reason to expect this will work on a subsequent
		// retry.  Just give up and let the lease get deleted.
		b.Logger().Warn("certificate revoke failed because not found in storage, treating as success", "serial", serial)
		return nil, nil
	}

	cert, err := x509.ParseCertificate(certEntry.Value)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	return revokeCert(sc, cert)
}
