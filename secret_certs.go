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
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// #nosec G101 -- Not a credential, just a type name
const EjbcaSecretCertsTypeName = "ejbca_certificate"

func secretCerts(b *ejbcaBackend) *framework.Secret {
	return &framework.Secret{
		Type: EjbcaSecretCertsTypeName,
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

func (b *ejbcaBackend) secretCertsRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if b.System().Tainted() {
		return nil, nil
	}
	if req.Secret == nil {
		return nil, fmt.Errorf("secret is nil in request")
	}
	logger := b.Logger().Named("ejbcaBackend.secretCertsRevoke")
	logger.Debug("Secrets Revoke called")

	if b.isRunningOnPerformanceStandby() {
		logger.Debug("Running on performance standby - anticipating Vault to forward request to active node - returning backend readonly error")
		// If we're running on performance standby, read requests are the only valid request.
		// Forward the request to the primary node.
		return nil, logical.ErrReadOnly
	}

	builder := &revokeBuilder{}
	return builder.Config(b.makeStorageContext(ctx, req.Storage), req.Path, data).RevokeCertificate()
}
