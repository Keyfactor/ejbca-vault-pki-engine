package ejbca_vault_pki_engine

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"strings"
)

type privateKeyHelper struct {
	keyBundle *certutil.KeyBundle
	warnings  []string
	isInit    bool
}

func (i *privateKeyHelper) Init(csrBundle *certutil.ParsedCSRBundle) *privateKeyHelper {
	i.keyBundle = &certutil.KeyBundle{}
	i.keyBundle.SetParsedPrivateKey(csrBundle.PrivateKey, csrBundle.PrivateKeyType, csrBundle.PrivateKeyBytes)

	i.isInit = true
	return i
}

func (i *privateKeyHelper) GetPrivateKeyType() certutil.PrivateKeyType {
	if !i.isInit {
		return ""
	}
	return i.keyBundle.PrivateKeyType
}

func (i *privateKeyHelper) GetPrivateKeyPemString() string {
	if !i.isInit {
		return ""
	}

	pemString, err := i.keyBundle.ToPrivateKeyPemString()
	if err != nil {
		i.warnings = append(i.warnings, fmt.Sprintf("Error converting private key to PEM string: %s", err.Error()))
		return ""
	}
	return pemString
}

func (i *privateKeyHelper) GetPrivateKeyDerString() string {
	if !i.isInit {
		return ""
	}

	return base64.StdEncoding.EncodeToString(i.keyBundle.PrivateKeyBytes)
}

func (i *privateKeyHelper) GetPKCS8PrivateKey(isPem bool) string {
	if !i.isInit {
		return ""
	}

	key, err := x509.MarshalPKCS8PrivateKey(i.keyBundle.PrivateKey)
	if err != nil {
		i.warnings = append(i.warnings, fmt.Sprintf("Error converting private key to PKCS8: %s", err.Error()))
		return ""
	}

	if isPem {
		return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})))
	}

	return base64.StdEncoding.EncodeToString(key)
}
