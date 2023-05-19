package ejbca_vault_pki_engine

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestPathRevoke(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	err := testConfigCreate(t, b, reqStorage, map[string]interface{}{
		"client_cert":                 clientCert,
		"client_key":                  clientKey,
		"hostname":                    hostname,
		"default_ca":                  _defaultCaName,
		"default_end_entity_profile":  defaultEndEntityProfile,
		"default_certificate_profile": defaultCertificateProfile,
	})
	assert.NoError(t, err)

	maxTTL, _ := time.ParseDuration("1h")
	notBeforeDuration, _ := time.ParseDuration("15m")
	var issueSignRole = map[string]interface{}{
		"max_ttl":        int(maxTTL.Seconds()),
		"ttl":            int(notBeforeDuration.Seconds()),
		"key_type":       "rsa",
		"key_bits":       2048,
		"signature_bits": 256,
		"use_pss":        false,
	}

	err = testRoleCreate(t, b, reqStorage, issueSignRole)
	assert.NoError(t, err)

	cn := "EJBCAVaultTest_" + generateRandomString(16)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("issue/%s", testRoleName),
		Storage:   reqStorage,
		Data: map[string]interface{}{
			"common_name": cn,
			"alt_names":   "example.com",
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	serialNumber := resp.Data["serial_number"].(string)

	t.Run("revoke", func(t *testing.T) {
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      fmt.Sprintf("revoke"),
			Storage:   reqStorage,
			Data: map[string]interface{}{
				"serial_number": serialNumber,
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})
}
