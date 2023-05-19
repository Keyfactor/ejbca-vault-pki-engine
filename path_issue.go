package ejbca_vault_pki_engine

type certificateInfo struct {
	Certificate    string   `json:"certificate"`
	CAChain        []string `json:"ca_chain"`
	SerialNumber   string   `json:"serial_number"`
	PrivateKey     string   `json:"private_key"`
	IssuingCA      string   `json:"issuing_ca"`
	PrivateKeyType string   `json:"private_key_type"`
}
