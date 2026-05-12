package config

// Config holds settings shared by run and init modes.
type Config struct {
	StorePath string

	// TPM settings
	TPMDevicePath string
	TPMHandle     uint

	// Vault settings
	VaultAddress       string
	VaultTLSCACert     string
	VaultTLSServerName string
}
