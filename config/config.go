package config

// Config holds the unseal daemon's configuration, populated from command-line flags.
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
