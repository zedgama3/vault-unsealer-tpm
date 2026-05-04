package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/aRestless/vault-unsealer-tpm/config"
	"github.com/aRestless/vault-unsealer-tpm/crypto"
	"github.com/aRestless/vault-unsealer-tpm/vault"
	"github.com/hashicorp/vault/api"
)

func run(cfg config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	keyGlobPattern := filepath.Join(cfg.StorePath, "unseal-key-*.tpm.enc")
	keyFiles, err := filepath.Glob(keyGlobPattern)
	if err != nil {
		return fmt.Errorf("failed to check for unseal key files: %w", err)
	}
	if len(keyFiles) == 0 {
		return fmt.Errorf("no TPM-encrypted unseal keys found at %s; run vault-unsealer-tpm-init first", keyGlobPattern)
	}

	vaultConfig, err := getVaultConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to get Vault configuration: %v", err)
	}

	log.Println("Validating TPM access...")
	if err := validateTPM(cfg); err != nil {
		return fmt.Errorf("TPM validation failed: %v", err)
	}
	log.Println("TPM access validated.")

	v, err := vault.NewVault(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %v", err)
	}

	store := &crypto.KeyStore{
		GlobPattern:   keyGlobPattern,
		TPMDevicePath: cfg.TPMDevicePath,
		TPMHandle:     uint32(cfg.TPMHandle),
	}
	return v.UnsealLoop(ctx, store)
}

// validateTPM opens the TPM and confirms a usable RSA key is present at the
// configured handle. It does not create or modify any keys.
func validateTPM(cfg config.Config) error {
	tpm, err := crypto.OpenTPM(cfg.TPMDevicePath, uint32(cfg.TPMHandle))
	if err != nil {
		return fmt.Errorf("failed to open TPM device: %v", err)
	}
	defer tpm.Close()

	return tpm.ValidateKey()
}

func getVaultConfig(cfg config.Config) (*api.Config, error) {
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = cfg.VaultAddress

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.VaultTLSServerName != "" {
		tlsConfig.ServerName = cfg.VaultTLSServerName
	}

	if cfg.VaultTLSCACert != "" {
		caCert, err := os.ReadFile(cfg.VaultTLSCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %v", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", cfg.VaultTLSCACert)
		}
		tlsConfig.RootCAs = caCertPool
	}
	vaultConfig.HttpClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return vaultConfig, nil
}

func main() {
	cfg := config.Config{}

	// Environment variables provide defaults; flags always take precedence.
	// VAULT_UNSEALER_TPM_HANDLE accepts decimal or 0x-prefixed hex (e.g. "0x81010001").
	envString := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback
	}
	envUint := func(key string, fallback uint) uint {
		if v := os.Getenv(key); v != "" {
			// strconv.ParseUint with base 0 handles "0x..." hex and plain decimal.
			parsed, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 32)
			if err != nil {
				// Try plain decimal.
				parsed, err = strconv.ParseUint(v, 10, 32)
			}
			if err != nil {
				log.Fatalf("Invalid value for %s: %q", key, v)
			}
			return uint(parsed)
		}
		return fallback
	}

	flag.StringVar(&cfg.TPMDevicePath, "tpm.device-path",
		envString("VAULT_UNSEALER_TPM_DEVICE", "/dev/tpmrm0"),
		"Path to the TPM device. Env: VAULT_UNSEALER_TPM_DEVICE")
	flag.UintVar(&cfg.TPMHandle, "tpm.handle",
		envUint("VAULT_UNSEALER_TPM_HANDLE", 0x81010001),
		"Persistent handle for the TPM key. Env: VAULT_UNSEALER_TPM_HANDLE")

	flag.StringVar(&cfg.VaultAddress, "vault.address",
		envString("VAULT_UNSEALER_VAULT_ADDR", "http://127.0.0.1:8200"),
		"Address of the Vault server. Env: VAULT_UNSEALER_VAULT_ADDR")
	flag.StringVar(&cfg.VaultTLSCACert, "vault.tls.ca-cert",
		envString("VAULT_UNSEALER_VAULT_TLS_CA_CERT", ""),
		"Path to a CA certificate file for TLS verification. Env: VAULT_UNSEALER_VAULT_TLS_CA_CERT")
	flag.StringVar(&cfg.VaultTLSServerName, "vault.tls.server-name",
		envString("VAULT_UNSEALER_VAULT_TLS_SERVER_NAME", ""),
		"Server name to use for TLS verification. Env: VAULT_UNSEALER_VAULT_TLS_SERVER_NAME")

	flag.StringVar(&cfg.StorePath, "store-path",
		envString("VAULT_UNSEALER_STORE_PATH", "./keys"),
		"Path to read encrypted unseal keys from. Env: VAULT_UNSEALER_STORE_PATH")

	flag.Parse()

	if err := run(cfg); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}
