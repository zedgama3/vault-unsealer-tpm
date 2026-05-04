package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aRestless/vault-unsealer-tpm/crypto"
	"github.com/hashicorp/vault/api"
)

const usage = `vault-unsealer-tpm-init: one-shot tool to provision TPM-encrypted unseal keys.

Subcommands:
  fresh    Initialize a new Vault instance, encrypt unseal keys with the TPM,
           and (optionally) save recovery-encrypted backups.
  adopt    Adopt an already-initialized Vault by reading existing unseal keys
           from stdin or a file, encrypting them with the TPM, and storing them.
  rekey    Re-encrypt the existing TPM-stored keys under a new TPM handle
           (for TPM key rotation/replacement).

Run a subcommand with -h for its options.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	sub := os.Args[1]
	args := os.Args[2:]

	var err error
	switch sub {
	case "fresh":
		err = cmdFresh(args)
	case "adopt":
		err = cmdAdopt(args)
	case "rekey":
		err = cmdRekey(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", sub, usage)
		os.Exit(2)
	}

	if err != nil {
		log.Fatalf("error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// shared flag set
// ---------------------------------------------------------------------------

type commonFlags struct {
	storePath          string
	tpmDevicePath      string
	tpmHandle          uint
	vaultAddress       string
	vaultTLSSkipVerify bool
	vaultTLSCACert     string
	vaultTLSServerName string
}

func registerCommonFlags(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.storePath, "store-path", "./keys", "Path to store encrypted keys.")
	fs.StringVar(&c.tpmDevicePath, "tpm.device-path", "/dev/tpmrm0", "Path to the TPM device.")
	fs.UintVar(&c.tpmHandle, "tpm.handle", 0x81010001, "Persistent handle for the TPM key.")
	fs.StringVar(&c.vaultAddress, "vault.address", "http://127.0.0.1:8200", "Address of the Vault server.")
	fs.BoolVar(&c.vaultTLSSkipVerify, "vault.tls.skip-verify", false,
		"INSECURE. Skip TLS verification. Only use for one-shot bootstrap against a temporary cert.")
	fs.StringVar(&c.vaultTLSCACert, "vault.tls.ca-cert", "", "Path to a CA certificate file for TLS verification.")
	fs.StringVar(&c.vaultTLSServerName, "vault.tls.server-name", "", "Server name to use for TLS verification.")
}

func newVaultClient(c commonFlags) (*api.Client, error) {
	cfg := api.DefaultConfig()
	cfg.Address = c.vaultAddress

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.vaultTLSSkipVerify {
		log.Println("WARNING: TLS verification is disabled (--vault.tls.skip-verify).")
		tlsConfig.InsecureSkipVerify = true
	}
	if c.vaultTLSServerName != "" {
		tlsConfig.ServerName = c.vaultTLSServerName
	}
	if c.vaultTLSCACert != "" {
		caCert, err := os.ReadFile(c.vaultTLSCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", c.vaultTLSCACert)
		}
		tlsConfig.RootCAs = pool
	}
	cfg.HttpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}

	return api.NewClient(cfg)
}

// ---------------------------------------------------------------------------
// fresh
// ---------------------------------------------------------------------------

func cmdFresh(args []string) error {
	fs := flag.NewFlagSet("fresh", flag.ExitOnError)
	var c commonFlags
	registerCommonFlags(fs, &c)
	keyShares := fs.Int("key-shares", 5, "Number of unseal key shares to generate.")
	keyThreshold := fs.Int("key-threshold", 3, "Number of unseal keys required to unseal.")
	sharesSaved := fs.Int("key-shares-saved", 3, "Number of unseal keys to save encrypted with the TPM.")
	recoveryPubKey := fs.String("recovery-public-key", "",
		"Optional path to an RSA public key. If set, all generated unseal keys will be encrypted under it as a recovery backup.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *keyShares < 1 || *keyThreshold < 1 {
		return errors.New("key-shares and key-threshold must be >= 1")
	}
	if *keyThreshold > *keyShares {
		return errors.New("key-threshold cannot exceed key-shares")
	}
	if *sharesSaved < *keyThreshold {
		return fmt.Errorf("key-shares-saved (%d) must be >= key-threshold (%d) or Vault cannot be unsealed", *sharesSaved, *keyThreshold)
	}
	if *sharesSaved > *keyShares {
		return fmt.Errorf("key-shares-saved (%d) cannot exceed key-shares (%d)", *sharesSaved, *keyShares)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(c.storePath, 0700); err != nil {
		return fmt.Errorf("failed to create store path: %w", err)
	}

	// Refuse to overwrite an existing store
	existing, err := filepath.Glob(filepath.Join(c.storePath, "unseal-key-*.tpm.enc"))
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return fmt.Errorf("refusing to run 'fresh': %d existing TPM-encrypted keys at %s. Use 'rekey' or remove them manually", len(existing), c.storePath)
	}

	var recPub *rsa.PublicKey
	if *recoveryPubKey != "" {
		recPub, err = loadRSAPublicKey(*recoveryPubKey)
		if err != nil {
			return fmt.Errorf("failed to load recovery public key: %w", err)
		}
	} else {
		log.Println("WARNING: no --recovery-public-key provided. If the TPM is lost, the unseal keys will be unrecoverable.")
	}

	client, err := newVaultClient(c)
	if err != nil {
		return err
	}

	if err := waitForVault(ctx, client); err != nil {
		return err
	}

	initStatus, err := client.Sys().InitStatus()
	if err != nil {
		return fmt.Errorf("failed to read init status: %w", err)
	}
	if initStatus {
		return errors.New("Vault is already initialized; use 'adopt' instead")
	}

	log.Println("Initializing Vault...")
	initResp, err := client.Sys().Init(&api.InitRequest{
		SecretShares:    *keyShares,
		SecretThreshold: *keyThreshold,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize Vault: %w", err)
	}

	// Save recovery-encrypted backups first (cheapest path to durability).
	if recPub != nil {
		for i, key := range initResp.Keys {
			ct, err := encryptRSA(recPub, []byte(key))
			if err != nil {
				return fmt.Errorf("failed to encrypt key %d with recovery key: %w", i, err)
			}
			path := filepath.Join(c.storePath, fmt.Sprintf("unseal-key-%d.recovery.enc", i))
			if err := os.WriteFile(path, ct, 0600); err != nil {
				return fmt.Errorf("failed to write %s: %w", path, err)
			}
		}
	}

	// Encrypt subset with the TPM.
	tpm, err := crypto.OpenTPM(c.tpmDevicePath, uint32(c.tpmHandle))
	if err != nil {
		return fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()
	if err := tpm.InitKey(); err != nil {
		return fmt.Errorf("failed to initialize TPM key: %w", err)
	}
	if err := tpm.ValidateKey(); err != nil {
		return fmt.Errorf("TPM key validation failed: %w", err)
	}

	var tpmFiles []string
	for i := 0; i < *sharesSaved; i++ {
		ct, err := tpm.Encrypt([]byte(initResp.Keys[i]))
		if err != nil {
			return fmt.Errorf("failed to TPM-encrypt key %d: %w", i, err)
		}
		path := filepath.Join(c.storePath, fmt.Sprintf("unseal-key-%d.tpm.enc", i))
		if err := os.WriteFile(path, ct, 0600); err != nil {
			return fmt.Errorf("failed to write %s: %w", path, err)
		}
		tpmFiles = append(tpmFiles, path)
	}

	// Unseal once with the threshold number of keys, then revoke the root token.
	if err := unsealWithKeys(client, initResp.Keys[:*keyThreshold]); err != nil {
		return fmt.Errorf("failed to unseal Vault after init: %w", err)
	}

	log.Println("Revoking root token...")
	client.SetToken(initResp.RootToken)
	if err := client.Auth().Token().RevokeSelf(""); err != nil {
		return fmt.Errorf("failed to revoke root token: %w", err)
	}
	client.ClearToken()

	printSummary("fresh", c, *keyShares, *keyThreshold, *sharesSaved, tpmFiles, recPub != nil)
	return nil
}

// ---------------------------------------------------------------------------
// adopt
// ---------------------------------------------------------------------------

func cmdAdopt(args []string) error {
	fs := flag.NewFlagSet("adopt", flag.ExitOnError)
	var c commonFlags
	registerCommonFlags(fs, &c)
	keysFile := fs.String("keys-file", "", "Path to a file containing one unseal key per line. If empty, keys are read from stdin.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(c.storePath, 0700); err != nil {
		return fmt.Errorf("failed to create store path: %w", err)
	}

	existing, err := filepath.Glob(filepath.Join(c.storePath, "unseal-key-*.tpm.enc"))
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return fmt.Errorf("refusing to run 'adopt': %d existing TPM-encrypted keys at %s", len(existing), c.storePath)
	}

	keys, err := readKeys(*keysFile)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("no unseal keys provided")
	}

	// Optional sanity check: confirm Vault is reachable and initialized.
	client, err := newVaultClient(c)
	if err != nil {
		return err
	}
	initialized, err := client.Sys().InitStatus()
	if err != nil {
		log.Printf("WARNING: could not contact Vault to verify initialization status: %v", err)
	} else if !initialized {
		return errors.New("Vault reports as not initialized; use 'fresh' instead")
	}

	tpm, err := crypto.OpenTPM(c.tpmDevicePath, uint32(c.tpmHandle))
	if err != nil {
		return fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()
	if err := tpm.InitKey(); err != nil {
		return fmt.Errorf("failed to initialize TPM key: %w", err)
	}
	if err := tpm.ValidateKey(); err != nil {
		return fmt.Errorf("TPM key validation failed: %w", err)
	}

	var tpmFiles []string
	for i, k := range keys {
		ct, err := tpm.Encrypt([]byte(k))
		if err != nil {
			return fmt.Errorf("failed to TPM-encrypt key %d: %w", i, err)
		}
		path := filepath.Join(c.storePath, fmt.Sprintf("unseal-key-%d.tpm.enc", i))
		if err := os.WriteFile(path, ct, 0600); err != nil {
			return fmt.Errorf("failed to write %s: %w", path, err)
		}
		tpmFiles = append(tpmFiles, path)
	}

	printSummary("adopt", c, len(keys), 0, len(keys), tpmFiles, false)
	return nil
}

// ---------------------------------------------------------------------------
// rekey
// ---------------------------------------------------------------------------

func cmdRekey(args []string) error {
	fs := flag.NewFlagSet("rekey", flag.ExitOnError)
	var c commonFlags
	registerCommonFlags(fs, &c)
	newHandle := fs.Uint("tpm.new-handle", 0, "New TPM persistent handle to migrate keys to. Required.")
	keepOldHandle := fs.Bool("keep-old-handle", false, "If set, do not evict the old TPM handle after re-encrypting.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *newHandle == 0 {
		return errors.New("--tpm.new-handle is required")
	}
	if *newHandle == c.tpmHandle {
		return errors.New("--tpm.new-handle must differ from --tpm.handle")
	}

	pattern := filepath.Join(c.storePath, "unseal-key-*.tpm.enc")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no TPM-encrypted unseal keys found at %s", pattern)
	}

	// Decrypt with the old handle.
	oldTPM, err := crypto.OpenTPM(c.tpmDevicePath, uint32(c.tpmHandle))
	if err != nil {
		return fmt.Errorf("failed to open TPM (old): %w", err)
	}
	plaintexts := make(map[string][]byte, len(files))
	for _, f := range files {
		ct, err := os.ReadFile(f)
		if err != nil {
			oldTPM.Close()
			return fmt.Errorf("failed to read %s: %w", f, err)
		}
		pt, err := oldTPM.Decrypt(ct)
		if err != nil {
			oldTPM.Close()
			return fmt.Errorf("failed to decrypt %s with old TPM key: %w", f, err)
		}
		plaintexts[f] = pt
	}

	// Initialize new handle (separate connection so we don't conflate state).
	if err := oldTPM.Close(); err != nil {
		return fmt.Errorf("failed to close old TPM connection: %w", err)
	}

	newTPM, err := crypto.OpenTPM(c.tpmDevicePath, uint32(*newHandle))
	if err != nil {
		return fmt.Errorf("failed to open TPM (new): %w", err)
	}
	defer newTPM.Close()
	if err := newTPM.InitKey(); err != nil {
		return fmt.Errorf("failed to initialize new TPM key: %w", err)
	}
	if err := newTPM.ValidateKey(); err != nil {
		return fmt.Errorf("new TPM key validation failed: %w", err)
	}

	// Re-encrypt and write atomically (write to .new, fsync, rename).
	for f, pt := range plaintexts {
		ct, err := newTPM.Encrypt(pt)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt %s: %w", f, err)
		}
		tmp := f + ".new"
		if err := os.WriteFile(tmp, ct, 0600); err != nil {
			return fmt.Errorf("failed to write %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, f); err != nil {
			return fmt.Errorf("failed to rename %s -> %s: %w", tmp, f, err)
		}
	}

	if !*keepOldHandle {
		oldTPM2, err := crypto.OpenTPM(c.tpmDevicePath, uint32(c.tpmHandle))
		if err != nil {
			log.Printf("WARNING: failed to reopen TPM to evict old handle: %v", err)
		} else {
			defer oldTPM2.Close()
			if err := oldTPM2.ClearKey(); err != nil {
				log.Printf("WARNING: failed to evict old TPM handle %#x: %v", c.tpmHandle, err)
			}
		}
	}

	fmt.Println()
	fmt.Println("Rekey complete.")
	fmt.Printf("  Re-encrypted %d unseal key file(s) at %s\n", len(plaintexts), c.storePath)
	fmt.Printf("  New TPM handle: %#x\n", *newHandle)
	if *keepOldHandle {
		fmt.Printf("  Old TPM handle %#x retained (--keep-old-handle).\n", c.tpmHandle)
	} else {
		fmt.Printf("  Old TPM handle %#x evicted.\n", c.tpmHandle)
	}
	fmt.Println("  Update the daemon's --tpm.handle flag before restarting.")
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func waitForVault(ctx context.Context, client *api.Client) error {
	for {
		_, err := client.Sys().Health()
		if err == nil {
			return nil
		}
		log.Printf("Waiting for Vault: %v", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func unsealWithKeys(client *api.Client, keys []string) error {
	for i, k := range keys {
		st, err := client.Sys().Unseal(k)
		if err != nil {
			return fmt.Errorf("submitting unseal key %d: %w", i, err)
		}
		if !st.Sealed {
			return nil
		}
	}
	return errors.New("provided keys did not unseal Vault")
}

func readKeys(path string) ([]string, error) {
	var data []byte
	var err error
	if path == "" {
		fmt.Fprintln(os.Stderr, "Reading unseal keys from stdin (one per line, EOF to finish):")
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaPub, nil
}

func encryptRSA(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	return crypto.EncryptRSAOAEP(pub, data)
}

func printSummary(mode string, c commonFlags, shares, threshold, saved int, tpmFiles []string, withRecovery bool) {
	fmt.Println()
	fmt.Printf("== %s complete ==\n", mode)
	fmt.Printf("Vault address:      %s\n", c.vaultAddress)
	fmt.Printf("Store path:         %s\n", c.storePath)
	fmt.Printf("TPM device:         %s\n", c.tpmDevicePath)
	fmt.Printf("TPM handle:         %#x\n", c.tpmHandle)
	if mode == "fresh" {
		fmt.Printf("Key shares:         %d\n", shares)
		fmt.Printf("Key threshold:      %d\n", threshold)
	}
	fmt.Printf("TPM keys written:   %d\n", saved)
	for _, f := range tpmFiles {
		fmt.Printf("  - %s\n", f)
	}
	if withRecovery {
		fmt.Println("Recovery backups written: yes")
		fmt.Println("  >> Move *.recovery.enc files to a secure offline location and delete from this host.")
	}
	fmt.Println()
	fmt.Println("Next: start the vault-unsealer-tpm daemon pointing to the same store-path,")
	fmt.Println("      tpm.device-path and tpm.handle.")
}
