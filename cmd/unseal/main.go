package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/aRestless/vault-unsealer-tpm/config"
	"github.com/aRestless/vault-unsealer-tpm/crypto"
	"github.com/aRestless/vault-unsealer-tpm/vault"
	"github.com/hashicorp/vault/api"
)

type initOptions struct {
	InitMode       bool
	KeyShares      int
	KeyThreshold   int
	KeySharesSaved int
	KeysFile       string
}

type initVaultClient interface {
	InitStatus() (bool, error)
	Init(*api.InitRequest) (*api.InitResponse, error)
	Unseal(string) (*api.SealStatusResponse, error)
}

type tpmKey interface {
	InitKey() error
	ValidateKey() error
	Encrypt([]byte) ([]byte, error)
	Close() error
}

type realInitVaultClient struct {
	client *api.Client
}

func (c *realInitVaultClient) InitStatus() (bool, error) {
	return c.client.Sys().InitStatus()
}

func (c *realInitVaultClient) Init(req *api.InitRequest) (*api.InitResponse, error) {
	return c.client.Sys().Init(req)
}

func (c *realInitVaultClient) Unseal(key string) (*api.SealStatusResponse, error) {
	return c.client.Sys().Unseal(key)
}

func run(cfg config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	keyFiles, err := crypto.ListTPMKeyFiles(cfg.StorePath)
	if err != nil {
		return fmt.Errorf("failed to check for unseal key files: %w", err)
	}
	if len(keyFiles) == 0 {
		return fmt.Errorf("no TPM-encrypted unseal keys found at %s; run vault-unsealer-tpm -init first", crypto.TPMKeyGlob(cfg.StorePath))
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
		StorePath:     cfg.StorePath,
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

type initRunner struct {
	cfg            config.Config
	opts           initOptions
	in             io.Reader
	out            io.Writer
	interactive    bool
	newVaultClient func(config.Config) (initVaultClient, error)
	openTPM        func(config.Config) (tpmKey, error)
}

func (r *initRunner) run() error {
	if err := validateInitOptions(r.opts); err != nil {
		return err
	}
	if err := os.MkdirAll(r.cfg.StorePath, 0700); err != nil {
		return fmt.Errorf("failed to create store path: %w", err)
	}

	reader := bufio.NewReader(r.in)
	if err := r.confirmDeleteExistingKeys(reader); err != nil {
		return err
	}

	client, err := r.newVaultClient(r.cfg)
	if err != nil {
		if r.opts.KeysFile != "" || r.interactive {
			fmt.Fprintf(r.out, "WARNING: could not create Vault client: %v\n", err)
			fmt.Fprintln(r.out, "Adopting provided keys without a Vault status check.")
			return r.adopt(reader)
		}
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	initialized, err := client.InitStatus()
	if err != nil {
		fmt.Fprintf(r.out, "WARNING: could not check Vault init status: %v\n", err)
		fmt.Fprintln(r.out, "Adopting provided keys without a Vault status check.")
		return r.adopt(reader)
	}

	if initialized {
		return r.adopt(reader)
	}
	return r.fresh(client)
}

func validateInitOptions(opts initOptions) error {
	if opts.KeyShares < 1 || opts.KeyThreshold < 1 {
		return errors.New("key-shares and key-threshold must be >= 1")
	}
	if opts.KeyThreshold > opts.KeyShares {
		return errors.New("key-threshold cannot exceed key-shares")
	}
	if opts.KeySharesSaved < opts.KeyThreshold {
		return fmt.Errorf("key-shares-saved (%d) must be >= key-threshold (%d)", opts.KeySharesSaved, opts.KeyThreshold)
	}
	if opts.KeySharesSaved > opts.KeyShares {
		return fmt.Errorf("key-shares-saved (%d) cannot exceed key-shares (%d)", opts.KeySharesSaved, opts.KeyShares)
	}
	return nil
}

func (r *initRunner) confirmDeleteExistingKeys(reader *bufio.Reader) error {
	files, err := crypto.ListOwnedKeyFiles(r.cfg.StorePath)
	if err != nil {
		return fmt.Errorf("failed to check for existing key files: %w", err)
	}
	if len(files) == 0 {
		return nil
	}

	fmt.Fprintf(r.out, "Found %d existing key file(s) in %s:\n", len(files), r.cfg.StorePath)
	for _, file := range files {
		fmt.Fprintf(r.out, "  - %s\n", file)
	}

	if !r.interactive {
		return errors.New("existing key files found; run interactively to delete them")
	}

	answer, err := promptLine(reader, r.out, "Delete these key files? [y/N]: ")
	if err != nil {
		return err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return errors.New("aborted; existing key files were left unchanged")
	}

	confirmation, err := promptLine(reader, r.out, `Type "delete keys" to confirm: `)
	if err != nil {
		return err
	}
	if strings.TrimSpace(confirmation) != "delete keys" {
		return errors.New("aborted; confirmation text did not match")
	}

	if err := crypto.DeleteOwnedKeyFiles(r.cfg.StorePath); err != nil {
		return err
	}
	fmt.Fprintln(r.out, "Deleted existing key files.")
	return nil
}

func (r *initRunner) fresh(client initVaultClient) error {
	tpm, err := r.openValidatedTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	if r.opts.KeysFile != "" {
		fmt.Fprintln(r.out, "WARNING: -keys-file was provided but Vault is not initialized, so a fresh init will be performed.")
	}
	fmt.Fprintln(r.out, "Vault is not initialized. Initializing Vault...")
	initResp, err := client.Init(&api.InitRequest{
		SecretShares:    r.opts.KeyShares,
		SecretThreshold: r.opts.KeyThreshold,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize Vault: %w", err)
	}
	if len(initResp.Keys) < r.opts.KeySharesSaved {
		return fmt.Errorf("Vault returned %d key share(s), need %d", len(initResp.Keys), r.opts.KeySharesSaved)
	}

	written, err := encryptAndWriteKeys(tpm, r.cfg.StorePath, initResp.Keys[:r.opts.KeySharesSaved])
	if err != nil {
		return err
	}

	if err := unsealWithKeys(client, initResp.Keys[:r.opts.KeyThreshold]); err != nil {
		return fmt.Errorf("failed to unseal Vault after init: %w", err)
	}

	printFreshSummary(r.out, r.cfg, r.opts, written, initResp.Keys, initResp.RootToken)
	return nil
}

func (r *initRunner) adopt(reader *bufio.Reader) error {
	keys, err := r.readAdoptKeys(reader)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("no unseal keys provided")
	}

	tpm, err := r.openValidatedTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	written, err := encryptAndWriteKeys(tpm, r.cfg.StorePath, keys)
	if err != nil {
		return err
	}

	printAdoptSummary(r.out, r.cfg, written)
	return nil
}

func (r *initRunner) readAdoptKeys(reader *bufio.Reader) ([]string, error) {
	if r.opts.KeysFile != "" {
		data, err := os.ReadFile(r.opts.KeysFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read keys file: %w", err)
		}
		return parseKeyLines(string(data)), nil
	}

	if !r.interactive {
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		keys := parseKeyLines(string(data))
		if len(keys) == 0 {
			return nil, errors.New("Vault is initialized; provide -keys-file or run interactively to enter unseal keys")
		}
		return keys, nil
	}

	fmt.Fprintln(r.out, "Vault is already initialized. Paste unseal keys, one per line.")
	fmt.Fprintln(r.out, "Submit an empty line when finished.")

	var lines []string
	for {
		line, err := promptLine(reader, r.out, "> ")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		lines = append(lines, line)
	}
	return parseKeyLines(strings.Join(lines, "\n")), nil
}

func (r *initRunner) openValidatedTPM() (tpmKey, error) {
	tpm, err := r.openTPM(r.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	if err := tpm.InitKey(); err != nil {
		tpm.Close()
		return nil, fmt.Errorf("failed to initialize TPM key: %w", err)
	}
	if err := tpm.ValidateKey(); err != nil {
		tpm.Close()
		return nil, fmt.Errorf("TPM key validation failed: %w", err)
	}
	return tpm, nil
}

func encryptAndWriteKeys(tpm tpmKey, storePath string, keys []string) ([]string, error) {
	var written []string
	for i, key := range keys {
		encrypted, err := tpm.Encrypt([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("failed to TPM-encrypt key %d: %w", i, err)
		}
		path, err := crypto.WriteTPMKeyFile(storePath, i, encrypted)
		if err != nil {
			return nil, err
		}
		written = append(written, path)
	}
	return written, nil
}

func unsealWithKeys(client initVaultClient, keys []string) error {
	for i, key := range keys {
		status, err := client.Unseal(key)
		if err != nil {
			return fmt.Errorf("submitting unseal key %d: %w", i, err)
		}
		if !status.Sealed {
			return nil
		}
	}
	return errors.New("provided keys did not unseal Vault")
}

func parseKeyLines(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func promptLine(reader *bufio.Reader, out io.Writer, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	line, err := reader.ReadString('\n')
	if errors.Is(err, io.EOF) && line != "" {
		return strings.TrimRight(line, "\r\n"), nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func printFreshSummary(out io.Writer, cfg config.Config, opts initOptions, files, keys []string, rootToken string) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "== init complete ==")
	fmt.Fprintf(out, "Mode:              initialized new Vault\n")
	fmt.Fprintf(out, "Vault address:     %s\n", cfg.VaultAddress)
	fmt.Fprintf(out, "Store path:        %s\n", cfg.StorePath)
	fmt.Fprintf(out, "TPM device:        %s\n", cfg.TPMDevicePath)
	fmt.Fprintf(out, "TPM handle:        %#x\n", cfg.TPMHandle)
	fmt.Fprintf(out, "Key shares:        %d\n", opts.KeyShares)
	fmt.Fprintf(out, "Key threshold:     %d\n", opts.KeyThreshold)
	fmt.Fprintf(out, "TPM keys written:  %d\n", len(files))
	for _, file := range files {
		fmt.Fprintf(out, "  - %s\n", file)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "WARNING: save these plaintext unseal keys somewhere secure now.")
	for i, key := range keys {
		fmt.Fprintf(out, "Unseal key %d: %s\n", i+1, key)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "WARNING: save this root token somewhere secure and revoke it after configuring normal Vault access.")
	fmt.Fprintf(out, "Root token: %s\n", rootToken)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next: start vault-unsealer-tpm with the same store path, TPM device, and TPM handle.")
}

func printAdoptSummary(out io.Writer, cfg config.Config, files []string) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "== init complete ==")
	fmt.Fprintf(out, "Mode:              adopted existing Vault keys\n")
	fmt.Fprintf(out, "Vault address:     %s\n", cfg.VaultAddress)
	fmt.Fprintf(out, "Store path:        %s\n", cfg.StorePath)
	fmt.Fprintf(out, "TPM device:        %s\n", cfg.TPMDevicePath)
	fmt.Fprintf(out, "TPM handle:        %#x\n", cfg.TPMHandle)
	fmt.Fprintf(out, "TPM keys written:  %d\n", len(files))
	for _, file := range files {
		fmt.Fprintf(out, "  - %s\n", file)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next: start vault-unsealer-tpm with the same store path, TPM device, and TPM handle.")
}

func newRealInitVaultClient(cfg config.Config) (initVaultClient, error) {
	vaultConfig, err := getVaultConfig(cfg)
	if err != nil {
		return nil, err
	}
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	return &realInitVaultClient{client: client}, nil
}

func openConfiguredTPM(cfg config.Config) (tpmKey, error) {
	return crypto.OpenTPM(cfg.TPMDevicePath, uint32(cfg.TPMHandle))
}

func parseCLI(args []string, getenv func(string) string, output io.Writer) (config.Config, initOptions, error) {
	tpmHandle, err := envUint(getenv, "VAULT_UNSEALER_TPM_HANDLE", 0x81010001)
	if err != nil {
		return config.Config{}, initOptions{}, err
	}

	cfg := config.Config{
		StorePath:          envString(getenv, "VAULT_UNSEALER_STORE_PATH", "./keys"),
		TPMDevicePath:      envString(getenv, "VAULT_UNSEALER_TPM_DEVICE", "/dev/tpmrm0"),
		TPMHandle:          tpmHandle,
		VaultAddress:       envString(getenv, "VAULT_UNSEALER_VAULT_ADDR", "http://127.0.0.1:8200"),
		VaultTLSCACert:     envString(getenv, "VAULT_UNSEALER_VAULT_TLS_CA_CERT", ""),
		VaultTLSServerName: envString(getenv, "VAULT_UNSEALER_VAULT_TLS_SERVER_NAME", ""),
	}
	opts := initOptions{
		KeyShares:      5,
		KeyThreshold:   3,
		KeySharesSaved: 3,
	}

	fs := flag.NewFlagSet("vault-unsealer-tpm", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.Usage = func() {
		fmt.Fprintln(output, "Usage: vault-unsealer-tpm [-init] [flags]")
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Run mode is the default daemon mode. Use -init for one-shot provisioning.")
		fmt.Fprintln(output)
		fs.PrintDefaults()
	}

	fs.BoolVar(&opts.InitMode, "init", false, "Run one-shot init/adopt provisioning instead of the unseal daemon.")
	fs.StringVar(&cfg.TPMDevicePath, "tpm.device-path", cfg.TPMDevicePath, "Path to the TPM device. Env: VAULT_UNSEALER_TPM_DEVICE")
	fs.UintVar(&cfg.TPMHandle, "tpm.handle", cfg.TPMHandle, "Persistent handle for the TPM key. Env: VAULT_UNSEALER_TPM_HANDLE")
	fs.StringVar(&cfg.VaultAddress, "vault.address", cfg.VaultAddress, "Address of the Vault server. Env: VAULT_UNSEALER_VAULT_ADDR")
	fs.StringVar(&cfg.VaultTLSCACert, "vault.tls.ca-cert", cfg.VaultTLSCACert, "Path to a CA certificate file for TLS verification. Env: VAULT_UNSEALER_VAULT_TLS_CA_CERT")
	fs.StringVar(&cfg.VaultTLSServerName, "vault.tls.server-name", cfg.VaultTLSServerName, "Server name to use for TLS verification. Env: VAULT_UNSEALER_VAULT_TLS_SERVER_NAME")
	fs.StringVar(&cfg.StorePath, "store-path", cfg.StorePath, "Path to encrypted key files. Env: VAULT_UNSEALER_STORE_PATH")
	fs.IntVar(&opts.KeyShares, "key-shares", opts.KeyShares, "Init mode: number of unseal key shares to generate.")
	fs.IntVar(&opts.KeyThreshold, "key-threshold", opts.KeyThreshold, "Init mode: number of unseal keys required to unseal.")
	fs.IntVar(&opts.KeySharesSaved, "key-shares-saved", opts.KeySharesSaved, "Init mode: number of unseal keys to save encrypted with the TPM.")
	fs.StringVar(&opts.KeysFile, "keys-file", "", "Init mode: file containing existing unseal keys to adopt, one per line.")

	if err := fs.Parse(args); err != nil {
		return config.Config{}, initOptions{}, err
	}
	if fs.NArg() > 0 {
		return config.Config{}, initOptions{}, fmt.Errorf("unexpected argument %q; use -init instead of init subcommands", fs.Arg(0))
	}

	return cfg, opts, nil
}

func envString(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

func envUint(getenv func(string) string, key string, fallback uint) (uint, error) {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(v, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s: %q", key, v)
	}
	return uint(parsed), nil
}

func stdinIsInteractive() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

func main() {
	cfg, opts, err := parseCLI(os.Args[1:], os.Getenv, os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		log.Fatalf("Configuration error: %v", err)
	}

	if opts.InitMode {
		runner := &initRunner{
			cfg:            cfg,
			opts:           opts,
			in:             os.Stdin,
			out:            os.Stdout,
			interactive:    stdinIsInteractive(),
			newVaultClient: newRealInitVaultClient,
			openTPM:        openConfiguredTPM,
		}
		if err := runner.run(); err != nil {
			log.Fatalf("Init error: %v", err)
		}
		return
	}

	if err := run(cfg); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}
