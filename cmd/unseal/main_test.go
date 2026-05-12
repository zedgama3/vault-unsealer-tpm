package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aRestless/vault-unsealer-tpm/config"
	"github.com/aRestless/vault-unsealer-tpm/crypto"
	"github.com/hashicorp/vault/api"
)

type fakeVaultClient struct {
	initialized bool
	statusErr   error
	initKeys    []string
	rootToken   string
	unsealAfter int

	initCalled bool
	initReq    *api.InitRequest
	unsealKeys []string
}

func (f *fakeVaultClient) InitStatus() (bool, error) {
	return f.initialized, f.statusErr
}

func (f *fakeVaultClient) Init(req *api.InitRequest) (*api.InitResponse, error) {
	f.initCalled = true
	f.initReq = req
	f.initialized = true
	return &api.InitResponse{
		Keys:      f.initKeys,
		RootToken: f.rootToken,
	}, nil
}

func (f *fakeVaultClient) Unseal(key string) (*api.SealStatusResponse, error) {
	f.unsealKeys = append(f.unsealKeys, key)
	return &api.SealStatusResponse{
		Sealed: len(f.unsealKeys) < f.unsealAfter,
	}, nil
}

type fakeTPM struct {
	initCalled     bool
	validateCalled bool
	closeCalled    bool
	encrypted      []string
}

func (f *fakeTPM) InitKey() error {
	f.initCalled = true
	return nil
}

func (f *fakeTPM) ValidateKey() error {
	f.validateCalled = true
	return nil
}

func (f *fakeTPM) Encrypt(data []byte) ([]byte, error) {
	f.encrypted = append(f.encrypted, string(data))
	return []byte("enc:" + string(data)), nil
}

func (f *fakeTPM) Close() error {
	f.closeCalled = true
	return nil
}

func testConfig(storePath string) config.Config {
	return config.Config{
		StorePath:          storePath,
		TPMDevicePath:      "/dev/test-tpm",
		TPMHandle:          0x81010001,
		VaultAddress:       "http://vault:8200",
		VaultTLSCACert:     "",
		VaultTLSServerName: "",
	}
}

func TestParseCLIEnvAndFlagPrecedence(t *testing.T) {
	env := map[string]string{
		"VAULT_UNSEALER_STORE_PATH":            "/env/keys",
		"VAULT_UNSEALER_TPM_DEVICE":            "/dev/env-tpm",
		"VAULT_UNSEALER_TPM_HANDLE":            "0x81010002",
		"VAULT_UNSEALER_VAULT_ADDR":            "https://env-vault:8200",
		"VAULT_UNSEALER_VAULT_TLS_CA_CERT":     "/env/ca.pem",
		"VAULT_UNSEALER_VAULT_TLS_SERVER_NAME": "env-vault",
	}
	getenv := func(key string) string { return env[key] }

	cfg, opts, err := parseCLI([]string{
		"-init",
		"-store-path=/flag/keys",
		"-tpm.handle=0x81010003",
		"-vault.address=https://flag-vault:8200",
		"-key-shares=4",
		"-key-threshold=2",
		"-key-shares-saved=2",
	}, getenv, io.Discard)
	if err != nil {
		t.Fatalf("parseCLI returned error: %v", err)
	}

	if !opts.InitMode {
		t.Fatal("expected init mode")
	}
	if cfg.StorePath != "/flag/keys" {
		t.Fatalf("expected flag store path, got %q", cfg.StorePath)
	}
	if cfg.TPMDevicePath != "/dev/env-tpm" {
		t.Fatalf("expected env TPM device, got %q", cfg.TPMDevicePath)
	}
	if cfg.TPMHandle != 0x81010003 {
		t.Fatalf("expected flag TPM handle, got %#x", cfg.TPMHandle)
	}
	if cfg.VaultAddress != "https://flag-vault:8200" {
		t.Fatalf("expected flag Vault address, got %q", cfg.VaultAddress)
	}
	if cfg.VaultTLSCACert != "/env/ca.pem" || cfg.VaultTLSServerName != "env-vault" {
		t.Fatalf("expected TLS settings from env, got cert=%q server=%q", cfg.VaultTLSCACert, cfg.VaultTLSServerName)
	}
	if opts.KeyShares != 4 || opts.KeyThreshold != 2 || opts.KeySharesSaved != 2 {
		t.Fatalf("unexpected init options: %+v", opts)
	}
}

func TestExistingKeyDeletionRequiresExactConfirmation(t *testing.T) {
	storePath := t.TempDir()
	writeTestFile(t, filepath.Join(storePath, "unseal-key-0.tpm.enc"), "old")
	writeTestFile(t, filepath.Join(storePath, "unseal-key-0.recovery.enc"), "legacy")

	runner := &initRunner{
		cfg:         testConfig(storePath),
		out:         io.Discard,
		interactive: true,
	}
	err := runner.confirmDeleteExistingKeys(bufio.NewReader(strings.NewReader("yes\nnot quite\n")))
	if err == nil {
		t.Fatal("expected confirmation mismatch error")
	}
	files, err := crypto.ListOwnedKeyFiles(storePath)
	if err != nil {
		t.Fatalf("ListOwnedKeyFiles returned error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected files to remain after failed confirmation, got %d", len(files))
	}

	runner = &initRunner{
		cfg:         testConfig(storePath),
		out:         io.Discard,
		interactive: true,
	}
	err = runner.confirmDeleteExistingKeys(bufio.NewReader(strings.NewReader("y\ndelete keys\n")))
	if err != nil {
		t.Fatalf("confirmDeleteExistingKeys returned error: %v", err)
	}
	files, err = crypto.ListOwnedKeyFiles(storePath)
	if err != nil {
		t.Fatalf("ListOwnedKeyFiles returned error: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected files to be deleted, got %d", len(files))
	}
}

func TestInitFreshWithFakes(t *testing.T) {
	storePath := t.TempDir()
	vaultClient := &fakeVaultClient{
		initialized: false,
		initKeys:    []string{"key-1", "key-2", "key-3"},
		rootToken:   "root-token",
		unsealAfter: 2,
	}
	tpm := &fakeTPM{}
	var out bytes.Buffer

	runner := &initRunner{
		cfg: testConfig(storePath),
		opts: initOptions{
			InitMode:       true,
			KeyShares:      3,
			KeyThreshold:   2,
			KeySharesSaved: 2,
		},
		in:          strings.NewReader(""),
		out:         &out,
		interactive: true,
		newVaultClient: func(config.Config) (initVaultClient, error) {
			return vaultClient, nil
		},
		openTPM: func(config.Config) (tpmKey, error) {
			return tpm, nil
		},
	}

	if err := runner.run(); err != nil {
		t.Fatalf("runner.run returned error: %v", err)
	}
	if !vaultClient.initCalled {
		t.Fatal("expected Vault init to be called")
	}
	if vaultClient.initReq.SecretShares != 3 || vaultClient.initReq.SecretThreshold != 2 {
		t.Fatalf("unexpected init request: %+v", vaultClient.initReq)
	}
	if got := strings.Join(vaultClient.unsealKeys, ","); got != "key-1,key-2" {
		t.Fatalf("unexpected unseal keys: %s", got)
	}
	if got := strings.Join(tpm.encrypted, ","); got != "key-1,key-2" {
		t.Fatalf("unexpected encrypted keys: %s", got)
	}
	assertFileContent(t, filepath.Join(storePath, "unseal-key-0.tpm.enc"), "enc:key-1")
	assertFileContent(t, filepath.Join(storePath, "unseal-key-1.tpm.enc"), "enc:key-2")
	if !strings.Contains(out.String(), "Unseal key 3: key-3") || !strings.Contains(out.String(), "Root token: root-token") {
		t.Fatalf("fresh summary did not include generated secrets:\n%s", out.String())
	}
}

func TestInitAdoptWithKeysFileAndFakes(t *testing.T) {
	storePath := t.TempDir()
	keysFile := filepath.Join(t.TempDir(), "keys.txt")
	writeTestFile(t, keysFile, "adopt-1\n# comment\n\nadopt-2\n")
	vaultClient := &fakeVaultClient{initialized: true}
	tpm := &fakeTPM{}
	var out bytes.Buffer

	runner := &initRunner{
		cfg: testConfig(storePath),
		opts: initOptions{
			InitMode:       true,
			KeyShares:      5,
			KeyThreshold:   3,
			KeySharesSaved: 3,
			KeysFile:       keysFile,
		},
		in:          strings.NewReader(""),
		out:         &out,
		interactive: false,
		newVaultClient: func(config.Config) (initVaultClient, error) {
			return vaultClient, nil
		},
		openTPM: func(config.Config) (tpmKey, error) {
			return tpm, nil
		},
	}

	if err := runner.run(); err != nil {
		t.Fatalf("runner.run returned error: %v", err)
	}
	if vaultClient.initCalled {
		t.Fatal("did not expect Vault init during adoption")
	}
	if got := strings.Join(tpm.encrypted, ","); got != "adopt-1,adopt-2" {
		t.Fatalf("unexpected encrypted keys: %s", got)
	}
	assertFileContent(t, filepath.Join(storePath, "unseal-key-0.tpm.enc"), "enc:adopt-1")
	assertFileContent(t, filepath.Join(storePath, "unseal-key-1.tpm.enc"), "enc:adopt-2")
	if !strings.Contains(out.String(), "adopted existing Vault keys") {
		t.Fatalf("adopt summary missing mode:\n%s", out.String())
	}
}

func TestInitAdoptPromptsForKeys(t *testing.T) {
	storePath := t.TempDir()
	vaultClient := &fakeVaultClient{initialized: true}
	tpm := &fakeTPM{}

	runner := &initRunner{
		cfg: testConfig(storePath),
		opts: initOptions{
			InitMode:       true,
			KeyShares:      5,
			KeyThreshold:   3,
			KeySharesSaved: 3,
		},
		in:          strings.NewReader("prompt-1\nprompt-2\n\n"),
		out:         io.Discard,
		interactive: true,
		newVaultClient: func(config.Config) (initVaultClient, error) {
			return vaultClient, nil
		},
		openTPM: func(config.Config) (tpmKey, error) {
			return tpm, nil
		},
	}

	if err := runner.run(); err != nil {
		t.Fatalf("runner.run returned error: %v", err)
	}
	if got := strings.Join(tpm.encrypted, ","); got != "prompt-1,prompt-2" {
		t.Fatalf("unexpected prompted keys: %s", got)
	}
}

func TestInitAdoptWithoutVaultStatusAllowsKeysFile(t *testing.T) {
	storePath := t.TempDir()
	keysFile := filepath.Join(t.TempDir(), "keys.txt")
	writeTestFile(t, keysFile, "offline-key\n")
	tpm := &fakeTPM{}

	runner := &initRunner{
		cfg: testConfig(storePath),
		opts: initOptions{
			InitMode:       true,
			KeyShares:      5,
			KeyThreshold:   3,
			KeySharesSaved: 3,
			KeysFile:       keysFile,
		},
		in:          strings.NewReader(""),
		out:         io.Discard,
		interactive: false,
		newVaultClient: func(config.Config) (initVaultClient, error) {
			return &fakeVaultClient{statusErr: errors.New("vault down")}, nil
		},
		openTPM: func(config.Config) (tpmKey, error) {
			return tpm, nil
		},
	}

	if err := runner.run(); err != nil {
		t.Fatalf("runner.run returned error: %v", err)
	}
	if got := strings.Join(tpm.encrypted, ","); got != "offline-key" {
		t.Fatalf("unexpected encrypted keys: %s", got)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func assertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if string(data) != expected {
		t.Fatalf("unexpected content for %s: got %q want %q", path, string(data), expected)
	}
}
