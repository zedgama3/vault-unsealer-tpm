package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	TPMKeyFileGlob            = "unseal-key-*.tpm.enc"
	LegacyRecoveryKeyFileGlob = "unseal-key-*.recovery.enc"
)

// KeyStore is a KeyStore implementation that reads keys encrypted by a TPM.
type KeyStore struct {
	StorePath     string
	GlobPattern   string
	TPMDevicePath string
	TPMHandle     uint32
}

func TPMKeyGlob(storePath string) string {
	return filepath.Join(storePath, TPMKeyFileGlob)
}

func ListTPMKeyFiles(storePath string) ([]string, error) {
	return filepath.Glob(TPMKeyGlob(storePath))
}

func ListOwnedKeyFiles(storePath string) ([]string, error) {
	var files []string
	for _, pattern := range []string{TPMKeyFileGlob, LegacyRecoveryKeyFileGlob} {
		matches, err := filepath.Glob(filepath.Join(storePath, pattern))
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	return files, nil
}

func DeleteOwnedKeyFiles(storePath string) error {
	files, err := ListOwnedKeyFiles(storePath)
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete %s: %w", file, err)
		}
	}
	return nil
}

func WriteTPMKeyFile(storePath string, index int, encryptedKey []byte) (string, error) {
	path := filepath.Join(storePath, fmt.Sprintf("unseal-key-%d.tpm.enc", index))
	if err := os.WriteFile(path, encryptedKey, 0600); err != nil {
		return "", fmt.Errorf("failed to write %s: %w", path, err)
	}
	return path, nil
}

// ReadKeys reads all TPM-encrypted key files in the store directory, decrypts them with the TPM,
// and returns the unseal keys.
func (s *KeyStore) ReadKeys() ([]string, error) {
	tpm, err := OpenTPM(s.TPMDevicePath, s.TPMHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	pattern := s.GlobPattern
	if pattern == "" {
		pattern = TPMKeyGlob(s.StorePath)
	}

	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to list key files: %w", err)
	}

	var keys []string
	for _, file := range files {
		encryptedKey, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", file, err)
		}
		decryptedKey, err := tpm.Decrypt(encryptedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt key %s: %w", file, err)
		}
		keys = append(keys, string(decryptedKey))
	}
	return keys, nil
}
