//go:build tpm_integration

package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aRestless/vault-unsealer-tpm/crypto"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDevicePath = "/dev/tpmrm0"
	testKeyHandle  = 0x81010002
)

func newTestUnsealServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	unsealProgress := 0
	mux.HandleFunc("/v1/sys/unseal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT for Unseal, got %s", r.Method)
		}
		unsealProgress++
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&api.SealStatusResponse{
			Sealed:   unsealProgress < 3,
			Progress: unsealProgress,
		})
	})

	return httptest.NewServer(mux)
}

func TestUnsealVault(t *testing.T) {
	server := newTestUnsealServer(t)
	defer server.Close()

	v, err := NewVault(&api.Config{Address: server.URL})
	require.NoError(t, err)

	tpm, err := crypto.OpenTPM(testDevicePath, testKeyHandle)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, tpm.Close())
	}()

	require.NoError(t, tpm.InitKey())
	defer func() {
		require.NoError(t, tpm.ClearKey())
	}()

	tempDir := t.TempDir()
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("key%d", i+1)
		encrypted, err := tpm.Encrypt([]byte(key))
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(tempDir, fmt.Sprintf("unseal-key-%d.tpm.enc", i)), encrypted, 0600)
		require.NoError(t, err)
	}

	store := &crypto.KeyStore{
		GlobPattern:   filepath.Join(tempDir, "unseal-key-*.tpm.enc"),
		TPMDevicePath: testDevicePath,
		TPMHandle:     testKeyHandle,
	}

	unsealed, err := v.Unseal(store)
	assert.NoError(t, err)
	assert.True(t, unsealed)
}
