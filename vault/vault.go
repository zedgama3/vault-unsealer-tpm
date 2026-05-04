package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/vault/api"
)

type Vault struct {
	client *api.Client
}

type KeyStore interface {
	ReadKeys() ([]string, error)
}

func NewVault(vaultConfig *api.Config) (*Vault, error) {
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	return &Vault{client: client}, nil
}

func (v *Vault) IsInitialized() (bool, error) {
	return v.client.Sys().InitStatus()
}

func (v *Vault) UnsealLoop(ctx context.Context, store KeyStore) error {
	log.Println("Starting unsealing loop...")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping Unseal loop.")
			return ctx.Err()
		case <-ticker.C:
			sealStatus, err := v.client.Sys().SealStatus()
			if err != nil {
				log.Printf("Error checking Vault seal status: %v", err)
				continue
			}

			if sealStatus.Sealed {
				log.Println("Vault is sealed. Attempting to Unseal...")
				unsealed, err := v.Unseal(store)
				if err != nil {
					log.Printf("Failed to Unseal Vault: %v", err)
				} else if unsealed {
					log.Println("Vault is now unsealed.")
				} else {
					log.Println("Vault remains sealed after Unseal attempts.")
				}
			}
		}
	}
}

func (v *Vault) Unseal(store KeyStore) (bool, error) {
	keys, err := store.ReadKeys()
	if err != nil {
		return false, fmt.Errorf("failed to read Unseal keys: %v", err)
	}

	if len(keys) == 0 {
		return false, errors.New("no Unseal keys available")
	}

	for i, key := range keys {
		status, err := v.client.Sys().Unseal(key)
		if err != nil {
			return false, fmt.Errorf("submitting Unseal key %d: %v", i, err)
		}

		if !status.Sealed {
			log.Println("Vault successfully unsealed.")
			return true, nil
		}
	}

	return false, nil
}
