# vault-unsealer-tpm

`vault-unsealer-tpm` automatically unseals HashiCorp Vault with unseal keys that are stored on disk encrypted by a
TPM 2.0 device.

There is one binary and one Docker image:

- Run mode, the default: a long-running daemon that watches Vault and unseals it when needed.
- Init mode, enabled with `-init`: a one-shot interactive setup command that initializes a new Vault or adopts keys
  for an already-initialized Vault.

## Docker Compose

Edit [.docker/compose.yml](.docker/compose.yml), especially the Vault address, TLS CA path, TPM device, and TPM handle.
The run and init services intentionally share the same image, environment, device, and key volume.

Initialize or adopt keys:

```sh
docker compose -f .docker/compose.yml --profile init run --rm unsealer-init
```

Pass init flags when you want non-default shares. Include `-init` because `docker compose run SERVICE ...` replaces
the service command:

```sh
docker compose -f .docker/compose.yml --profile init run --rm unsealer-init \
  -init -key-shares=5 -key-threshold=3 -key-shares-saved=3
```

Start the daemon after init completes:

```sh
docker compose -f .docker/compose.yml up -d vault-unsealer-tpm
```

## Init Mode

Init mode chooses the action from Vault's current state:

- If Vault is not initialized, it initializes Vault, encrypts the configured number of unseal keys with the TPM, writes
  them to the key store, unseals Vault once, and prints the generated unseal keys and root token.
- If Vault is already initialized, it adopts existing unseal keys from `-keys-file` or prompts for them interactively.

If key files already exist, init asks whether to delete them and then requires this exact confirmation:

```text
delete keys
```

Only tool-owned files are deleted: `unseal-key-*.tpm.enc` and legacy `unseal-key-*.recovery.enc`.

Host example:

```sh
vault-unsealer-tpm -init \
  -vault.address=https://vault.example.com:8200 \
  -vault.tls.ca-cert=/etc/vault/ca.pem \
  -store-path=/etc/vault-unsealer/keys \
  -tpm.device-path=/dev/tpmrm0 \
  -tpm.handle=0x81010001
```

Adopt an existing Vault without prompts:

```sh
vault-unsealer-tpm -init -keys-file ./unseal-keys.txt
```

The keys file must contain one unseal key per line. Blank lines and lines beginning with `#` are ignored.

## Run Mode

Run mode reads configuration from environment variables or flags and never prompts:

```sh
vault-unsealer-tpm \
  -vault.address=https://vault.example.com:8200 \
  -vault.tls.ca-cert=/etc/vault/ca.pem \
  -store-path=/etc/vault-unsealer/keys \
  -tpm.device-path=/dev/tpmrm0 \
  -tpm.handle=0x81010001
```

The daemon expects `unseal-key-*.tpm.enc` files to already exist in the key store. Mount the key store read-only in
run mode.

## Configuration

Flags override environment variables.

| Environment variable | Flag | Default |
|---|---|---|
| `VAULT_UNSEALER_VAULT_ADDR` | `-vault.address` | `http://127.0.0.1:8200` |
| `VAULT_UNSEALER_VAULT_TLS_CA_CERT` | `-vault.tls.ca-cert` | empty |
| `VAULT_UNSEALER_VAULT_TLS_SERVER_NAME` | `-vault.tls.server-name` | empty |
| `VAULT_UNSEALER_STORE_PATH` | `-store-path` | `./keys` |
| `VAULT_UNSEALER_TPM_DEVICE` | `-tpm.device-path` | `/dev/tpmrm0` |
| `VAULT_UNSEALER_TPM_HANDLE` | `-tpm.handle` | `0x81010001` |

Init-only flags:

| Flag | Default |
|---|---|
| `-key-shares` | `5` |
| `-key-threshold` | `3` |
| `-key-shares-saved` | `3` |
| `-keys-file` | empty; prompt when adopting |

## Scope

Kept or added: auto-unseal daemon, fresh initialization, adoption of existing keys, TPM-backed key encryption,
TLS CA/server-name configuration, Docker Compose usage, direct Docker/host usage, `-init`, interactive prompts, and
safe deletion confirmation.

Removed: the separate init binary, init subcommands, AppRole bootstrap setup, root-token revocation, RSA recovery
backup files, TPM rekey/export commands, and duplicate Docker docs.

## Tests

```sh
go test ./...
```

TPM integration tests require hardware:

```sh
go test -tags tpm_integration ./...
```
