# vault-unsealer-tpm

vault-unsealer-tpm is a purpose-built tool for automatically unsealing a HashiCorp Vault instance using a TPM 2.0
device. It is split into two binaries with distinct responsibilities:

- **`vault-unsealer-tpm`** (`cmd/unseal`) — a long-running daemon that monitors Vault and unseals it whenever it is
  found sealed, using keys stored encrypted on disk and decrypted at runtime by the TPM.
- **`vault-unsealer-tpm-init`** (`cmd/init`) — a one-shot, human-supervised CLI tool for provisioning the encrypted
  key store. Run this once during setup; it does not run as a daemon.

## Recommended Setup

An ideal setup involves three separate machines:

- A machine with a TPM 2.0 device that runs the `vault-unsealer-tpm` daemon and the `vault-unsealer-tpm-init` tool.
- A machine running a HashiCorp Vault server.
- A secure, ideally air-gapped machine to store recovery key backups.

## Provisioning with `vault-unsealer-tpm-init`

`vault-unsealer-tpm-init` has three subcommands. Run any with `-h` for its full flag reference.

### `fresh` — Initialize a new Vault

Use this when Vault has not yet been initialized. It initializes Vault, encrypts the unseal keys with the TPM, and
optionally writes recovery-encrypted backups.

```sh
vault-unsealer-tpm-init fresh \
  --vault.address https://vault.example.com:8200 \
  --vault.tls.ca-cert /etc/vault/ca.pem \
  --tpm.device-path /dev/tpmrm0 \
  --tpm.handle 0x81010001 \
  --store-path /etc/vault-unsealer/keys \
  --key-shares 5 \
  --key-threshold 3 \
  --key-shares-saved 3 \
  --recovery-public-key /path/to/recovery.public.pem
```

**Key flags:**

| Flag | Default | Description |
|---|---|---|
| `--key-shares` | `5` | Total number of unseal key shares to generate |
| `--key-threshold` | `3` | Number of shares required to unseal |
| `--key-shares-saved` | `3` | Number of shares to encrypt with the TPM (must be ≥ threshold) |
| `--recovery-public-key` | _(none)_ | Optional RSA public key path; if set, all shares are also encrypted as recovery backups |
| `--vault.tls.skip-verify` | `false` | **INSECURE.** Skip TLS verification; only for bootstrap against a temporary certificate |

The tool refuses to run if TPM-encrypted keys already exist at `--store-path`.

After `fresh` completes, the root token is revoked. No AppRole or policy is created — use your standard Vault
provisioning tooling (Terraform, Ansible, etc.) for that.

### `adopt` — Adopt an existing Vault instance

Use this when Vault is already initialized and you have the unseal keys. The keys are read from a file or stdin,
encrypted with the TPM, and written to the store.

```sh
# From a file:
vault-unsealer-tpm-init adopt \
  --store-path /etc/vault-unsealer/keys \
  --tpm.device-path /dev/tpmrm0 \
  --tpm.handle 0x81010001 \
  --keys-file /path/to/unseal-keys.txt

# From stdin:
vault-unsealer-tpm-init adopt \
  --store-path /etc/vault-unsealer/keys \
  --tpm.device-path /dev/tpmrm0 \
  --tpm.handle 0x81010001
```

The keys file should contain one unseal key per line; blank lines and lines beginning with `#` are ignored.

### `rekey` — Rotate the TPM key

Use this when replacing the TPM or rotating the TPM key handle. The existing keys are decrypted with the old handle,
re-encrypted under the new handle, and written atomically. The old handle is evicted unless `--keep-old-handle` is set.

```sh
vault-unsealer-tpm-init rekey \
  --store-path /etc/vault-unsealer/keys \
  --tpm.device-path /dev/tpmrm0 \
  --tpm.handle 0x81010001 \
  --tpm.new-handle 0x81010002
```

After rekeying, update the daemon's `--tpm.handle` flag to the new handle before restarting it.

## Running the Daemon

Once keys are in place, start the daemon:

```sh
vault-unsealer-tpm \
  --vault.address https://vault.example.com:8200 \
  --vault.tls.ca-cert /etc/vault/ca.pem \
  --tpm.device-path /dev/tpmrm0 \
  --tpm.handle 0x81010001 \
  --store-path /etc/vault-unsealer/keys
```

The daemon polls Vault every 10 seconds. If Vault is sealed, it decrypts the stored keys with the TPM and submits
them. It refuses to start if no TPM-encrypted key files are present at `--store-path`.

**Daemon flags:**

| Flag | Default | Description |
|---|---|---|
| `--vault.address` | `http://127.0.0.1:8200` | Vault server address |
| `--vault.tls.ca-cert` | _(none)_ | Path to CA certificate for TLS verification |
| `--vault.tls.server-name` | _(none)_ | Override TLS server name |
| `--tpm.device-path` | `/dev/tpmrm0` | Path to the TPM device |
| `--tpm.handle` | `0x81010001` | Persistent TPM handle holding the RSA key |
| `--store-path` | `./keys` | Directory containing the `unseal-key-*.tpm.enc` files |

TLS verification is always enforced in the daemon. There is no `--vault.tls.skip-verify` flag.

## Recovery Procedure

If the TPM is lost or damaged and recovery-encrypted backups were written during `fresh`:

1. Transfer the `unseal-key-*.recovery.enc` files to the secure recovery machine.
2. Decrypt each file using the recovery private key:

```sh
openssl pkeyutl -decrypt \
  -inkey recovery.private.pem \
  -in unseal-key-0.recovery.enc \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256
```

3. Once you have the plaintext keys, use `vault-unsealer-tpm-init adopt` on a new TPM-equipped machine to re-provision
   the key store.

## Preparing a Recovery Key Pair

On the secure recovery machine:

```sh
openssl genpkey -algorithm RSA -out recovery.private.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in recovery.private.pem -out recovery.public.pem
```

Keep `recovery.private.pem` on the offline machine. Transfer only `recovery.public.pem` to the machine running the
init tool.

## Tests

Unit tests run without hardware:

```sh
go test ./...
```

Integration tests require a real TPM device and appropriate privileges:

```sh
go test -tags tpm_integration ./...
```