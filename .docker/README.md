# Docker Guide

This directory contains the Dockerfile and Compose example for the `vault-unsealer-tpm` daemon.

The **init tool** (`vault-unsealer-tpm-init`) is not distributed as a Docker image. It is a static binary intended
to be run directly on the provisioning host. See the main [README](../README.md) for setup instructions.

---

## Prerequisites

- Docker 20.10+
- A TPM 2.0 device exposed as `/dev/tpmrm0` (resource manager interface) on the host
- The host user or Docker daemon must have read/write access to the TPM device
- The key store must be populated by running `vault-unsealer-tpm-init` on the host before starting the container

---

## Building the Image

Build from the repository root (the build context must include the full source tree):

```sh
docker build -f .docker/Dockerfile -t vault-unsealer-tpm:latest .
```

Multi-platform builds (requires `docker buildx`):

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f .docker/Dockerfile \
  -t vault-unsealer-tpm:latest \
  --load .
```

---

## Volumes and Mounts

| Mount | Type | Purpose |
|---|---|---|
| `/keys` | Volume or bind mount | TPM-encrypted unseal key files (`unseal-key-*.tpm.enc`) |
| `/certs` | Bind mount (optional) | TLS CA certificate |

The `/keys` directory must persist across container restarts. Use a named Docker volume or a bind mount to a
directory owned and readable only by the container user.

---

## TPM Device Access

Pass the TPM device through at `docker run` time:

```sh
--device /dev/tpmrm0:/dev/tpmrm0
```

Using the resource manager interface (`/dev/tpmrm0`) is strongly preferred over the raw device (`/dev/tpm0`) as it
allows concurrent access from other processes on the host.

---

## Running the Daemon

### docker run

Configuration can be provided via environment variables, command-line flags, or both. Flags always take precedence
over environment variables.

```sh
docker run -d \
  --name vault-unsealer-tpm \
  --restart unless-stopped \
  --device /dev/tpmrm0:/dev/tpmrm0 \
  -v vault-unsealer-keys:/keys:ro \
  -v /path/to/certs:/certs:ro \
  -e VAULT_UNSEALER_VAULT_ADDR=https://vault.example.com:8200 \
  -e VAULT_UNSEALER_VAULT_TLS_CA_CERT=/certs/ca.pem \
  -e VAULT_UNSEALER_TPM_HANDLE=0x81010001 \
  vault-unsealer-tpm:latest
```

The `/keys` volume is mounted read-only — the daemon only decrypts keys, never writes them.

### Docker Compose

An annotated Compose file is provided at [compose.yml](compose.yml). Start from that template and adjust the
environment variables for your deployment:

```sh
docker compose -f .docker/compose.yml up -d
```

---

## Configuration Reference

All settings can be provided as environment variables or command-line flags. Flags always win.

| Environment variable | Flag | Default | Description |
|---|---|---|---|
| `VAULT_UNSEALER_VAULT_ADDR` | `--vault.address` | `http://127.0.0.1:8200` | Vault server address |
| `VAULT_UNSEALER_VAULT_TLS_CA_CERT` | `--vault.tls.ca-cert` | _(none)_ | Path to CA certificate for TLS verification |
| `VAULT_UNSEALER_VAULT_TLS_SERVER_NAME` | `--vault.tls.server-name` | _(none)_ | Override TLS server name (SNI) |
| `VAULT_UNSEALER_TPM_DEVICE` | `--tpm.device-path` | `/dev/tpmrm0` | Path to TPM device inside container |
| `VAULT_UNSEALER_TPM_HANDLE` | `--tpm.handle` | `0x81010001` | Persistent TPM handle (decimal or `0x` hex) |
| `VAULT_UNSEALER_STORE_PATH` | `--store-path` | `./keys` | Directory containing `unseal-key-*.tpm.enc` files |

---

## Security Notes

- The image is built `FROM scratch` with no shell, package manager, or other tooling. There is no attack surface
  beyond the single binary.
- Mount `/keys` **read-only** (`ro`). Only the init tool (run on the host) needs write access.
- Mount certificate directories read-only.
- Use `read_only: true` and `no-new-privileges:true` (see [compose.yml](compose.yml) for an example).
- Use `/dev/tpmrm0` (resource manager) rather than `/dev/tpm0` (direct) to avoid conflicting with other TPM users
  on the host.
- Do not store plaintext unseal keys in environment variables or Docker secrets — the whole point of this tool
  is that plaintext keys never need to exist at runtime.

## Prerequisites

- Docker 20.10+
- A TPM 2.0 device exposed as `/dev/tpmrm0` (resource manager interface) on the host
- The host user or Docker daemon must have read/write access to the TPM device

---

## Building the Images

Build from the repository root (the build context must include the full source tree):

```sh
# Daemon
docker build -f .docker/Dockerfile -t vault-unsealer-tpm:latest .

# Init tool
docker build -f .docker/Dockerfile.init -t vault-unsealer-tpm-init:latest .
```

Multi-platform builds (requires `docker buildx`):

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f .docker/Dockerfile \
  -t vault-unsealer-tpm:latest \
  --load .
```

---

## Volumes and Mounts

| Mount | Type | Purpose |
|---|---|---|
| `/keys` | Volume or bind mount | TPM-encrypted unseal key files (`unseal-key-*.tpm.enc`) |
| `/certs` | Bind mount (optional) | TLS CA certificate and/or server certificate |

The `/keys` directory must persist across container restarts. Use a named Docker volume or a bind mount to a
directory owned and readable only by the container user.

---

## TPM Device Access

Both containers need access to the TPM device. Pass it at `docker run` time:

```sh
--device /dev/tpmrm0:/dev/tpmrm0
```

If your TPM is only accessible as `/dev/tpm0` (direct, no resource manager), substitute accordingly. Using the
resource manager interface (`/dev/tpmrm0`) is strongly preferred as it allows concurrent access from other processes
on the host.

---

## Step 1 — Provisioning with the Init Tool

Run `vault-unsealer-tpm-init` **once** per Vault instance. It is interactive and requires human supervision.

### Fresh initialization

```sh
docker run --rm \
  --device /dev/tpmrm0:/dev/tpmrm0 \
  -v vault-unsealer-keys:/keys \
  -v /path/to/certs:/certs:ro \
  vault-unsealer-tpm-init:latest fresh \
    --vault.address https://vault.example.com:8200 \
    --vault.tls.ca-cert /certs/ca.pem \
    --tpm.device-path /dev/tpmrm0 \
    --tpm.handle 0x81010001 \
    --store-path /keys \
    --key-shares 5 \
    --key-threshold 3 \
    --key-shares-saved 3 \
    --recovery-public-key /certs/recovery.public.pem
```

### Adopting an existing Vault (pipe keys from stdin)

```sh
cat unseal-keys.txt | docker run --rm -i \
  --device /dev/tpmrm0:/dev/tpmrm0 \
  -v vault-unsealer-keys:/keys \
  vault-unsealer-tpm-init:latest adopt \
    --tpm.device-path /dev/tpmrm0 \
    --tpm.handle 0x81010001 \
    --store-path /keys
```

### TPM key rotation (rekey)

```sh
docker run --rm \
  --device /dev/tpmrm0:/dev/tpmrm0 \
  -v vault-unsealer-keys:/keys \
  vault-unsealer-tpm-init:latest rekey \
    --tpm.device-path /dev/tpmrm0 \
    --tpm.handle 0x81010001 \
    --tpm.new-handle 0x81010002 \
    --store-path /keys
```

After rekeying, update the daemon's `--tpm.handle` value before restarting it.

---

## Step 2 — Running the Daemon

```sh
docker run -d \
  --name vault-unsealer-tpm \
  --restart unless-stopped \
  --device /dev/tpmrm0:/dev/tpmrm0 \
  -v vault-unsealer-keys:/keys:ro \
  -v /path/to/certs:/certs:ro \
  vault-unsealer-tpm:latest \
    --vault.address https://vault.example.com:8200 \
    --vault.tls.ca-cert /certs/ca.pem \
    --tpm.device-path /dev/tpmrm0 \
    --tpm.handle 0x81010001 \
    --store-path /keys
```

The `/keys` volume is mounted read-only (`ro`) for the daemon — it only decrypts keys, never writes them.

---

## Configuration Reference

All configuration is passed as command-line flags. There are no environment variables.

### Daemon (`vault-unsealer-tpm`)

| Flag | Default | Description |
|---|---|---|
| `--vault.address` | `http://127.0.0.1:8200` | Vault server address |
| `--vault.tls.ca-cert` | _(none)_ | Path to CA certificate for TLS verification |
| `--vault.tls.server-name` | _(none)_ | Override TLS server name (SNI) |
| `--tpm.device-path` | `/dev/tpmrm0` | Path to TPM device inside container |
| `--tpm.handle` | `0x81010001` | Persistent TPM handle for the RSA key |
| `--store-path` | `./keys` | Directory containing `unseal-key-*.tpm.enc` files |

### Init tool (`vault-unsealer-tpm-init fresh`)

| Flag | Default | Description |
|---|---|---|
| `--vault.address` | `http://127.0.0.1:8200` | Vault server address |
| `--vault.tls.ca-cert` | _(none)_ | Path to CA certificate |
| `--vault.tls.server-name` | _(none)_ | Override TLS server name |
| `--vault.tls.skip-verify` | `false` | **INSECURE.** Disable TLS verification |
| `--tpm.device-path` | `/dev/tpmrm0` | Path to TPM device |
| `--tpm.handle` | `0x81010001` | Persistent TPM handle |
| `--store-path` | `./keys` | Directory to write encrypted key files |
| `--key-shares` | `5` | Total unseal key shares to generate |
| `--key-threshold` | `3` | Shares required to unseal |
| `--key-shares-saved` | `3` | Shares to encrypt with the TPM (≥ threshold) |
| `--recovery-public-key` | _(none)_ | RSA public key path for recovery backups |

Run `vault-unsealer-tpm-init adopt -h` or `vault-unsealer-tpm-init rekey -h` for their specific flags.

---

## Docker Compose Example

```yaml
services:
  vault-unsealer-tpm:
    image: vault-unsealer-tpm:latest
    restart: unless-stopped
    devices:
      - /dev/tpmrm0:/dev/tpmrm0
    volumes:
      - vault-unsealer-keys:/keys:ro
      - ./certs:/certs:ro
    command:
      - --vault.address=https://vault.example.com:8200
      - --vault.tls.ca-cert=/certs/ca.pem
      - --tpm.device-path=/dev/tpmrm0
      - --tpm.handle=0x81010001
      - --store-path=/keys
    read_only: true
    security_opt:
      - no-new-privileges:true

volumes:
  vault-unsealer-keys:
    external: true
```

The init tool is not included in the Compose file — it is run manually as a `docker run` command before starting
the stack.

---

## Security Notes

- The images are built `FROM scratch` with no shell, package manager, or other tooling. There is no attack surface
  beyond the single binary.
- Mount `/keys` **read-only** (`ro`) for the daemon. Only the init tool needs write access.
- Mount certificate directories read-only.
- Use `read_only: true` and `no-new-privileges:true` in Compose or the equivalent `--read-only` and
  `--security-opt no-new-privileges` flags with `docker run`.
- The TPM device should be the resource manager interface (`/dev/tpmrm0`) rather than the raw device
  (`/dev/tpm0`) to avoid conflicting with other TPM users on the host.
- Do not store plaintext unseal keys in environment variables or Docker secrets — the whole point of this tool
  is that plaintext keys never need to exist at runtime.
