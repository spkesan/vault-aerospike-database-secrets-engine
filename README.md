# Vault Aerospike Database Secrets Engine

A Vault plugin to dynamically generate credentials based on configured roles for Aerospike database. It also supports [Static Roles](https://www.vaultproject.io/docs/secrets/databases#static-roles).

## Vault Version

- Vault 1.6+

## Capabilities

| Root Credential Rotation | Dynamic Roles | Static Roles |
| ------------------------ | ------------- | ------------ |
|           Yes            |      Yes      |      Yes     |

## Build

### Clone the repository,
```sh
$ git clone https://github.com/spkesan/vault-aerospike-database-secrets-engine.git
$ cd vault-aerospike-database-secrets-engine/
```

### Build the plugin
```sh
$ make plugin
```

## Usage

### Install the plugin

Add the plugin binary `vault-aerospike-database-secrets-engine` to the `plugin_directory` configured in Vault.

Register the plugin,
```sh
$ vault write sys/plugins/catalog/database/vault-aerospike-database-secrets-engine \
    sha256=$(sha256sum vault-aerospike-database-secrets-engine | awk '{print $1}') \
    command="vault-aerospike-database-secrets-engine"
```

### Setup

Enable the database secrets engine if it is not already enabled
```sh
$ vault secrets enable database
Success! Enabled the database secrets engine at: database/
```
By default, the secrets engine will enable at the name of the engine. To enable the secrets engine at a different path, use the `-path` argument.

Configure Vault with the proper plugin and connection information
```sh
$ vault write database/config/aerospike-enterprise \
plugin_name=vault-aerospike-database-secrets-engine \
allowed_roles="*" \
db_host="localhost" \
db_port=3000 \
username="admin" \
password="admin"
```

See [configurations for Aerospike connection](#configurations-for-aerospike-connection)

*It is recommended that you immediately rotate the root user's password. The root user's password will not be accessible once rotated so you must create a separate user with `user-admin` access for Vault to utilize rather than using the actual root user.*

Configure a role that maps a name in Vault to a role definition in Aerospike
```sh
$ vault write database/roles/superuser \
db_name=aerospike-enterprise \
creation_statements='{"roles":["sys-admin","user-admin","data-admin","read-write-udf"]}' \
default_ttl=60s \
max_ttl=300s
```

### Usage

After the secrets engine is configured and a user/machine has a Vault token with the proper permission, it can generate credentials.

Generate a new credentials by reading from the `/creds` endpoint with the name of the role
```sh
$ vault read database/creds/superuser
```

### Static Roles

Configure a static role that maps a name in Vault to an existing Aerospike user.
```sh
$ vault write database/static-roles/static-superuser \
  db_name="aerospike-enterprise" \
  username="spkesan" \
  rotation_period=5m
```

Retrieve the credentials from the `/static-creds` endpoint
```sh
vault read database/static-creds/static-superuser
```

### Configurations for Aerospike connection

| Configs | Description | Type |
| ------- | ----------- | ---- |
| `username`| User with `user-admin` access to Aerospike | `string` |
| `password` | Password for the `user-admin` user | `string` |
| `auth_mode` | Auth mode against Aerospike - `internal` or `external` | `string` |
| `db_host` | Aerospike seed IP to connect | `string` |
| `db_port` | Aerospike seed Port to connect | `integer` |
| `timeout` | Aerospike connection timeout | `integer` |
| `cert_file` | Client certificate for TLS connection | `string` |
| `key_file` | Private key associated with the certificate | `string` |
| `key_file_passphrase` | Passphrase for encrypted private key | `string` |
| `tls_name` | TLS name of the Aerospike server | `string` |
| `root_ca` | Root CA to verify server certificate | `string` |

- Certificates (`cert_file`, `key_file`, `root_ca`) can be passed in following formats,
	  - `"<file-path>"`
	  - `"file:<file-path>"`
	  - `"env-b64:<environment-variable-containing-base64-encoded-certificate>"`
	  - `"b64:<base64-encoded-certificate>"`

- Credentials (`username`, `password`, `key_file_passphrase`) can be passed in following formats,
	  - `"<secret>"`
	  - `"file:<file-containing-the-secret>"`
	  - `"env:<environment-variable-containing-the-secret>"`
	  - `"env-b64:<environment-variable-containing-the-base64-encoded-secret>"`
	  - `"b64:<bas64-encoded-value-of-the-secret>"`
