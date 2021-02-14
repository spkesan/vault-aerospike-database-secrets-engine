# Variables required for this Makefile
VERSION = $(shell git describe --tags --always)

# Builds plugin binary
.PHONY: plugin
plugin:
	go build -ldflags="-X 'main.version=$(VERSION)'" -o vault-aerospike-database-secrets-engine ./cmd/vault-plugin/

# Clean up
.PHONY: clean
clean:
	rm -rf vault-aerospike-database-secrets-engine
