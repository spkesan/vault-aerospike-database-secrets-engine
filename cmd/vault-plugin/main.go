package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/hashicorp/vault/api"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	engine "github.com/spkesan/vault-aerospike-database-secrets-engine/engine"
)

// ----------------------------------------------
// Internal API
// ----------------------------------------------

var (
	version = "0.1.0"
)

// Main
func main() {
	// command line inputs
	printVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	// print version
	if *printVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	err := Run()
	if err != nil {
		log.Fatal(err)
	}
}

// ----------------------------------------------
// Public API
// ----------------------------------------------

// Run instantiates an Aerospike object
// starts the RPC server to serve the plugin
func Run() error {
	dbType, err := engine.New()
	if err != nil {
		return err
	}

	dbplugin.Serve(dbType.(dbplugin.Database))

	return nil
}
