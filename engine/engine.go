package aerospike

import (
	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

// ----------------------------------------------
// Public API
// ----------------------------------------------

// New creates a new Aerospike instance
func New() (interface{}, error) {
	db := NewAerospike()

	// Wrap the plugin with middleware to sanitize errors
	dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return dbType, nil
}

// NewAerospike initializes Aerospike instance
func NewAerospike() *Aerospike {
	// create Aerospike instance with defaults
	return &Aerospike{
		Username: "admin",
		Password: "admin",
		AuthMode: "internal",
		DbHost:   "localhost",
		DbPort:   3000,
		Timeout:  10000,
		TypeName: databaseType,
	}
}

// ----------------------------------------------
// Internal API
// ----------------------------------------------

func (a *Aerospike) secretValues() map[string]string {
	return map[string]string{
		a.Password: "[password]",
	}
}
