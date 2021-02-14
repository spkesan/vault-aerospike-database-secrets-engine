package aerospike

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"github.com/mitchellh/mapstructure"

	aerospike "github.com/aerospike/aerospike-client-go"
)

// Database Type
const databaseType = "aerospike-enterprise"

// Aerospike Object
type Aerospike struct {
	// Aerospike client instance
	client *aerospike.Client

	// Access control parameters for Aerospike DB
	Username string `json:"username" mapstructure:"username" structs:"username"`
	Password string `json:"password" mapstructure:"password" structs:"password"`
	AuthMode string `json:"auth_mode" mapstructure:"auth_mode" structs:"auth_mode"`

	// Seed IP and Port for Aerospike DB
	DbHost string `json:"db_host" mapstructure:"db_host" structs:"db_host"`
	DbPort uint16 `json:"db_port" mapstructure:"db_port" structs:"db_port"`

	// Connection timeout
	Timeout uint16 `json:"timeout" mapstructure:"timeout" structs:"timeout"`

	// TLS Configurations for Aerospike DB
	CertFile          string `json:"cert_file" mapstructure:"cert_file" structs:"cert_file"`
	KeyFile           string `json:"key_file" mapstructure:"key_file" structs:"key_file"`
	KeyFilePassphrase string `json:"key_file_passphrase" mapstructure:"key_file_passphrase" structs:"key_file_passphrase"`
	TLSName           string `json:"tls_name" mapstructure:"tls_name" structs:"tls_name"`
	RootCA            string `json:"root_ca" mapstructure:"root_ca" structs:"root_ca"`

	// Mutex
	mutex sync.Mutex

	// Other parameters
	RawConfig map[string]interface{}
	TypeName  string
}

// NewUserStatement Object
type NewUserStatement struct {
	Roles []string `json:"roles"`
}

// --------------------------------
// Aerospike Client Implementation
// --------------------------------
// Internal API
// --------------------------------

// initAerospikeClient initializes Aerospike client
func (a *Aerospike) initAerospikeClient() (*aerospike.Client, error) {
	authMode := strings.ToLower(strings.TrimSpace(a.AuthMode))
	if authMode != "internal" && authMode != "external" {
		return nil, fmt.Errorf("invalid auth mode")
	}

	// Get aerospike auth username
	username, err := getSecret(a.Username)
	if err != nil {
		return nil, err
	}

	// Get aerospike auth password
	password, err := getSecret(a.Password)
	if err != nil {
		return nil, err
	}

	clientPolicy := aerospike.NewClientPolicy()

	clientPolicy.User = string(username)
	clientPolicy.Password = string(password)
	if authMode == "external" {
		clientPolicy.AuthMode = aerospike.AuthModeExternal
	}

	clientPolicy.Timeout = time.Duration(a.Timeout) * time.Second

	clientPolicy.TlsConfig = a.initAerospikeTLSConfig()

	host := aerospike.NewHost(a.DbHost, int(a.DbPort))
	host.TLSName = a.TLSName

	client, err := aerospike.NewClientWithPolicyAndHost(clientPolicy, host)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// refreshClientConnections verifies the client connections
// and re-initializes the client if it's broken
func (a *Aerospike) refreshClientConnections(ctx context.Context) error {
	if a.client != nil {
		// client exists, validate connections
		if a.client.IsConnected() {
			// client is alright, return
			return nil
		}

		// close client connections, we will re-initialize the client anyway
		a.client.Close()
		a.client = nil
	}

	var err error
	// initialize the client
	a.client, err = a.initAerospikeClient()
	if err != nil {
		return fmt.Errorf("failed to initialize aerospike client: %v", err)
	}

	// success
	return nil
}

// initAerospikeTLSConfig initializes TLS configuration to connect to Aerospike DB
func (a *Aerospike) initAerospikeTLSConfig() *tls.Config {
	if len(a.RootCA) == 0 && len(a.CertFile) == 0 && len(a.KeyFile) == 0 {
		return nil
	}

	var clientPool []tls.Certificate
	var serverPool *x509.CertPool
	var err error

	serverPool, err = loadCACert(a.RootCA)
	if err != nil {
		log.Fatal(err)
	}

	if len(a.CertFile) > 0 || len(a.KeyFile) > 0 {
		clientPool, err = loadServerCertAndKey(a.CertFile, a.KeyFile, a.KeyFilePassphrase)
		if err != nil {
			log.Fatal(err)
		}
	}

	tlsConfig := &tls.Config{
		Certificates:             clientPool,
		RootCAs:                  serverPool,
		InsecureSkipVerify:       false,
		PreferServerCipherSuites: true,
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig
}

// ----------------------------------------------
// Vault database plugin interface implementation
// ----------------------------------------------
// Public API
// ----------------------------------------------

// Supports Vault 1.6+

// Initialize the database plugin.
// Initialize(ctx context.Context, req InitializeRequest) (InitializeResponse, error)

// NewUser creates a new user within the database.
// NewUser(ctx context.Context, req NewUserRequest) (NewUserResponse, error)

// UpdateUser updates an existing user within the database.
// UpdateUser(ctx context.Context, req UpdateUserRequest) (UpdateUserResponse, error)

// DeleteUser from the database.
// DeleteUser(ctx context.Context, req DeleteUserRequest) (DeleteUserResponse, error)

// Type returns the Name for the particular database backend implementation.
// Type() (string, error)

// Close attempts to close the underlying database connection that was established by the backend.
// Close() error

// Initialize the database plugin.
// Parses configuration, initializes Aerospike client and verifies the connections
func (a *Aerospike) Initialize(ctx context.Context, initReq dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	initResp := dbplugin.InitializeResponse{}
	a.RawConfig = initReq.Config

	err := mapstructure.WeakDecode(initReq.Config, &a)
	if err != nil {
		return initResp, err
	}

	if len(a.DbHost) == 0 {
		return initResp, fmt.Errorf("db_host is empty")
	}

	// Verify client connections
	if initReq.VerifyConnection {
		err = a.refreshClientConnections(ctx)
		if err != nil {
			return initResp, fmt.Errorf("error while verifying connections: %v", err)
		}

		// sanity check
		if !a.client.IsConnected() {
			return initResp, fmt.Errorf("error while verifying connections: client is not connected")
		}
	}

	initResp.Config = initReq.Config

	return initResp, nil
}

// NewUser creates a new user within the database.
func (a *Aerospike) NewUser(ctx context.Context, newUserReq dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	newUserResp := dbplugin.NewUserResponse{}

	if len(newUserReq.Statements.Commands) == 0 {
		return newUserResp, dbutil.ErrEmptyCreationStatement
	}

	if len(newUserReq.Statements.Commands) > 1 {
		return newUserResp, fmt.Errorf("more than one creation statement found")
	}

	cmd := newUserReq.Statements.Commands[0]
	stmt := &NewUserStatement{}
	if err := json.Unmarshal([]byte(cmd), stmt); err != nil {
		return newUserResp, fmt.Errorf("failed to unmarshal %s: %v", []byte(cmd), err)
	}

	// generate username
	username, err := credsutil.GenerateUsername(
		credsutil.DisplayName(newUserReq.UsernameConfig.DisplayName, 15),
		credsutil.RoleName(newUserReq.UsernameConfig.RoleName, 15),
		credsutil.MaxLength(63),
		credsutil.Separator("-"),
	)
	if err != nil {
		return newUserResp, fmt.Errorf("failed to generate username for %q: %w", newUserReq.UsernameConfig, err)
	}

	// validate roles provided
	if len(stmt.Roles) == 0 {
		return newUserResp, fmt.Errorf("no roles specified, please specify atleast one role")
	}

	// refresh client connections
	err = a.refreshClientConnections(ctx)
	if err != nil {
		return newUserResp, fmt.Errorf("error while refreshing client: %v", err)
	}

	// create user
	err = a.client.CreateUser(a.client.DefaultAdminPolicy, username, newUserReq.Password, stmt.Roles)
	if err != nil {
		return newUserResp, fmt.Errorf("failed to create user: %v", err)
	}

	newUserResp.Username = username

	// success
	return newUserResp, nil
}

// UpdateUser updates an existing user within the database.
func (a *Aerospike) UpdateUser(ctx context.Context, updateUserReq dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	updateUserResp := dbplugin.UpdateUserResponse{}

	if updateUserReq.Password == nil && updateUserReq.Expiration == nil {
		// no password and expiration provided
		return updateUserResp, fmt.Errorf("no change requested")
	}

	// refresh client connections
	err := a.refreshClientConnections(ctx)
	if err != nil {
		return updateUserResp, fmt.Errorf("error while refreshing client: %v", err)
	}

	// change password for the user
	if updateUserReq.Password != nil {
		err = a.client.ChangePassword(a.client.DefaultAdminPolicy, updateUserReq.Username, updateUserReq.Password.NewPassword)
		if err != nil {
			return updateUserResp, fmt.Errorf("failed to update password: %v", err)
		}
	}

	// expiration change is a no-op for aerospike

	// success
	return updateUserResp, nil
}

// DeleteUser from the database.
func (a *Aerospike) DeleteUser(ctx context.Context, delUserReq dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	delUserResp := dbplugin.DeleteUserResponse{}

	// refresh client connections
	err := a.refreshClientConnections(ctx)
	if err != nil {
		return delUserResp, fmt.Errorf("error while refreshing client: %v", err)
	}

	// delete user
	err = a.client.DropUser(a.client.DefaultAdminPolicy, delUserReq.Username)
	if err != nil {
		return delUserResp, fmt.Errorf("failed to delete user: %v", err)
	}

	// success
	return delUserResp, nil
}

// Type returns the name of the backend database
func (a *Aerospike) Type() (string, error) {
	return a.TypeName, nil
}

// Close closes all client connections to Aerospike DB nodes
func (a *Aerospike) Close() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.client != nil {
		a.client.Close()
	}

	a.client = nil

	return nil
}
