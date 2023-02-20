package horizonsecretsengine

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests     = "VAULT_ACC"
	envVarHorizonUsername = "TEST_HORIZON_USERNAME"
	envVarHorizonPassword = "TEST_HORIZON_PASSWORD"
	envVarHorizonURL      = "TEST_HORIZON_URL"
)

func getTestBackend(tb testing.TB) (*horizonBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*horizonBackend), config.StorageView
}

type testEnv struct {
	Username string
	Password string
	Endpoint string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage
}

func (e *testEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/plugin-test",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"username":         username,
			"password":         password,
			"horizon_endpoint": horizon_endpoint,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) AddUserCredsRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-user-token",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"username": e.Username,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testEnv) ReadUserToken(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/plugin-test",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)

	if t, ok := resp.Data["username"]; ok {
		e.Username = t.(string)
	}
	if t, ok := resp.Data["password"]; ok {
		e.Password = t.(string)
	}
}

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"
