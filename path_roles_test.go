package horizonsecretsengine

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	instance   = "vault-plugin-testing"
	testTTL    = int64(120)
	testMaxTTL = int64(3600)
)

func TestUserRole(t *testing.T) {
	b, s := getTestBackend(t)

	t.Run("List all roles", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			_, err := testCredsRoleCreate(t, b, s,
				instance+strconv.Itoa(i),
				map[string]interface{}{
					"instance":          instance,
					"username":          username,
					"ttl":               testTTL,
					"max_ttl":           testMaxTTL,
					"credential_config": map[string]interface{}{},
				})
			require.Nil(t, err)
		}
		resp, err := testCredsRoleList(t, b, s)
		require.NoError(t, err)
		require.NotNil(t, resp.Data["keys"])
		require.Len(t, resp.Data["keys"].([]string), 10)
	})

	t.Run("Create User Role - pass", func(t *testing.T) {
		resp, err := testCredsRoleCreate(t, b, s, instance, map[string]interface{}{
			"instance":          instance,
			"username":          username,
			"ttl":               testTTL,
			"max_ttl":           testMaxTTL,
			"credential_config": map[string]interface{}{},
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Read User Role", func(t *testing.T) {
		resp, err := testCredsRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, instance, resp.Data["instance"])
	})
	t.Run("Update User Role", func(t *testing.T) {
		resp, err := testCredsRoleUpdate(t, b, s, map[string]interface{}{
			"instance": instance,
			"ttl":      "1m",
			"max_ttl":  "5h",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Re-read User Role", func(t *testing.T) {
		resp, err := testCredsRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, instance, resp.Data["instance"])
	})

	t.Run("Delete User Role", func(t *testing.T) {
		_, err := testCredsRoleDelete(t, b, s)

		require.NoError(t, err)
	})
}

func testCredsRoleCreate(t *testing.T, b *horizonBackend, s logical.Storage, instance string, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + instance,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func testCredsRoleUpdate(t *testing.T, b *horizonBackend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + instance,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	return resp, nil
}

func testCredsRoleRead(t *testing.T, b *horizonBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/" + instance,
		Storage:   s,
	})
}

func testCredsRoleList(t *testing.T, b *horizonBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
}

func testCredsRoleDelete(t *testing.T, b *horizonBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/" + instance,
		Storage:   s,
	})
}
