package horizonsecretsengine

import (
	"context"
	"fmt"
	"net/url"

	horizon "github.com/evertrust/horizon-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func secretCreds(b *horizonBackend) *framework.Secret {
	return &framework.Secret{
		Type:   SecretCredsType,
		Fields: map[string]*framework.FieldSchema{},

		Renew:  b.secretCredsRenew(),
		Revoke: b.secretCredsRevoke(),
	}
}

func (b *horizonBackend) secretCredsRenew() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Get the username from the internal data
		usernameRaw, ok := req.Secret.InternalData["username"]
		if !ok {
			return nil, fmt.Errorf("secret is missing username internal data")
		}
		username := usernameRaw.(string)

		roleNameRaw, ok := req.Secret.InternalData["role"]
		if !ok {
			return nil, fmt.Errorf("could not find role with name: %q", req.Secret.InternalData["role"])
		}
		roleName := roleNameRaw.(string)

		role, err := b.Role(ctx, req.Storage, roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return nil, fmt.Errorf("error during renew: could not find role with name %q", req.Secret.InternalData["role"])
		}

		b.secretCredsRevoke()

		config, err := b.getConfig(ctx, req.Storage, role.Instance)
		if err != nil {
			return nil, err
		}

		endpoint, err := url.Parse(config.HorizonEndpoint)
		if err != nil {
			return nil, err
		}

		h := new(horizon.Horizon)
		h.Init(*endpoint, config.ConnectionDetails["username"].(string), config.ConnectionDetails["password"].(string), "", "")

		h.Local.Create(username, role.Contact)

		resp := &logical.Response{Secret: req.Secret}
		resp.Secret.TTL = role.TTL
		resp.Secret.MaxTTL = role.MaxTTL
		return resp, nil
	}
}

func (b *horizonBackend) secretCredsRevoke() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Get the username from the internal data
		usernameRaw, ok := req.Secret.InternalData["username"]
		if !ok {
			return nil, fmt.Errorf("secret is missing username internal data")
		}
		username := usernameRaw.(string)

		roleNameRaw, ok := req.Secret.InternalData["role"]
		if !ok {
			return nil, fmt.Errorf("no role name was provided")
		}
		roleName := roleNameRaw.(string)

		role, err := b.Role(ctx, req.Storage, roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
		}

		config, err := b.getConfig(ctx, req.Storage, role.Instance)
		if err != nil {
			return nil, err
		}

		endpoint, err := url.Parse(config.HorizonEndpoint)
		if err != nil {
			return nil, err
		}

		h := new(horizon.Horizon)
		h.Init(*endpoint, config.ConnectionDetails["username"].(string), config.ConnectionDetails["password"].(string), "", "")
		acc, err := h.Local.GetAccount(username)
		if err != nil {
			return nil, err
		}

		err = h.Local.Delete(acc)
		if err != nil {
			return nil, err
		}

		var resp *logical.Response

		return resp, nil
	}
}
