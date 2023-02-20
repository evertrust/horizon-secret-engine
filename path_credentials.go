package horizonsecretsengine

import (
	"context"
	"fmt"

	horizonrightssdk "github.com/AdrienDucourthial/horizon-rights-sdk"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const SecretCredsType = "creds"

func pathCredentials(b *horizonBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredsCreateRead(),
		},

		HelpSynopsis:    pathCredsCreateReadHelpSyn,
		HelpDescription: pathCredsCreateReadHelpDesc,
	}
}

func (b *horizonBackend) pathCredsCreateRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := data.Get("name").(string)

		// Get the role
		role, err := b.Role(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", name)), nil
		}

		config, err := b.getConfig(ctx, req.Storage, role.Instance)
		if err != nil {
			return nil, err
		}

		respData := make(map[string]interface{})

		h := new(horizonrightssdk.HorizonRights)
		h.Init(config.HorizonEndpoint, config.ConnectionDetails["username"].(string), config.ConnectionDetails["password"].(string))

		ug := newUsernameGenerator(config.UsernamePolicy)
		username, err := ug.generate(ctx, b)
		if err != nil {
			return nil, err
		}

		acc, err := h.Locals.Create(username, role.Contact)
		if err != nil {
			return nil, err
		}

		pg := newPasswordGenerator(config.PasswordPolicy)
		pwd, err := pg.generate(ctx, b)
		if err != nil {
			return nil, err
		}
		_, err = h.Locals.SetPassword(acc, pwd)
		if err != nil {
			return nil, err
		}

		err = h.Locals.AssignRoles(acc, role.Contact, role.Roles)
		if err != nil {
			return nil, err
		}

		respData["username"] = acc.Identifier
		respData["password"] = pwd

		internal := map[string]interface{}{
			"username": acc.Identifier,
			"role":     name,
		}

		resp := b.Secret(SecretCredsType).Response(respData, internal)
		resp.Secret.TTL = role.TTL
		resp.Secret.MaxTTL = role.MaxTTL

		return resp, nil
	}
}

const pathCredsCreateReadHelpSyn = `
Request horizon credentials for a certain role.
`

const pathCredsCreateReadHelpDesc = `
This path reads horizon credentials for a certain role. The
horizon credentials will be generated on demand and will be automatically
revoked when the lease is up.
`
