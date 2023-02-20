package horizonsecretsengine

import (
	"context"
	"fmt"

	horizonrightssdk "github.com/AdrienDucourthial/horizon-rights-sdk"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotateRootCredentials(b *horizonBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "rotate-root/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of this database connection",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateRootCredentialsUpdate(),
					ForwardPerformanceSecondary: true,
					ForwardPerformanceStandby:   true,
				},
			},

			HelpSynopsis:    pathRotateCredentialsUpdateHelpSyn,
			HelpDescription: pathRotateCredentialsUpdateHelpDesc,
		},
	}
}

func (b *horizonBackend) pathRotateRootCredentialsUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		name := data.Get("name").(string)
		if name == "" {
			return logical.ErrorResponse(respErrEmptyName), nil
		}

		config, err := b.getConfig(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}

		rootUsername, ok := config.ConnectionDetails["username"].(string)
		if !ok || rootUsername == "" {
			return nil, fmt.Errorf("unable to rotate root credentials: no username in configuration")
		}

		generator := newPasswordGenerator("")
		if err != nil {
			return nil, fmt.Errorf("failed to construct credential generator: %s", err)
		}
		generator.PasswordPolicy = config.PasswordPolicy

		// Generate new credentials
		oldPassword := config.ConnectionDetails["password"].(string)
		newPassword, err := generator.generate(ctx, b)
		if err != nil {
			return nil, fmt.Errorf("failed to generate password: %s", err)
		}
		config.ConnectionDetails["password"] = newPassword

		h := new(horizonrightssdk.HorizonRights)
		h.Init(config.HorizonEndpoint, config.ConnectionDetails["username"].(string), oldPassword)
		root, err := h.Locals.GetAccount(rootUsername)
		if err != nil {
			return nil, err
		}
		h.Locals.SetPassword(root, newPassword)

		err = storeConfig(ctx, req.Storage, name, config)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}
}

const pathRotateCredentialsUpdateHelpSyn = `
Request to rotate the root credentials for a certain database connection.
`

const pathRotateCredentialsUpdateHelpDesc = `
This path attempts to rotate the root credentials for the given database. 
`
