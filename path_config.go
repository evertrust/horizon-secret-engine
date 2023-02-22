package horizonsecretsengine

import (
	"context"
	"fmt"

	"github.com/fatih/structs"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type horizonConfig struct {
	HorizonEndpoint string `json:"horizon_endpoint"`
	// ConnectionDetails stores the horizon specific connection settings.
	ConnectionDetails               map[string]interface{} `json:"connection_details" structs:"connection_details" mapstructure:"connection_details"`
	RootCredentialsRotateStatements []string               `json:"root_rotation_statements" structs:"root_rotation_statements" mapstructure:"root_rotation_statements"`
	PasswordPolicy                  string                 `json:"password_policy" structs:"password_policy" mapstructure:"password_policy"`
	UsernamePolicy                  string                 `json:"username_template" structs:"username_template" mapstructure:"username_template"`
}

var (
	respErrEmptyInstance = "Empty horizon instance."
	respErrEmptyName     = "empty name attribute given"
)

func pathConfig(b *horizonBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("config/%s", framework.GenericNameRegex("instance")),
		Fields: map[string]*framework.FieldSchema{
			"instance": {
				Type:        framework.TypeString,
				Description: "Instance of horizon.",
			},

			"horizon_endpoint": {
				Type:        framework.TypeString,
				Description: "The endpoint for the horizon instance.",
			},

			"password_policy": {
				Type:        framework.TypeString,
				Description: `Password policy to use when generating passwords.`,
			},

			"username_policy": {
				Type:        framework.TypeString,
				Description: `Username policy to use when generating usernames.`,
			},
		},
		ExistenceCheck: b.pathConfigExistenceCheck(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathConfigWrite(),
			logical.UpdateOperation: b.pathConfigWrite(),
			logical.ReadOperation:   b.pathConfigRead(),
			logical.DeleteOperation: b.pathConfigDelete(),
		},

		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

func (b *horizonBackend) pathConfigWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		instance := data.Get("instance").(string)
		if instance == "" {
			return logical.ErrorResponse(respErrEmptyInstance), nil
		}

		// Baseline
		config := &horizonConfig{}

		entry, err := req.Storage.Get(ctx, fmt.Sprintf("config/%s", instance))
		if err != nil {
			return nil, fmt.Errorf("failed to read connection configuration: %w", err)
		}
		if entry != nil {
			if err := entry.DecodeJSON(config); err != nil {
				return nil, err
			}
		}

		if horizonEndpoint, ok := data.GetOk("horizon_endpoint"); ok {
			config.HorizonEndpoint = horizonEndpoint.(string)
		} else if req.Operation == logical.CreateOperation {
			config.HorizonEndpoint = data.Get("horizon_endpoint").(string)
		}
		if config.HorizonEndpoint == "" {
			return logical.ErrorResponse("Empty horizon endpoint"), nil
		}

		if rootRotationStatementsRaw, ok := data.GetOk("root_rotation_statements"); ok {
			config.RootCredentialsRotateStatements = rootRotationStatementsRaw.([]string)
		} else if req.Operation == logical.CreateOperation {
			// config.RootCredentialsRotateStatements = data.Get("root_rotation_statements").([]string)
			config.RootCredentialsRotateStatements = nil
		}

		if passwordPolicyRaw, ok := data.GetOk("password_policy"); ok {
			config.PasswordPolicy = passwordPolicyRaw.(string)
		}

		if usernamePolicyRaw, ok := data.GetOk("username_policy"); ok {
			config.UsernamePolicy = usernamePolicyRaw.(string)
		}

		// Remove these entries from the data before we store it keyed under
		// ConnectionDetails.
		delete(data.Raw, "instance")
		delete(data.Raw, "horizon_endpoint")
		delete(data.Raw, "root_rotation_statements")
		delete(data.Raw, "password_policy")
		delete(data.Raw, "username_policy")

		// If this is an update, take any new values, overwrite what was there
		// before, and pass that in as the "new" set of values to the plugin,
		// then save what results
		if req.Operation == logical.CreateOperation {
			config.ConnectionDetails = data.Raw
		} else {
			if config.ConnectionDetails == nil {
				config.ConnectionDetails = make(map[string]interface{})
			}
			for k, v := range data.Raw {
				config.ConnectionDetails[k] = v
			}
		}

		err = storeConfig(ctx, req.Storage, instance, config)
		if err != nil {
			return nil, err
		}

		resp := &logical.Response{}

		if len(resp.Warnings) == 0 {
			return nil, nil
		}

		return resp, nil
	}
}

func (b *horizonBackend) pathConfigRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		instance := data.Get("instance").(string)
		if instance == "" {
			return logical.ErrorResponse(respErrEmptyInstance), nil
		}

		entry, err := req.Storage.Get(ctx, fmt.Sprintf("config/%s", instance))
		if err != nil {
			return nil, fmt.Errorf("failed to read connection configuration: %w", err)
		}
		if entry == nil {
			return nil, nil
		}

		var config horizonConfig
		if err := entry.DecodeJSON(&config); err != nil {
			return nil, err
		}

		delete(config.ConnectionDetails, "password")
		delete(config.ConnectionDetails, "private_key")

		return &logical.Response{
			Data: structs.New(config).Map(),
		}, nil
	}
}

func (b *horizonBackend) pathConfigDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		instance := data.Get("instance").(string)
		if instance == "" {
			return logical.ErrorResponse(respErrEmptyInstance), nil
		}

		err := req.Storage.Delete(ctx, fmt.Sprintf("config/%s", instance))
		if err != nil {
			return nil, fmt.Errorf("failed to delete connection configuration: %w", err)
		}

		return nil, nil
	}
}

func (b *horizonBackend) pathConfigExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		out, err := req.Storage.Get(ctx, req.Path)
		if err != nil {
			return false, fmt.Errorf("existence check failed: %w", err)
		}

		return out != nil, nil
	}
}

func storeConfig(ctx context.Context, storage logical.Storage, instance string, config *horizonConfig) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("config/%s", instance), config)
	if err != nil {
		return fmt.Errorf("unable to marshal object to JSON: %w", err)
	}

	err = storage.Put(ctx, entry)
	if err != nil {
		return fmt.Errorf("failed to save object: %w", err)
	}
	return nil
}

const pathConfigHelpSynopsis = `
Configure the Horizon Backend.
`

const pathConfigHelpDescription = `
This path configures the connection details used to connect to a particular horizon instance. 
See the documentation for the plugin specified for a full list of accepted connection details.
`
