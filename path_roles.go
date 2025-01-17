package horizonsecretsengine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type horizonRoleEntry struct {
	Instance         string                 `json:"instance"`
	Roles            []string               `json:"roles"`
	Contact          string                 `json:"contact"`
	TTL              time.Duration          `json:"ttl"`
	MaxTTL           time.Duration          `json:"max_ttl"`
	CredentialConfig map[string]interface{} `json:"credential_config"`
}

func pathListRoles(b *horizonBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/?$",

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},

			HelpSynopsis:    pathRoleHelpSyn,
			HelpDescription: pathRoleHelpDesc,
		},
	}
}

func pathRoles(b *horizonBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern:        "roles/" + framework.GenericNameRegex("name"),
			Fields:         fieldsForType(horizonRolePath),
			ExistenceCheck: b.pathRoleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathRoleRead,
				logical.CreateOperation: b.pathRoleWrite,
				logical.UpdateOperation: b.pathRoleWrite,
				logical.DeleteOperation: b.pathRoleDelete,
			},

			HelpSynopsis:    pathRoleHelpSyn,
			HelpDescription: pathRoleHelpDesc,
		},
	}
}

func fieldsForType(roleType string) map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "Name of the role.",
		},
		"instance": {
			Type:        framework.TypeString,
			Description: "Horizon instance",
		},
		"roles": {
			Type:        framework.TypeStringSlice,
			Description: "List of all the roles you want to assign to the new account.",
		},
		"contact": {
			Type:        framework.TypeString,
			Description: "Contact needed for the role assignement",
		},
		"credential_config": {
			Type:        framework.TypeMap,
			Description: "Password and Username policies",
		},
	}

	for k, v := range dynamicFields() {
		fields[k] = v
	}

	return fields
}

func dynamicFields() map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{
		"ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "Default ttl for role.",
		},
		"max_ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "Maximum time a credential is valid for",
		},
	}
	return fields
}

func (b *horizonBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.Role(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *horizonBackend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, horizonRolePath+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting horizon role: %w", err)
	}

	return nil, nil
}

func (b *horizonBackend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role, err := b.Role(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, errors.New("no role")
	}

	data := map[string]interface{}{
		"instance":    role.Instance,
		"default_ttl": role.TTL.Seconds(),
		"max_ttl":     role.MaxTTL.Seconds(),
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *horizonBackend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	path := horizonRolePath
	entries, err := req.Storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathRolesWrite makes a request to Vault storage to update a role based on the attributes passed to the role configuration
func (b *horizonBackend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &horizonRoleEntry{}
	}

	createOperation := (req.Operation == logical.CreateOperation)

	var credentialConfig map[string]interface{}
	if raw, ok := d.GetOk("credential_config"); ok {
		credentialConfig = raw.(map[string]interface{})
	} else if req.Operation == logical.CreateOperation {
		credentialConfig = d.Get("credential_config").(map[string]interface{})
	}
	if err := roleEntry.setCredentialConfig(credentialConfig); err != nil {
		return logical.ErrorResponse("credential_config validation failed: %s", err), nil
	}

	if instance, ok := d.GetOk("instance"); ok {
		roleEntry.Instance = instance.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing instance in role")
	}

	// Faire un check sur les roles existants
	if rolesRaw, ok := d.GetOk("roles"); ok {
		roles := rolesRaw.([]string)
		roleEntry.Roles = roles
	}

	if contactRaw, ok := d.GetOk("contact"); ok {
		roleEntry.Contact = contactRaw.(string)
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// setRole adds the role to the Vault storage API
func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *horizonRoleEntry) error {
	entry, err := logical.StorageEntryJSON(horizonRolePath+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// getRole gets the role from the Vault storage API
func (b *horizonBackend) getRole(ctx context.Context, s logical.Storage, name string) (*horizonRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role horizonRoleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// setCredentialConfig validates and sets the credential configuration
// for the role using the role's credential type. It will also populate
// all default values. Returns an error if the configuration is invalid.
func (r *horizonRoleEntry) setCredentialConfig(config map[string]interface{}) error {
	c := make(map[string]interface{})
	for k, v := range config {
		c[k] = v
	}

	pwGenerator, err := newPasswordGenerator(c)
	if err != nil {
		return err
	}
	cm1, err := pwGenerator.configMap()
	if err != nil {
		return err
	}
	if len(cm1) > 0 {
		r.CredentialConfig = cm1
	}

	nameGenerator, err := newUsernameGenerator(c)
	if err != nil {
		return err
	}
	cm2, err := nameGenerator.configMap()
	if err != nil {
		return err
	}
	if len(cm2) > 0 {
		r.CredentialConfig = cm2
	}

	return nil
}

const pathRoleHelpSyn = `
Manage the roles that can be created with this backend.
`
const pathRoleHelpDesc = `
This path lets you manage the roles that can be created with this backend.

The "instance" parameter references the backend to use with the role. 

The "roles" parameter should be the roles that are already defined in horizon, and those you want 
to assign the accounts you will create.

For more details, take a look on the documentation.
`
