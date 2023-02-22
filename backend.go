package horizonsecretsengine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	horizon "github.com/evertrust/horizon-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	horizonConfigPath      = "config/"
	horizonRolePath        = "roles/"
	minRootCredRollbackAge = 1 * time.Minute
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	err := b.Setup(ctx, conf)
	if err != nil {
		return nil, err
	}
	return b, err
}

type horizonBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *horizon.Horizon
}

func backend() *horizonBackend {
	var b = horizonBackend{}
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},

		Paths: framework.PathAppend(
			pathListRoles(&b),
			pathRoles(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCredentials(&b),
			},
			pathRotateRootCredentials(&b),
		),
		Secrets: []*framework.Secret{
			secretCreds(&b),
		},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	return &b
}

func (b *horizonBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *horizonBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *horizonBackend) Role(ctx context.Context, s logical.Storage, roleName string) (*horizonRoleEntry, error) {
	return b.roleAtPath(ctx, s, roleName, horizonRolePath)
}

func (b *horizonBackend) roleAtPath(ctx context.Context, s logical.Storage, roleName string, pathPrefix string) (*horizonRoleEntry, error) {
	entry, err := s.Get(ctx, pathPrefix+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result horizonRoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *horizonBackend) getConfig(ctx context.Context, s logical.Storage, instance string) (*horizonConfig, error) {
	entry, err := s.Get(ctx, horizonConfigPath+instance)
	if err != nil {
		return nil, fmt.Errorf("failed to read horizon configuration: %w", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("nothing found at path: %s", horizonConfigPath+instance)
	}

	var config horizonConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

const backendHelp = `
The Horizon secrets backend dynamically generates credentials (username, password) for Horizon.
After mounting this backend, credentials must be configured with the "config/" path.
`
