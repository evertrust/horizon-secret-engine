package horizonsecretsengine

import (
	"context"

	"github.com/hashicorp/vault/helper/random"
	"github.com/mitchellh/mapstructure"
)

// passwordGenerator generates password credentials.
// A zero value passwordGenerator is usable.
type passwordGenerator struct {
	// PasswordPolicy is the named password policy used to generate passwords.
	// If empty (default), a random string of 20 characters will be generated.
	PasswordPolicy string `mapstructure:"password_policy,omitempty"`
}

// newPasswordGenerator returns a new passwordGenerator using the given config.
// Default values will be set on the returned passwordGenerator if not provided
// in the config.
func newPasswordGenerator(config map[string]interface{}) (passwordGenerator, error) {
	var pg passwordGenerator
	if err := mapstructure.WeakDecode(config, &pg); err != nil {
		return pg, err
	}

	return pg, nil
}

// Generate generates a password credential using the configured password policy.
// Returns the generated password or an error.
func (pg passwordGenerator) generate(ctx context.Context, b *horizonBackend) (string, error) {
	if pg.PasswordPolicy == "" {
		return random.DefaultStringGenerator.Generate(ctx, b.GetRandomReader())
	}
	return b.System().GeneratePasswordFromPolicy(ctx, pg.PasswordPolicy)
}

// configMap returns the configuration of the passwordGenerator
// as a map from string to string.
func (pg passwordGenerator) configMap() (map[string]interface{}, error) {
	config := make(map[string]interface{})
	if err := mapstructure.WeakDecode(pg, &config); err != nil {
		return nil, err
	}
	return config, nil
}

type usernameGenerator struct {
	UsernamePolicy string `mapstructure:"username_policy,omitempty"`
}

func newUsernameGenerator(config map[string]interface{}) (usernameGenerator, error) {
	var ug usernameGenerator
	if err := mapstructure.WeakDecode(config, &ug); err != nil {
		return ug, err
	}

	return ug, nil
}

func (ug usernameGenerator) generate(ctx context.Context, b *horizonBackend) (string, error) {
	if ug.UsernamePolicy == "" {
		return random.DefaultStringGenerator.Generate(ctx, b.GetRandomReader())
	}
	return b.System().GeneratePasswordFromPolicy(ctx, ug.UsernamePolicy)
}

func (ug usernameGenerator) configMap() (map[string]interface{}, error) {
	config := make(map[string]interface{})
	if err := mapstructure.WeakDecode(ug, &config); err != nil {
		return nil, err
	}
	return config, nil
}
