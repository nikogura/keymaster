/*
	Describes the config file expected by secrets-backend

	Each config file is an org, and is expected to be stored in
*/
package secrets_backend

import (
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

const ERR_ORG_DATA_LOAD = "failed to load data in supplied config"
const ERR_NAMELESS_ORG = "nameless orgs are not supported"
const ERR_NAMELESS_ROLE = "nameless roles are not supported"
const ERR_NAMELESS_SECRET = "nameless secrets are not supported"
const ERR_MISSING_SECRET = "missing secret in role"
const ERR_MISSING_GENERATOR = "missing generator in secret"
const ERR_BAD_GENERATOR = "unable to create generator"

// Org An organization such as 'core-infra', 'core-platform', or 'core-services'.
type Org struct {
	Name       string   `yaml:"name"`
	Roles      []Role   `yaml:"roles"`
	Secrets    []Secret `yaml:"secrets"`
	SecretsMap map[string]Secret
	RolesMap   map[string]Role
}

// Role A named set of secrets a Principal is given access to.
type Role struct {
	Name       string   `yaml:"name"`
	Secrets    []Secret `yaml:"secrets"`
	SecretsMap map[string]Secret
}

type GeneratorData map[string]interface{}

// Secret a set of information describing a string value in Vault that is protected from unauthorized access, and varies by business environment.
type Secret struct {
	Name          string        `yaml:"name"`
	Org           string        `yaml:"org"`
	GeneratorData GeneratorData `yaml:"generator"`
	Generator     Generator     `yaml:"-"`

	DevValue   string `yaml:"dev_value"`
	StageValue string `yaml:"-"`
	ProdValue  string `yaml:"-"`
}

// LoadOrgData Created an Org interface from
func LoadOrgData(data []byte) (org Org, err error) {
	err = yaml.Unmarshal(data, &org)
	if err != nil {
		err = errors.Wrap(err, ERR_ORG_DATA_LOAD)
		return org, err
	}

	// Error out if there's a missing org tag
	if org.Name == "" {
		err = errors.New(ERR_NAMELESS_ORG)
		return org, err
	}

	// Generate maps for O(1) lookups
	org.SecretsMap = make(map[string]Secret)
	org.RolesMap = make(map[string]Role)

	// If there's no org listed for the secret, it belongs to the org of the file from which it's loaded.
	for _, secret := range org.Secrets {
		if secret.Org == "" {
			secret.Org = org.Name
		}

		if len(secret.GeneratorData) == 0 {
			err = errors.New(ERR_MISSING_GENERATOR)
			return org, err
		}

		if secret.Name == "" {
			err = errors.New(ERR_NAMELESS_SECRET)
			return org, err
		}

		generator, err := NewGenerator(secret.GeneratorData)
		if err != nil {
			err = errors.Wrap(err, ERR_BAD_GENERATOR)
			return org, err
		}
		//
		secret.Generator = generator

		org.SecretsMap[secret.Name] = secret
	}

	// Error out if we're passed a role without a name
	for _, role := range org.Roles {
		if role.Name == "" {
			err = errors.New(ERR_NAMELESS_ROLE)
			return org, err
		}

		for _, secret := range role.Secrets {
			if secret.Org == "" {
				secret.Org = org.Name
			}

			if secret.Org == org.Name {
				_, ok := org.SecretsMap[secret.Name]

				if !ok {
					err = errors.New(fmt.Sprintf(ERR_MISSING_SECRET))
					return org, err
				}
			}
		}

		org.RolesMap[role.Name] = role
	}

	return org, err
}
