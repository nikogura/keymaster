package keymaster

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"regexp"
)

const ERR_NS_DATA_LOAD = "failed to load data in supplied config"
const ERR_NAMELESS_NS = "nameless namespaces are not supported"
const ERR_NAMELESS_ROLE = "nameless roles are not supported"
const ERR_NAMELESS_SECRET = "nameless secrets are not supported"
const ERR_MISSING_SECRET = "missing secret in role"
const ERR_MISSING_GENERATOR = "missing generator in secret"
const ERR_BAD_GENERATOR = "unable to create generator"
const ERR_REALMLESS_ROLE = "realmless roles are not supported"
const ERR_SLASH_IN_NAMESPACE = "namespaces cannot contain slashes"
const ERR_SLASH_IN_ROLE_NAME = "role names cannot contain slashes"

// Environment Scribd's deployment environments.   One of "Prod", "Stage", "Dev"
type Environment int

const (
	Prod Environment = iota + 1
	Stage
	Dev
)

const PROD_NAME = "prod"
const STAGE_NAME = "stage"
const DEV_NAME = "dev"

var Envs = []Environment{
	Prod,
	Stage,
	Dev,
}

// KeyMaster The KeyMaster Interface
type KeyMaster struct {
	VaultClient *api.Client
}

// NewKeyMaster Creates a new KeyMaster with the vault client supplied.
func NewKeyMaster(client *api.Client) (km *KeyMaster) {
	km = &KeyMaster{
		VaultClient: client,
	}
	return km
}

// Namespace Namespace for secrets.  Might map to a namespace such as 'core-infra', 'core-platform', or 'core-services', but also may not.  Maps directly to a Namespace in K8s.
type Namespace struct {
	Name       string    `yaml:"name"`
	Roles      []Role    `yaml:"roles"`
	Secrets    []*Secret `yaml:"secrets"`
	SecretsMap map[string]*Secret
	RolesMap   map[string]Role
}

// Role A named set of Secrets that is instantiated as an Auth endpoint in Vault for each computing realm.
type Role struct {
	Name       string   `yaml:"name"`
	Secrets    []Secret `yaml:"secrets"`
	SecretsMap map[string]Secret
	Realms     []string `yaml:"realms"`
	Namespace  string   `yaml:"namespace"`
}

// VaultPolicy Vault Policy that allows a Role access to a Secret
type VaultPolicy struct {
	Name    string
	Path    string
	Payload map[string]interface{}
}

// GeneratorData  Generic data map for configuring a Generator
type GeneratorData map[string]interface{}

// Secret a set of information describing a string value in Vault that is protected from unauthorized access, and varies by business environment.
type Secret struct {
	Name          string        `yaml:"name"`
	Namespace     string        `yaml:"namespace"`
	GeneratorData GeneratorData `yaml:"generator"`
	Generator     Generator     `yaml:"-"`

	DevValue   string `yaml:"dev_value"`
	StageValue string `yaml:"-"`
	ProdValue  string `yaml:"-"`
}

// SetGenerator What else?  Set's the generator on the Secret.
func (s *Secret) SetGenerator(generator Generator) {
	s.Generator = generator
}

// NewNamespace Create a new Namespace from the data provided.
func (km *KeyMaster) NewNamespace(data []byte) (ns Namespace, err error) {
	err = yaml.Unmarshal(data, &ns)
	if err != nil {
		err = errors.Wrap(err, ERR_NS_DATA_LOAD)
		return ns, err
	}

	// Error out if there's a missing namespace tag
	if ns.Name == "" {
		err = errors.New(ERR_NAMELESS_NS)
		return ns, err
	}

	if regexp.MustCompile(`/`).MatchString(ns.Name) {
		err = errors.New(ERR_SLASH_IN_NAMESPACE)
		return ns, err
	}

	// Generate maps for O(1) lookups
	ns.SecretsMap = make(map[string]*Secret)
	ns.RolesMap = make(map[string]Role)

	// If there's no namespace listed for the secret, it belongs to the namespace of the file from which it's loaded.
	for _, secret := range ns.Secrets {
		if secret.Namespace == "" {
			secret.Namespace = ns.Name
		}

		if len(secret.GeneratorData) == 0 {
			err = errors.New(ERR_MISSING_GENERATOR)
			return ns, err
		}

		if secret.Name == "" {
			err = errors.New(ERR_NAMELESS_SECRET)
			return ns, err
		}

		generator, err := km.NewGenerator(secret.GeneratorData)
		if err != nil {
			err = errors.Wrap(err, ERR_BAD_GENERATOR)
			return ns, err
		}

		secret.SetGenerator(generator)

		ns.SecretsMap[secret.Name] = secret
	}

	// Error out if we're passed a role without a name
	for _, role := range ns.Roles {
		if role.Name == "" {
			err = errors.New(ERR_NAMELESS_ROLE)
			return ns, err
		}

		if regexp.MustCompile(`/`).MatchString(role.Name) {
			err = errors.New(ERR_SLASH_IN_ROLE_NAME)
			return ns, err
		}

		if len(role.Realms) == 0 {
			err = errors.New(ERR_REALMLESS_ROLE)
			return ns, err
		}

		role.Namespace = ns.Name

		for _, secret := range role.Secrets {
			if secret.Namespace == "" {
				secret.Namespace = ns.Name
			}

			if secret.Namespace == ns.Name {
				_, ok := ns.SecretsMap[secret.Name]

				if !ok {
					err = errors.New(fmt.Sprintf(ERR_MISSING_SECRET))
					return ns, err
				}
			}
		}

		ns.RolesMap[role.Name] = role
	}

	return ns, err
}

// NameToEnvironment Maps an Environment name to the actual Environment type interface.
func NameToEnvironment(name string) (env Environment, err error) {
	switch name {
	case PROD_NAME:
		env = Prod
	case STAGE_NAME:
		env = Stage
	case DEV_NAME:
		env = Dev
	default:
		err = errors.New(fmt.Sprintf("Unable to relate %s to any known environment", name))
	}

	return env, err
}
