package keymaster

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

const ERR_NS_DATA_LOAD = "failed to load data in supplied config"
const ERR_NAMELESS_NS = "nameless namespaces are not supported"
const ERR_NAMELESS_ROLE = "nameless roles are not supported"
const ERR_NAMELESS_SECRET = "nameless secrets are not supported"
const ERR_MISSING_SECRET = "missing secret in role"
const ERR_MISSING_GENERATOR = "missing generator in secret"
const ERR_BAD_GENERATOR = "unable to create generator"
const ERR_REALMLESS_ROLE = "realmless roles are not supported"

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

// Role A named set of secrets a Principal is given access to.
type Role struct {
	Name       string   `yaml:"name"`
	Secrets    []Secret `yaml:"secrets"`
	SecretsMap map[string]Secret
	Realms     []string `yaml:"realms"`
	Namespace  string   `yaml:"namespace"`
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

// SecretPath Given a Name, Namespace, and Environment, returns the proper path in Vault where that secret is stored.
func SecretPath(name string, namespace string, env Environment) (path string) {
	switch env {
	case Prod:
		path = fmt.Sprintf("%s/data/%s/%s", PROD_NAME, namespace, name)
	case Stage:
		path = fmt.Sprintf("%s/data/%s/%s", STAGE_NAME, namespace, name)
	default:
		path = fmt.Sprintf("%s/data/%s/%s", DEV_NAME, namespace, name)
	}

	return path
}

// CertPath Given a Name, Namespace, and Environment, returns the proper path in Vault where that secret is stored.
func CertPath(name string, namespace string, env Environment) (path string) {
	switch env {
	case Prod:
		path = fmt.Sprintf("%s/data/certs/%s/%s", PROD_NAME, namespace, name)
	case Stage:
		path = fmt.Sprintf("%s/data/certs/%s/%s", STAGE_NAME, namespace, name)
	default:
		path = fmt.Sprintf("%s/data/certs/%s/%s", DEV_NAME, namespace, name)
	}

	return path
}

// WriteSecretIfBlank writes a secret to each environment, but only if there's not already a value there.
func (km *KeyMaster) WriteSecretIfBlank(secret *Secret) (err error) {
	for _, env := range Envs {
		secretPath := SecretPath(secret.Name, secret.Namespace, env)

		// check to see if the secret does not exist
		s, err := km.VaultClient.Logical().Read(secretPath)
		if err != nil {
			err = errors.Wrapf(err, "failed to read secret at %s", secretPath)
			return err
		}

		// s will be nil if the secret does not exist
		// warning: s will not be nil if there's a warning returned by the read
		if s == nil {
			if secret.Generator == nil {
				err = errors.New(fmt.Sprintf("nil generators are not suppported.  secret: %q", secret.Name))
				return err
			}

			switch secret.GeneratorData["type"] {
			case "tls":
				value, err := secret.Generator.Generate()
				if err != nil {
					err = errors.Wrapf(err, "failed to generate value for %q", secret.Name)
					return err
				}

				data := make(map[string]interface{})
				sdata := make(map[string]interface{})

				data["data"] = sdata

				var vcert VaultCert
				certPath := CertPath(secret.Name, secret.Namespace, env)

				// value is a string, due to the signature on Generate(), but in this case it's parts that have to be unmarshalled and converted to interface types for writing.
				err = json.Unmarshal([]byte(value), &vcert)
				if err != nil {
					err = errors.Wrapf(err, "failed to unmarshal cert info returned from generator")
					return err
				}

				sdata["private_key"] = vcert.Key
				sdata["certificate"] = vcert.Cert
				sdata["issuing_ca"] = vcert.CA
				sdata["serial_number"] = vcert.Serial
				sdata["ca_chain"] = vcert.Chain
				sdata["private_kye_type"] = vcert.Type
				sdata["expiration"] = vcert.Expiration

				jsonBytes, err := json.Marshal(secret.GeneratorData)
				if err != nil {
					err = errors.Wrapf(err, "failed to marshal generator data for %q", secret.Name)
				}

				sdata["generator_data"] = base64.StdEncoding.EncodeToString(jsonBytes)

				_, err = km.VaultClient.Logical().Write(certPath, data)
				if err != nil {
					err = errors.Wrapf(err, "failed to write secret to %s", certPath)
				}

			case "rsa":
				// TODO Implement saving RSA Secrets
			default:
				value, err := secret.Generator.Generate()
				if err != nil {
					err = errors.Wrapf(err, "failed to generate value for %q", secret.Name)
					return err
				}

				data := make(map[string]interface{})
				sdata := make(map[string]interface{})

				data["data"] = sdata

				sdata["value"] = value

				jsonBytes, err := json.Marshal(secret.GeneratorData)
				if err != nil {
					err = errors.Wrapf(err, "failed to marshal generator data for %q", secret.Name)
				}

				sdata["generator_data"] = base64.StdEncoding.EncodeToString(jsonBytes)

				_, err = km.VaultClient.Logical().Write(secretPath, data)
				if err != nil {
					err = errors.Wrapf(err, "failed to write secret to %s", secretPath)
				}
			}
		}
	}

	return err
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

// NewGenerator creates a new generator from the options given
func (km *KeyMaster) NewGenerator(options GeneratorData) (generator Generator, err error) {
	if genType, ok := options["type"].(string); ok {
		switch genType {
		case "alpha":
			return NewAlphaGenerator(options)
		case "hex":
			return NewHexGenerator(options)
		case "uuid":
			return NewUUIDGenerator(options)
		case "chbs":
			return NewCHBSGenerator(options)
		case "rsa":
			return NewRSAGenerator(options)
		case "tls":
			return NewTlsGenerator(km.VaultClient, options)
		default:
			err = errors.New(fmt.Sprintf("%s: %s", ERR_UNKNOWN_GENERATOR, genType))
			return generator, err
		}
	}

	err = errors.New(ERR_BAD_GENERATOR)

	return generator, err
}
