package keymaster

import (
	"fmt"
	"git.lo/ops/scrutil/pkg/scrutil"
	"github.com/hashicorp/vault/api"
	"github.com/nikogura/dbt/pkg/dbt"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
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
const ERR_UNSUPPORTED_REALM = "unsupported realm"

// Environment Scribd's deployment environments.   One of "Prod", "Stage", "Dev"
type Environment int

const (
	Prod Environment = iota + 1
	Stage
	Dev
)

type Realm int

const (
	K8S = iota + 1
	AWS
	SL
)

const PROD_NAME = "prod"
const STAGE_NAME = "stage"
const DEV_NAME = "dev"
const K8S_NAME = "k8s"
const AWS_NAME = "aws"
const SL_NAME = "sl"

var Realms = []Realm{
	K8S,
	AWS,
	SL,
}

var Envs = []Environment{
	Prod,
	Stage,
	Dev,
}

var EnvToName = map[Environment]string{
	Prod:  PROD_NAME,
	Stage: STAGE_NAME,
	Dev:   DEV_NAME,
}

var RealmToName = map[Realm]string{
	K8S: K8S_NAME,
	AWS: AWS_NAME,
	SL:  SL_NAME,
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
	Roles      []*Role   `yaml:"roles"`
	Secrets    []*Secret `yaml:"secrets"`
	SecretsMap map[string]*Secret
	RolesMap   map[string]*Role
}

// Role A named set of Secrets that is instantiated as an Auth endpoint in Vault for each computing realm.
type Role struct {
	Name       string    `yaml:"name"`
	Secrets    []*Secret `yaml:"secrets"`
	SecretsMap map[string]*Secret
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

func (s *Secret) SetNamespace(namespace string) {
	s.Namespace = namespace
}

func (r *Role) SetNamespace(namespace string) {
	r.Namespace = namespace
}

// NewNamespace Create a new Namespace from the data provided.
func (km *KeyMaster) NewNamespace(data []byte, verbose bool) (ns Namespace, err error) {
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

	scrutil.VerboseOutput(verbose, "parsing namespace %s", ns.Name)

	// Generate maps for O(1) lookups
	ns.SecretsMap = make(map[string]*Secret)
	ns.RolesMap = make(map[string]*Role)

	// If there's no namespace listed for the secret, it belongs to the namespace of the file from which it's loaded.
	for _, secret := range ns.Secrets {
		scrutil.VerboseOutput(verbose, "  parsing secret %s", secret.Name)
		if secret.Namespace == "" {
			secret.SetNamespace(ns.Name)
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

		scrutil.VerboseOutput(verbose, "  ... success!")
		ns.SecretsMap[secret.Name] = secret
	}

	for _, role := range ns.Roles {
		scrutil.VerboseOutput(verbose, "  parsing role %s", role.Name)
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

		for _, realm := range role.Realms {
			if !dbt.StringInSlice(realm, []string{K8S_NAME, AWS_NAME, SL_NAME}) {
				err = errors.New(ERR_UNSUPPORTED_REALM)
				return ns, err
			}
		}

		if role.Namespace == "" {
			role.SetNamespace(ns.Name)
		}

		for _, secret := range role.Secrets {
			scrutil.VerboseOutput(verbose, "  parsing role secrets %s", secret.Name)
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
			scrutil.VerboseOutput(verbose, "  ... done")
		}

		scrutil.VerboseOutput(verbose, "  ... role successfully loaded")
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

// ConfigureNamespace  The grand unified config loader that, after the yaml file is read into memory, applies it to Vault.
func (km *KeyMaster) ConfigureNamespace(namespace Namespace, verbose bool) (err error) {
	scrutil.VerboseOutput(verbose, "--- Configuring namespace %s ---", namespace.Name)
	// populate secrets
	scrutil.VerboseOutput(verbose, "--- Populating Secrets ---")
	for _, secret := range namespace.Secrets {
		scrutil.VerboseOutput(verbose, "    configuring secret %s", secret.Name)
		err = km.WriteSecretIfBlank(secret, verbose)
		if err != nil {
			err = errors.Wrapf(err, "failed writing secret %s in namespace %s", secret.Name, secret.Namespace)
			return err
		}
	}
	scrutil.VerboseOutput(verbose, "done")

	scrutil.VerboseOutput(verbose, "--- Configuring Roles ---")
	for _, role := range namespace.Roles {
		scrutil.VerboseOutput(verbose, "  configuring role %s", role.Name)
		if role.Namespace == "" {
			err = errors.New("Unnamespaced Role!")
			return err
		}

		scrutil.VerboseOutput(verbose, "  walking environments...")
		for _, env := range Envs {
			scrutil.VerboseOutput(verbose, "    handling %s...", EnvToName[env])
			// write policies
			scrutil.VerboseOutput(verbose, "      new policy for role %s in env %s...", role.Name, EnvToName[env])
			policy, err := km.NewPolicy(role, env)
			if err != nil {
				err = errors.Wrapf(err, "failed to create policy")
				return err
			}

			scrutil.VerboseOutput(verbose, "      writing policy to %s ...", policy.Path)
			err = km.WritePolicyToVault(policy, verbose)
			if err != nil {
				err = errors.Wrapf(err, "failed writing policy %q for role %q in env %q", policy.Name, role.Name, EnvToName[env])
				return err
			}
			scrutil.VerboseOutput(verbose, "      written")

			scrutil.VerboseOutput(verbose, "      creating auth configs...")
			// create auth configs
			for _, realm := range role.Realms {
				scrutil.VerboseOutput(verbose, "        config for realm %s...", realm)
				switch realm {
				case K8S_NAME:
					scrutil.VerboseOutput(verbose, "          k8s")
					for _, cluster := range ClustersByEnvironment[env] {
						err = km.AddPolicyToK8sRole(cluster, role, policy)
						if err != nil {
							err = errors.Wrapf(err, "failed to add K8S Auth for role:%q policy:%q cluster:%q env:%q", role.Name, policy.Name, cluster.Name, EnvToName[env])
							return err
						}
					}

				case SL_NAME:
					scrutil.VerboseOutput(verbose, "          sl")
					err = km.AddPolicyToTlsRole(role, env, policy)
					if err != nil {
						err = errors.Wrapf(err, "failed to add TLS auth for role: %q policy: %q env: %q", role.Name, policy.Name, EnvToName[env])
						return err
					}
				case AWS_NAME:
					scrutil.VerboseOutput(verbose, "          aws")
					err = errors.New("AWS Realm not yet implemented")
					return err

				default:
					err = errors.New(fmt.Sprintf("unsupported realm %q", realm))
					return err
				}
			}
			scrutil.VerboseOutput(verbose, "      done")
		}
		scrutil.VerboseOutput(verbose, "  done")
	}

	scrutil.VerboseOutput(verbose, "done")

	return err
}

func LoadSecretYamls(files []string, verbose bool) (data [][]byte, err error) {
	data = make([][]byte, 0)
	scrutil.VerboseOutput(verbose, "Loading Secret Yamls")

	for _, fileName := range files {
		scrutil.VerboseOutput(verbose, "  examining %s", fileName)
		fi, err := os.Stat(fileName)
		if err != nil {
			err = errors.Wrap(err, fmt.Sprintf("failed to read yaml %s", fileName))
			return data, err
		}

		switch mode := fi.Mode(); {
		case mode.IsRegular():
			scrutil.VerboseOutput(verbose, "    regular file")
			configBytes, err := ioutil.ReadFile(fileName)
			if err != nil {
				err = errors.Wrapf(err, "Error reading yaml %s", fileName)
				return data, err
			}

			scrutil.VerboseOutput(verbose, "    ... loaded")
			data = append(data, configBytes)

		case mode.IsDir():
			scrutil.VerboseOutput(verbose, "    directory")
			// start off true, set false on any failure
			err := filepath.Walk(fileName, func(path string, info os.FileInfo, err error) error {
				scrutil.VerboseOutput(verbose, "  examining file")
				if err != nil {
					return err
				}
				if !info.IsDir() { // we only care about files
					scrutil.VerboseOutput(verbose, "    regular file")
					// and we only care about yaml files
					fileName := filepath.Base(path)
					pat := regexp.MustCompile(`.+\.ya?ml`)
					if !pat.MatchString(fileName) {
						return nil
					}

					configBytes, err := ioutil.ReadFile(path)
					if err != nil {
						err = errors.Wrapf(err, "error reading yaml %s", fileName)
						return err
					}

					scrutil.VerboseOutput(verbose, "    ... loaded")
					data = append(data, configBytes)

					return nil
				}

				return nil
			})

			if err != nil {
				err = errors.Wrapf(err, "error walking directory %s", fileName)
				return data, err
			}
		}
	}

	return data, err
}
