package keymaster

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
)

const VERSION = "0.3.0"
const ERR_TEAM_DATA_LOAD = "failed to load team data in supplied config"
const ERR_NAMELESS_TEAM = "nameless teams are not supported"
const ERR_NAMELESS_ROLE = "nameless roles are not supported"
const ERR_NAMELESS_SECRET = "nameless secrets are not supported"
const ERR_MISSING_SECRET = "missing secret in role"
const ERR_MISSING_GENERATOR = "missing generator in secret"
const ERR_BAD_GENERATOR = "unable to create generator"
const ERR_REALMLESS_ROLE = "realmless roles are not supported"
const ERR_SLASH_IN_TEAM_NAME = "team names cannot contain slashes"
const ERR_SLASH_IN_ROLE_NAME = "role names cannot contain slashes"
const ERR_UNSUPPORTED_REALM = "unsupported realm"
const ERR_MISSING_ENVIRONMENTS = "no environments list found in config"

type Realm struct {
	Type        string   `yaml:"type"`        // k8s iam sl
	Identifiers []string `yaml:"identifiers"` // cluster names for k8s, hostnames for TLS, meaningless for IAM unless account number?
	Principals  []string `yaml:"principals"`  // namespaces for k8s, ARN's for IAM
	Environment string   `yaml:"environment"` // Environment the realm occupies
}

const K8S = "k8s"
const IAM = "iam"
const TLS = "tls"

var RealmTypes = []string{
	IAM,
	K8S,
	TLS,
}

// KeyMaster The KeyMaster Interface
type KeyMaster struct {
	VaultClient       *api.Client
	IpRestrictTlsAuth bool
	IpRestrictK8sAuth bool
	TlsAuthCaCert     string
	K8sClusters       []*Cluster
	K8sClustersByName map[string]*Cluster
}

// NewKeyMaster Creates a new KeyMaster with the vault client supplied.
func NewKeyMaster(vaultClient *api.Client) (km *KeyMaster) {
	km = &KeyMaster{
		VaultClient: vaultClient,
	}

	return km
}

func (km *KeyMaster) SetTlsAuthCaCert(certificate string) {
	km.TlsAuthCaCert = certificate
}

func (km *KeyMaster) SetIpRestrictTlsAuth(enabled bool) {
	km.IpRestrictTlsAuth = enabled
}

func (km *KeyMaster) SetIpRestrictK8sAuth(enabled bool) {
	km.IpRestrictK8sAuth = enabled
}

func (km *KeyMaster) SetK8sClusters(clusters []*Cluster) {
	km.K8sClusters = clusters

	km.K8sClustersByName = make(map[string]*Cluster)
	for _, c := range clusters {
		km.K8sClustersByName[c.Name] = c
	}
}

// Team  Group of humans who control their own destiny in regard to secrets
type Team struct {
	Name         string    `yaml:"name"`
	Roles        []*Role   `yaml:"roles"`
	Secrets      []*Secret `yaml:"secrets"`
	Environments []string  `yaml:"environments"`
	SecretsMap   map[string]*Secret
	RolesMap     map[string]*Role
}

// Role A named set of Secrets that is instantiated as an Auth endpoint in Vault for each computing realm.
type Role struct {
	Name       string    `yaml:"name"`
	Secrets    []*Secret `yaml:"secrets"`
	SecretsMap map[string]*Secret
	Realms     []*Realm `yaml:"realms"`
	Team       string   `yaml:"team"`
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
	Team          string        `yaml:"team"`
	GeneratorData GeneratorData `yaml:"generator"`
	Generator     Generator     `yaml:"-"`
	Environments  []string      `yaml:"-"`
}

// SetGenerator What else?  Set's the generator on the Secret.
func (s *Secret) SetGenerator(generator Generator) {
	s.Generator = generator
}

func (s *Secret) SetTeam(team string) {
	s.Team = team
}

func (s *Secret) SetEnvironments(environments []string) {
	s.Environments = environments
}

func (r *Role) SetTeam(team string) {
	r.Team = team
}

// NewTeam Create a new Team from the data provided.
func (km *KeyMaster) NewTeam(data []byte, verbose bool) (team *Team, err error) {
	err = yaml.Unmarshal(data, &team)
	if err != nil {
		err = errors.Wrap(err, ERR_TEAM_DATA_LOAD)
		return team, err
	}

	// Error out if there's a missing team name
	if team.Name == "" {
		err = errors.New(ERR_NAMELESS_TEAM)
		return team, err
	}

	if regexp.MustCompile(`/`).MatchString(team.Name) {
		err = errors.New(ERR_SLASH_IN_TEAM_NAME)
		return team, err
	}

	if len(team.Environments) == 0 {
		err = errors.New(ERR_MISSING_ENVIRONMENTS)
		return team, err
	}

	verboseOutput(verbose, "parsing team %s", team.Name)

	// Generate maps for O(1) lookups
	team.SecretsMap = make(map[string]*Secret)
	team.RolesMap = make(map[string]*Role)

	// If there's no team listed for the secret, it belongs to the team of the file from which it's loaded.
	for _, secret := range team.Secrets {
		verboseOutput(verbose, "  parsing secret %s", secret.Name)
		if secret.Team == "" {
			secret.SetTeam(team.Name)
		}

		if len(secret.GeneratorData) == 0 {
			err = errors.New(ERR_MISSING_GENERATOR)
			return team, err
		}

		if secret.Name == "" {
			err = errors.New(ERR_NAMELESS_SECRET)
			return team, err
		}

		generator, err := km.NewGenerator(secret.GeneratorData)
		if err != nil {
			err = errors.Wrap(err, ERR_BAD_GENERATOR)
			return team, err
		}

		secret.SetGenerator(generator)
		secret.SetEnvironments(team.Environments)

		verboseOutput(verbose, "  ... success!")
		team.SecretsMap[secret.Name] = secret
	}

	for _, role := range team.Roles {
		verboseOutput(verbose, "  parsing role %s", role.Name)
		if role.Name == "" {
			err = errors.New(ERR_NAMELESS_ROLE)
			return team, err
		}

		if regexp.MustCompile(`/`).MatchString(role.Name) {
			err = errors.New(ERR_SLASH_IN_ROLE_NAME)
			return team, err
		}

		if len(role.Realms) == 0 {
			err = errors.New(ERR_REALMLESS_ROLE)
			return team, err
		}

		for _, realm := range role.Realms {
			if !stringInSlice(realm.Type, RealmTypes) {
				err = errors.New(ERR_UNSUPPORTED_REALM)
				return team, err
			}
		}

		if role.Team == "" {
			role.SetTeam(team.Name)
		}

		for _, secret := range role.Secrets {
			verboseOutput(verbose, "  parsing role secrets %s", secret.Name)
			if secret.Team == "" {
				secret.Team = team.Name
			}

			if secret.Team == team.Name {
				_, ok := team.SecretsMap[secret.Name]

				if !ok {
					err = errors.New(fmt.Sprintf(ERR_MISSING_SECRET))
					return team, err
				}
			}
			verboseOutput(verbose, "  ... done")
		}

		verboseOutput(verbose, "  ... role successfully loaded")
		team.RolesMap[role.Name] = role
	}

	return team, err
}

// ConfigureTeam  The grand unified config loader that, after the yaml file is read into memory, applies it to Vault.
func (km *KeyMaster) ConfigureTeam(team *Team, verbose bool) (err error) {
	verboseOutput(verbose, "--- Configuring team %s ---", team.Name)
	// populate secrets
	verboseOutput(verbose, "--- Populating Secrets ---")
	for _, secret := range team.Secrets {
		verboseOutput(verbose, "    configuring secret %s", secret.Name)
		err = km.WriteSecretIfBlank(secret, verbose)
		if err != nil {
			err = errors.Wrapf(err, "failed writing secret %s for team %s", secret.Name, secret.Team)
			return err
		}
	}
	verboseOutput(verbose, "done")

	verboseOutput(verbose, "--- Configuring Roles ---")
	for _, role := range team.Roles {
		verboseOutput(verbose, "  configuring role %s", role.Name)
		if role.Team == "" {
			err = errors.New("Role without a Team!")
			return err
		}

		verboseOutput(verbose, "  defining realms...")
		// create auth configs
		for _, realm := range role.Realms {
			env := realm.Environment
			verboseOutput(verbose, "    handling %s env %s...", realm.Type, env)

			// write policies
			verboseOutput(verbose, "      new policy for role %s realm %s in env %s...", role.Name, realm.Type, env)
			policy, err := km.NewPolicy(role, env)
			if err != nil {
				err = errors.Wrapf(err, "failed to create policy")
				return err
			}

			verboseOutput(verbose, "      writing policy to %s ...", policy.Path)
			err = km.WritePolicyToVault(policy, verbose)
			if err != nil {
				err = errors.Wrapf(err, "failed writing policy %q for role %q in env %q", policy.Name, role.Name, env)
				return err
			}
			verboseOutput(verbose, "      written")

			verboseOutput(verbose, "      creating auth configs...")
			switch realm.Type {
			case K8S:
				verboseOutput(verbose, "          k8s")
				// TODO AddPolicyToK8sRole doesn't overwrite.  If you change the policy the old policy needs deleting.  Should probably fix this.
				for _, cluster := range realm.Identifiers {
					verboseOutput(verbose, "            %s", cluster)
					err = km.AddPolicyToK8sRole(km.K8sClustersByName[cluster], role, realm, policy)
					if err != nil {
						err = errors.Wrapf(err, "failed to add K8S Auth for role:%q policy:%q cluster:%q env:%q", role.Name, policy.Name, cluster, env)
						return err
					}
				}

			case TLS:
				verboseOutput(verbose, "          tls")
				// TODO AddPolicyToTlsRole doesn't overwrite.  If you add a new host to the policy, the old policy needs deleting.  Should probably fix this.
				err = km.AddPolicyToTlsRole(role, env, policy)
				if err != nil {
					err = errors.Wrapf(err, "failed to add TLS auth for role: %q policy: %q env: %q", role.Name, policy.Name, env)
					return err
				}
			case IAM:
				verboseOutput(verbose, "          aws")
				err = km.AddPolicyToIamRole(role, realm, policy)
				if err != nil {
					err = errors.Wrapf(err, "failed to add IAM auth for role: %q policy: %q env: %q", role.Name, policy.Name, env)
					return err
				}

			default:
				err = errors.New(fmt.Sprintf("unsupported realm %q", realm))
				return err
			}
		}
		verboseOutput(verbose, "      done")
		verboseOutput(verbose, "  done")
	}

	verboseOutput(verbose, "done")

	return err
}

func LoadSecretYamls(files []string, verbose bool) (data [][]byte, err error) {
	data = make([][]byte, 0)
	verboseOutput(verbose, "\nLoading Secret Yamls")

	for _, fileName := range files {
		verboseOutput(verbose, "  examining %q", fileName)
		fi, err := os.Stat(fileName)
		if err != nil {
			err = errors.Wrap(err, fmt.Sprintf("failed to read yaml %s", fileName))
			return data, err
		}

		switch mode := fi.Mode(); {
		case mode.IsRegular():
			verboseOutput(verbose, "      it's a regular file")
			configBytes, err := ioutil.ReadFile(fileName)
			if err != nil {
				err = errors.Wrapf(err, "Error reading yaml %s", fileName)
				return data, err
			}

			verboseOutput(verbose, "      ... loaded")
			data = append(data, configBytes)

		case mode.IsDir():
			verboseOutput(verbose, "      it's a directory")
			// start off true, set false on any failure
			err := filepath.Walk(fileName, func(path string, info os.FileInfo, err error) error {
				verboseOutput(verbose, "  examining %q", path)
				if err != nil {
					return err
				}
				if !info.IsDir() { // we only care about files
					verboseOutput(verbose, "        it's a regular file")
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

					verboseOutput(verbose, "          ... loaded")
					data = append(data, configBytes)

					return nil
				}
				verboseOutput(verbose, "        it's a directory")

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

func verboseOutput(verbose bool, message string, args ...interface{}) {
	if verbose {
		if len(args) == 0 {
			fmt.Printf("%s\n", message)
			return
		}

		msg := fmt.Sprintf(message, args...)
		fmt.Printf("%s\n", msg)
	}
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
