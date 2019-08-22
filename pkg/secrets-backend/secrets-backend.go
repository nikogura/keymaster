package secrets_backend

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

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

// SecretPath Given a Name, Org, and Environment, returns the proper path in Vault where that secret is stored.
func SecretPath(name string, org string, env Environment) (path string) {
	switch env {
	case Prod:
		path = fmt.Sprintf("%s/data/%s/%s", PROD_NAME, org, name)
	case Stage:
		path = fmt.Sprintf("%s/data/%s/%s", STAGE_NAME, org, name)
	default:
		path = fmt.Sprintf("%s/data/%s/%s", DEV_NAME, org, name)
	}

	return path
}

// WriteSecretIfBlank writes a secret to each environment, but only if there's not already a value there.
func WriteSecretIfBlank(client *api.Client, secret *Secret) (err error) {
	for _, env := range Envs {
		secretPath := SecretPath(secret.Name, secret.Org, env)

		// check to see if the secret does not exist
		s, err := client.Logical().Read(secretPath)
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

			_, err = client.Logical().Write(secretPath, data)
			if err != nil {
				err = errors.Wrapf(err, "failed to write secret to %s", secretPath)
			}
		}
	}

	return err
}