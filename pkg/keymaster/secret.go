package keymaster

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
)

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

// SecretPath Given a Name, Namespace, and Environment, returns the proper path in Vault where that secret is stored.
func (km *KeyMaster) SecretPath(name string, namespace string, env Environment) (path string, err error) {
	if namespace == "" {
		err = errors.New("cannot make secret path for blank namespace")
		return path, err
	}

	switch env {
	case Prod:
		path = fmt.Sprintf("%s/data/%s/%s", PROD_NAME, namespace, name)
	case Stage:
		path = fmt.Sprintf("%s/data/%s/%s", STAGE_NAME, namespace, name)
	default:
		path = fmt.Sprintf("%s/data/%s/%s", DEV_NAME, namespace, name)
	}

	return path, err
}

// CertPath Given a Name, Namespace, and Environment, returns the proper path in Vault where that Cert Secret is stored.
func (km *KeyMaster) CertPath(name string, namespace string, env Environment) (path string, err error) {
	if namespace == "" {
		err = errors.New("cannot make cert secret path for blank namespace")
		return path, err
	}

	switch env {
	case Prod:
		path = fmt.Sprintf("%s/data/certs/%s/%s", PROD_NAME, namespace, name)
	case Stage:
		path = fmt.Sprintf("%s/data/certs/%s/%s", STAGE_NAME, namespace, name)
	default:
		path = fmt.Sprintf("%s/data/certs/%s/%s", DEV_NAME, namespace, name)
	}

	return path, err
}

// WriteSecretIfBlank writes a secret to each environment, but only if there's not already a value there.
func (km *KeyMaster) WriteSecretIfBlank(secret *Secret) (err error) {
	for _, env := range Envs {
		secretPath, err := km.SecretPath(secret.Name, secret.Namespace, env)
		if err != nil {
			err = errors.Wrapf(err, "failed to create secret path")
			return err
		}

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
				certPath, err := km.CertPath(secret.Name, secret.Namespace, env)
				if err != nil {
					err = errors.Wrapf(err, "failed to create cert path")
					return err
				}

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
