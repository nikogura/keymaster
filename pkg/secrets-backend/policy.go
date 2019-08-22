package secrets_backend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"strings"
)

type VaultPolicy struct {
	Name    string
	Path    string
	Payload map[string]interface{}
}

// PolicyName constructs the policy name form the inputs in a regular fashion. Note: orgs like 'core-platform' will make policy names with embedded hyphens.  This could be a problem if we ever need to split the policy name to reconstruct the inputs, but I suspect this is a non issue. (and so long as it's just 3 elements we can split, grab the first and last, and recombine any middle bits)
func PolicyName(role string, org string, env Environment) (name string) {
	switch env {
	case Prod:
		name = fmt.Sprintf("%s-%s-%s", PROD_NAME, org, role)
	case Stage:
		name = fmt.Sprintf("%s-%s-%s", STAGE_NAME, org, role)
	default:
		name = fmt.Sprintf("%s-%s-%s", DEV_NAME, org, role)
	}

	return name
}

// PolicyPath constructs the path to the policy for the role
func PolicyPath(role string, org string, env Environment) (path string) {
	path = fmt.Sprintf("sys/policy/%s", PolicyName(role, org, env))

	return path
}

// NewPolicy creates a new Policy object for a given Role and Environment
func NewPolicy(role Role, env Environment) (policy VaultPolicy) {
	policy = VaultPolicy{
		Name:    PolicyName(role.Name, role.Org, env),
		Path:    PolicyPath(role.Name, role.Org, env),
		Payload: MakePolicyPayload(role, env),
	}

	return policy
}

// MakePolicyPayload is the access policy to a specific secret path.  Policy Payloads give access to a single path, wildcards are not supported.
/* example policy:  We will only ever set 'read'.
{
  "path": {  # alphabetical by key
    "service/sign/cert-issuer": {
      "capabilities": [
        "read"
      ]
    }
  }
}
*/
func MakePolicyPayload(role Role, env Environment) (policy map[string]interface{}) {
	policy = make(map[string]interface{})
	pathElem := make(map[string]interface{})

	for _, secret := range role.Secrets {
		secretPath := SecretPath(secret.Name, secret.Org, env)
		caps := []interface{}{"read"}
		pathPolicy := map[string]interface{}{"capabilities": caps}
		pathElem[secretPath] = pathPolicy
	}

	// add ability to read own policy
	secretPath := PolicyPath(role.Name, role.Org, env)
	caps := []interface{}{"read"}
	pathPolicy := map[string]interface{}{"capabilities": caps}
	pathElem[secretPath] = pathPolicy
	policy["path"] = pathElem

	return policy
}

// WritePolicyToVault does just that.  It takes a vault client and the policy and takes care of the asshattery that is the vault api for policies.
func WritePolicyToVault(policy VaultPolicy, client *api.Client) (err error) {
	// policies are not normal writes, and a royal pain the butt.  Thank you Mitch.
	jsonBytes, err := json.Marshal(policy.Payload)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal payload for %s", policy.Name)
		return err
	}

	payload := string(jsonBytes)

	payload = base64.StdEncoding.EncodeToString(jsonBytes)

	body := map[string]string{
		"policy": payload,
	}

	reqPath := fmt.Sprintf("/v1/%s", policy.Path)

	r := client.NewRequest("PUT", reqPath)
	if err := r.SetJSONBody(body); err != nil {
		err = errors.Wrapf(err, "failed to set json body on request")
		return err
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	resp, err := client.RawRequestWithContext(ctx, r)
	if err != nil {
		err = errors.Wrapf(err, "policy set request failed")
		return err
	}

	defer resp.Body.Close()

	return err
}

// ReadPolicyFromVault fetches a policy from vault and converts it back to a VaultPolicy object
func ReadPolicyFromVault(path string, client *api.Client) (policy VaultPolicy, err error) {
	s, err := client.Logical().Read(path)
	if err != nil {
		return policy, err
	}

	var policyName string

	if s != nil {
		n, ok := s.Data["name"]
		if ok {
			name, ok := n.(string)
			if ok {
				policyName = name
			}
		}

		raw := s.Data["rules"]
		rawRules, ok := raw.(string)
		if ok {
			jsonString := strings.ReplaceAll(rawRules, "\\", "")

			payload := make(map[string]interface{})

			err := json.Unmarshal([]byte(jsonString), &payload)
			if err != nil {
				err = errors.Wrapf(err, "failed to unmarshal policy rules")
				return policy, err
			}

			policy = VaultPolicy{
				Name:    policyName,
				Path:    path,
				Payload: payload,
			}

			return policy, err
		}
	}

	return policy, err
}

// DeletePolicyFromVault  deletes a policy from vault.  It only deletes the policy, it doesn't do anything about the auth method or the secrets.
func DeletePolicyFromVault(path string, client *api.Client) (err error) {
	_, err = client.Logical().Delete(path)
	if err != nil {
		err = errors.Wrapf(err, "failed to delete path %s", path)
		return err
	}

	return err
}

/*
	LDAP Auth can access only dev secrets

	k8s dev auth can access dev secrets
	k8s stage auth can access stage secrets
	k8s prod auth can access prod secrets

	aws dev auth can access dev secrets
	aws stage auth can access stage secrets
	aws prod auth can access prod secrets

	tls prod auth can access prod secrets
	do we need tls stage / dev access at all?

*/