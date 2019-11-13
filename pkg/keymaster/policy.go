package keymaster

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"git.lo/ops/scrutil/pkg/scrutil"
	"github.com/pkg/errors"
	"strings"
)

// PolicyName constructs the policy name form the inputs in a regular fashion. Note: team names like 'core-platform' will make policy names with embedded hyphens.  This could be a problem if we ever need to split the policy name to reconstruct the inputs.
func (km *KeyMaster) PolicyName(team string, role string, env string) (name string, err error) {
	if role == "" {
		err = errors.New("empty role names are not supported")
		return name, err
	}

	if team == "" {
		err = errors.New("teamless roles are not supported")
		return name, err
	}

	if env == "" {
		err = errors.New("blank environments are not supported")
		return name, err
	}

	name = fmt.Sprintf("%s-%s-%s", team, role, env)

	return name, err
}

// PolicyPath constructs the path to the policy for the role
func (km *KeyMaster) PolicyPath(team string, role string, env string) (path string, err error) {
	policyName, err := km.PolicyName(team, role, env)
	if err != nil {
		err = errors.Wrapf(err, "failed to create policy name")
		return path, err
	}

	path = fmt.Sprintf("sys/policy/%s", policyName)

	return path, err
}

// NewPolicy creates a new Policy object for a given Role and Environment
func (km *KeyMaster) NewPolicy(role *Role, env string) (policy VaultPolicy, err error) {
	payload, err := km.MakePolicyPayload(role, env)
	if err != nil {
		err = errors.Wrapf(err, "failed to create payload")
		return policy, err
	}

	pName, err := km.PolicyName(role.Team, role.Name, env)
	if err != nil {
		err = errors.Wrapf(err, "failed to create policy name")
		return policy, err
	}

	pPath, err := km.PolicyPath(role.Team, role.Name, env)
	if err != nil {
		err = errors.Wrapf(err, "failed to create policy path")
		return policy, err
	}

	policy = VaultPolicy{
		Name:    pName,
		Path:    pPath,
		Payload: payload,
	}

	return policy, err
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
func (km *KeyMaster) MakePolicyPayload(role *Role, env string) (policy map[string]interface{}, err error) {
	policy = make(map[string]interface{})
	pathElem := make(map[string]interface{})

	for _, secret := range role.Secrets {
		secretPath, err := km.SecretPath(secret.Team, secret.Name, env)
		if err != nil {
			err = errors.Wrapf(err, "failed to create secret path for %s role %s", secret.Name, role.Name)
			return policy, err
		}

		caps := []interface{}{"read"}
		pathPolicy := map[string]interface{}{"capabilities": caps}
		pathElem[secretPath] = pathPolicy
	}

	// add ability to read own policy
	secretPath, err := km.PolicyPath(role.Team, role.Name, env)
	if err != nil {
		err = errors.Wrapf(err, "failed to create policy path")
		return policy, err
	}

	caps := []interface{}{"read"}
	pathPolicy := map[string]interface{}{"capabilities": caps}
	pathElem[secretPath] = pathPolicy
	policy["path"] = pathElem

	return policy, err
}

// WritePolicyToVault does just that.  It takes a vault client and the policy and takes care of the asshattery that is the vault api for policies.
func (km *KeyMaster) WritePolicyToVault(policy VaultPolicy, verbose bool) (err error) {
	scrutil.VerboseOutput(verbose, "----------------------------------------------------------------------------------------------------------------")
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
	scrutil.VerboseOutput(verbose, "        request path: %s", reqPath)

	bbytes, err := json.Marshal(body)
	if err != nil {
		err = errors.Wrapf(err, "unable to marshal policy request body to json")
		return err
	}

	scrutil.VerboseOutput(verbose, "        request body: %s", string(bbytes))

	r := km.VaultClient.NewRequest("PUT", reqPath)
	if err := r.SetJSONBody(body); err != nil {
		err = errors.Wrapf(err, "failed to set json body on request")
		return err
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	resp, err := km.VaultClient.RawRequestWithContext(ctx, r)
	if err != nil {
		err = errors.Wrapf(err, "policy set request failed")
		return err
	}

	code := resp.StatusCode
	scrutil.VerboseOutput(verbose, "        response code: %d", code)
	if code != 204 {
		err = errors.New(fmt.Sprintf("failed writing to %s", policy.Path))
		return err
	}

	defer resp.Body.Close()

	return err
}

// ReadPolicyFromVault fetches a policy from vault and converts it back to a VaultPolicy object
func (km *KeyMaster) ReadPolicyFromVault(path string) (policy VaultPolicy, err error) {
	s, err := km.VaultClient.Logical().Read(path)
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
func (km *KeyMaster) DeletePolicyFromVault(path string) (err error) {
	_, err = km.VaultClient.Logical().Delete(path)
	if err != nil {
		err = errors.Wrapf(err, "failed to delete path %s", path)
		return err
	}

	return err
}

// TODO how to grant universal access to development?
