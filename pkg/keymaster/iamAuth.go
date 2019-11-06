package keymaster

import (
	"fmt"
	"github.com/nikogura/dbt/pkg/dbt"
	"github.com/pkg/errors"
	"strings"
)

// IamAuthPath constructs an auth path in a predictable fashion
func (km *KeyMaster) IamAuthPath(role *Role) (path string, err error) {
	if role.Name == "" {
		err = errors.New("empty role names are not supported")
		return path, err
	}

	if role.Team == "" {
		err = errors.New("teamless roles are not supported")
		return path, err
	}

	path = fmt.Sprintf("auth/aws/role/%s-%s", role.Team, role.Name)

	return path, err
}

// AddPolicyToIamRole Add a policy to an IAM auth role
func (km *KeyMaster) AddPolicyToIamRole(role *Role, realm *Realm, policy VaultPolicy) (err error) {
	policies, err := km.GrantedPoliciesForIamRole(role)
	if err != nil {
		return err
	}

	// exit early if it's already there
	if dbt.StringInSlice(policy.Name, policies) {
		return err
	}

	policies = append(policies, policy.Name)

	return km.WriteIamAuth(role, realm, policies)

	return err
}

// RemovePolicyFromIamRole  removes a policy from an IAM Role
func (km *KeyMaster) RemovePolicyFromIamRole(role *Role, realm *Realm, policy VaultPolicy) (err error) {
	current, err := km.GrantedPoliciesForIamRole(role)
	if err != nil {
		return err
	}

	updated := make([]string, 0)

	for _, p := range current {
		if p != policy.Name {
			updated = append(updated, p)
		}
	}

	return km.WriteIamAuth(role, realm, updated)

	return err
}

// GrantedPoliciesForIamRole
func (km *KeyMaster) GrantedPoliciesForIamRole(role *Role) (policies []string, err error) {
	policies = make([]string, 0)

	previousData, err := km.ReadIamAuth(role)
	if err != nil {
		err = errors.Wrapf(err, "failed to fetch policy data for role %s", role.Name)
		return policies, err
	}

	// fetch current policies for this host
	if previousData != nil {
		previousPolicies, ok := previousData["policies"].([]interface{})
		if ok {
			for _, p := range previousPolicies {
				pname, ok := p.(string)
				if ok {
					policies = append(policies, pname)
				}
			}
		}
		return policies, err
	}

	// else return a list with the default policy
	policies = append(policies, "default")

	return policies, err
}

// WriteIamAuth writes an AWS IAM auth role to vault
func (km *KeyMaster) WriteIamAuth(role *Role, realm *Realm, policies []string) (err error) {
	data := make(map[string]interface{})
	data["bound_iam_principal_arn"] = strings.Join(realm.Principals, ",")
	data["policies"] = policies
	data["auth_type"] = "iam"

	path, err := km.IamAuthPath(role)
	if err != nil {
		err = errors.Wrapf(err, "failed building k8s auth path")
		return err
	}

	_, err = km.VaultClient.Logical().Write(path, data)
	if err != nil {
		err = errors.Wrapf(err, "failed to write ")
		return err
	}

	return err
}

// ReadIamAuth read an IAM role out of vault
func (km *KeyMaster) ReadIamAuth(role *Role) (data map[string]interface{}, err error) {
	path, err := km.IamAuthPath(role)
	if err != nil {
		err = errors.Wrapf(err, "failed building k8s auth path")
		return data, err
	}

	s, err := km.VaultClient.Logical().Read(path)
	if err != nil {
		err = errors.Wrapf(err, "failed to read %s", path)
		return data, err
	}

	if s != nil {
		data = s.Data
	}

	return data, err
}

// DeleteIamAuth deletes an IAM Auth role
func (km *KeyMaster) DeleteIamAuth(role *Role) (err error) {
	path, err := km.IamAuthPath(role)
	if err != nil {
		err = errors.Wrapf(err, "failed building k8s auth path")
		return err
	}

	_, err = km.VaultClient.Logical().Delete(path)
	if err != nil {
		err = errors.Wrapf(err, "failed to delete %s", path)
		return err
	}

	return err
}
