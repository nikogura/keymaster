/*
	These functions manage auth configs for instantiating Roles in K8S.

	Each Auth Role will enable a number of policies.

	It is expected that the consumer of the secret will know, and ask for the role they need.

*/
package keymaster

import (
	"fmt"
	"github.com/pkg/errors"
	"strings"
)

/*

per cluster (manual):
	vault auth-enable -path=k8s-alpha kubernetes
	vault write auth/k8s-alpha/config kubernetes_host=<apiserver url> kubernetes_ca_cert=@k8s-ca.crt token_reviewer_jwt=”<token for service account from k8s>”

*/

const ERR_CLUSTER_DATA_LOAD = "failed to load data in supplied config"

type Cluster struct {
	Name         string `yaml:"name"`
	ApiServerUrl string `yaml:"apiserver"`
	CACert       string `yaml:"ca_cert"`
	EnvName      string `yaml:"environment"`
	Environment  string
	BoundCidrs   []string `yaml:"bound_cidrs"`
}

//func (km *KeyMaster) NewCluster(data []byte, verbose bool) (cluster Cluster, err error) {
//	err = yaml.Unmarshal(data, &cluster)
//	if err != nil {
//		err = errors.Wrap(err, ERR_CLUSTER_DATA_LOAD)
//		return cluster, err
//	}
//
//	return cluster, err
//}
//
// K8sAuthPath constructs the auth path in a regular fashion.
func (km *KeyMaster) K8sAuthPath(cluster *Cluster, role *Role) (path string, err error) {
	if role.Name == "" {
		err = errors.New("empty role names are not supported")
		return path, err
	}

	if role.Team == "" {
		err = errors.New("teamless roles are not supported")
		return path, err
	}

	path = fmt.Sprintf("auth/k8s-%s/role/%s-%s", cluster.Name, role.Team, role.Name)

	return path, err
}

func (km *KeyMaster) AddPolicyToK8sRole(cluster *Cluster, role *Role, realm *Realm, policy VaultPolicy) (err error) {
	policies, err := km.GrantedPoliciesForK8sRole(cluster, role)
	if err != nil {
		return err
	}

	// exit early if it's already there
	if stringInSlice(policy.Name, policies) {
		return err
	}

	policies = append(policies, policy.Name)

	return km.WriteK8sAuth(cluster, role, realm, policies)
}

func (km *KeyMaster) RemovePolicyFromK8sRole(cluster *Cluster, role *Role, realm *Realm, policy VaultPolicy) (err error) {
	current, err := km.GrantedPoliciesForK8sRole(cluster, role)
	if err != nil {
		return err
	}

	updated := make([]string, 0)

	for _, p := range current {
		if p != policy.Name {
			updated = append(updated, p)
		}
	}

	return km.WriteK8sAuth(cluster, role, realm, updated)
}

func (km *KeyMaster) GrantedPoliciesForK8sRole(cluster *Cluster, role *Role) (policies []string, err error) {
	policies = make([]string, 0)

	previousData, err := km.ReadK8sAuth(cluster, role)
	if err != nil {
		err = errors.Wrapf(err, "failed to fetch policy data for role %s in cluster %s", role.Name, cluster.Name)
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

// WriteK8sAuth Writes the Vault Auth definition for the Role.
func (km *KeyMaster) WriteK8sAuth(cluster *Cluster, role *Role, realm *Realm, policies []string) (err error) {

	data := make(map[string]interface{})
	data["bound_service_account_names"] = "default"
	data["bound_service_account_namespaces"] = strings.Join(realm.Principals, ",")
	data["policies"] = policies

	boundCidrs := strings.Join(cluster.BoundCidrs, ",")
	data["bound_cidrs"] = boundCidrs

	path, err := km.K8sAuthPath(cluster, role)
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

// ReadK8sAuth Reach into Vault and get the Auth config for the Role given.
func (km *KeyMaster) ReadK8sAuth(cluster *Cluster, role *Role) (data map[string]interface{}, err error) {
	path, err := km.K8sAuthPath(cluster, role)
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

// DeleteK8sAuth Delete a Vault K8s Auth config.
func (km *KeyMaster) DeleteK8sAuth(cluster *Cluster, role *Role) (err error) {
	path, err := km.K8sAuthPath(cluster, role)
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
