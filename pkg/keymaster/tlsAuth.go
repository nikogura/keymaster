/*
	These functions manage auth configs for instantiating Roles in Vault via TLS Certs.

	Each Auth Role will enable a number of policies.

	It is expected that the consumer of the secret will know, and ask for the Role they need.

*/
package keymaster

import (
	"fmt"
	"github.com/pkg/errors"
	"net"
	"strings"
)

// TlsAuthPath constructs the auth path in a regular fashion.
func (km *KeyMaster) TlsAuthPath(role *Role, env string) (path string, err error) {
	if role.Name == "" {
		err = errors.New("empty role names are not supported")
		return path, err
	}

	if role.Team == "" {
		err = errors.New("teamless roles are not supported")
		return path, err
	}

	path = fmt.Sprintf("auth/cert/certs/%s-%s-%s", role.Team, role.Name, env)

	return path, err
}

func (km *KeyMaster) AddPolicyToTlsRole(role *Role, env string, policy VaultPolicy) (err error) {
	policies, err := km.GrantedPoliciesForTlsRole(role, env)
	if err != nil {
		return err
	}

	// exit early if it's already there
	if stringInSlice(policy.Name, policies) {
		return err
	}

	policies = append(policies, policy.Name)

	return km.WriteTlsAuth(role, env, policies)
}

func (km *KeyMaster) RemovePolicyFromTlsRole(role *Role, env string, policy VaultPolicy) (err error) {
	current, err := km.GrantedPoliciesForTlsRole(role, env)
	if err != nil {
		return err
	}

	updated := make([]string, 0)

	for _, p := range current {
		if p != policy.Name {
			updated = append(updated, p)
		}
	}

	return km.WriteTlsAuth(role, env, updated)
}

func (km *KeyMaster) GrantedPoliciesForTlsRole(role *Role, env string) (policies []string, err error) {
	policies = make([]string, 0)

	previousData, err := km.ReadTlsAuth(role, env)
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

// Read TlsAuth path and return it's data
func (km *KeyMaster) ReadTlsAuth(role *Role, env string) (data map[string]interface{}, err error) {
	path, err := km.TlsAuthPath(role, env)
	if err != nil {
		err = errors.Wrapf(err, "failed to create tls auth path")
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

// DeleteTlsAuth Delete a Tls auth config for a Role.
func (km *KeyMaster) DeleteTlsAuth(role *Role, env string) (err error) {
	path, err := km.TlsAuthPath(role, env)
	if err != nil {
		err = errors.Wrapf(err, "failed to create tls auth path")
		return err
	}

	_, err = km.VaultClient.Logical().Delete(path)
	if err != nil {
		err = errors.Wrapf(err, "failed to delete %s", path)
		return err
	}

	return err
}

// WriteTlsAuth writes the auth config to vault
func (km *KeyMaster) WriteTlsAuth(role *Role, env string, policies []string) (err error) {
	hostnames := make([]string, 0)
	ips := make([]string, 0)

	if km.TlsAuthCaCert == "" {
		err = errors.New("Cannot configure TLS Auth without a CA certificate.  call SetTlsAuthCaCert(cert) on keymaster object.")
		return err
	}

	if km.IpRestrictTlsAuth {
		for _, realm := range role.Realms {
			if realm.Type == "tls" {
				for _, hostname := range realm.Principals {
					hostnames = append(hostnames, hostname)

					addrs, err := net.LookupIP(hostname)
					if err != nil {
						err = errors.Wrapf(err, "failed to look up ip addresses for %s", hostname)
						return err
					}

					for _, ip := range addrs {
						ips = append(ips, ip.String())
					}
				}
			}
		}
	}

	data := make(map[string]interface{})
	data["allowed_common_names"] = strings.Join(hostnames, ",")
	data["bound_cidrs"] = strings.Join(ips, ",")
	data["policies"] = policies
	data["display_name"] = fmt.Sprintf("%s-%s-%s", role.Team, role.Name, env)
	data["certificate"] = km.TlsAuthCaCert
	// these appear to need to be set to empty lists
	data["allowed_dns_sans"] = []string{}
	data["allowed_email_sans"] = []string{}
	data["allowed_names"] = []string{}
	data["allowed_organizational_units"] = []string{}
	data["allowed_uri_sans"] = []string{}
	data["required_extensions"] = []string{}

	path, err := km.TlsAuthPath(role, env)
	if err != nil {
		err = errors.Wrapf(err, "failed to create tls auth path")
		return err
	}

	_, err = km.VaultClient.Logical().Write(path, data)
	if err != nil {
		err = errors.Wrapf(err, "failed to write to %s", path)
		return err
	}

	return err
}

/*
{
  "allowed_common_names": [
    "artifactory02.inf.scribd.com"
  ],
  "allowed_dns_sans": [],
  "allowed_email_sans": [],
  "allowed_names": [],
  "allowed_organizational_units": [],
  "allowed_uri_sans": [],
  "bound_cidrs": [
    "10.177.148.216"
  ],
  "certificate": "-----BEGIN CERTIFICATE-----\n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\n8no=\n-----END CERTIFICATE-----",
  "display_name": "artifactory",
  "max_ttl": 300,
  "period": 0,
  "policies": [
    "artifactory",
    "create-service-cert",
    "default"
  ],
  "required_extensions": [],
  "ttl": 300
}
*/
