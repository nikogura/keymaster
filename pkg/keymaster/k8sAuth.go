/*
	These functions manage auth configs for instantiating Roles in K8S.

	Each Auth Role will enable a number of policies.

	It is expected that the consumer of the secret will know, and ask for the role they need.

*/
package keymaster

import (
	"fmt"
	"github.com/nikogura/dbt/pkg/dbt"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"strings"
)

/*

per cluster (manual):
	vault auth-enable -path=k8s-bravo kubernetes
	vault write auth/k8s-bravo/config kubernetes_host=<apiserver url> kubernetes_ca_cert=@k8s-ca.crt token_reviewer_jwt=”<token for service account from k8s>”

*/

const ERR_CLUSTER_DATA_LOAD = "failed to load data in supplied config"

type Cluster struct {
	Name         string `yaml:"name"`
	ApiServerUrl string `yaml:"apiserver"`
	CACert       string `yaml:"ca_cert"`
	EnvName      string `yaml:"environment"`
	Environment  Environment
	BoundCidrs   []string `yaml:"bound_cidrs"`
}

var Clusters []Cluster
var ClustersByName map[string]Cluster
var ClustersByEnvironment map[Environment][]Cluster

func init() {
	Clusters = make([]Cluster, 0)
	ClustersByName = make(map[string]Cluster)
	ClustersByEnvironment = make(map[Environment][]Cluster)

	for _, env := range Envs {
		ClustersByEnvironment[env] = make([]Cluster, 0)
	}

	// bravo
	bravo := Cluster{
		Name:         "bravo",
		ApiServerUrl: "https://kube-bravo-master01:6443",
		CACert: `-----BEGIN CERTIFICATE-----
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
Kxq0lynHENJpP/eXjfyC8sLDVJN8YO3n4w==
-----END CERTIFICATE-----`,
		Environment: Prod,
		BoundCidrs: []string{
			"10.177.148.183",
			"10.177.148.163",
			"10.177.148.175",
			"10.177.148.153",
			"10.177.105.201",
			"10.177.148.171",
		},
	}

	Clusters = append(Clusters, bravo)
	ClustersByName[bravo.Name] = bravo

	// foxtrot
	foxtrot := Cluster{
		Name:         "foxtrot",
		ApiServerUrl: "https://www.lo:6448",
		CACert: `-----BEGIN CERTIFICATE-----
MIIDOzCCAiOgAwIBAgIUJADHvMnuCenRnDrcBL3KKVN7IG4wDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAxMNa3ViZXJuZXRlcy1jYTAeFw0xOTA5MDMxNTEwMDZaFw0y
NDA5MDExNTEwMzZaMBgxFjAUBgNVBAMTDWt1YmVybmV0ZXMtY2EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTxXZC5GUWMAD3l3U5NwKDNnpEWOihr8S0
iEd34jkGGaDW6CKWDAu7oi5s+vhRLF6a+xsyFgJYv9p6/jmOzFXNM9zuqsj8YKye
5YzVX/uKAdvzmxI8wdHFptzSIar8KEnJUIdE6AbrFxSyc2MIuLgzJ2Y2RN1isGYm
VYVJTUTLMt5G9YTumPAym5ZwAhPq9Byp2rpXdg7Hpmdrlz8JRz+rAJ42pfQyvcEO
ogzSXZCk5BYReJEHaE9KGUA9KQV5U4YCRMArtE7JMVJY2LrRvF0rzbdoHcfjBaLv
MgfMfx4XiZbNGEJP31TKXWsJ2cqqLuryMqNITyxf1QSsClnLxzhNAgMBAAGjfTB7
MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS9jPki
B3YkJsRdwmwdNSZpWDoRcDAfBgNVHSMEGDAWgBS9jPkiB3YkJsRdwmwdNSZpWDoR
cDAYBgNVHREEETAPgg1rdWJlcm5ldGVzLWNhMA0GCSqGSIb3DQEBCwUAA4IBAQAH
MUy1/QvOhbJ6sR24/q5g1V+EUkKzrJCiil2SXKZBpKU0NFIvqRB9Yh40AgviLhsA
/EKmRSQSVgD8TUhGUb1oew3/lnVkePZWBOKL6Y8ImUjaMl+ECBkM/FX4pznP4/Ga
4pOXfETemw0Mbm42gdXTNQw/LlVUvam3HQX73Y3QhZ5n6Iu0ToD/ANECKbRS00gM
0FrZql/AFFOVy9BWYra6mWbYVWlyI0YL7c57vu/0VqjOslLArW2SCs+Lff5jCyFU
kNoCEVDI5C2RN36GljQpCFkQ8IR5eyDC4PeqXBkxg8nzrl06NN2R89H1oB3OgiL2
5bmcZjJIZiCcbgdAJSvf
-----END CERTIFICATE-----`,
		Environment: Prod,
		BoundCidrs: []string{
			"10.177.148.193",
			"10.177.148.229",
			"10.177.148.211",
			"10.177.148.223",
			"10.177.148.166",
			"10.177.148.186",
		},
	}

	Clusters = append(Clusters, foxtrot)
	ClustersByName[foxtrot.Name] = foxtrot

	// golf
	golf := Cluster{
		Name:         "golf",
		ApiServerUrl: "https://kube-golf01:6443",
		CACert: `-----BEGIN CERTIFICATE-----
MIICyDCCAbCgAwIBAgIBADANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwprdWJl
cm5ldGVzMB4XDTE5MDkyMzE5MDczOFoXDTI5MDkyMDE5MDczOFowFTETMBEGA1UE
AxMKa3ViZXJuZXRlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANgv
rfc2gZuHaopOScLAje0kSdyNixyi98qTwp61yGx/7KeRItQ4sgABm9d6A/352wpZ
M41zm+N5nvVgHh6cHB4yiNt4U+jhOBCXWajYRlHqMP3eJS5cWjYpBWpHncNDDdC1
FSarlkJmiMHVPimSoVNBCdNr6WyL4CP/nBXPcDBdECBgCXRrqidMiY8I3QynuoXx
c6VNKshlxTvCPf8oin679KMwMQbzH6CZ9QBiEF4F9D0JWvpgpkM4iJ5wYQ9H1+ia
CZrI9KjECuEriLr6gv/vrgRf/FhESCNvHmJDUPGVEhaDU+qp8YjNrEXkGp0599Oy
HRvu8J5E5x1Wf/4HCSMCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAAXsbNVcADziyLUN9vcr21j3JXxD
FmuYDEoyW0SgsCFwXwbT/JnFCntQGBcgf273hS9i9XZYcbg2v6HPqVObzsGwv960
iqfhsHwB0vkF6+HIbV7GuYVHbufq8bxQl/6aH9zt6px63/canlQsYneEBVE/VxwB
IYDDkFzddRCPc4sMv6m+NaFclL8KE3gn241kJFGNoNDabBNMQPooSsPRYQVlnSF7
pQuIfEhzZIVhpEJwCwjwnKT7SBTgsKhkXprmQon1kcKgm+8RVBAOP+4V6uAxOszP
hpffi7blzHapGacvtE8O0mJN2bWdMTEMYfr3XB+iRRF6ddkVTr0NCZZs4bk=
-----END CERTIFICATE-----`,
		Environment: Prod,
		BoundCidrs: []string{
			"10.177.148.240",
		},
	}

	Clusters = append(Clusters, golf)
	ClustersByName[golf.Name] = golf

	// Core Services Development
	csvcDevel := Cluster{
		Name:         "development-apps",
		ApiServerUrl: "https://56E51D0A7A4FF7587BE0F094B93B1521.sk1.us-east-2.eks.amazonaws.com",
		CACert: `-----BEGIN CERTIFICATE-----
	MIICyDCCAbCgAwIBAgIBADANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwprdWJl
	cm5ldGVzMB4XDTE5MDkyNTEzMDkzNFoXDTI5MDkyMjEzMDkzNFowFTETMBEGA1UE
	AxMKa3ViZXJuZXRlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALhs
	yg2Sk2ojQn5QPm4+BkUwZWKHHSm1iyVCrLF9VssG6tQI1XkkbPrpNdIVbPYozKZf
	qo1Hb6xaQMdTTTP7AElMkVacSDVMcgcjDOQ4Sptkh7mj9ubxMJBQQ68d02+JBM0k
	Wn8f2QIVFQntSh492LTIL2vr9rzF+Lrz2GPbkyL+MySelLBmNm3LxajETHbfukAK
	cpo91c/BBg5weiJV64idviGODayRaBYmHzOuOjdzywgRpG3aJ/5GFDP3YOI0LjbD
	9mRbCJDhUP1d3gi2rOCH5izUg9y0LoiyGCX1hBy0hEYWDAVwNBQb23TA7Y2QaE9w
	eXnRaT33MHASo0l6dskCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB
	/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAHlDp8/Din/eaxlRMaONREgc2RfQ
	2OgiSN9W+emEYY5D1avleYQ1NBW+0rc8hYR8ADCh0lpH/ZOQgY58z0HJmHIXB1h0
	o6w41E7wUCzgpFGT5D3gK6rDCIy68TwfFNyJ/IdQ9cVK9RrfhJrIfAO94wN9OEYQ
	A7/GAhV4Ml0W4ThP+MD6QM20vmftW3md0eqpn+gV6Vq2ptD6nEOOo8TEIT0CIFh6
	sj6yFaHX5RBT7mY6pXve6hmbdkA97Ub40OCTbvryhrAGe/ueD02ntswToAcM3NnC
	lTYORq5Eksf5zoqyQi6aBMKpytzD8P7j4dZtFiavws1oUXbKd05WofMhrqI=
	-----END CERTIFICATE-----`,
		Environment: Dev,
		BoundCidrs: []string{
			"10.226.0.0/19",
			"10.226.32.0/19",
			"10.226.64.0/19",
		},
	}

	Clusters = append(Clusters, csvcDevel)
	ClustersByName[csvcDevel.Name] = csvcDevel

	// Populate the map of ClustersByEnvironment
	for _, cluster := range Clusters {
		ClustersByEnvironment[cluster.Environment] = append(ClustersByEnvironment[cluster.Environment], cluster)
	}
}

func (km *KeyMaster) NewCluster(data []byte, verbose bool) (cluster Cluster, err error) {
	err = yaml.Unmarshal(data, &cluster)
	if err != nil {
		err = errors.Wrap(err, ERR_CLUSTER_DATA_LOAD)
		return cluster, err
	}

	return cluster, err
}

// K8sAuthPath constructs the auth path in a regular fashion.
func (km *KeyMaster) K8sAuthPath(cluster Cluster, role *Role) (path string, err error) {
	if role.Name == "" {
		err = errors.New("empty role names are not supported")
		return path, err
	}

	if role.Namespace == "" {
		err = errors.New("empty role namespaces are not supported")
		return path, err
	}

	path = fmt.Sprintf("auth/k8s-%s/role/%s-%s", cluster.Name, role.Namespace, role.Name)

	return path, err
}

func (km *KeyMaster) AddPolicyToK8sRole(cluster Cluster, role *Role, policy VaultPolicy) (err error) {
	policies, err := km.GrantedPoliciesForK8sRole(cluster, role)
	if err != nil {
		return err
	}

	// exit early if it's already there
	if dbt.StringInSlice(policy.Name, policies) {
		return err
	}

	policies = append(policies, policy.Name)

	return km.WriteK8sAuth(cluster, role, policies)
}

func (km *KeyMaster) RemovePolicyFromK8sRole(cluster Cluster, role *Role, policy VaultPolicy) (err error) {
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

	return km.WriteK8sAuth(cluster, role, updated)
}

func (km *KeyMaster) GrantedPoliciesForK8sRole(cluster Cluster, role *Role) (policies []string, err error) {
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
func (km *KeyMaster) WriteK8sAuth(cluster Cluster, role *Role, policies []string) (err error) {

	data := make(map[string]interface{})
	data["bound_service_account_names"] = "default"
	data["bound_service_account_namespaces"] = role.Namespace
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
func (km *KeyMaster) ReadK8sAuth(cluster Cluster, role *Role) (data map[string]interface{}, err error) {
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
func (km *KeyMaster) DeleteK8sAuth(cluster Cluster, role *Role) (err error) {
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
