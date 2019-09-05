package keymaster

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"strings"
)

/*

per cluster:
	vault auth-enable -path=k8s-bravo kubernetes
	vault write auth/k8s-bravo/config kubernetes_host=<apiserver url> kubernetes_ca_cert=@k8s-ca.crt token_reviewer_jwt=”<token for service account from k8s>”

per role:
	vault write auth/k8s-bravo/role/test-role bound_service_account_names=default bound_service_account_namespaces=sso policies=user
*/

type Cluster struct {
	Name         string
	ApiServerUrl string
	CACert       string
	Environment  Environment
	BoundCidrs   []string
}

var Clusters []Cluster
var ClustersByName map[string]Cluster

func init() {
	Clusters = make([]Cluster, 0)
	ClustersByName = make(map[string]Cluster)

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

	// charlie
	// delta
	delta := Cluster{
		Name:         "delta",
		ApiServerUrl: "https://devkube.inf.scribd.com:6443",
		CACert: `-----BEGIN CERTIFICATE-----
MIIDVTCCAj2gAwIBAgIUUUYfYM6Mu/Brko7u/BKLBobWlN8wDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAxMVZGV2a3ViZS1jYS5zY3JpYmQuY29tMB4XDTE5MDUzMTE3
NDk0NFoXDTI0MDUyOTE3NTAxNFowIDEeMBwGA1UEAxMVZGV2a3ViZS1jYS5zY3Jp
YmQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2p3z+IBHIcrS
x9FMlyRT/HgSV/wZw/KffSfxfiXIuaK/cCDxqoDK+QzKe9cwRLHYuUKR2zaS57Zv
5KUP67wzmhMhotoXaVSr7Zht6XBL1BYbjhnn64P5OJ7aHmoZupybQF8w2AtxYlwM
JaLhHe7An4CgPDD7i+bZWyHQm8IO0x2BuhqZhqz2dcfWURXXnRKq/oX7s8QjqSE3
7vxUTu8+UKRlnzIbDdQGhwlNMZ9g+2OXFP0VCVzfAB5N0RkH7uH67BjqXaJ2cG3A
3gDab3Mc381W9RBnPkuOwVKxZMmJH8STv6phOXeok/8+kWzQmS4z0gNPQDDHfQdW
mOMMpuNSZwIDAQABo4GGMIGDMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBSiP999ex76YHothR5ImP6YCQNF7zAfBgNVHSMEGDAWgBSi
P999ex76YHothR5ImP6YCQNF7zAgBgNVHREEGTAXghVkZXZrdWJlLWNhLnNjcmli
ZC5jb20wDQYJKoZIhvcNAQELBQADggEBAEmMQNyRLfrQziU2SGRRUIAwHRFnrtei
Y6TeFJKLiXWXaDRG1ZNMFK6I01FDAufsTIoKmFNxlQ8DRp7SoFM4qKkI/7SzSzKL
7j+G0ZUIdAZB6rpop9hX03D5Ftiu7IFC4j65OdUw6k5FIUKf13AvWZDRabzdLKM7
Jc15hAN5H3FGOTppW1LHTJn6wfioN2VPKlkqI3k03hEHaib9bp02zZPGxsGqumYn
GdmD9Caj9/8jE8YYO+n/9Y9rEEg+3k8F9bvNjCMIq7Avs6aPn05MZ0QCWmG+a6ez
2zAnZuKyLCOnT4kBYsP0bmsplL4/YWitMWkAr4xcIvb7OeFKHL26KiY=
-----END CERTIFICATE-----`,
		Environment: Dev,
		BoundCidrs: []string{
			"10.177.148.209",
		},
	}

	Clusters = append(Clusters, delta)
	ClustersByName[delta.Name] = delta

	// echo

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
	ClustersByName[delta.Name] = foxtrot

	// EKS Airflow

	// EKS Prod

	// EKS Stage

	// EKS Dev

}

// AuthName constructs the policy name form the inputs in a regular fashion. Environment is not an input as the cluster's name is known, and each cluster only serves a single environment.
func AuthName(role string, namespace string) (name string) {
	name = fmt.Sprintf("%s-%s", namespace, role)

	return name
}

// AuthPath constructs the auth path in a regular fashion.
func AuthPath(cluster string, role Role) (path string) {
	path = fmt.Sprintf("auth/%s/role/%s", cluster, AuthName(role.Name, role.Namespace))

	return path
}

// WriteK8sAuth Writes the Vault Auth definition for the Role.
func WriteK8sAuth(cluster Cluster, role Role, policy VaultPolicy, client *api.Client) (err error) {

	data := make(map[string]interface{})
	data["bound_service_account_names"] = "default"
	data["bound_service_account_namespaces"] = role.Namespace
	data["policies"] = policy.Name

	boundCidrs := strings.Join(cluster.BoundCidrs, ",")
	data["bound_cidrs"] = boundCidrs

	path := AuthPath(cluster.Name, role)

	_, err = client.Logical().Write(path, data)
	if err != nil {
		err = errors.Wrapf(err, "failed to write ")
		return err
	}

	return err
}

// ReadK8sAuth Reach into Vault and get the Auth config for the Role given.
func ReadK8sAuth(cluster string, role Role, client *api.Client) (data map[string]interface{}, err error) {
	path := AuthPath(cluster, role)

	s, err := client.Logical().Read(path)
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
func DeleteK8sAuth(cluster string, role Role, client *api.Client) (err error) {
	path := AuthPath(cluster, role)

	_, err = client.Logical().Delete(path)
	if err != nil {
		err = errors.Wrapf(err, "failed to delete %s", path)
		return err
	}

	return err
}
