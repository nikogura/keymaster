package keymaster

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"reflect"
	"testing"
)

// anonymizeStringArray turns an []string into []interface{} so that we can use reflect.DeepEqual() to compare.
func anonymizeStringArray(input []string) (output []interface{}) {
	output = make([]interface{}, 0)
	for _, i := range input {
		output = append(output, i)
	}

	return output
}

func TestK8sAuthCrud(t *testing.T) {
	km := NewKeyMaster(kmClient)

	addPolicy1, err := km.NewPolicy(&Role{
		Name: "app2",
		Secrets: []*Secret{
			{
				Name: "bar",
				Team: "core-services",
				Generator: AlphaGenerator{
					Type:   "alpha",
					Length: 10,
				},
			},
		},
		Team: "core-services",
	}, DEV)
	if err != nil {
		log.Printf("Error creating policy: %s", err)
		t.Fail()
	}

	addPolicy2, err := km.NewPolicy(&Role{
		Name: "app3",
		Secrets: []*Secret{
			{
				Name: "baz",
				Team: "core-platform",
				Generator: AlphaGenerator{
					Type:   "alpha",
					Length: 10,
				},
			},
		},
		Team: "core-platform",
	}, DEV)
	if err != nil {
		log.Printf("Error creating policy: %s", err)
		t.Fail()
	}

	inputs := []struct {
		name    string
		cluster Cluster
		role    *Role
		first   map[string]interface{}
		add     VaultPolicy
		second  map[string]interface{}
	}{
		{
			"app1",
			Clusters[0],
			&Role{
				Name: "app1",
				Secrets: []*Secret{
					{
						Name: "foo",
						Team: "core-services",
						Generator: AlphaGenerator{
							Type:   "alpha",
							Length: 10,
						},
					},
				},
				Team: "core-services",
				Realms: []*Realm{
					&Realm{
						Type:        "k8s",
						Identifiers: []string{"bravo"},
						Principals:  []string{"default"},
					},
				},
			},
			map[string]interface{}{
				"bound_cidrs":                      anonymizeStringArray(Clusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"default"},
				"policies": []interface{}{
					"core-services-development-app1",
				},
				"token_bound_cidrs":       anonymizeStringArray(Clusters[0].BoundCidrs),
				"token_explicit_max_ttl":  json.Number("0"),
				"token_max_ttl":           json.Number("0"),
				"token_no_default_policy": false,
				"token_num_uses":          json.Number("0"),
				"token_period":            json.Number("0"),
				"token_policies": []interface{}{
					"core-services-development-app1",
				},
				"token_ttl":  json.Number("0"),
				"token_type": "default",
			},
			addPolicy1,
			map[string]interface{}{
				"bound_cidrs":                      anonymizeStringArray(Clusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"default"},
				"policies": []interface{}{
					"core-services-development-app1",
					"core-services-development-app2",
				},
				"token_bound_cidrs":       anonymizeStringArray(Clusters[0].BoundCidrs),
				"token_explicit_max_ttl":  json.Number("0"),
				"token_max_ttl":           json.Number("0"),
				"token_no_default_policy": false,
				"token_num_uses":          json.Number("0"),
				"token_period":            json.Number("0"),
				"token_policies": []interface{}{
					"core-services-development-app1",
					"core-services-development-app2",
				},
				"token_ttl":  json.Number("0"),
				"token_type": "default",
			},
		},
		{
			"app2",
			Clusters[0],
			&Role{
				Name: "app2",
				Secrets: []*Secret{
					{
						Name: "foo",
						Team: "core-platform",
						Generator: AlphaGenerator{
							Type:   "alpha",
							Length: 10,
						},
					},
					{
						Name: "bar",
						Team: "core-platform",
						Generator: UUIDGenerator{
							Type: "uuid",
						},
					},
				},
				Team: "core-platform",
				Realms: []*Realm{
					&Realm{
						Type:        "k8s",
						Identifiers: []string{"bravo"},
						Principals:  []string{"default"},
					},
				},
			},
			map[string]interface{}{
				"bound_cidrs":                      anonymizeStringArray(Clusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"default"},
				"policies": []interface{}{
					"core-platform-development-app2",
				},
				"token_bound_cidrs":       anonymizeStringArray(Clusters[0].BoundCidrs),
				"token_explicit_max_ttl":  json.Number("0"),
				"token_max_ttl":           json.Number("0"),
				"token_no_default_policy": false,
				"token_num_uses":          json.Number("0"),
				"token_period":            json.Number("0"),
				"token_policies": []interface{}{
					"core-platform-development-app2",
				},
				"token_ttl":  json.Number("0"),
				"token_type": "default",
			},
			addPolicy2,
			map[string]interface{}{
				"bound_cidrs":                      anonymizeStringArray(Clusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"default"},
				"policies": []interface{}{
					"core-platform-development-app2",
					"core-platform-development-app3",
				},
				"token_bound_cidrs":       anonymizeStringArray(Clusters[0].BoundCidrs),
				"token_explicit_max_ttl":  json.Number("0"),
				"token_max_ttl":           json.Number("0"),
				"token_no_default_policy": false,
				"token_num_uses":          json.Number("0"),
				"token_period":            json.Number("0"),
				"token_policies": []interface{}{
					"core-platform-development-app2",
					"core-platform-development-app3",
				},
				"token_ttl":  json.Number("0"),
				"token_type": "default",
			},
		},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := km.NewPolicy(tc.role, DEV)
			if err != nil {
				log.Printf("Error creating policy: %s", err)
				t.Fail()
			}
			err = km.WriteK8sAuth(tc.cluster, tc.role, tc.role.Realms[0], []string{policy.Name})
			if err != nil {
				fmt.Printf("Failed writing auth: %s", err)
				t.Fail()
			}

			authData, err := km.ReadK8sAuth(tc.cluster, tc.role)
			if err != nil {
				fmt.Printf("Failed reading auth: %s", err)
				t.Fail()
			}

			assert.True(t, reflect.DeepEqual(authData, tc.first))

			err = km.AddPolicyToK8sRole(tc.cluster, tc.role, tc.role.Realms[0], tc.add)
			if err != nil {
				fmt.Printf("Failed adding policy")
				t.Fail()
			}

			authData, err = km.ReadK8sAuth(tc.cluster, tc.role)
			if err != nil {
				fmt.Printf("Failed reading auth: %s", err)
				t.Fail()
			}

			assert.True(t, reflect.DeepEqual(authData, tc.second), "role successfully added")

			err = km.RemovePolicyFromK8sRole(tc.cluster, tc.role, tc.role.Realms[0], tc.add)
			if err != nil {
				fmt.Printf("Failed removing policy")
				t.Fail()
			}

			authData, err = km.ReadK8sAuth(tc.cluster, tc.role)
			if err != nil {
				fmt.Printf("Failed reading auth: %s", err)
				t.Fail()
			}

			assert.True(t, reflect.DeepEqual(authData, tc.first))
		})
	}
}
