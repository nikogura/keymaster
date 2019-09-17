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
				Name:      "bar",
				Namespace: "core-services",
				Generator: AlphaGenerator{
					Type:   "alpha",
					Length: 10,
				},
			},
		},
		Namespace: "core-services",
	}, Dev)
	if err != nil {
		log.Printf("Error creating policy: %s", err)
		t.Fail()
	}

	addPolicy2, err := km.NewPolicy(&Role{
		Name: "app3",
		Secrets: []*Secret{
			{
				Name:      "baz",
				Namespace: "core-platform",
				Generator: AlphaGenerator{
					Type:   "alpha",
					Length: 10,
				},
			},
		},
		Namespace: "core-platform",
	}, Dev)
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
						Name:      "foo",
						Namespace: "core-services",
						Generator: AlphaGenerator{
							Type:   "alpha",
							Length: 10,
						},
					},
				},
				Namespace: "core-services",
			},
			map[string]interface{}{
				"bound_cidrs":                      anonymizeStringArray(Clusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"core-services"},
				"max_ttl":                          json.Number("0"),
				"num_uses":                         json.Number("0"),
				"period":                           json.Number("0"),
				"policies":                         []interface{}{"dev-core-services-app1"},
				"ttl":                              json.Number("0"),
			},
			addPolicy1,
			map[string]interface{}{
				"bound_cidrs":                      anonymizeStringArray(Clusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"core-services"},
				"max_ttl":                          json.Number("0"),
				"num_uses":                         json.Number("0"),
				"period":                           json.Number("0"),
				"policies": []interface{}{
					"dev-core-services-app1",
					"dev-core-services-app2",
				},
				"ttl": json.Number("0"),
			},
		},
		{
			"app2",
			Clusters[0],
			&Role{
				Name: "app2",
				Secrets: []*Secret{
					{
						Name:      "foo",
						Namespace: "core-platform",
						Generator: AlphaGenerator{
							Type:   "alpha",
							Length: 10,
						},
					},
					{
						Name:      "bar",
						Namespace: "core-platform",
						Generator: UUIDGenerator{
							Type: "uuid",
						},
					},
				},
				Namespace: "core-platform",
			},
			map[string]interface{}{
				"bound_cidrs":                      anonymizeStringArray(Clusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"core-platform"},
				"max_ttl":                          json.Number("0"),
				"num_uses":                         json.Number("0"),
				"period":                           json.Number("0"),
				"policies":                         []interface{}{"dev-core-platform-app2"},
				"ttl":                              json.Number("0"),
			},
			addPolicy2,
			map[string]interface{}{
				"bound_cidrs":                      anonymizeStringArray(Clusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"core-platform"},
				"max_ttl":                          json.Number("0"),
				"num_uses":                         json.Number("0"),
				"period":                           json.Number("0"),
				"policies": []interface{}{
					"dev-core-platform-app2",
					"dev-core-platform-app3",
				},
				"ttl": json.Number("0"),
			},
		},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := km.NewPolicy(tc.role, Dev)
			if err != nil {
				log.Printf("Error creating policy: %s", err)
				t.Fail()
			}
			err = km.WriteK8sAuth(tc.cluster, tc.role, []string{policy.Name})
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

			err = km.AddPolicyToK8sRole(tc.cluster, tc.role, tc.add)
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

			err = km.RemovePolicyFromK8sRole(tc.cluster, tc.role, tc.add)
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
