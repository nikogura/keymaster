package secrets_backend

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func anonymizeStringArray(input []string) (output []interface{}) {
	output = make([]interface{}, 0)
	for _, i := range input {
		output = append(output, i)
	}

	return output
}

func TestAuthCrud(t *testing.T) {
	inputs := []struct {
		name    string
		cluster Cluster
		role    Role
		out     map[string]interface{}
	}{
		{
			"app1",
			Clusters[0],
			Role{
				Name: "app1",
				Secrets: []Secret{
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
		},
		{
			"app2",
			Clusters[0],
			Role{
				Name: "app2",
				Secrets: []Secret{
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
		},
	}

	client := testServer.VaultTestClient()

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			err := WriteK8sAuth(tc.cluster, tc.role, NewPolicy(tc.role, Dev), client)
			if err != nil {
				fmt.Printf("Failed writing auth: %s", err)
				t.Fail()
			}

			authData, err := ReadK8sAuth(tc.cluster.Name, tc.role, client)
			if err != nil {
				fmt.Printf("Failed reading auth: %s", err)
				t.Fail()
			}

			assert.True(t, reflect.DeepEqual(authData, tc.out))
		})
	}
}
