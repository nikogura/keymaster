package keymaster

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"reflect"
	"testing"
)

func TestPolicyName(t *testing.T) {
	inputs := []struct {
		name      string
		roleName  string
		namespace string
		env       Environment
		output    string
	}{
		{
			"role1",
			"foo",
			"core-services",
			Prod,
			"prod-core-services-foo",
		},
		{
			"role2",
			"bar",
			"core-platform",
			Stage,
			"stage-core-platform-bar",
		},
		{
			"role3",
			"baz",
			"core-infra",
			Dev,
			"dev-core-infra-baz",
		},
		{
			"role4",
			"wip",
			"payments",
			17,
			"dev-payments-wip",
		},
	}

	km := NewKeyMaster(testServer.VaultTestClient())

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			path, err := km.PolicyName(tc.roleName, tc.namespace, tc.env)
			if err != nil {
				log.Printf("error creating policy name: %s", err)
				t.Fail()
			}

			assert.Equal(t, tc.output, path, "Created expected policy.")
		})
	}
}

func TestPolicyPath(t *testing.T) {
	km := NewKeyMaster(testServer.VaultTestClient())
	inputs := []struct {
		name string
		role Role
		env  Environment
		out  string
	}{
		{
			"app1",
			Role{
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
			Dev,
			"sys/policy/dev-core-services-app1",
		},
	}

	for _, tc := range inputs {
		path, err := km.PolicyPath(tc.role.Name, tc.role.Namespace, tc.env)
		if err != nil {
			log.Printf("error creating policy name: %s", err)
			t.Fail()
		}
		assert.Equal(t, tc.out, path, "generated policy path looks like what we expect")
	}
}

func TestPolicyPayload(t *testing.T) {
	km := NewKeyMaster(testServer.VaultTestClient())

	path1, err := km.SecretPath("foo", "core-services", Dev)
	if err != nil {
		log.Printf("Failed to create path: %s", err)
		t.Fail()
	}

	path2, err := km.SecretPath("foo", "core-platform", Dev)
	if err != nil {
		log.Printf("Failed to create path: %s", err)
		t.Fail()
	}

	path3, err := km.SecretPath("bar", "core-platform", Dev)
	if err != nil {
		log.Printf("Failed to create path: %s", err)
		t.Fail()
	}

	inputs := []struct {
		name string
		in   *Role
		out  map[string]interface{}
	}{
		{
			"app1",
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
				"path": map[string]interface{}{
					path1: map[string]interface{}{
						"capabilities": []interface{}{
							"read",
						},
					},
					"sys/policy/dev-core-services-app1": map[string]interface{}{
						"capabilities": []interface{}{
							"read",
						},
					},
				},
			},
		},
		{
			"app2",
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
				"path": map[string]interface{}{
					path2: map[string]interface{}{
						"capabilities": []interface{}{
							"read",
						},
					},
					path3: map[string]interface{}{
						"capabilities": []interface{}{
							"read",
						},
					},
					"sys/policy/dev-core-platform-app2": map[string]interface{}{
						"capabilities": []interface{}{
							"read",
						},
					},
				},
			},
		},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := km.MakePolicyPayload(tc.in, Dev)
			if err != nil {
				log.Printf("error creating policy: %s", err)
				t.Fail()
			}
			assert.True(t, reflect.DeepEqual(policy, tc.out), "Generated policy matches expectations")
		})
	}
}

func TestPolicyCrud(t *testing.T) {
	km := NewKeyMaster(testServer.VaultTestClient())

	path1, err := km.SecretPath("foo", "core-services", Dev)
	if err != nil {
		log.Printf("error creating path: %s", err)
		t.Fail()
	}

	pName1, err := km.PolicyName("app1", "core-services", Dev)
	if err != nil {
		log.Printf("error creating policy name: %s", err)
		t.Fail()
	}

	pPath1, err := km.PolicyPath("app1", "core-services", Dev)
	if err != nil {
		log.Printf("error creating policy path: %s", err)
		t.Fail()
	}

	inputs := []struct {
		name string
		in   VaultPolicy
		out  VaultPolicy
	}{
		{
			"policy1",
			VaultPolicy{
				Name: pName1,
				Path: pPath1,
				Payload: map[string]interface{}{
					"path": map[string]interface{}{
						path1: map[string]interface{}{
							"capabilities": []interface{}{
								"read",
							},
						},
						"sys/policy/dev-core-services-app1": map[string]interface{}{
							"capabilities": []interface{}{
								"read",
							},
						},
					},
				},
			},
			VaultPolicy{
				Name: pName1,
				Path: pPath1,
				Payload: map[string]interface{}{
					"path": map[string]interface{}{
						path1: map[string]interface{}{
							"capabilities": []interface{}{
								"read",
							},
						},
						"sys/policy/dev-core-services-app1": map[string]interface{}{
							"capabilities": []interface{}{
								"read",
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range inputs {
		// write
		err := km.WritePolicyToVault(tc.in, true)
		if err != nil {
			fmt.Printf("Policy write error: %s", err)
			t.Fail()
		}

		// read
		policy, err := km.ReadPolicyFromVault(tc.in.Path)
		if err != nil {
			fmt.Printf("Failed to read policy: %s", err)
			t.Fail()
		}

		// compare
		assert.Equal(t, tc.in, policy, "Fetched policy matches what was input")
		// delete
		err = km.DeletePolicyFromVault(tc.in.Path)
		if err != nil {
			fmt.Printf("failed to delete policy: %s", err)
			t.Fail()
		}

		// confirm
		policy, err = km.ReadPolicyFromVault(tc.in.Path)
		if err != nil {
			fmt.Printf("Failed to read policy: %s", err)
			t.Fail()
		}
		assert.True(t, reflect.DeepEqual(policy, VaultPolicy{}), "Policy deleted")
	}
}
