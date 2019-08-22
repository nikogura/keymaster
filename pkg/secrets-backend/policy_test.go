package secrets_backend

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestPolicyPath(t *testing.T) {
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
				Secrets: []Secret{
					{
						Name: "foo",
						Org:  "core-services",
						Generator: AlphaGenerator{
							Type:   "alpha",
							Length: 10,
						},
					},
				},
				Org: "core-services",
			},
			Dev,
			"sys/policy/dev-core-services-app1",
		},
	}

	for _, tc := range inputs {
		path := PolicyPath(tc.role.Name, tc.role.Org, tc.env)
		assert.Equal(t, tc.out, path, "generated policy path looks like what we expect")
	}
}

func TestPolicyPayload(t *testing.T) {
	inputs := []struct {
		name string
		in   Role
		out  map[string]interface{}
	}{
		{
			"app1",
			Role{
				Name: "app1",
				Secrets: []Secret{
					{
						Name: "foo",
						Org:  "core-services",
						Generator: AlphaGenerator{
							Type:   "alpha",
							Length: 10,
						},
					},
				},
				Org: "core-services",
			},
			map[string]interface{}{
				"path": map[string]interface{}{
					SecretPath("foo", "core-services", Dev): map[string]interface{}{
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
			Role{
				Name: "app2",
				Secrets: []Secret{
					{
						Name: "foo",
						Org:  "core-platform",
						Generator: AlphaGenerator{
							Type:   "alpha",
							Length: 10,
						},
					},
					{
						Name: "bar",
						Org:  "core-platform",
						Generator: UUIDGenerator{
							Type: "uuid",
						},
					},
				},
				Org: "core-platform",
			},
			map[string]interface{}{
				"path": map[string]interface{}{
					SecretPath("foo", "core-platform", Dev): map[string]interface{}{
						"capabilities": []interface{}{
							"read",
						},
					},
					SecretPath("bar", "core-platform", Dev): map[string]interface{}{
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
			policy := MakePolicyPayload(tc.in, Dev)
			assert.True(t, reflect.DeepEqual(policy, tc.out), "Generated policy matches expectations")
		})
	}
}

func TestPolicyCrud(t *testing.T) {
	inputs := []struct {
		name string
		in   VaultPolicy
		out  VaultPolicy
	}{
		{
			"policy1",
			VaultPolicy{
				Name: PolicyName("app1", "core-services", Dev),
				Path: PolicyPath("app1", "core-services", Dev),
				Payload: map[string]interface{}{
					"path": map[string]interface{}{
						SecretPath("foo", "core-services", Dev): map[string]interface{}{
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
				Name: PolicyName("app1", "core-services", Dev),
				Path: PolicyPath("app1", "core-services", Dev),
				Payload: map[string]interface{}{
					"path": map[string]interface{}{
						SecretPath("foo", "core-services", Dev): map[string]interface{}{
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

	client := testServer.VaultTestClient()

	for _, tc := range inputs {
		// write
		err := WritePolicyToVault(tc.in, client)
		if err != nil {
			fmt.Printf("Policy write error: %s", err)
			t.Fail()
		}

		// read
		policy, err := ReadPolicyFromVault(tc.in.Path, client)
		if err != nil {
			fmt.Printf("Failed to read policy: %s", err)
			t.Fail()
		}

		// compare
		assert.Equal(t, tc.in, policy, "Fetched policy matches what was input")
		// delete
		err = DeletePolicyFromVault(tc.in.Path, client)
		if err != nil {
			fmt.Printf("failed to delete policy: %s", err)
			t.Fail()
		}

		// confirm
		policy, err = ReadPolicyFromVault(tc.in.Path, client)
		if err != nil {
			fmt.Printf("Failed to read policy: %s", err)
			t.Fail()
		}
		assert.True(t, reflect.DeepEqual(policy, VaultPolicy{}), "Policy deleted")
	}
}