package keymaster

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"reflect"
	"testing"
)

func TestTlsAuthCrud(t *testing.T) {
	km := NewKeyMaster(kmClient)

	policy1, err := km.NewPolicy(&Role{
		Name: "app1",
		Secrets: []*Secret{
			{
				Name:      "foo",
				Namespace: "testns1",
				Generator: AlphaGenerator{
					Type:   "alpha",
					Length: 10,
				},
			},
		},
		Namespace: "testns1",
	}, Prod)
	if err != nil {
		log.Printf("error creating policy: %s", err)
		t.Fail()
	}

	//policy2, err :=
	//	km.NewPolicy(&Role{
	//		Name: "app3",
	//		Secrets: []*Secret{
	//			{
	//				Name:      "baz",
	//				Namespace: "testns2",
	//				Generator: AlphaGenerator{
	//					Type:   "alpha",
	//					Length: 10,
	//				},
	//			},
	//		},
	//		Namespace: "testns2",
	//	}, Prod)
	//if err != nil {
	//	log.Printf("error creating policy: %s", err)
	//	t.Fail()
	//}

	inputs := []struct {
		name   string
		role   *Role
		first  map[string]interface{}
		add    VaultPolicy
		second map[string]interface{}
	}{
		{
			"role1",
			&Role{
				Name: "app1",
				Secrets: []*Secret{
					{
						Name:      "foo",
						Namespace: "testns1",
						Generator: AlphaGenerator{
							Type:   "alpha",
							Length: 10,
						},
					},
				},
				Namespace: "testns1",
			},
			map[string]interface{}{
				"allowed_common_names":         []interface{}{"testbed01.inf.scribd.com"},
				"allowed_dns_sans":             []interface{}{},
				"allowed_email_sans":           []interface{}{},
				"allowed_names":                []interface{}{},
				"allowed_organizational_units": []interface{}{},
				"allowed_uri_sans":             []interface{}{},
				"bound_cidrs":                  []interface{}{"10.171.154.154"},
				"certificate":                  "-----BEGIN CERTIFICATE-----\n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\n8no=\n-----END CERTIFICATE-----",
				"display_name":                 "prod-testns1-app1",
				"max_ttl":                      json.Number("0"),
				"period":                       json.Number("0"),
				"policies": []interface{}{
					"prod-testns1-app1",
				},
				"required_extensions": []interface{}{},
				"ttl":                 json.Number("0"),
			},
			policy1,
			map[string]interface{}{
				"allowed_common_names":         []interface{}{},
				"allowed_dns_sans":             []interface{}{},
				"allowed_email_sans":           []interface{}{},
				"allowed_names":                []interface{}{},
				"allowed_organizational_units": []interface{}{},
				"allowed_uri_sans":             []interface{}{},
				"bound_cidrs":                  []interface{}{},
				"certificate":                  "-----BEGIN CERTIFICATE-----\n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\n8no=\n-----END CERTIFICATE-----",
				"display_name":                 "app1",
				"max_ttl":                      json.Number("0"),
				"period":                       json.Number("0"),
				"policies": []interface{}{
					"prod-testns1-app1",
					"prod-testns1-app2",
				},
				"required_extensions": []interface{}{},
				"ttl":                 json.Number("0"),
			},
		},
		//{
		//	"app2",
		//	&Role{
		//		Name: "app2",
		//		Secrets: []*Secret{
		//			{
		//				Name:      "foo",
		//				Namespace: "testns2",
		//				Generator: AlphaGenerator{
		//					Type:   "alpha",
		//					Length: 10,
		//				},
		//			},
		//			{
		//				Name:      "bar",
		//				Namespace: "testns2",
		//				Generator: UUIDGenerator{
		//					Type: "uuid",
		//				},
		//			},
		//		},
		//		Namespace: "testns2",
		//	},
		//	map[string]interface{}{
		//		"allowed_common_names":         []interface{}{"testbed01.inf.scribd.com"},
		//		"allowed_dns_sans":             []interface{}{},
		//		"allowed_email_sans":           []interface{}{},
		//		"allowed_names":                []interface{}{},
		//		"allowed_organizational_units": []interface{}{},
		//		"allowed_uri_sans":             []interface{}{},
		//		"bound_cidrs":                  []interface{}{"10.171.154.154"},
		//		"certificate":                  "-----BEGIN CERTIFICATE-----\n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\n8no=\n-----END CERTIFICATE-----",
		//		"display_name":                 "app2",
		//		"max_ttl":                      json.Number("0"),
		//		"period":                       json.Number("0"),
		//		"policies": []interface{}{
		//			"dev-testns2-app2",
		//		},
		//		"required_extensions": []interface{}{},
		//		"ttl":                 json.Number("0"),
		//	},
		//	policy2,
		//	map[string]interface{}{
		//		"allowed_common_names":         []interface{}{},
		//		"allowed_dns_sans":             []interface{}{},
		//		"allowed_email_sans":           []interface{}{},
		//		"allowed_names":                []interface{}{},
		//		"allowed_organizational_units": []interface{}{},
		//		"allowed_uri_sans":             []interface{}{},
		//		"bound_cidrs":                  []interface{}{},
		//		"certificate":                  "-----BEGIN CERTIFICATE-----\n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\n8no=\n-----END CERTIFICATE-----",
		//		"display_name":                 "app2",
		//		"max_ttl":                      json.Number("0"),
		//		"period":                       json.Number("0"),
		//		"policies": []interface{}{
		//			"dev-testns2-app2",
		//			"dev-testns2-app3",
		//		},
		//		"required_extensions": []interface{}{},
		//		"ttl":                 json.Number("0"),
		//	},
		//},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := km.NewPolicy(tc.role, Prod)
			if err != nil {
				log.Printf("error creating policy: %s", err)
				t.Fail()
			}
			err = km.WriteTlsAuth(tc.role, Prod, []string{policy.Name})
			if err != nil {
				fmt.Printf("Failed writing auth: %s", err)
				t.Fail()
			}

			authData, err := km.ReadTlsAuth(tc.role, Prod)
			if err != nil {
				fmt.Printf("Failed reading auth: %s", err)
				t.Fail()
			}

			//fmt.Printf("--- Expected ---\n")
			//spew.Dump(tc.first)
			//fmt.Printf("--- Actual ---\n")
			//spew.Dump(authData)

			assert.True(t, reflect.DeepEqual(authData, tc.first))

			err = km.AddPolicyToTlsRole(tc.role, Prod, tc.add)
			if err != nil {
				fmt.Printf("Failed adding policy")
				t.Fail()
			}

			authData, err = km.ReadTlsAuth(tc.role, Prod)
			if err != nil {
				fmt.Printf("Failed reading auth: %s", err)
				t.Fail()
			}

			assert.True(t, reflect.DeepEqual(authData, tc.first), "role successfully added without info being in lda without info being in ldapp")

			// TODO The rest of these crud tests need to have a test ldap directory integrated.
			//assert.True(t, reflect.DeepEqual(authData, tc.second), "role successfully added")

			//err = km.RemovePolicyFromTlsRole(tc.role, Prod, tc.add)
			//if err != nil {
			//	fmt.Printf("Failed removing policy")
			//	t.Fail()
			//}
			//
			//authData, err = km.ReadTlsAuth(tc.role)
			//if err != nil {
			//	fmt.Printf("Failed reading auth: %s", err)
			//	t.Fail()
			//}
			//
			//assert.True(t, reflect.DeepEqual(authData, tc.first))
		})
	}
}
