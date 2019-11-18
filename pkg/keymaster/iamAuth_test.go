package keymaster

import (
	"fmt"
	"github.com/scribd/vaultlibs/pkg/vaultlibs"
	"github.com/stretchr/testify/assert"
	"log"
	"os"
	"testing"
)

func TestIamAuthCrud(t *testing.T) {
	km := NewKeyMaster(kmClient)

	// Test AWS ARN from environment
	testArn := os.Getenv("TEST_ARN")

	fmt.Printf("Test ARN: %s\n", testArn)

	testArnList := AnonymizeStringArray([]string{testArn})

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
	}, "development")
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
	}, "development")
	if err != nil {
		log.Printf("Error creating policy: %s", err)
		t.Fail()
	}

	inputs := []struct {
		name   string
		role   *Role
		first  map[string]interface{}
		add    VaultPolicy
		second map[string]interface{}
	}{
		{
			"app1",
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
						Type:       "iam",
						Principals: []string{testArn},
					},
				},
			},
			map[string]interface{}{
				"auth_type":               "iam",
				"bound_iam_principal_arn": testArnList,
				"policies": []interface{}{
					"core-services-app1-development",
				},
			},
			addPolicy1,
			map[string]interface{}{
				"auth_type":               "iam",
				"bound_iam_principal_arn": testArnList,
				"policies": []interface{}{
					"core-services-app1-development",
					"core-services-app2-development",
				},
			},
		},
		{
			"app2",
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
						Type:       "iam",
						Principals: []string{testArn},
					},
				},
			},
			map[string]interface{}{
				"auth_type":               "iam",
				"bound_iam_principal_arn": testArnList,
				"policies": []interface{}{
					"core-platform-app2-development",
				},
			},
			addPolicy2,
			map[string]interface{}{
				"auth_type":               "iam",
				"bound_iam_principal_arn": testArnList,
				"policies": []interface{}{
					"core-platform-app2-development",
					"core-platform-app3-development",
				},
			},
		},
	}

	awsRegion := vaultlibs.GetAwsRegion(true)

	// don't run tests if we cannot get the aws region (means we're not running in aws)
	if awsRegion != "" {
		fmt.Printf("--- Running in AWS.  Running IAM Auth tests ---")
		for _, tc := range inputs {
			t.Run(tc.name, func(t *testing.T) {
				policy, err := km.NewPolicy(tc.role, "development")
				if err != nil {
					log.Printf("Error creating policy: %s\n", err)
					t.Fail()
				}
				err = km.WriteIamAuth(tc.role, tc.role.Realms[0], []string{policy.Name})
				if err != nil {
					fmt.Printf("Failed writing auth: %s\n", err)
					t.Fail()
				}

				authData, err := km.ReadIamAuth(tc.role)
				if err != nil {
					fmt.Printf("Failed reading auth\n: %s", err)
					t.Fail()
				}

				matchKeys := []string{
					"auth_type",
					"bound_iam_principal_arn",
					"policies",
				}

				err = PartialMatch(matchKeys, tc.first, authData)
				if err != nil {
					fmt.Printf("Initial values do not meet expectations: %s\n", err)
					t.Fail()
					return
				}

				err = km.AddPolicyToIamRole(tc.role, tc.role.Realms[0], tc.add)
				if err != nil {
					fmt.Printf("Failed adding policy\n")
					t.Fail()
					return
				}

				authData, err = km.ReadIamAuth(tc.role)
				if err != nil {
					fmt.Printf("Failed reading auth: %s\n", err)
					t.Fail()
					return
				}

				err = PartialMatch(matchKeys, tc.second, authData)
				if err != nil {
					fmt.Printf("Failed adding policy to role: %s\n", err)
					t.Fail()
					return
				}

				err = km.RemovePolicyFromIamRole(tc.role, tc.role.Realms[0], tc.add)
				if err != nil {
					fmt.Printf("Failed removing policy\n")
					t.Fail()
					return
				}

				authData, err = km.ReadIamAuth(tc.role)
				if err != nil {
					fmt.Printf("Failed reading auth: %s\n", err)
					t.Fail()
					return
				}

				err = PartialMatch(matchKeys, tc.first, authData)
				if err != nil {
					fmt.Printf("Failed to remove policy from role: %s\n", err)
					t.Fail()
					return
				}
			})
		}

	} else {
		assert.True(t, awsRegion == "", "aws region detection confused.")
		fmt.Printf("--- Not running in AWS.  IAM Auth tests will not be performed ---\n")
	}
	// this nonsense test makes sure this test file runs at least 1 test, which stops some test runners from being confused when run outside of AWS.
	assert.True(t, 1 == 1, "Houston, we have a problem.")
}

/* Example Policy Output

allow_instance_migration          false
auth_type                         iam
bound_account_id                  []
bound_ami_id                      []
bound_ec2_instance_id             <nil>
bound_iam_instance_profile_arn    []
bound_iam_principal_arn           [arn:aws:iam::130231011399:role/fargle-role20191025175930670600000001]
bound_iam_principal_id            [AROAR4US7RBD4KMWR4AIP]
bound_iam_role_arn                []
bound_region                      []
bound_subnet_id                   []
bound_vpc_id                      []
disallow_reauthentication         false
inferred_aws_region               n/a
inferred_entity_type              n/a
max_ttl                           500h
policies                          [test]
resolve_aws_unique_ids            true
role_id                           e2f414ff-2807-81d8-dd4c-24b1e18ad423
role_tag                          n/a
token_bound_cidrs                 []
token_explicit_max_ttl            0s
token_max_ttl                     500h
token_no_default_policy           false
token_num_uses                    0
token_period                      0s
token_policies                    [test]
token_ttl                         0s
token_type                        default

*/
