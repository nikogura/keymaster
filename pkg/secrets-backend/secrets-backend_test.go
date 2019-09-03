package secrets_backend

import (
	"fmt"
	"git.lo/ops/vaulttest/pkg/vaulttest"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"testing"
	"time"
)

var tmpDir string
var testServer *vaulttest.VaultDevServer

func TestMain(m *testing.M) {
	setUp()

	code := m.Run()

	tearDown()

	os.Exit(code)
}

func setUp() {
	dir, err := ioutil.TempDir("", "psst")
	if err != nil {
		fmt.Printf("Error creating temp dir %q: %s\n", tmpDir, err)
		os.Exit(1)
	}

	tmpDir = dir

	port, err := freeport.GetFreePort()
	if err != nil {
		log.Fatalf("Failed to get a free port on which to run the test vault server: %s", err)
	}

	testAddress := fmt.Sprintf("127.0.0.1:%d", port)

	testServer = vaulttest.NewVaultDevServer(testAddress)

	if !testServer.Running {
		testServer.ServerStart()
		// configure the secret backends
		client := testServer.VaultTestClient()

		for _, endpoint := range []string{
			"prod",
			"stage",
			"dev",
		} {
			data := map[string]interface{}{
				"type":        "kv-v2",
				"description": "Production Secrets",
			}
			_, err := client.Logical().Write(fmt.Sprintf("sys/mounts/%s", endpoint), data)
			if err != nil {
				log.Fatalf("Unable to create secret engine %q: %s", endpoint, err)
			}
		}

		for _, cluster := range Clusters {
			data := map[string]interface{}{
				"type":        "kubernetes",
				"description": fmt.Sprintf("Kubernetes Cluster %s", cluster.Name),
			}

			_, err := client.Logical().Write(fmt.Sprintf("sys/auth/%s", cluster.Name), data)
			if err != nil {
				log.Fatalf("Failed to enable k8s auth at %s: %s", cluster.Name, err)
			}
		}
	}
}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		os.Remove(tmpDir)
	}

	testServer.ServerShutDown()
}

func TestSecretPath(t *testing.T) {
	var inputs = []struct {
		name       string
		secretName string
		secretOrg  string
		env        Environment
		output     string
	}{
		{
			"secret1",
			"foo",
			"core-services",
			Prod,
			"prod/data/core-services/foo",
		},
		{
			"secret2",
			"bar",
			"core-platform",
			Stage,
			"stage/data/core-platform/bar",
		},
		{
			"secret3",
			"baz",
			"core-infra",
			Dev,
			"dev/data/core-infra/baz",
		},
		{
			"secret4",
			"wip",
			"payments",
			17,
			"dev/data/payments/wip",
		},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			path := SecretPath(tc.secretName, tc.secretOrg, tc.env)

			assert.Equal(t, tc.output, path, "Created expected path.")
		})
	}
}

func TestPolicyName(t *testing.T) {
	var inputs = []struct {
		name     string
		roleName string
		orgName  string
		env      Environment
		output   string
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

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			path := PolicyName(tc.roleName, tc.orgName, tc.env)

			assert.Equal(t, tc.output, path, "Created expected policy.")
		})
	}
}

func TestWriteSecretIfBlank(t *testing.T) {
	var inputs = []struct {
		name string
		in   *Secret
		out  *regexp.Regexp
	}{
		{
			"foo",
			&Secret{
				Name: "foo",
				Org:  "core-platform",
				GeneratorData: GeneratorData{
					"type":   "alpha",
					"length": 10,
				},
			},
			regexp.MustCompile(`[a-zA-Z0-9]{10}`),
		},
		{
			"bar",
			&Secret{
				Name: "bar",
				Org:  "core-services",
				GeneratorData: GeneratorData{
					"type":   "hex",
					"length": 32,
				},
			},
			regexp.MustCompile(`[a-f0-9]{32}`),
		},
		{
			"wip",
			&Secret{
				Name: "wip",
				Org:  "core-infra",
				GeneratorData: GeneratorData{
					"type": "uuid",
				},
			},
			regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`),
		},
		{
			"zoz",
			&Secret{
				Name: "zoz",
				Org:  "payments",
				GeneratorData: GeneratorData{
					"type":  "chbs",
					"words": 6,
				},
			},
			regexp.MustCompile(`\w+-\w+-\w+-\w+-\w+-\w+`),
		},
	}

	client := testServer.VaultTestClient()

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			secret := tc.in
			g, err := NewGenerator(secret.GeneratorData)
			if err != nil {
				log.Printf("Error creating generator %q: %s", tc.name, err)
				t.Fail()
			}

			secret.SetGenerator(g)

			err = WriteSecretIfBlank(client, tc.in)
			if err != nil {
				log.Printf("Failed to write secret %q: %s\n", secret.Name, err)
				t.Fail()
			} else {
				// give the write a moment to propagate.  If we hit vault directly the secret may not be there yet.
				time.Sleep(time.Second)
				for _, env := range Envs {
					path := SecretPath(secret.Name, secret.Org, env)
					s, err := client.Logical().Read(path)
					if err != nil {
						log.Printf("Unable to read %q: %s\n", path, err)
						t.Fail()
					}
					if s == nil {
						log.Printf("Nill secret at %s\n", path)
						t.Fail()
					} else {
						secretData, ok := s.Data["data"].(map[string]interface{})
						if ok {
							value, ok := secretData["value"].(string)
							if ok {
								assert.True(t, tc.out.MatchString(value), "Stored secret meets expectations")
							} else {
								fmt.Printf("Secret value at %s is not a string\n", path)
								t.Fail()
							}

						}
					}
				}
				// Uncomment the following to debug manually
				//fmt.Printf("VAULT_TOKEN=%s VAULT_ADDR=http://%s\n", testServer.RootToken, testServer.Address)
				//time.Sleep(10 * time.Minute)
			}
		})

		input := inputs[0]
		expected := make([]string, 0)

		for _, env := range Envs {
			path := SecretPath(input.in.Name, input.in.Org, env)
			s, err := client.Logical().Read(path)
			if err != nil {
				log.Printf("Unable to read %q: %s\n", path, err)
				t.Fail()
			}
			if s == nil {
				log.Printf("Nill secret at %s\n", path)
				t.Fail()
			} else {
				secretData, ok := s.Data["data"].(map[string]interface{})
				if ok {
					value, ok := secretData["value"].(string)
					if ok {
						expected = append(expected, value)
					} else {
						fmt.Printf("Secret value at %s is not a string\n", path)
						t.Fail()
					}
				}
			}
		}

		err := WriteSecretIfBlank(client, input.in)
		if err != nil {
			log.Printf("Failed to write secret %q: %s\n", input.in.Name, err)
			t.Fail()
		}
		for _, env := range Envs {
			path := SecretPath(input.in.Name, input.in.Org, env)
			s, err := client.Logical().Read(path)
			if err != nil {
				log.Printf("Unable to read %q: %s\n", path, err)
				t.Fail()
			}
			if s == nil {
				log.Printf("Nill secret at %s\n", path)
				t.Fail()
			} else {
				secretData, ok := s.Data["data"].(map[string]interface{})
				if ok {
					value, ok := secretData["value"].(string)
					if ok {
						assert.Equal(t, expected[env-1], value, "Secrets don't overwrite if already set")
					} else {
						fmt.Printf("Secret value at %s is not a string\n", path)
						t.Fail()
					}
				}
			}
		}
	}
}
