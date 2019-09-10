package keymaster

import (
	"fmt"
	"git.lo/ops/vaulttest/pkg/vaulttest"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
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

		data := map[string]interface{}{
			"type":        "pki",
			"description": "PKI backend",
		}
		_, err := client.Logical().Write("sys/mounts/pki", data)
		if err != nil {
			log.Fatalf("Failed to create pki secrets engine: %s", err)
		}

		data = map[string]interface{}{
			"common_name": "test-ca",
			"ttl":         "43800h",
		}
		_, err = client.Logical().Write("pki/root/generate/internal", data)
		if err != nil {
			log.Fatalf("Failed to create root cert: %s", err)
		}

		data = map[string]interface{}{
			"max_ttl":         "24h",
			"ttl":             "24h",
			"allow_ip_sans":   true,
			"allow_localhost": true,
			"allow_any_name":  true,
		}
		_, err = client.Logical().Write("pki/roles/keymaster", data)
		if err != nil {
			log.Fatalf("Failed to create cert issuing role: %s", err)
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
	inputs := []struct {
		name       string
		secretName string
		namespace  string
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
			path := SecretPath(tc.secretName, tc.namespace, tc.env)

			assert.Equal(t, tc.output, path, "Created expected path.")
		})
	}
}

func TestCertPath(t *testing.T) {
	inputs := []struct {
		name       string
		secretName string
		namespace  string
		env        Environment
		output     string
	}{
		{
			"cert1",
			"foo",
			"red",
			Prod,
			"prod/data/certs/red/foo",
		},
		{
			"cert2",
			"bar",
			"green",
			Stage,
			"stage/data/certs/green/bar",
		},
		{
			"cert3",
			"baz",
			"blue",
			Dev,
			"dev/data/certs/blue/baz",
		},
		{
			"cert4",
			"wip",
			"payments",
			17,
			"dev/data/certs/payments/wip",
		},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			path := CertPath(tc.secretName, tc.namespace, tc.env)

			assert.Equal(t, tc.output, path, "Created expected path.")
		})
	}
}

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

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			path := PolicyName(tc.roleName, tc.namespace, tc.env)

			assert.Equal(t, tc.output, path, "Created expected policy.")
		})
	}
}

func TestWriteSecretIfBlank(t *testing.T) {
	inputs := []struct {
		name string
		in   *Secret
		out  *regexp.Regexp
	}{
		{
			"foo",
			&Secret{
				Name:      "foo",
				Namespace: "core-platform",
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
				Name:      "bar",
				Namespace: "core-services",
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
				Name:      "wip",
				Namespace: "core-infra",
				GeneratorData: GeneratorData{
					"type": "uuid",
				},
			},
			regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`),
		},
		{
			"zoz",
			&Secret{
				Name:      "zoz",
				Namespace: "payments",
				GeneratorData: GeneratorData{
					"type":  "chbs",
					"words": 6,
				},
			},
			regexp.MustCompile(`\w+-\w+-\w+-\w+-\w+-\w+`),
		},
		{
			"foo.scribd.com",
			&Secret{
				Name:      "",
				Namespace: "chartreuse",
				GeneratorData: GeneratorData{
					"type": "tls",
					"cn":   "foo.scribd.com",
					"ca":   "pki",
				},
			},
			regexp.MustCompile(`.+`),
		},
	}

	km := NewKeyMaster(testServer.VaultTestClient())

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			secret := tc.in
			g, err := km.NewGenerator(secret.GeneratorData)
			if err != nil {
				log.Printf("Error creating generator %q: %s", tc.name, err)
				t.Fail()
			}

			secret.SetGenerator(g)

			err = km.WriteSecretIfBlank(tc.in)
			if err != nil {
				log.Printf("Failed to write secret %q: %s\n", secret.Name, err)
				t.Fail()
			} else {
				// give the write a moment to propagate.  If we hit vault directly the secret may not be there yet.
				time.Sleep(time.Second)
				for _, env := range Envs {
					var path string
					if secret.GeneratorData["type"] == "tls" {
						path = CertPath(secret.Name, secret.Namespace, env)
					} else {
						path = SecretPath(secret.Name, secret.Namespace, env)
					}

					s, err := km.VaultClient.Logical().Read(path)
					if err != nil {
						log.Printf("Unable to read %q: %s\n", path, err)
						t.Fail()
					}
					if s == nil {
						log.Printf("Nil secret at %s\n", path)
						t.Fail()
					} else {
						secretData, ok := s.Data["data"].(map[string]interface{})
						if ok {

							if secret.GeneratorData["type"] == "tls" {
								_, ok := secretData["certificate"]
								if !ok {
									fmt.Printf("No Certificate stored for %s\n", secret.Name)
									t.Fail()
								}
								_, ok = secretData["private_key"]
								if !ok {
									fmt.Printf("No key stored for %s\n", secret.Name)
									t.Fail()
								}

							} else {
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
				}
				// Uncomment the following to debug manually
				//fmt.Printf("VAULT_TOKEN=%s VAULT_ADDR=http://%s\n", testServer.RootToken, testServer.Address)
				//time.Sleep(10 * time.Minute)
			}
		})

		input := inputs[0]
		expected := make([]string, 0)

		for _, env := range Envs {
			path := SecretPath(input.in.Name, input.in.Namespace, env)
			s, err := km.VaultClient.Logical().Read(path)
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

		err := km.WriteSecretIfBlank(input.in)
		if err != nil {
			log.Printf("Failed to write secret %q: %s\n", input.in.Name, err)
			t.Fail()
		}
		for _, env := range Envs {
			path := SecretPath(input.in.Name, input.in.Namespace, env)
			s, err := km.VaultClient.Logical().Read(path)
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

func TestNewNamespace(t *testing.T) {
	inputs := []struct {
		name string
		in   string
		out  string
	}{
		{
			"good-ns",
			`---
name: test-ns
secrets:
  - name: foo
    generator: 
      type: alpha
      length: 8
  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - name: app1
    realms: 
      - k8s
    secrets:
      - name: foo
      - name: bar
      - name: baz
        namespace: core-infra`,
			"",
		},
		{
			"name-ns",
			`---
secrets:
  - name: foo
    generator: 
      type: alpha
      length: 8

  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - name: app1
    realms: 
      - sl
    secrets:
      - name: foo
      - name: bar
      - name: baz
        namespace: core-infra`,
			ERR_NAMELESS_NS,
		},
		{
			"nameless-role",
			`---
name: test-ns
secrets:
  - name: foo
    generator: 
      type: alpha
      length: 8

  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - realms: 
      - k8s
    secrets:
      - name: foo
      - name: bar
      - name: baz
        namespace: core-infra`,
			ERR_NAMELESS_ROLE,
		},
		{
			"missing-secret",
			`---
name: test-ns
secrets:
  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - name: app1
    realms: 
      - sl
    secrets:
      - name: foo
      - name: wip
      - name: baz
        namespace: core-infra`,
			ERR_MISSING_SECRET,
		},
		{
			"garbage",
			`asd;lkfjqw4p9rui4tw`,
			ERR_NS_DATA_LOAD,
		},
		{
			"missing-generator",
			`---
name: test-ns
secrets:
  - name: foo
  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - name: app1
    realms:
      - k8s
    secrets:
      - name: foo
      - name: wip
      - name: baz
        namespace: core-infra`,
			ERR_MISSING_GENERATOR,
		},
		{
			"nameless secret",
			`---
name: test-ns
secrets:
  - name: foo
    generator: 
      type: alpha
      length: 8

  - generator:
      type: hex
      length: 12
roles:
  - name: app1
    realms: 
      - k8s
    secrets:
      - name: foo
      - name: wip
      - name: baz
        namespace: core-infra`,
			ERR_NAMELESS_SECRET,
		},
		{
			"empty realms role",
			`---
name: test-ns
secrets:
  - name: foo
    generator: 
      type: alpha
      length: 8

  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - name: app1
    realms: 
    secrets:
      - name: foo
      - name: wip
      - name: baz
        namespace: core-infra`,
			ERR_REALMLESS_ROLE,
		},
		{
			"realmless role",
			`---
name: test-ns
secrets:
  - name: foo
    generator: 
      type: alpha
      length: 8

  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - name: app1
    realms: 
    secrets:
      - name: foo
      - name: wip
      - name: baz
        namespace: core-infra`,
			ERR_REALMLESS_ROLE,
		},
	}
	km := NewKeyMaster(testServer.VaultTestClient())

	for _, tt := range inputs {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.in)
			_, err := km.NewNamespace(data)
			errstr := ""
			if err != nil {
				errstr = err.Error()
			}
			if tt.out == "" && errstr != "" {
				log.Printf("Error on %s expected %q, got %q", tt.name, tt.out, errstr)
				t.Fail()
			} else {
				if !strings.HasPrefix(errstr, tt.out) {
					log.Printf("Error on %s expected %q, got %q", tt.name, tt.out, errstr)
					t.Fail()
				}
			}
		})
	}
}
