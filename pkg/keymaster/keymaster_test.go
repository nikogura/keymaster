package keymaster

import (
	"fmt"
	"git.lo/ops/vaulttest/pkg/vaulttest"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
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
		_, err := client.Logical().Write("sys/mounts/service", data)
		if err != nil {
			log.Fatalf("Failed to create 'service' pki secrets engine: %s", err)
		}

		data = map[string]interface{}{
			"common_name": "test-ca",
			"ttl":         "43800h",
		}
		_, err = client.Logical().Write("service/root/generate/internal", data)
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
		_, err = client.Logical().Write("service/roles/keymaster", data)
		if err != nil {
			log.Fatalf("Failed to create cert issuing role: %s", err)
		}

		data = map[string]interface{}{
			"type":        "cert",
			"description": "TLS Cert Auth endpoint",
		}

		_, err = client.Logical().Write("sys/auth/cert", data)
		if err != nil {
			log.Fatalf("Failed to enable TLS cert auth: %s", err)
		}

	}
}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		os.Remove(tmpDir)
	}

	testServer.ServerShutDown()
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
		{
			"slash-in-ns",
			`---
name: foo/bar
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
			ERR_SLASH_IN_NAMESPACE,
		},
		{
			"slash-in-role",
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
  - name: foo/bar
    realms: 
      - k8s
    secrets:
      - name: foo
      - name: bar
      - name: baz
        namespace: core-infra`,
			ERR_SLASH_IN_ROLE_NAME,
		},
		{
			"unsupported-realm",
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
      - foo
    secrets:
      - name: foo
      - name: bar
      - name: baz
        namespace: core-infra`,
			ERR_UNSUPPORTED_REALM,
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

func TestNameToEnvironment(t *testing.T) {
	inputs := []struct {
		in  string
		out Environment
	}{
		{
			"prod",
			Prod,
		},
		{
			"stage",
			Stage,
		},
		{
			"dev",
			Dev,
		},
	}

	for _, tc := range inputs {
		t.Run(tc.in, func(t *testing.T) {
			env, err := NameToEnvironment(tc.in)
			if err != nil {
				log.Printf("Error: %s", err)
				t.Fail()
			}
			assert.Equal(t, env, tc.out, "outputted environment matches expectations")
		})
	}
}

func TestConfigureNamespace(t *testing.T) {
	inputFile := `---
name: redns
secrets:
  - name: foo
    generator:
      type: alpha
      length: 10

  - name: bar
    generator:
      type: hex
      length: 12

  - name: baz
    generator:
      type: uuid

  - name: wip
    generator:
      type: chbs
      words: 6

  - name: foo.scribd.com
    generator:
      type: tls
      cn: foo.scribd.com
      ca: service
      sans:
        - bar.scribd.com
        - baz.scribd.com

roles:
  - name: app1
    realms:
      - k8s
    secrets:
      - name: foo
      - name: wip
      - name: baz
        namespace: bluens
`

	km := NewKeyMaster(testServer.VaultTestClient())

	certheader := regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)
	keyheader := regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`)

	ns, err := km.NewNamespace([]byte(inputFile))
	if err != nil {
		log.Printf("Failed to load namespace: %s", err)
		t.Fail()
	} else {
		err = km.ConfigureNamespace(ns)
		if err != nil {
			log.Printf("Failed to configure namespace: %s", err)
			t.Fail()
		}

		for _, env := range Envs {
			// Check Secrets
			for _, secret := range ns.Secrets {
				var path string
				if secret.GeneratorData["type"] == "tls" {
					path = km.CertPath(secret.Name, secret.Namespace, env)

					s, err := km.VaultClient.Logical().Read(path)
					if err != nil {
						log.Printf("Unable to read %q: %s\n", path, err)
						t.Fail()
					}
					if s == nil {
						log.Printf("Nil secret at %s\n", path)
						t.Fail()
					} else {
						data, ok := s.Data["data"].(map[string]interface{})
						if ok {
							cert, ok := data["certificate"].(string)
							if !ok {
								log.Printf("Non-string stored as a certificate at %s", path)
								t.Fail()
							}

							assert.True(t, certheader.MatchString(cert))

							key, ok := data["private_key"].(string)
							if !ok {
								log.Printf("Non-string stored as a private_key at %s", path)
								t.Fail()
							}

							assert.True(t, keyheader.MatchString(key))
						}
					}

				} else {
					path = km.SecretPath(secret.Name, secret.Namespace, env)

					s, err := km.VaultClient.Logical().Read(path)
					if err != nil {
						log.Printf("Unable to read %q: %s\n", path, err)
						t.Fail()
					}
					if s == nil {
						log.Printf("Nil secret at %s\n", path)
						t.Fail()
					} else {
						data, ok := s.Data["data"].(map[string]interface{})
						if ok {
							value, ok := data["value"].(string)
							if !ok {
								log.Printf("Non-string stored as a secret at %s", path)
								t.Fail()
							}
							assert.True(t, value != "", "Autogenerated secret has a value")
						}
					}
				}
			}

			for _, role := range ns.Roles {
				// Check Policies
				policy := km.NewPolicy(role, env)

				readPolicy, err := km.ReadPolicyFromVault(policy.Path)
				if err != nil {
					fmt.Printf("Failed to read policy: %s", err)
					t.Fail()
				}

				assert.True(t, reflect.DeepEqual(policy.Payload, readPolicy.Payload), "payload meets expectations")

				// Check Auth configs
				for _, realm := range role.Realms {
					switch realm {
					case K8S_NAME:
						for _, cluster := range ClustersByEnvironment[env] {
							_, err := km.ReadK8sAuth(cluster, role)
							if err != nil {
								log.Printf("failed to read k8s policy for %s and %s", cluster.Name, role.Name)
								t.Fail()
							}

							// Not worried about parsing auth data, as input-> output verification is handled in the unit test
							//log.Printf("K8s Role Data for %s %s:", cluster.Name, role.Name)
							//spew.Dump(data)
						}
					case SL_NAME:
						_, err := km.ReadTlsAuth(role)
						if err != nil {
							log.Printf("failed to read tls policy for %s", role.Name)
							t.Fail()
						}

					case AWS_NAME:
						// TODO Add AWS Auth config when implemented
					default:
						log.Printf("Unsupported Realm: %s", realm)
						t.Fail()
					}
				}
			}
		}
	}
}
