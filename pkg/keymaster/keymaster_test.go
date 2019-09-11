package keymaster

import (
	"fmt"
	"git.lo/ops/vaulttest/pkg/vaulttest"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
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
