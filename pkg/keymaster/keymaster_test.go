package keymaster

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"git.lo/ops/vaulttest/pkg/vaulttest"
	"github.com/hashicorp/vault/api"
	"github.com/phayes/freeport"
	"github.com/pkg/errors"
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
var kmClient *api.Client
var rootClient *api.Client

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

			_, err := client.Logical().Write(fmt.Sprintf("sys/auth/k8s-%s", cluster.Name), data)
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

		err = WriteKeyMasterPolicy(client)
		if err != nil {
			log.Fatalf("Failed to write keymaster policy: %s", err)
		}

		rootClient = testServer.VaultTestClient()
		data = make(map[string]interface{})
		data["policies"] = []string{"keymaster"}
		data["no_parent"] = true

		s, err := rootClient.Logical().Write("/auth/token/create-orphan", data)
		if err != nil {
			log.Fatalf("failed to create token for test: %s", err)
		}

		kmToken := s.Auth.ClientToken

		kmClient, err = rootClient.Clone()
		if err != nil {
			log.Fatalf("Failed to clone vault client: %s", err)
		}

		kmClient.SetToken(kmToken)

		ks, _ := kmClient.Auth().Token().LookupSelf()
		policies, ok := ks.Data["policies"].([]interface{})
		if ok {
			log.Printf("--- Policies on Keymaster Token: ---")
			for _, policy := range policies {
				log.Printf("  %s\n", policy)
			}
		}

		s, err = kmClient.Logical().Read("sys/policy/keymaster")
		if err != nil {
			log.Fatalf("Failed to lookup policy: %s", err)
		}

		rules, ok := s.Data["rules"].(string)
		if ok {
			var rulesObj map[string]interface{}
			err := json.Unmarshal([]byte(rules), &rulesObj)
			if err != nil {
				log.Fatalf("failed to unmarshal rules string into json: %s", err)
			}

			jb, err := json.MarshalIndent(rulesObj, "", "  ")
			if err != nil {
				log.Printf("failed to marshal rules back into json: %s", err)

			}
			log.Printf("--- Rules ---")
			log.Printf("%s", string(jb))
		}
	}
}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		os.Remove(tmpDir)
	}

	testServer.ServerShutDown()
}

func WriteKeyMasterPolicy(client *api.Client) (err error) {
	paths := []string{
		"prod/*",
		"stage/*",
		"dev/*",
		"sys/policy/*",
		"auth/cert/certs/*",
		"service/issue/keymaster",
	}

	for _, cluster := range Clusters {
		paths = append(paths, fmt.Sprintf("auth/k8s-%s/*", cluster.Name))
	}

	policy := make(map[string]interface{})
	pathElem := make(map[string]interface{})
	capabilities := []interface{}{
		"create",
		"read",
		"update",
		"delete",
		"list",
	}

	for _, path := range paths {
		pathPolicy := map[string]interface{}{"capabilities": capabilities}
		pathElem[path] = pathPolicy

	}

	policy["path"] = pathElem

	// policies are not normal writes, and a royal pain the butt.  Thank you Mitch.
	jsonBytes, err := json.Marshal(policy)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal keymaster payload")
		return err
	}

	payload := string(jsonBytes)

	payload = base64.StdEncoding.EncodeToString(jsonBytes)

	body := map[string]string{
		"policy": payload,
	}

	reqPath := fmt.Sprintf("/v1/sys/policy/keymaster")

	r := client.NewRequest("PUT", reqPath)
	if err := r.SetJSONBody(body); err != nil {
		err = errors.Wrapf(err, "failed to set json body on request")
		return err
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	resp, err := client.RawRequestWithContext(ctx, r)
	if err != nil {
		err = errors.Wrapf(err, "policy set request failed")
		return err
	}

	defer resp.Body.Close()

	return err
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
	km := NewKeyMaster(kmClient)

	for _, tt := range inputs {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.in)
			_, err := km.NewTeam(data, true)
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

func TestConfigureNamespace(t *testing.T) {
	inputFile1 := `---
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
      - sl
    secrets:
      - name: foo
      - name: wip
      - name: baz
        namespace: bluens
`
	inputFile2 := `---
name: greenns
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
      - sl
    secrets:
      - name: foo
      - name: wip
      - name: baz
        namespace: redns
`
	inputFile3 := `---
name: bluens
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
      - sl
    secrets:
      - name: foo
      - name: wip
      - name: foo.scribd.com
      - name: baz
        namespace: redns
`
	km := NewKeyMaster(kmClient)

	certheader := regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)
	keyheader := regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`)

	manifestDir := fmt.Sprintf("%s/secrets", tmpDir)
	subDir := fmt.Sprintf("%s/subdir", manifestDir)

	err := os.MkdirAll(manifestDir, 0755)
	if err != nil {
		log.Printf("Error creating dir %s", manifestDir)
		t.Fail()
	}

	err = os.MkdirAll(subDir, 0755)
	if err != nil {
		log.Printf("Error creating dir %s", manifestDir)
		t.Fail()
	}

	files := make([]string, 0)

	fileName := fmt.Sprintf("%s/ns1.yml", manifestDir)
	err = ioutil.WriteFile(fileName, []byte(inputFile1), 0644)
	if err != nil {
		log.Printf("Failed writing %s: %s", fileName, err)
		t.Fail()
	}

	files = append(files, fileName)

	fileName = fmt.Sprintf("%s/ns2.yml", manifestDir)
	err = ioutil.WriteFile(fileName, []byte(inputFile2), 0644)
	if err != nil {
		log.Printf("Failed writing %s: %s", fileName, err)
		t.Fail()
	}

	files = append(files, fileName)

	fileName = fmt.Sprintf("%s/ns3.yml", subDir)
	err = ioutil.WriteFile(fileName, []byte(inputFile3), 0644)
	if err != nil {
		log.Printf("Failed writing %s: %s", fileName, err)
		t.Fail()
	}

	files = append(files, fileName)

	configs, err := LoadSecretYamls(files, true)
	if err != nil {
		log.Printf("Failed to load secrets from %s: %s", fileName, err)
		t.Fail()
	}

	log.Printf("--- %d files for processing ---", len(files))
	assert.True(t, len(files) == 3, "Expect 3 files for processing.")

	log.Printf("--- %d configs for processing ---", len(configs))
	assert.True(t, len(configs) == 3, "expect 3 configs for processing.")

	for _, config := range configs {
		ns, err := km.NewTeam(config, true)
		log.Printf("--- Processing data for namespace: %s ---", ns.Name)
		if err != nil {
			log.Printf("Failed to load namespace: %s", err)
			t.Fail()
		} else {
			err = km.ConfigureTeam(ns, true)
			if err != nil {
				log.Printf("Failed to configure namespace: %s", err)
				t.Fail()
			}

			for _, env := range Envs {
				// Check Secrets
				for _, secret := range ns.Secrets {
					var path string
					if secret.GeneratorData["type"] == "tls" {
						path, err = km.SecretPath(secret.Name, secret.Namespace, env)
						if err != nil {
							log.Printf("Error creating path: %s", err)
							t.Fail()
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
						path, err = km.SecretPath(secret.Name, secret.Namespace, env)
						if err != nil {
							log.Printf("Error creating path: %s", err)
							t.Fail()
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
					policy, err := km.NewPolicy(role, env)
					if err != nil {
						log.Printf("doh! error creating policy: %s", err)
						t.Fail()
					}

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
							_, err := km.ReadTlsAuth(role, env)
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

	for _, cluster := range Clusters {
		path := fmt.Sprintf("/auth/k8s-%s/role", cluster.Name)
		s, err := km.VaultClient.Logical().List(path)
		if err != nil {
			log.Printf("Failed to list k8s roles: %s", err)
			t.Fail()
		}

		log.Printf("--- K8S Roles for %s (%s) ---", cluster.Name, cluster.Environment)
		keys, ok := s.Data["keys"].([]interface{})
		if ok {
			for _, key := range keys {
				path := fmt.Sprintf("/auth/k8s-%s/role/%s", cluster.Name, key)
				s, err := km.VaultClient.Logical().Read(path)
				if err != nil {
					log.Printf("Failed to list k8s roles: %s", err)
					t.Fail()
				}

				log.Printf("--- Policies for K8S Role %s ---", key)
				policies, ok := s.Data["policies"].([]interface{})
				if ok {
					for _, policy := range policies {
						log.Printf("  %s", policy)
					}
				}
			}
		}
	}

	s, err := km.VaultClient.Logical().List("auth/cert/certs")
	if err != nil {
		log.Printf("Failed to list TLS Roles: %s", err)
		t.Fail()
	}

	log.Printf("--- TLS Roles ---")
	if s != nil {
		keys, ok := s.Data["keys"].([]interface{})
		if ok {
			for _, key := range keys {
				log.Printf("  %s", key)
				path := fmt.Sprintf("/auth/cert/certs/%s", key)
				s, err := km.VaultClient.Logical().Read(path)
				if err != nil {
					log.Printf("Failed to list k8s roles: %s", err)
					t.Fail()
				}

				log.Printf("--- Policies For TLS Role: %s ---", key)
				policies, ok := s.Data["policies"].([]interface{})
				if ok {
					for _, policy := range policies {
						log.Printf("  %s", policy)
					}
				}

			}
		}

	}

	s, err = km.VaultClient.Logical().List("/sys/policy")
	if err != nil {
		log.Printf("Failed to list policies: %s", err)
		t.Fail()
	}

	log.Printf("--- All Policies ---")
	keys, ok := s.Data["keys"].([]interface{})
	if ok {
		for _, key := range keys {
			fmt.Printf("  %s\n", key)
		}
	}

	// TODO Make this more flexible.
	// This is 1 test of 1 secret, and yes, it should hold true for all, but a more thorough and considered approach would help.

	log.Printf("--- Create Test Token ---")
	policy := "dev-bluens-app1"

	data := make(map[string]interface{})
	data["policies"] = []string{policy}
	data["no_parent"] = true

	s, err = rootClient.Logical().Write("/auth/token/create-orphan", data)
	if err != nil {
		log.Printf("failed to create token for test: %s", err)
		t.Fail()
	}

	assert.True(t, s != nil, "Generated a test token.")
	testToken := s.Auth.ClientToken

	testClient, err := km.VaultClient.Clone()
	if err != nil {
		log.Printf("Failed to clone vault client: %s", err)
		t.Fail()
	}

	testClient.ClearToken()
	testClient.SetToken(testToken)

	ts, _ := testClient.Auth().Token().LookupSelf()
	policies, ok := ts.Data["policies"].([]interface{})
	if ok {
		log.Printf("--- Policies on Test Token: ---")
		for _, policy := range policies {
			log.Printf("  %s\n", policy)
		}
	}

	s, err = testClient.Logical().Read("sys/policy/dev-bluens-app1")
	if err != nil {
		log.Printf("Failed to lookup policy: %s", err)
		t.Fail()
	}

	rules, ok := s.Data["rules"].(string)
	if ok {
		var rulesObj map[string]interface{}
		err := json.Unmarshal([]byte(rules), &rulesObj)
		if err != nil {
			log.Printf("failed to unmarshal rules string into json: %s", err)
			t.Fail()
		}

		jb, err := json.MarshalIndent(rulesObj, "", "  ")
		if err != nil {
			log.Printf("failed to marshal rules back into json: %s", err)

		}
		log.Printf("--- Rules ---")
		log.Printf("%s", string(jb))
	}

	goodpath := "dev/data/bluens/wip"

	s, err = testClient.Logical().Read(goodpath)
	if err != nil {
		log.Printf("Failed to lookup path %s : %s", goodpath, err)
		t.Fail()
	}

	if s != nil {
		data, ok = s.Data["data"].(map[string]interface{})
		if ok {
			value, ok := data["value"].(string)
			if ok {
				log.Printf("Value: %s", value)
			}
		}

	}

	badpath := "prod/data/redns/foo"

	if s != nil {
		s, err = testClient.Logical().Read(badpath)
		if err == nil {
			log.Printf("Lookup badpath %s should cause error: %s", badpath, err)
			t.Fail()
		}
	}
}
