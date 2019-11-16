package keymaster

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/api"
	"github.com/phayes/freeport"
	"github.com/pkg/errors"
	"github.com/scribd/vaulttest/pkg/vaulttest"
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
var testVault *vaulttest.VaultDevServer
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

	testVault = vaulttest.NewVaultDevServer(testAddress)

	if !testVault.Running {
		testVault.ServerStart()

		// Create normal Secret engines
		client := testVault.VaultTestClient()

		for _, endpoint := range []string{
			"team1",
			"team2",
			"team3",
			"team4",
			"secret-team1",
			"secret-team2",
			"secret-team3",
			"secret-team4",
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

		// Create K8s Auth endpoints
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

		// Create PKI Engine
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

		// Create IAM Auth endpoint
		data = map[string]interface{}{
			"type":        "aws",
			"description": "AWS Auth",
		}
		_, err = client.Logical().Write("sys/auth/aws", data)
		if err != nil {
			log.Fatalf("Failed to create root cert: %s", err)
		}

		// Create Keymaster TLS role
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

		// Create TLS Auth endpoint
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

		rootClient = testVault.VaultTestClient()
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

			//jb, err := json.MarshalIndent(rulesObj, "", "  ") if err != nil {
			//	log.Printf("failed to marshal rules back into json: %s", err)
			//
			//}
			//log.Printf("--- Rules ---")
			//log.Printf("%s", string(jb))
		}
	}

}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		os.Remove(tmpDir)
	}

	testVault.ServerShutDown()
}

func WriteKeyMasterPolicy(client *api.Client) (err error) {
	paths := []string{
		"team1/*",
		"team2/*",
		"team3/*",
		"team4/*",
		"secret-team1/*",
		"secret-team2/*",
		"secret-team3/*",
		"secret-team4/*",
		"sys/policy/*",
		"auth/cert/certs/*",
		"service/issue/keymaster",
		"auth/aws/role/*",
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

func TestNewTeam(t *testing.T) {
	inputs := []struct {
		name string
		in   string
		out  string
	}{
		{
			"good-team",
			`---
name: team1
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
      - type: k8s
        identifiers: 
          - bravo
        principals: 
          - app1
        environment: production
    secrets:
      - name: foo
      - name: bar
      - name: baz
        team: core-infra
environments:
  - production
  - staging
  - development
`,
			"",
		},
		{
			"missing-environments",
			`---
name: team1
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
      - type: k8s
        identifiers: 
          - bravo
        principals: 
          - app1
        environment: production
    secrets:
      - name: foo
      - name: bar
      - name: baz
        team: core-infra
`,
			ERR_MISSING_ENVIRONMENTS,
		},
		{
			"nameless-team",
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
      - type: tls
        principals: 
          - www.scribd.com
        environment: production
    secrets:
      - name: foo
      - name: bar
      - name: baz
        team: core-infra
environments:
  - production
  - staging
  - development
`,
			ERR_NAMELESS_TEAM,
		},
		{
			"nameless-role",
			`---
name: team1
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
      - type: k8s
        identifiers: 
          - bravo
        principals: 
          - app1
        environment: production
    secrets:
      - name: foo
      - name: bar
      - name: baz
        team: core-infra
environments:
  - production
  - staging
  - development
`,
			ERR_NAMELESS_ROLE,
		},
		{
			"missing-secret",
			`---
name: team1
secrets:
  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - name: app1
    realms: 
      - type: tls
        principals:
          - app1
        environment: production
    secrets:
      - name: foo
      - name: wip
      - name: baz
        team: core-infra
environments:
  - production
  - staging
  - development
`,
			ERR_MISSING_SECRET,
		},
		{
			"garbage",
			`asd;lkfjqw4p9rui4tw`,
			ERR_TEAM_DATA_LOAD,
		},
		{
			"missing-generator",
			`---
name: team1
secrets:
  - name: foo
  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - name: app1
    realms:
      - type: k8s
        identifiers: 
          - bravo
        principals:
          - app1
        environment: production
    secrets:
      - name: foo
      - name: wip
      - name: baz
        team: core-infra
environments:
  - production
  - staging
  - development
`,
			ERR_MISSING_GENERATOR,
		},
		{
			"nameless secret",
			`---
name: team1
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
      - type: k8s
        identifiers:
          - bravo
        principals:
          - app1
        environment: production
    secrets:
      - name: foo
      - name: wip
      - name: baz
        team: core-infra
environments:
  - production
  - staging
  - development
`,
			ERR_NAMELESS_SECRET,
		},
		{
			"empty realms role",
			`---
name: team1
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
        team: core-infra
environments:
  - production
  - staging
  - development
`,
			ERR_REALMLESS_ROLE,
		},
		{
			"realmless role",
			`---
name: team1
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
        team: core-infra
environments:
  - production
  - staging
  - development
`,
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
      - type: k8s
        identifiers:
          - bravo
        principals:
          - app1
        environment: production
    secrets:
      - name: foo
      - name: bar
      - name: baz
        team: core-infra
environments:
  - production
  - staging
  - development
`,
			ERR_SLASH_IN_TEAM_NAME,
		},
		{
			"slash-in-role",
			`---
name: team1
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
      - type: k8s
        identifiers:
          - bravo
        principals:
          - foo/bar
        environment: production
    secrets:
      - name: foo
      - name: bar
      - name: baz
        team: core-infra
environments:
  - production
  - staging
  - development
`,
			ERR_SLASH_IN_ROLE_NAME,
		},
		{
			"unsupported-realm",
			`---
name: team1
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
      - type: foo
        identifiers:
          - bar
        principals:
          - app1
        environment: production
    secrets:
      - name: foo
      - name: bar
      - name: baz
        team: core-infra
environments:
  - production
  - staging
  - development
`,
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

func TestConfigureTeam(t *testing.T) {
	inputFile1 := `---
name: team1
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
      - type: k8s
        identifiers:
          - bravo
        principals:
          - app1
        environment: production
      - type: tls
        principals:
          - www.scribd.com
        environment: production
    secrets:
      - name: foo
      - name: wip
      - name: baz
        team: team4

environments:
  - production
  - staging
  - development
`
	inputFile2 := `---
name: team2
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
      - type: k8s
        identifiers:
          - bravo
        principals:
          - app1
        environment: production
      - type: tls
        principals:
          - www.scribd.com
        environment: production
    secrets:
      - name: foo
      - name: wip
      - name: baz
        team: team4

environments:
  - production
  - staging
  - development
`
	inputFile3 := `---
name: team3
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
      - type: k8s
        identifiers:
          - bravo
        principals:
          - app1
        environment: production
      - type: tls
        principals:
          - www.scribd.com
        environment: production
    secrets:
      - name: foo
      - name: wip
      - name: foo.scribd.com
      - name: baz
        team: team1

environments:
  - production
  - staging
  - development
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
		return
	}

	err = os.MkdirAll(subDir, 0755)
	if err != nil {
		log.Printf("Error creating dir %s", manifestDir)
		t.Fail()
		return
	}

	files := make([]string, 0)

	fileName := fmt.Sprintf("%s/team1.yml", manifestDir)
	err = ioutil.WriteFile(fileName, []byte(inputFile1), 0644)
	if err != nil {
		log.Printf("Failed writing %s: %s", fileName, err)
		t.Fail()
		return
	}

	files = append(files, fileName)

	fileName = fmt.Sprintf("%s/team2.yml", manifestDir)
	err = ioutil.WriteFile(fileName, []byte(inputFile2), 0644)
	if err != nil {
		log.Printf("Failed writing %s: %s", fileName, err)
		t.Fail()
		return
	}

	files = append(files, fileName)

	fileName = fmt.Sprintf("%s/team3.yml", subDir)
	err = ioutil.WriteFile(fileName, []byte(inputFile3), 0644)
	if err != nil {
		log.Printf("Failed writing %s: %s", fileName, err)
		t.Fail()
		return
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
		team, err := km.NewTeam(config, true)
		log.Printf("--- Processing data for team: %s ---", team.Name)
		if err != nil {
			log.Printf("Failed to load team: %s", err)
			t.Fail()
			return
		} else {
			err = km.ConfigureTeam(team, true)
			if err != nil {
				log.Printf("Failed to configure team: %s", err)
				t.Fail()
				return
			}

			for _, env := range team.Environments {
				// Check Secrets
				for _, secret := range team.Secrets {
					var path string
					if secret.GeneratorData["type"] == "tls" {
						path, err = km.SecretPath(secret.Team, secret.Name, env)
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
						path, err = km.SecretPath(secret.Team, secret.Name, env)
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

			}

			for _, role := range team.Roles {
				fmt.Printf("Checking role %s\n", role.Name)
				for _, realm := range role.Realms {
					// Check Policies
					policy, err := km.NewPolicy(role, realm.Environment)
					if err != nil {
						log.Printf("doh! error creating policy: %s", err)
						t.Fail()
					}

					readPolicy, err := km.ReadPolicyFromVault(policy.Path)
					if err != nil {
						fmt.Printf("Failed to read policy: %s", err)
						t.Fail()
					}

					err = MapDiff(policy.Payload, readPolicy.Payload)
					if err != nil {
						fmt.Printf("%s\n", err)
						fmt.Printf("Expected: \n")
						spew.Dump(policy.Payload)
						fmt.Printf("Actual: \n")
						spew.Dump(readPolicy.Payload)
						t.Fail()
					} else {
						fmt.Printf("  ... Match!\n")
					}

					assert.True(t, reflect.DeepEqual(policy.Payload, readPolicy.Payload), "payload meets expectations")

					// Check Auth configs
					for _, realm := range role.Realms {
						switch realm.Type {
						case K8S:
							for _, cluster := range realm.Identifiers {
								_, err := km.ReadK8sAuth(ClustersByName[cluster], role)
								if err != nil {
									log.Printf("failed to read k8s policy for %s and %s", cluster, role.Name)
									t.Fail()
								}

								// Not worried about parsing auth data, as input-> output verification is handled in the unit test
								//log.Printf("K8s Role Data for %s %s:", cluster.Name, role.Name)
								//spew.Dump(data)
							}
						case TLS:
							_, err := km.ReadTlsAuth(role, realm.Environment)
							if err != nil {
								log.Printf("failed to read tls policy for %s", role.Name)
								t.Fail()
							}

						case IAM:
							// TODO Add IAM Auth config when implemented
						default:
							log.Printf("Unsupported Realm: %s", realm)
							t.Fail()
						}
					}
				}
			}
		}
	}

	// Test k8s auth configs
	for _, cluster := range Clusters {
		path := fmt.Sprintf("/auth/k8s-%s/role", cluster.Name)
		s, err := km.VaultClient.Logical().List(path)
		if err != nil {
			log.Printf("Failed to list k8s roles: %s", err)
			t.Fail()
		}

		if s != nil {
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
	policy := "team3-app1-production"

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

	s, err = testClient.Logical().Read("sys/policy/team3-app1-production")
	if err != nil {
		log.Printf("Failed to lookup policy: %s", err)
		t.Fail()
	}

	if s != nil {
		rules, ok := s.Data["rules"].(string)
		if ok {
			var rulesObj map[string]interface{}
			err := json.Unmarshal([]byte(rules), &rulesObj)
			if err != nil {
				log.Printf("failed to unmarshal rules string into json: %s", err)
				t.Fail()
			}

			//jb, err := json.MarshalIndent(rulesObj, "", "  ")
			//if err != nil {
			//	log.Printf("failed to marshal rules back into json: %s", err)
			//
			//}
			//log.Printf("--- Rules ---")
			//log.Printf("%s", string(jb))
		}

	} else {
		log.Printf("No policy at sys/policy/team3-app1-production")
		t.Fail()
	}

	goodpath := "team3/data/wip/production"

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

	badpath := "team1/data/foo/production"

	if s != nil {
		s, err = testClient.Logical().Read(badpath)
		if err == nil {
			log.Printf("Lookup badpath %s should cause error: %s", badpath, err)
			t.Fail()
		}
	}
}
