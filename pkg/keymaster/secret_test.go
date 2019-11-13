package keymaster

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"regexp"
	"testing"
	"time"
)

func TestSecretPath(t *testing.T) {
	inputs := []struct {
		name       string
		secretName string
		team       string
		env        string
		output     string
	}{
		{
			"secret1",
			"foo",
			"team6",
			"production",
			"team6/data/foo/production",
		},
		{
			"secret2",
			"bar",
			"team7",
			"staging",
			"team7/data/bar/staging",
		},
		{
			"secret3",
			"baz",
			"team5",
			"development",
			"team5/data/baz/development",
		},
		{
			"secret4",
			"wip",
			"team7",
			"development",
			"team7/data/wip/development",
		},
	}

	km := NewKeyMaster(kmClient)

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			path, err := km.SecretPath(tc.team, tc.secretName, tc.env)
			if err != nil {
				log.Printf("error creating path: %s", err)
				t.Fail()
			}

			assert.Equal(t, tc.output, path, "Created expected path.")
		})
	}
}

//func TestCertPath(t *testing.T) {
//	inputs := []struct {
//		name       string
//		secretName string
//		team       string
//		env        Environment
//		output     string
//	}{
//		{
//			"cert1",
//			"foo",
//			"red",
//			Prod,
//			"prod/data/certs/red/foo",
//		},
//		{
//			"cert2",
//			"bar",
//			"green",
//			Stage,
//			"stage/data/certs/green/bar",
//		},
//		{
//			"cert3",
//			"baz",
//			"blue",
//			Dev,
//			"dev/data/certs/blue/baz",
//		},
//		{
//			"cert4",
//			"wip",
//			"team3",
//			17,
//			"dev/data/certs/team3/wip",
//		},
//	}
//
//	km := NewKeyMaster(kmClient)
//
//	for _, tc := range inputs {
//		t.Run(tc.name, func(t *testing.T) {
//			path, err := km.SecretPath(tc.team, tc.secretName, tc.env)
//			if err != nil {
//				log.Printf("error creating path: %s", err)
//				t.Fail()
//			}
//
//			assert.Equal(t, tc.output, path, "Created expected path.")
//		})
//	}
//}

func TestWriteSecretIfBlank(t *testing.T) {
	inputs := []struct {
		name string
		in   *Secret
		out  *regexp.Regexp
	}{
		{
			"foo",
			&Secret{
				Name: "foo",
				Team: "secret-team1",
				GeneratorData: GeneratorData{
					"type":   "alpha",
					"length": 10,
				},
				Environments: []string{
					"production",
					"staging",
					"development",
				},
			},
			regexp.MustCompile(`[a-zA-Z0-9]{10}`),
		},
		{
			"bar",
			&Secret{
				Name: "bar",
				Team: "secret-team2",
				GeneratorData: GeneratorData{
					"type":   "hex",
					"length": 32,
				},
				Environments: []string{
					"production",
					"staging",
					"development",
				},
			},
			regexp.MustCompile(`[a-f0-9]{32}`),
		},
		{
			"wip",
			&Secret{
				Name: "wip",
				Team: "secret-team2",
				GeneratorData: GeneratorData{
					"type": "uuid",
				},
				Environments: []string{
					"production",
					"staging",
					"development",
				},
			},
			regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`),
		},
		{
			"zoz",
			&Secret{
				Name: "zoz",
				Team: "secret-team4",
				GeneratorData: GeneratorData{
					"type":  "chbs",
					"words": 6,
				},
				Environments: []string{
					"production",
					"staging",
					"development",
				},
			},
			regexp.MustCompile(`\w+-\w+-\w+-\w+-\w+-\w+`),
		},
		{
			"foo.scribd.com",
			&Secret{
				Name: "",
				Team: "secret-team3",
				GeneratorData: GeneratorData{
					"type": "tls",
					"cn":   "foo.scribd.com",
					"ca":   "service",
				},
				Environments: []string{
					"production",
					"staging",
					"development",
				},
			},
			regexp.MustCompile(`.+`),
		},
	}

	km := NewKeyMaster(kmClient)

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			secret := tc.in
			g, err := km.NewGenerator(secret.GeneratorData)
			if err != nil {
				log.Printf("Error creating generator %q: %s", tc.name, err)
				t.Fail()
			}

			secret.SetGenerator(g)

			err = km.WriteSecretIfBlank(tc.in, true)
			if err != nil {
				log.Printf("Failed to write secret %q: %s\n", secret.Name, err)
				t.Fail()
			} else {
				// give the write a moment to propagate.  If we hit vault directly the secret may not be there yet.
				time.Sleep(time.Second)
				for _, env := range secret.Environments {
					var path string
					if secret.GeneratorData["type"] == "tls" {
						path, err = km.SecretPath(secret.Team, secret.Name, env)
						if err != nil {
							log.Printf("error creating path: %s", err)
							t.Fail()
						}
					} else {
						path, err = km.SecretPath(secret.Team, secret.Name, env)
						if err != nil {
							log.Printf("error creating path: %s", err)
							t.Fail()
						}
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
				//fmt.Printf("VAULT_TOKEN=%s VAULT_ADDR=http://%s\n", testVault.RootToken, testVault.Address)
				//time.Sleep(10 * time.Minute)
			}
		})

		input := inputs[0]
		expected := make([]string, 0)

		for _, env := range input.in.Environments {
			path, err := km.SecretPath(input.in.Team, input.in.Name, env)
			if err != nil {
				log.Printf("error creating path: %s", err)
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

		//log.Printf("--- Expected ---")
		//spew.Dump(expected)

		//err := km.WriteSecretIfBlank(input.in)
		//if err != nil {
		//	log.Printf("Failed to write secret %q: %s\n", input.in.Name, err)
		//	t.Fail()
		//}
		//for i, env := range Envs {
		//	path, err := km.SecretPath(input.in.Team, input.in.Name, env)
		//	if err != nil {
		//		log.Printf("error creating path: %s", err)
		//		t.Fail()
		//	}
		//	s, err := km.VaultClient.Logical().Read(path)
		//	if err != nil {
		//		log.Printf("Unable to read %q: %s\n", path, err)
		//		t.Fail()
		//	}
		//	if s == nil {
		//		log.Printf("Nill secret at %s\n", path)
		//		t.Fail()
		//	} else {
		//		secretData, ok := s.Data["data"].(map[string]interface{})
		//		if ok {
		//			value, ok := secretData["value"].(string)
		//			if ok {
		//				if len(expected) + 1 == i {
		//					assert.Equal(t, expected[i], value, "Secrets don't overwrite if already set")
		//				}
		//			} else {
		//				fmt.Printf("Secret value at %s is not a string\n", path)
		//				t.Fail()
		//			}
		//		}
		//	}
		//}
	}
}
