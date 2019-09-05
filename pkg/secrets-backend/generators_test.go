package secrets_backend

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"regexp"
	"testing"
)

var newGeneratorErrors = []struct {
	name string
	in   GeneratorData
	out  string
}{
	{
		"alpha",
		GeneratorData{
			"type":   "alpha",
			"length": 10,
		},
		"",
	},
	{
		"empty type",
		GeneratorData{
			"type": "",
		},
		fmt.Sprintf("%s: ", ERR_UNKNOWN_GENERATOR),
	},
	{
		"nil type",
		GeneratorData{
			"type": nil,
		},
		ERR_BAD_GENERATOR,
	},
	{
		"alpha",
		GeneratorData{
			"type": "fargle",
		},
		fmt.Sprintf("%s: fargle", ERR_UNKNOWN_GENERATOR),
	},
}

func TestNewGenerator(t *testing.T) {
	client := testServer.VaultTestClient()
	km := NewKeyMaster(client)

	for _, tc := range newGeneratorErrors {
		t.Run(tc.name, func(t *testing.T) {
			_, err := km.NewGenerator(tc.in)
			if err != nil {
				assert.Equal(t, tc.out, err.Error())
			}
		})
	}
}

func TestGeneratorValues(t *testing.T) {
	client := testServer.VaultTestClient()
	km := NewKeyMaster(client)

	inputs := []struct {
		name string
		in   GeneratorData
		out  *regexp.Regexp
	}{
		{
			"alpha-output",
			GeneratorData{
				"type":   "alpha",
				"length": 10,
			},
			regexp.MustCompile(`[a-zA-Z0-9]{10}`),
		},
		{
			"hex-output",
			GeneratorData{
				"type":   "hex",
				"length": 32,
			},
			regexp.MustCompile(`[a-f0-9]{32}`),
		},
		{
			"uuid-output",
			GeneratorData{
				"type": "uuid",
			},
			regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`),
		},
		{
			"chbs-output",
			GeneratorData{
				"type":  "chbs",
				"words": 6,
			},
			regexp.MustCompile(`\w+-\w+-\w+-\w+-\w+-\w+`),
		},
		{
			"tls-output",
			GeneratorData{
				"type": "tls",
				"cn":   "foo.scribd.com",
				"ca":   "pki",
			},
			regexp.MustCompile(`\{.+\}`),
		},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			g, err := km.NewGenerator(tc.in)
			if err != nil {
				log.Printf("Error creating generator %q: %s", tc.name, err)
				t.Fail()
			}

			if g != nil {
				value, err := g.Generate()
				if err != nil {
					log.Printf("Error running generator: %s", err)
					t.Fail()
				}

				assert.True(t, tc.out.MatchString(value), "%s output %q matches %s", tc.name, value, tc.out.String())

			}
		})
	}
}
