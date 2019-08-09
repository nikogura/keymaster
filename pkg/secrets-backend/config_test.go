package secrets_backend

import (
	"log"
	"strings"
	"testing"
)

// examples of org yamls and common errors
var orgyamls = []struct {
	name string
	in   string
	out  string
}{
	{
		"good-org",
		`---
name: test-org
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
    secrets:
      - name: foo
      - name: bar
      - name: baz
        org: core-infra`,
		"",
	},
	{
		"name-org",
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
    secrets:
      - name: foo
      - name: bar
      - name: baz
        org: core-infra`,
		ERR_NAMELESS_ORG,
	},
	{
		"nameless-role",
		`---
name: test-org
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
  - secrets:
      - name: foo
      - name: bar
      - name: baz
        org: core-infra`,
		ERR_NAMELESS_ROLE,
	},
	{
		"missing-secret",
		`---
name: test-org
secrets:
  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - name: app1
    secrets:
      - name: foo
      - name: wip
      - name: baz
        org: core-infra`,
		ERR_MISSING_SECRET,
	},
	{
		"garbage",
		`asd;lkfjqw4p9rui4tw`,
		ERR_ORG_DATA_LOAD,
	},
	{
		"missing-generator",
		`---
name: test-org
secrets:
  - name: foo
  - name: bar
    generator:
      type: hex
      length: 12
roles:
  - name: app1
    secrets:
      - name: foo
      - name: wip
      - name: baz
        org: core-infra`,
		ERR_MISSING_GENERATOR,
	},
	{
		"nameless secret",
		`---
name: test-org
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
    secrets:
      - name: foo
      - name: wip
      - name: baz
        org: core-infra`,
		ERR_NAMELESS_SECRET,
	},
}

func TestLoadOrgData(t *testing.T) {
	for _, tt := range orgyamls {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.in)
			_, err := LoadOrgData(data)
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
