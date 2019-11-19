package keymaster

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"log"
	"reflect"
	"testing"
)

func TestK8sAuthCrud(t *testing.T) {
	km := NewKeyMaster(kmClient)

	clusters := make([]*Cluster, 0)
	alpha := Cluster{
		Name:         "alpha",
		ApiServerUrl: "https://kubernetes-alpha:6443",
		CACert: `-----BEGIN CERTIFICATE-----
MIIF5TCCA82gAwIBAgIJALblM1q8ZozEMA0GCSqGSIb3DQEBCwUAMIGZMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFDAS
BgNVBAoMC1NjcmliZCBJbmMuMREwDwYDVQQLDAhPcHMgVGVhbTEdMBsGA1UEAwwU
U2NyaWJkIEluYy4gUm9vdCBDQSAxHTAbBgkqhkiG9w0BCQEWDm9wc0BzY3JpYmQu
Y29tMB4XDTE4MTIxMDE4NDk1MFoXDTI4MTIwNzE4NDk1MFowYjELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtTY3JpYmQgSW5jLjERMA8GA1UECwwI
T3BzIFRlYW0xHTAbBgNVBAMMFFNjcmliZCBJbmMuIEJyYXZvIENBMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAu4ejlHaS/kfEXWsc8ecOgKFBiqa28JRR
c8UvTBCeGZB+13WPa6QFIfGkAYtcweMbVdDs576klt9OzWoscOzH43QbRGdYBYVY
VFWhqRc470xgk3YxrE7Y+fNFJZRKOcifssYBjSadLHufhH2tgGhzPAhC1tGCEyLB
PZ82tSOnnaUM9K45mSXHI/2AIhABXn2mK/OzMCcRlntXWpny1uI26kN1urnworVY
SDGgnyJCyhrPBlgD1xmX/EmzxcHw6wrSZ9q3ipK25l5TLfot5kSds5oys8bBC8mI
dPE/rUmkSIWpEx+g4BXSAGUlUES+kKu+GiDH3pPfFptkiyTRzV2utxhgTmsKjYhh
Uv50dDxUIHdo9O8caQnaz0CN1an9dhd3HHGHy0kuhtRKPaDeHd3ob8Siuai/ZlDR
3AAFt0VRe8KZmMUvve/gu/e9CFjA8+KzFbRWMUfMR5QqwaVOn8DRRHXJcVI90I2J
Tad++4XXmon7ejb50fLiCTg7/KjDEirhUQvldtqfcGvjsDJQ7Bm6W8mpR2bl6WQ9
v2BCzuRSfu6SwVJGF+0iubdnDXspkeXilWK8h2a63R0OZEzOUn/LZYfPEvVTwJ2H
K6AsrcxkNLrbKlBRm6mANoOQbz7Mm99QFI3DaCfwlJDVWxB2C2UT/l60+EnjxODq
h+u8j2I5E5cCAwEAAaNmMGQwHQYDVR0OBBYEFP29TBMxureQSSvwqpYMukMT7Khz
MB8GA1UdIwQYMBaAFHFqeKdxvp4OHqFUt83vPONL/wZdMBIGA1UdEwEB/wQIMAYB
Af8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQCMtPqVa43A
gtgTXh0tC0+nSIU6ORrG+hp7mFlUB0royRMZSa3u3Ar19xpRhAD4yFiW2t/LQJH2
TfftYYvMNFZtQ4APsKFV3RVXNuQuXlme7ZrAvFWMSEbij7c2G4fMSwwWZKzqMUUS
i7AMs7OLHDpaOuU6TL99myO1EO7jbjwnArukChiBQPiv5u0T1rwi9ZwRMd1UxjwJ
urBI1BR9UjGNjzdGytEHvllxuje6n9SrpspDGIgSO3ayhOPSPa0rei5DlxiuuVgL
6bfPqba/GewegywG1OFO93HIz2zNiF/0rRH+patzx9632lkLYkBJ9RZEgDOJvs0c
lR0wKB4BSaN9LB/TbU9eeELZk2WGczm3LbuQRk7+SksbfOO/hgIxOvHwALgxy3dJ
Sg/xLThPxh5tl4oQ+lJMdN3WMnrZtLtvlnOJW6l9HUL5FP0TkhY0Qwb/uci67qtM
kSk2VXyz5YZFIW7PDiig+0elOMsjRRXAs1rMF5+Q6xRoC383daN8BvUmXiCSP7By
oSw0zT6wr3offAX1eSmgCIlnd5icE1jTit7jQE1osbscBY/xhk7D7mrE/mxqT9ey
7wRL8S6kMjh5SjF0vS+5cEiT6fm4TXwqDHCq6/AGfBNU0szTDRKrbA71POm94WKf
Kxq0lynHENJpP/eXjfyC8sLDVJN8YO3n4w==
-----END CERTIFICATE-----`,
		Environment: "production",
		BoundCidrs:  []string{"1.2.3.4"},
	}

	clusters = append(clusters, &alpha)

	km.SetK8sClusters(clusters)
	km.SetIpRestrictK8sAuth(true)

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
		name    string
		cluster *Cluster
		role    *Role
		first   map[string]interface{}
		add     VaultPolicy
		second  map[string]interface{}
	}{
		{
			"app1",
			km.K8sClusters[0],
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
						Type:        "k8s",
						Identifiers: []string{"alpha"},
						Principals:  []string{"default"},
					},
				},
			},
			map[string]interface{}{
				"bound_cidrs":                      AnonymizeStringArray(km.K8sClusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"default"},
				"policies": []interface{}{
					"core-services-app1-development",
				},
				"token_bound_cidrs":       AnonymizeStringArray(km.K8sClusters[0].BoundCidrs),
				"token_explicit_max_ttl":  json.Number("0"),
				"token_max_ttl":           json.Number("0"),
				"token_no_default_policy": false,
				"token_num_uses":          json.Number("0"),
				"token_period":            json.Number("0"),
				"token_policies": []interface{}{
					"core-services-app1-development",
				},
				"token_ttl":  json.Number("0"),
				"token_type": "default",
			},
			addPolicy1,
			map[string]interface{}{
				"bound_cidrs":                      AnonymizeStringArray(km.K8sClusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"default"},
				"policies": []interface{}{
					"core-services-app1-development",
					"core-services-app2-development",
				},
				"token_bound_cidrs":       AnonymizeStringArray(km.K8sClusters[0].BoundCidrs),
				"token_explicit_max_ttl":  json.Number("0"),
				"token_max_ttl":           json.Number("0"),
				"token_no_default_policy": false,
				"token_num_uses":          json.Number("0"),
				"token_period":            json.Number("0"),
				"token_policies": []interface{}{
					"core-services-app1-development",
					"core-services-app2-development",
				},
				"token_ttl":  json.Number("0"),
				"token_type": "default",
			},
		},
		{
			"app2",
			km.K8sClusters[0],
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
						Type:        "k8s",
						Identifiers: []string{"alpha"},
						Principals:  []string{"default"},
					},
				},
			},
			map[string]interface{}{
				"bound_cidrs":                      AnonymizeStringArray(km.K8sClusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"default"},
				"policies": []interface{}{
					"core-platform-app2-development",
				},
				"token_bound_cidrs":       AnonymizeStringArray(km.K8sClusters[0].BoundCidrs),
				"token_explicit_max_ttl":  json.Number("0"),
				"token_max_ttl":           json.Number("0"),
				"token_no_default_policy": false,
				"token_num_uses":          json.Number("0"),
				"token_period":            json.Number("0"),
				"token_policies": []interface{}{
					"core-platform-app2-development",
				},
				"token_ttl":  json.Number("0"),
				"token_type": "default",
			},
			addPolicy2,
			map[string]interface{}{
				"bound_cidrs":                      AnonymizeStringArray(km.K8sClusters[0].BoundCidrs),
				"bound_service_account_names":      []interface{}{"default"},
				"bound_service_account_namespaces": []interface{}{"default"},
				"policies": []interface{}{
					"core-platform-app2-development",
					"core-platform-app3-development",
				},
				"token_bound_cidrs":       AnonymizeStringArray(km.K8sClusters[0].BoundCidrs),
				"token_explicit_max_ttl":  json.Number("0"),
				"token_max_ttl":           json.Number("0"),
				"token_no_default_policy": false,
				"token_num_uses":          json.Number("0"),
				"token_period":            json.Number("0"),
				"token_policies": []interface{}{
					"core-platform-app2-development",
					"core-platform-app3-development",
				},
				"token_ttl":  json.Number("0"),
				"token_type": "default",
			},
		},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := km.NewPolicy(tc.role, "development")
			if err != nil {
				log.Printf("Error creating policy: %s", err)
				t.Fail()
			}
			err = km.WriteK8sAuth(tc.cluster, tc.role, tc.role.Realms[0], []string{policy.Name})
			if err != nil {
				fmt.Printf("Failed writing auth: %s", err)
				t.Fail()
			}

			authData, err := km.ReadK8sAuth(tc.cluster, tc.role)
			if err != nil {
				fmt.Printf("Failed reading auth: %s", err)
				t.Fail()
			}

			err = MapDiff(tc.first, authData)
			if err != nil {
				fmt.Printf("%s", err)
				t.Fail()
			}

			assert.True(t, reflect.DeepEqual(authData, tc.first))

			err = km.AddPolicyToK8sRole(tc.cluster, tc.role, tc.role.Realms[0], tc.add)
			if err != nil {
				fmt.Printf("Failed adding policy")
				t.Fail()
			}

			authData, err = km.ReadK8sAuth(tc.cluster, tc.role)
			if err != nil {
				fmt.Printf("Failed reading auth: %s", err)
				t.Fail()
			}

			assert.True(t, reflect.DeepEqual(authData, tc.second), "role successfully added")

			err = km.RemovePolicyFromK8sRole(tc.cluster, tc.role, tc.role.Realms[0], tc.add)
			if err != nil {
				fmt.Printf("Failed removing policy")
				t.Fail()
			}

			authData, err = km.ReadK8sAuth(tc.cluster, tc.role)
			if err != nil {
				fmt.Printf("Failed reading auth: %s", err)
				t.Fail()
			}

			assert.True(t, reflect.DeepEqual(authData, tc.first))
		})
	}
}
