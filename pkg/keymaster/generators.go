package keymaster

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/sethvargo/go-diceware/diceware"
	"math/rand"
	"strings"
)

type GeneratorType int

const (
	ALPHA GeneratorType = iota + 1
	HEX
	UUID
	CHBS
	RSA
	TLS
	STATIC
)

const ERR_UNKNOWN_GENERATOR = "unknown generator"

// Generator an interface for a function that creates a string according to a pattern.  E. g.
type Generator interface {
	Generate() (value string, err error)
}

// Alphanumerics
// AlphaGenerator generates alphanumeric strings of any length given
type AlphaGenerator struct {
	Type   string
	Length int
}

// Generate produces the required string of the length indicated
func (g AlphaGenerator) Generate() (string, error) {
	letters := []rune("abcdefghijklmnopqrstuvqxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, g.Length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b), nil
}

// NewAlphaGenerator produces a new AlphaGenerator from the provided options
func NewAlphaGenerator(options GeneratorData) (generator AlphaGenerator, err error) {
	if length, ok := options["length"].(int); ok {
		generator = AlphaGenerator{
			Type:   "alpha",
			Length: int(length),
		}

		return generator, err
	}

	err = errors.New("length must be an integer")

	return generator, err
}

// Hex strings
// HexGenerator generates hecadecimal strings
type HexGenerator struct {
	Type   string
	Length int
}

// Generate creates a random hex string of the length indicated
func (g HexGenerator) Generate() (string, error) {
	letters := []rune("0123456789abcdef")

	b := make([]rune, g.Length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b), nil
}

// NewHexGenerator creates a new HexGenerator from the options given
func NewHexGenerator(options GeneratorData) (generator HexGenerator, err error) {
	if length, ok := options["length"].(int); ok {
		generator = HexGenerator{
			Type:   "hex",
			Length: int(length),
		}

		return generator, err
	}

	err = errors.New("length must be an integer")
	return generator, err
}

// UUID's
// UUIDGenerator produces random UUIDs
type UUIDGenerator struct {
	Type string
}

// Generate produces a random UUID string
func (g UUIDGenerator) Generate() (string, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return u.String(), err
}

// NewUUIDGenerator produces a UUIDGenerator from the provided options
func NewUUIDGenerator(options GeneratorData) (generator Generator, err error) {
	generator = UUIDGenerator{}
	return generator, err
}

// Correct Horse Battery Staple Secrets
// CHBSGenerator a Correct Horse Battery Staple passphrase generator
type CHBSGenerator struct {
	Type  string
	Words int
}

// Generate produces a random word list separated by hyphens
func (g CHBSGenerator) Generate() (string, error) {
	list, err := diceware.Generate(g.Words)
	if err != nil {
		return "", err
	}

	return strings.Join(list, "-"), nil
}

// NewCHBSGenerator creates a CHBSGenerator from the provided options
func NewCHBSGenerator(options GeneratorData) (generator Generator, err error) {
	if words, ok := options["words"].(int); ok {
		generator = CHBSGenerator{
			Type:  "chbs",
			Words: words,
		}

		return generator, err
	}

	err = errors.New("words must be an integer")
	return generator, err
}

// RSA Keys
// RSAGenerator generates RSA Keys
type RSAGenerator struct {
	Type      string
	Blocksize int
}

// Generate produces new RSA keys
func (g RSAGenerator) Generate() (string, error) {
	// TODO Implement RSAGenerator.Generate()
	return "", nil
}

// NewRSAGenerrator makes an RSAGenerator from the options provided
func NewRSAGenerator(options GeneratorData) (generator Generator, err error) {
	if bs, ok := options["blocksize"].(float64); ok {
		generator = RSAGenerator{
			Type:      "rsa",
			Blocksize: int(bs),
		}

		return generator, err
	}

	return generator, err
}

// TLS Certs
// TLSGenerator generates TLS certs
type TLSGenerator struct {
	Type        string
	CommonName  string
	Sans        []string
	IPSans      []string
	CA          string
	TTL         string
	VaultClient *api.Client
}

// VaultCert a struct representing what Vault returns when you create a cert in one shot.
type VaultCert struct {
	Chain      []string `json:"ca_chain"`
	Cert       string   `json:"certificate"`
	Expiration int      `json:"expiration"`
	CA         string   `json:"issuing_ca"`
	Key        string   `json:"private_key"`
	Type       string   `json:"private_key_type"`
	Serial     string   `json:"serial_number"`
}

// Generate Hits Vault to generate TLS certs
func (g TLSGenerator) Generate() (string, error) {
	role := "keymaster" // this probably needs it's own role for secrets-backend
	vaultPath := fmt.Sprintf("%s/issue/%s", g.CA, role)

	data := make(map[string]interface{})

	data["common_name"] = g.CommonName
	data["ttl"] = g.TTL

	// hit vault endpoint to create cert
	s, err := g.VaultClient.Logical().Write(vaultPath, data)
	if err != nil {
		err = errors.Wrapf(err, "failed to create certificate")
		return "", err
	}

	if s == nil {
		err = errors.New("failed to get certificate from vault")
		return "", err
	}

	b, err := json.Marshal(s.Data)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal certificate secret into json")
		return "", err
	}

	return string(b), nil
}

// NewTlsGenerator produces a new TlSGenerator from the options indicated
func NewTlsGenerator(vaultClient *api.Client, options GeneratorData) (generator Generator, err error) {
	cn, ok := options["cn"].(string)
	if !ok {
		err = errors.New("Bad value for option 'cn' in generator")
		return generator, err
	}

	ca := "service"
	ttl := "8760h"
	sans := make([]string, 0)
	ipSans := make([]string, 0)

	rawCa, ok := options["ca"]
	if ok {
		c, ok := rawCa.(string)
		if !ok {
			err = errors.New("Bad value for option 'ca' in generator")
			return generator, err
		}
		ca = c
	}

	rawTtl, ok := options["ttl"]
	if ok {
		t, ok := rawTtl.(string)
		if !ok {
			err = errors.New("Bad value for option 'ttl' in generator")
			return generator, err
		}

		ttl = t
	}

	rs, ok := options["sans"]
	if ok {
		rawSans, ok := rs.([]interface{})
		if !ok {
			err = errors.New("Bad value for option 'sans' in generator")
			return generator, err
		}

		for _, rawSan := range rawSans {
			san, ok := rawSan.(string)
			if !ok {
				err = errors.New("Bad value for option 'sans' in generator")
				return generator, err
			}
			sans = append(sans, san)
		}
	}

	ris, ok := options["ip_sans"]
	if ok {
		rawIpSans, ok := ris.([]interface{})
		if !ok {
			err = errors.New("Bad value for option 'ip_sans' in generator")
			return generator, err
		}

		for _, rawSan := range rawIpSans {
			san, ok := rawSan.(string)
			if !ok {
				err = errors.New("Bad value for option 'sans' in generator")
				return generator, err
			}
			ipSans = append(ipSans, san)
		}
	}

	generator = TLSGenerator{
		Type:        "tls",
		CommonName:  cn,
		Sans:        sans,
		IPSans:      ipSans,
		CA:          ca,
		TTL:         ttl,
		VaultClient: vaultClient,
	}

	return generator, err
}

// Static Secrets
// Static Secrets don't chenge, hence this is just a no-op
type StaticGenerator struct {
	Type string
}

// Generate produces.... nothing.
func (g StaticGenerator) Generate() (string, error) {
	return "", nil
}

// NewStaticGenerrator makes an StaticGenerator
func NewStaticGenerator() (generator Generator, err error) {
	generator = StaticGenerator{
		Type: "static",
	}

	return generator, err
}
