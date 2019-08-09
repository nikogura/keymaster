package secrets_backend

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
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
)

// Generator an interface for a function that creates a string according to a pattern.  E. g.
type Generator interface {
	Generate() (value string, err error)
	//	UnmarshalJSON(data[]byte) (err error)
	//	MarshalJSON()(data[]byte, err error)
}

//type Generator struct {
//
//}

/*
	alpha-N N digit alphanumeric
	hex-N  N digit hex
	uuid UUID
	chbs-N correct-horse-battery-staple (N words)
	rsa-N rsa key with cipher block of size N
	tls-N tls cert with common name N
*/

const ERR_UNKNOWN_GENERATOR = "unknown generator"

func NewGenerator(options GeneratorData) (generator Generator, err error) {
	if genType, ok := options["type"].(string); ok {
		switch genType {
		case "alpha":
			return NewAlphaGenerator(options)
		case "hex":
			return NewHexGenerator(options)
		case "uuid":
			return NewUUIDGenerator(options)
		case "chbs":
			return NewCHBSGenerator(options)
		case "rsa":
			return NewRSAGenerator(options)
		case "tls":
			return NewTlsGenerator(options)
		default:
			err = errors.New(fmt.Sprintf("%s: %s", ERR_UNKNOWN_GENERATOR, genType))
			return generator, err
		}
	}

	err = errors.New(ERR_BAD_GENERATOR)

	return generator, err
}

// Alphanumerics
type AlphaGenerator struct {
	Type   string
	Length int
}

func (g AlphaGenerator) Generate() (string, error) {
	letters := []rune("abcdefghijklmnopqrstuvqxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, g.Length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b), nil
}

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
type HexGenerator struct {
	Type   string
	Length int
}

func (g HexGenerator) Generate() (string, error) {
	letters := []rune("0123456789abcdef")

	b := make([]rune, g.Length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b), nil
}
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
type UUIDGenerator struct {
	Type string
}

func (g UUIDGenerator) Generate() (string, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return u.String(), err
}

func NewUUIDGenerator(options GeneratorData) (generator Generator, err error) {
	generator = UUIDGenerator{}
	return generator, err
}

// Correct Horse Battery Staple Secrets
type CHBSGenerator struct {
	Type  string
	Words int
}

func (g CHBSGenerator) Generate() (string, error) {
	list, err := diceware.Generate(g.Words)
	if err != nil {
		return "", err
	}

	return strings.Join(list, "-"), nil
}

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
type RSAGenerator struct {
	Type      string
	Blocksize int
}

func (g RSAGenerator) Generate() (string, error) {
	// TODO Implement RSAGenerator.Generate()
	return "", nil
}

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

type TLSGenerator struct {
	Type       string
	CommonName string
	Sans       []string
	IPSans     []string
}

func (g TLSGenerator) Generate() (string, error) {
	// TODO Implement TLSGenerator.Generate()

	return "", nil
}

// TLS Certificates
func NewTlsGenerator(options GeneratorData) (generator Generator, err error) {
	// TODO Implement NewTlsGenerator

	return generator, err
}
