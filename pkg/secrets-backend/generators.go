package secrets_backend

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
	Generate() string
}

/*
	alpha-N N digit alphanumeric
	hex-N  N digit hex
	uuid UUID
	chbs-N correct-horse-battery-staple (N words)
	rsa-N rsa key with cipher block of size N
	tls-N tls cert with common name N
*/
