package secrets_backend

// Environment Scribd's deployment environments.   One of "Prod", "Stage", "Dev"
type Environment int

const (
	Prod Environment = iota + 1
	Stage
	Dev
)

/*
	LDAP Auth can access only dev secrets

	k8s dev auth can access dev secrets
	k8s stage auth can access stage secrets
	k8s prod auth can access prod secrets

	aws dev auth can access dev secrets
	aws stage auth can access stage secrets
	aws prod auth can access prod secrets

	tls prod auth can access prod secrets
	do we need tls stage / dev access at all?

*/
