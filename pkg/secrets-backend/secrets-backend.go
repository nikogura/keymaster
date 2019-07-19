package secrets_backend

// Environment Scribd's deployment environments.   One of "Prod", "Stage", "Dev"
type Environment int

const (
	Prod Environment = iota + 1
	Stage
	Dev
)

// Generator an interface for a function that creates a string according to a pattern.  E. g.
type Generator interface {
	Generate() string
}

// How do we maintain Environment distinctions?  One easy way is to have 3 separate Vault instances.
// How can we do with 1?  Should we?

type Org struct {
	Name  string `yaml:"org""`
	Roles []Role `yaml:"roles"`
}

type Role struct {
	Org     string   `yaml:"org"`
	Name    string   `yaml:"name"`
	Secrets []Secret `yaml:"secrets"`
}

type Secret struct {
	Name      string    `yaml:"name"`
	Generator Generator `yaml:"generator"`

	DevValue   string `yaml:"dev_value"`
	StageValue string `yaml:"stage_value"`
	ProdValue  string `yaml:"prod_value"`
}

type SecretMetadata struct {
	/*
		{
		  "data": {
		    "created_time": "2018-03-22T02:24:06.945319214Z",
		    "current_version": 3,
		    "max_versions": 0,
		    "oldest_version": 0,
		    "updated_time": "2018-03-22T02:36:43.986212308Z",
		    "versions": {
		      "1": {
		        "created_time": "2018-03-22T02:24:06.945319214Z",
		        "deletion_time": "",
		        "destroyed": false
		      },
		      "2": {
		        "created_time": "2018-03-22T02:36:33.954880664Z",
		        "deletion_time": "",
		        "destroyed": false
		      },
		      "3": {
		        "created_time": "2018-03-22T02:36:43.986212308Z",
		        "deletion_time": "",
		        "destroyed": false
		      }
		    }
		  }
		}
	*/

}

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
