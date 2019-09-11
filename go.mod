module git.lo/dbt/keymaster

go 1.12

require (
	git.lo/dbt/secrets-backend v0.0.0-20190904172909-61b395bf6b8c
	git.lo/ops/ldapclient v0.0.0-20190910200915-20df3f7d669d
	git.lo/ops/vaulttest v0.0.0-20190708201423-cb974752a825
	github.com/davecgh/go-spew v1.1.1
	github.com/google/uuid v1.1.1
	github.com/hashicorp/vault/api v1.0.2
	github.com/mitchellh/go-homedir v1.1.0
	github.com/nikogura/dbt v0.0.0-20190325225132-7ffb3ac85ec0
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/pkg/errors v0.8.1
	github.com/sethvargo/go-diceware v0.0.0-20181024230814-74428ac65346
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
	github.com/stretchr/testify v1.3.0
	gopkg.in/yaml.v2 v2.2.2
)
