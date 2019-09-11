# keymaster

Secrets Definition and Management tool.

Based on a config file, `keymaster` does the following:

* Defines Secrets and their Generators.

* Generate Secrets for each Environment, storing the Secrets in Vault. 

* Creates Vault Policies granting access to the above Secrets in each Environment.

* Creates Roles, generating Vault Auth endpoints allowing the `secrets` client or any other Vault savvy user to authenticate in various computing realms (k8s, Sl, etc).

Users of the `secrets` tool will have to request their Role by name, and if their environment/credentials are appropriate, they'll be able to successfully retrieve secrets for that Role.

## Design Docs

* https://scribdjira.atlassian.net/wiki/spaces/SEC/pages/559317160/Secret+Management+Options+and+Requirements+-+2019-Q3

* https://scribdjira.atlassian.net/wiki/spaces/SEC/pages/572950716/SecretsV2+-+2019-Q3

* https://scribdjira.atlassian.net/wiki/spaces/SEC/pages/573603988/Secrets+Backend+keymaster+-+2019-Q3