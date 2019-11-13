# keymaster

Secrets Definition and Management tool.

Based on a config file, `keymaster` does the following:

* Defines Secrets and their Generators for a Team.

* Generate Secrets for a Team in each Environment, storing the Secrets in Vault. 

* Creates Vault Policies allowing Principals to access the above Secrets in each Environment.

* Creates Roles per Team, generating Vault Auth endpoints allowing the `secrets` client or any other Vault savvy user to authenticate to Vault and get a token.

* Does *not* create the per team secrets engines in Vault.  That has to be done manually by a Vault Admin.  This is deliberate, and allows `keymaster` to run with limited permissions (creating new storage engines would require `keymaster` to run with root permissions).

Users of the `secrets` tool will have to request their Role by name, and if they successfully authenticate, they'll be able to successfully retrieve secrets for that Role in that Environment.

* At present, CA engines are general purpose - not per Team.

## Design Docs

* https://scribdjira.atlassian.net/wiki/spaces/SEC/pages/602835575/Managed+Secrets+-+2019+-+Q4

## Admin Notes

The `keymaster` tool cannot create secret engines.  This is a deliberate choice.

Every time a new team is onboarded to Managed Secrets, an admin will need to run:

    vault secrets enable -version=2 -path=<team name> -description="<team name> Secrets" kv
    
   