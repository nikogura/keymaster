# keymaster

[![Status](https://codebuild.us-east-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiV1FnWVg1ZlNiTmg0OCt2Q2RMeEZEQm5HKzFMWTJ1VnRBL2JuZFVRNGg5Nm9TUjlnODJMblpNV2hEeUZheTdSV0dVcm8zbEtQZ0g5L0hzcmJXQVd4ZUlBPSIsIml2UGFyYW1ldGVyU3BlYyI6IlZCSWd3ZzF3SmVyR0dtU28iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)](https://us-east-2.console.aws.amazon.com/codesuite/codebuild/projects/keymaster/history?region=us-east-2)

Yaml Interface for machine access to Hashicorp Vault.

Based on a config file, these libs do the following:

* Defines Secrets and their Generators for a Team.

* Generate Secrets for a Team in each Environment, storing the Secrets in Vault. 

* Creates Vault Policies allowing Principals to access the above Secrets in each Environment.

* Creates Roles per Team, generating Vault Auth endpoints allowing the `secrets` client or any other Vault savvy user to authenticate to Vault and get a token.

* Roles have 'Realms' which are computing environments.  Each Realm configures a different flavor of Authentication backend.  Choices are 'k8s', 'iam', 'tls', and 'external'.  'External' auth means the Role is configured, but authentication is handled by some other system (such as LDAP).

* Does *not* create the per team secrets engines in Vault.  That has to be done manually by a Vault Admin.  This is deliberate, and allows `keymaster` to run with limited permissions (creating new storage engines would require `keymaster` to run with root permissions).

* At present, CA engines are general purpose - not per Team.


## Admin Notes

These cannot create secret engines.  This is a deliberate choice.

Every time a new team is onboarded to Managed Secrets, an admin will need to manually run:

    vault secrets enable -version=2 -path=<team name> -description="<team name> Secrets" kv
    
   