# keymaster

[![Status](https://codebuild.us-east-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiV1FnWVg1ZlNiTmg0OCt2Q2RMeEZEQm5HKzFMWTJ1VnRBL2JuZFVRNGg5Nm9TUjlnODJMblpNV2hEeUZheTdSV0dVcm8zbEtQZ0g5L0hzcmJXQVd4ZUlBPSIsIml2UGFyYW1ldGVyU3BlYyI6IlZCSWd3ZzF3SmVyR0dtU28iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)](https://us-east-2.console.aws.amazon.com/codesuite/codebuild/projects/keymaster/history?region=us-east-2)

## Overview
This repo contains a library that configures your secrets provider for something called "Managed Secrets".

Managed Secrets are an _interface_ on your secrets provider. HashiCorp Vault is the reference implementation, but there's nothing stopping us from adding modules for AWS's Secrets Manager, SSM Parameter Store, or any other storage backend. 

The idea behind Managed Secrets is that your secrets are `managed`.  Users do not need to know where the secrets are stored within the backend, how it's configured, or even what it is. They don't need to know anything about the backend at all. What's more, the backend could be swapped out at any time and nobody should notice or care.

## Why Manage Secrets?

Secrets management is an important job, but it sucks.  Why does it suck?

First off, anyone who's actually run/managed a secrets system knows that making sure your app has the secrets it needs is just the tip of the iceberg.  Yeah, that's all the developers care about, and that's all most people think of.  Just about any solution can provide for that use case.

For the unsung heroes who maintain the system however, there's more.  What?  Here's a short list:

* Audit (who has access to what?)

* Logging (Who accessed what when?)

* 'Rotation' (i.e. changing secrets)

* Granting of access

* Revocation of access

* Generating hard to guess secrets

The problem with the above tasks is, they're necessary, but they're time consuming and inglorious, so most of the time, they _don't get done_.

This is the point of Managed Secrets.  Make the necessary painless, so you have a chance at actually doing it.

## What are Secrets?

Secrets are defined as string values that must be kept from disclosure to unauthorized entities.

Secrets are key-value pairs that are owned by a Team. One secret 'key' has multiple values, one for each Environment (e.g., development, staging, or production, though there is no limit on the names or numbers of environments). The `secrets` client can be configured to be environmentally aware based on CIDRs of client machines, and can automatically return the appropriate value for an Environment. You can specify different secrets for different environments, or just use the same secret name for all environments.

You gain access to Secrets via Roles. The Roles define which Principal can access which Secret in a given Environment. While Roles have no functional significance in terms of which Principals have access to which Secrets, and it is possible to put all such combinations inside a single Role, Roles function as an administrative aid to keep specified combinations of Principals, Secrets, and Environments logically grouped together for human interpretation.

The details of your client application will determine how you attach a Principal identity to that client. If using an IAM role as a Principal in the 'iam realm' (see below), for example, you could attach the IAM role to an EC2 instance to allow all applications on the instance to access your Secrets.

Each Secret has a 'generator' which can create and recreate the value of the Secret in each Environment (with the exception of static secret values, which are manually entered by an admin; see below). This is used to initially provision a Secret, and to rotate it as needed.

Ultimately, access to Secrets is controlled entirely by human code review for changes to this repo. As an example, developers on Team A can request access to Secrets owned by Team B simply by creating a Role in Team B's yaml file which provides access to that Secret to a principal controlled by Team A, such as an IAM role. There are no additional automated controls that prevent access from being granted. The only control is a human one: an admin will confirm with Team B that they intend to grant access to one of their secrets. This is a deliberate design feature. It is also something that could absolutely be used by evil conspirators on different teams. However well/poorly code review is handled will determine how 'safe' secrets access really is. Can everyone get together and agree that everyone gets access to everything? They sure can. Is that a good idea? In a production environment, probably not.

## Capabilities

Based on the contents of a config file, these libs do the following:

* Defines Secrets and their Generators for a Team.

* Generate Secrets for a Team in each Environment, storing the Secrets in Vault. 

* Creates Vault Policies allowing Principals to access the above Secrets in each Environment.

* Creates Roles per Team, generating Vault Auth endpoints allowing the `secrets` client or any other Vault savvy user to authenticate to Vault and get a token.

* Roles have 'Realms' which are computing environments.  Each Realm configures a different flavor of Authentication backend.  Choices are 'k8s', 'iam', and 'tls'.

* Does *not* create the per team secrets engines in Vault.  That has to be done manually by a Vault Admin.  This is deliberate, and allows `keymaster` to run with limited permissions (creating new secrets engines would require `keymaster` to run with root permissions).

* At present, CA engines are general purpose - not per Team.

## Other Components

This repo contains the libraries behind https://github.com/scribd/keymaster-cli.  `keymaster-cli` would be run against a set of config files as described above to configure Vault for Managed Secrets.

An example client for Managed Secrets is https://github.com/scribd/secrets.  It leverages libraries in https://github.com/scribd/vault-authenticator to attempt parallel login methods to Vault, and then grab secrets from your Role.

Under Managed Secrets, your users take your version of `secrets`, and either bake it into your containers, or use a dynamic binary system such as [dbt](https://github.com/nikogura/dbt) to inject `secrets` into containers at runtime.

With `secrets` providing your access, and `keymaster-cli` configuring Vault for you, you can make Secrets for your organization a self-service proposition while you do more interesting things.

## Static Secrets

Some Secrets cannot be generated, and must be manually placed into the storage backend. Third party API credentials are a good example of such 'static' secrets.

In the case of static secrets, the appropriate 'bucket' will be created in Vault when a configuration is merged, but any values will be an empty string. Note, however, that the Generator that creates values for other types of Secrets still operates on the storage bucket, and also creates a 'generator' value string for use in comparing buckets created at different times.

Although not strictly necessary, it is probably easier to use LDAP authentication for human users for entering static secrets manually. If you have another form of human user authentication configured for Vault, that works, too. The policy authorizations to secret paths for any authentication methods aside from IAM, Kubernetes, or TLS certificate are NOT configured by Managed Secrets. Thus, while you are able to _create_ an (empty) static secret accessible by your applications via your yaml file, you will not be able to _set_ the value of the secret unless your personal username is manually given write permissions to the specific Vault path. (This is the only scenario in which some knowledge of the Vault backend, namely, the exact path at which secrets provisioned by `keymaster` are stored, is required, although all secrets belonging to a given theam are stored at the team_name/ path, making them easy to find.)

## TLS Secrets

TLS certificates are handled much in the same way as any other secret, but they are multi-valued.  

For a TLS Secret named 'foo.scribd.com', you should expect to find a 'foo.scribd.com.key', 'foo.scribd.com.crt', 'foo.scribd.com.serial', etc.  

TLS certificate secrets are automatically renewed when they are near expiration. *N.B.: At the time of this writing, this has not been implemented. The code to regenerate exists, but it's not wired up to anything.*

The Roles defined in this repo have the power to _consume_ TLS Secrets, but they cannot _generate_ them. This is an important point. By separating generation from consumption, it severely limits the blast radius of a compromised application. The attacker can steal the credentials, but they cannot create new ones.


# Sample Management Workflow

## 1. Create Directory

Create a directory for your Team.  Put it under the path in this repo `secrets`.  

Name it whatever you like.  Only yaml files in the directory `secrets` in this repo are parsed and synced to Vault.  
  
It's probably best to name the directory after your Team, but hey, you're the one that needs to keep track of it and communicate it to others.  Knock yourself out.

## 2. Create Yaml File and Define Team Name

Under that directory, create a yaml file (example below). The file name doesn't matter here, either. Again, the author recommends you name the file after your Team, but it's only a suggestion.  

Each file defines a Team. The `name` value at the top of this file will be the name of the Team's secret container. Even _this_ name doesn't matter. Only one Team is allowed per file, but each directory can have multiple files. Note, however, that spreading a single Team's info across multiple files is not currently supported; each file in a directory must contain a different Team name at the top.

## 3. Define Secrets, Roles, and Environments

In your yaml file, define your Secrets, Roles, and Environments.  

The Roles allow specified Principals to read specified Secrets. As noted above, Roles are merely an administrative aid to keep specified combinations of Principals and Secrets logically grouped together. To associate a single Role with different Principals and/or grant access to different secret values in different Environments, make multiple Realm blocks (specifying 'realms', 'principals', and 'secrets') for the same Role name (the 'name' of the Role can optionally be restated for readability). See the example below for the 'app1' Role.

Environments are merely the "buckets" that each secret is split into. If three different Environments are defined for a team, each secret will have three different buckets in which to place unique values for all the Secrets defined in the yaml, though they don't all need to be used. The names of the Environments can be anything, but the `secrets` binary can be customized to treat recognize certain environments by CIDR. When a client has a source IP in a CIDR that corresponds to one of these environments, `secrets` automatically recognizes the environment, and saves the calling process from needing to specify the `-e` flag with `secrets`.

## 4. Add Realms to Roles

Realms have 'types' ('k8s', 'iam', 'tls'), as well as 'principals'.  The 'identifiers' list is only used by the 'k8s' type and is the name of the Kubernetes Cluster.
  
The possible 'principals' are:
  * the ARNs of the IAM role (or IAM user) for the 'iam' type
  * the FQDN of the host for the 'tls' type
  * the namespace for the 'k8s' type (the `secrets` tool uses the `default` service account in the specified namespace to authenticate)

Note: a Managed Secrets Role (defined by this README) is _unrelated_ to an AWS IAM role (a technical AWS term). A single IAM role could be specified as a Principal in multiple Managed Secrets Roles. However, keeping the scope of both types of roles the same (i.e., logically mapping one Managed Secrets Role to one AWS IAM role) makes it easier to keep track of which IAM roles have access to which Secrets. Giving them each the same name helps, too.

Note: although LDAP authentication to Vault is possible, it isn't one of the authentication methods that is configured by Managed Secrets automation. A Vault admin must manually configure a specific Vault policy to allow LDAP authentication. How you set this up is dependent on how you assign users to LDAP groups.

## 5. Create a Pull Request

Once you have your secrets defined, open a PR to master. Scribd configures its CI to check yaml files for syntax when a PR is opened.

## 6. Get it Reviewed.

Get someone to review your PR.

Keeping it all secure and sane is _everyone's_ responsibility.

## 7. Onboard with a Vault admin  

Make a Jira task, send a Slack message, etc.

**_Some manual setup must be completed by a Vault admin before a new Managed Secrets configuration can be provisioned_**. This was a deliberate choice (see "Capabilities" section, above).

## 8. Merge your PR to Master

A Vault admin must configure the storage for your secrets _before_ you merge to master or CD will fail. See Step 7.


## Config Example

This example defines a Team

    ---
    name: test-team1                        # The name of the Team
    secrets:                                # Definitions of the Secrets in the Team
      - name: foo
        generator:
          type: alpha                       # A 10 digit alphanumeric secert
          length: 10

      - name: bar
        generator:
          type: hex                         # A 12 digit hexadecimal secret
          length: 12

      - name: baz
        generator:
          type: uuid                        # A UUID secret

      - name: wip
        generator:
          type: chbs
          words: 6                          # A 6 word 'correct-horse-battery-staple' secret.  6 random commonly used words joined by hyphens.

      - name: zoz
        generator:
          type: rsa
          blocksize: 2048                   # A RSA keypair expressed as a secret (Not currently supported)

      - name: blort                         # I've clearly run out of standard throwaway names here.
        generator:
          type: static                      # Static secrets have to be placed manually.  API keys are a good use case for Static Secrets.

      - name: foo.scribd.com
        generator:
          type: tls                         # A TLS Certificate/ Private Key expressed as a secret.
          cn: foo.scribd.com
          ca: service                       # This cert is created off of the 'service' CA
          sans:
            - bar.scribd.com                # Allowed alternate names for this cert
            - baz.scribd.com
          ip_sans:                          # IP SANS allow you to use TLS and target an IP directly
            - 1.2.3.4

    roles:                                  # Your Secret Roles  This is what you authenticate to in order to access the Secrets above.
      - name: app1                          # A role unimaginatively named 'app1'; NOT case sensitive
        realms:
          - type: k8s                       # legal types are 'k8s', 'tls', and 'iam'
            identifiers:
              - bravo                       # for k8s, this is the name of the cluster.  Has no meaning for other realms.
            principals:
              - app1                        # for k8s, this is the namespace that's allowed to access the secret
            environment: production         # each role maps to a single environment.  Which one is this?

          - type: tls                       # 'tls' specifies authentication by client certs (generally only applies to SL hosts)
            principals:
              - foo.scribd.com              # for tls, this is the FQDN of a host that possesses a root CA-signed certificate
            environment: development        # when this host connects, it gets development secrets

          - type: iam                       # only works if the client has an IAM identity, which usually means the client
            principals:                     # is running inside AWS
              - "arn:aws:iam::<team-stage-account>:role/foo"
              - "arn:aws:iam::<team-stage-account>:user/foo"
              - "arn:aws:iam::<team-stage-account>:role/foo-*" # wildcards allowed!
              - "arn:aws:sts::<team-stage-account>:assumed-role/foo/*" # allows entities that can assume the role to authenticate
            environment: staging            # each principal auths to a role in a single environment.

        secrets:
          - name: foo                       # These Secrets are defined above. No 'team' in the config means 'team from this file'
          - name: wip
          - name: baz
            team: test-team2                # This secret is owned by another Team.

      - name: app1                          # The "realms:" type and/or the principals can be modified in repeated blocks beneath role names
        realms:                             # to give the same (or different) principals access to different versions of the same (or different)
          - type: iam                       # secrets in different environments. This example is a "maximum" differential of
            principals:                     # principal, environment, and secret names, but it is also possible to change just
              - "arn:aws:iam::<team-prod-account>:role/foo" # one or two of these parameters
            environment: production         # Restating the "name" and "realms:" lines is not necessary, but increases readability

        secrets:
          - name: blah                      # The top two secrets are completely different than "foo" and "wip", above
          - name: bloo
          - name: wip                       # This is the same secret as above, but refers to the "production" version
                                            #  instead of the "staging" version


    environments:
      - production
      - staging
      - development      

## Admin Notes

The machine running `keymaster` requires broad Vault permissions to configure secrets. We don't list them here, but the Vault API operations conducted by `keymaster` are readily apparent in the code. Additionally, `keymaster` requires create and update access to each new secrets engine enabled (and all subpaths), the AWS authentication method path, and each new Kubernetes authentication method path created.

The libraries cannot enable Vault secrets engines. The root token is required for this operation. Relying on a human user to enable a secrets engine both removes the requirement for the libraries to be run as root, and forces a human to take an affirmative action to approve an onboarding of a new team.

Every time a new team is onboarded to Managed Secrets, an admin will need to manually run:

    vault secrets enable -version=2 -path=<team name> -description="<team name> Managed Secrets" kv
    
Keymaster does not _remove_ deprecated secrets or Managed Secrets roles. Although it would likely be trivial to fork `keymaster` and add functionality to automatically delete secrets and roles based solely on their removal from a yaml file, we do not recommend doing this. Secret values and secret access authorization configurations are some of the most sensitive data in any environment. Retaining deletion authorization for a human user reduces the risk of loss of potentially irreplaceable information due to compromise of a CD system.

This isn’t necessary for the new or renamed role or secret to work, but over time, it will lead to a proliferation of unused roles and secret paths inside the storage backend, which will make auditing (and troubleshooting!) more difficult.

If a Managed Secrets role or secret name has changed or removed, you should manually remove the access authorization and secret. Using the reference Vault backend, this requires deleting the Vault policy corresponding to the deprecated role and the environment(s) for which it authorized secret access, and/or the old secret paths: 

    $ vault policy delete <team-name>-<old-role-name>-<environment>

    $ vault kv destroy <team-name>/<secret-name>

Before removing a secret path with `kv destroy`, ensure you have moved the secret values to the new secret path. If the secret value will no longer be used, but you wish to retain the value and version history, use `vault kv delete <team-name>/<secret-name>`


Using the IAM and Kubernetes authentication methods requires some understanding of these systems that is beyond the scope of Managed Secrets. HashiCorp has voluminous documentation on reference architectures for these authentication methods. Some necessary, but possibly not sufficient, key points for you to implement Managed Secrets using Vault as a storage backend:

### IAM Authentication

Initial points to avoid confusion:
- "Vault permissions" and "IAM permissions" are two different things, and we've tried to make clear which one we're talking about below
- Some necessary Vault permissions and _all_ necessary IAM permissions are _manually configured_, i.e., **_`keymaster` does not configure IAM permissions or any other AWS infrastructure_**

Morever, although it would likely be trivial to fork `keymaster` and add functionality to automatically configure AWS as well as Vault based solely on the yaml file, we do not recommend doing this. As with secret and role deletion, above, separating the Vault configuration from the AWS configuration creates a barrier between catastrophic compromise of your secrets. It also lends itself to having a human admin in the loop reviewing secret setups of various developer teams.

The machine that runs Vault (and therefore Vault itself) must be able to call `sts:GetCallerIdentity` in the AWS account in which it exists (this is configured by the current [HashiCorp reference Terraform](https://github.com/scribd/terraform-vault)). Vault must also be able to assume an IAM role in the account that contains the IAM principal specified in the Managed Secrets yaml. This assumed role must be granted the `ec2:DescribeInstances`,`iam:GetInstanceProfile`,`iam:GetUser`, and `iam:GetRole` permissions. This assumed role, its permissions, _and_ the permission for Vault to assume it must be configured in AWS, independently of Managed Secrets. Additionally, this role must be [manually specified in Vault](https://www.vaultproject.io/api-docs/auth/aws#create-sts-role) as an "STS role".

A reference architecture and workflow is: 

1) an EC2 machine running `keymaster` in the same (ideally, dedicated) AWS account in which Vault runs, which 
2) authenticates to Vault using IAM authentication (manually configured outside of Managed Secrets) and 
3) grants `keymaster` the Vault permission to make the appropriate API call to Vault to configure the specified IAM principal to retrieve secrets from Vault
4) Vault uses its default IAM role (from reference Terraform) with an IAM permission policy (manually configured) to assume an IAM role (manually configured, we'll call it the `VaultLookup` IAM role) in the AWS account that contains the specified IAM principal; this `VaultLookup` IAM role must be manually specified in Vault as an "STS role" (see above)
5) Vault makes various AWS API calls (using the `VaultLookup` role it has assumed) to validate that the specified IAM principal exists

If you fail to specify the `VaultLookup` role as an "STS role" in Vault, you'll receive the following error, which is unhelpful unless you are very familiar with AWS IAM terminology ("internal ID") and also understand the mechanics of how Vault integrates with IAM (using a "client"):

    URL: PUT https://vault.foo.com/v1/auth/aws/role/specified-IAM-principal
    Code: 400. Errors:

    unable to resolve ARN "arn:aws:iam::<id of account containing IAM principal>:role/specified-IAM-principal" to internal ID: unable to fetch client for account ID "<id of account containing IAM principal>" -- default client is for account "<Vault account id>"

### Kubernetes Authentication

Each K8s authentication method is [manually enabled in Vault](https://www.vaultproject.io/docs/auth/kubernetes#configuration) at a unique path. This path must be added to the Vault permissions granted to `keymaster`.

### TLS Authentication

A CA-signed certificate must be hardcoded into your private fork of [`keymaster-cli`]() in order for TLS authentication methods to be configured.

Managed Secrets currently only configures the `allowed_common_names` parameter in Vault based on the principals specified in a team’s yaml. It does not configure other restrictions, such as `token_bound_cidrs`. Additional restrictions have to be manually configured after Managed Secrets has already configured the TLS role. For example, using the example yaml configuration above:

    $ curl -XPOST -d @payload.json --header "X-Vault-Token: $(< .vault-token)" https://vault.foo.com/v1/auth/cert/certs/test-team1-app1

with `payload.json` as:

    {
      "token_bound_cidrs": [
        "10.1.2.3",
        "10.2.3.4",
        <additional IP addresses>
        ]
    }

There are several other restrictions that can be configured manually. See Vault documentation. We'd like to extend `keymaster`'s ability to automatically configure these additional parameters. Make a PR!
