# keymaster

[![Status](https://codebuild.us-east-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiV1FnWVg1ZlNiTmg0OCt2Q2RMeEZEQm5HKzFMWTJ1VnRBL2JuZFVRNGg5Nm9TUjlnODJMblpNV2hEeUZheTdSV0dVcm8zbEtQZ0g5L0hzcmJXQVd4ZUlBPSIsIml2UGFyYW1ldGVyU3BlYyI6IlZCSWd3ZzF3SmVyR0dtU28iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)](https://us-east-2.console.aws.amazon.com/codesuite/codebuild/projects/keymaster/history?region=us-east-2)

## Overview
This repo contains a library that configures your secrets provider for something called "Managed Secrets".

Managed Secrets are an _interface_ on your secrets provider. Hashicorp Vault is the reference implementation, but there's nothing stopping us from adding modules for AWS's Secrets Manager, SSM Parameter Store, or any other engine. 

The idea behind Managed Secrets is that your secrets are managed. You do not need to know or care that we're currently using Vault to store secrets, or where the secrets are stored within Vault, or how Vault is configured. You don't need to know anything about Vault at all to use secrets. What's more, Vault could be swapped out for a different storage solution at any time and nobody should notice or care.

## Why Manage Secrets?

Anyone who's actually run/managed a secrets system knows that making sure your app has the secrets it needs is just the tip of the iceberg. Developers only care about accessing secrets, and that's all most people think of. Just about any solution can provide for that use case.

For the unsung heroes who maintain the system however, there's more:

* Audit (who has access to what?)

* Logging (who accessed what, and when?)

* 'Rotation' (i.e. changing secrets)

* Granting of access

* Revocation of access

* Generating hard to guess secrets

The above tasks are time consuming and inglorious. Most of the time, they _don't get done_.

This is the point of Managed Secrets. Make the necessary painless, so you have a chance at actually doing it.

## What are Secrets?

Secrets are defined as string values that must be kept from disclosure to unauthorized entities.

Secrets are basically key-value pairs that are owned by a Team. One secret 'key' has multiple values, one for each Environment (development, staging, or production). You don't generally need to know or care which Environment you're fetching Secrets for. The system is environmentally aware, and will automatically return the appropriate value for your Environment.

Each Secret has a 'generator' which can create and recreate the value of the Secret in each Environment. This is used to initially provision a Secret, and to rotate it as needed.

You gain access to Secrets via Roles. The Roles define which Principal can access which Secret in a given Environment.

In this manner, developers can create Secrets in a (mostly) self-service fashion, and automatically make the Secrets available to their application in each Environment without needing to specify what the values actually are. The generator populates the actual values in each Environment (with the exception of static secrets; see below).   

Ultimately, access to Secrets is controlled entirely by human code review for changes to a separate repo that stores the config files (see below). As an example, developers on one Team can request access to Secrets owned by another Team simply by creating a Role in that other Team's .yml file which provides access to that Secret. There are no additional automated controls that prevent access from being granted. The only control is a human one: a Security admin will confirm with the second Team that they intend to grant access to one of their secrets. This is a deliberate design feature. It is also something that could absolutely be used by evil conspirators on different teams. However well/poorly code review is handled will determine how 'safe' secrets access really is. Can everyone get together and agree that everyone gets access to everything? They sure can. Is that a good idea? In a production environment, probably not.

## Capabilities

Based on the contents of a config file, these libs do the following in the secrets provider (again, HashiCorp Vault is the reference implementation):

* Defines Secrets and a Generator string (the latter as a key/value pair) for a Team.

* Generate Secrets for a Team in each Environment, storing the Secrets in Vault. 

* Creates Vault Policies allowing Principals to access the Secrets in the designated Environments.

* Creates Roles per Team, generating Vault Auth endpoints allowing [the `secrets` client](https://github.com/scribd/secrets) or any other Vault savvy user to authenticate to Vault and get a token.

* Configures authentication methods called 'Realms'. Choices are 'k8s', 'iam', and 'tls'.

Managed Secrets (specifically, the keymaster component) should not run with full admin permissions to the secrets provider. This was a deliberate choice, as programmatically accessing secret storage with root privileges while running in CI (currently AWS CodeBuild) is never a good idea. Running as non-admin necessitates some preparatory manual steps by a human when using Vault as a secrets provider, however. Keymaster can configure Secrets within a Team's configuration, but creation of a new group of Secrets for a team in Vault has to be done manually by a human administrator of Vault prior to running keymaster. Vault stores secrets in objects called "paths". While it doesn't require full admin access to write secret values to paths that already exist, it does require full admin privileges to create new paths. A different secrets provider, other than Vault, may not have such restrictions, and thus you may be able to run keymaster without needing to perform any manual preparatory steps.

At present, CA engines are general purpose - not per Team.

## Other Components

This repo contains the libraries behind https://github.com/scribd/keymaster-cli.  `keymaster-cli` would be run against a set of config files as described above to configure Vault for Managed Secrets.

An example client for Managed Secrets is https://github.com/scribd/secrets.  It leverages libraries in https://github.com/scribd/vault-authenticator to attempt parallel login methods to Vault, and then grab secrets from your Role.

Under Managed Secrets, your users take your version of `secrets`, and either bake it into your containers, or use a dynamic binary system such as [dbt](https://github.com/nikogura/dbt) to inject `secrets` into containers at runtime.

With `secrets` providing your access, and `keymaster-cli` configuring Vault for you, you can make Secrets for your organization a self-service proposition while you do more interesting things.

## Manual or Static Secrets

Some Secrets cannot be generated, and must be manually placed.  3rd party API credentials are a good example of this.  

In the case of static secrets, the appropriate 'bucket' will be created in Vault when a configuration is merged, but any values will be an empty string. Note, however, that the Generator that creates values for other types of Secrets still operates on the storage bucket, and also creates a 'generator' value string for use in comparing buckets created at different times.

## TLS Secrets

TLS certificates are handled much in the same way as any other secret, but they are multi-valued.  

For a TLS Secret named 'foo.scribd.com', you should expect to find a 'foo.scribd.com.key', 'foo.scribd.com.crt', 'foo.scribd.com.serial', etc.  

TLS certificate secrets are automatically renewed when they are near expiration.  *N.B.: At the time of this writing, this has not been implemented. The code to regenerate exists, but it's not wired up to anything.*

The Roles defined in this repo have the power to _consume_ TLS Secrets, but they cannot _generate_ them.  This is an important point.  By separating generation from consumption, it severely limits the blast radius of a compromised application.  The attacker can steal the credentials, but they cannot create new ones.


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

          - type: tls                       # 'tls' specifies authenticated by client certs (generally only applies to SL hosts)
            principals:
              - ci08.inf.scribd.com         # for tls, this is the FQDN of the host
            environment: development        # when this host connects, it gets development secrets

          - type: iam                       # only works if you're running in AWS
            principals:
              - "arn:aws:iam::123456789012:role/vaultadmin-role20191254858394857285048328"
              - "arn:aws:iam::123456789012:role/vault-role-2"
            environment: staging            # each principal auths to a role in a single environment.
        secrets:
          - name: foo                       # These Secrets are defined above.  No 'team' in the config means 'team from this file'
          - name: wip
          - name: baz
            team: test-team2                # This secret is owned by another Team.
            
    environments:                           # Environments are just strings. Use whatever you want. Many people would like Scribd to use standardized Environment names. That's a people problem, not a tech problem. To the code, they're all just strings.
      - production
      - staging
      - development
      

## Admin Notes

These cannot create secret engines.  This is a deliberate choice.

Every time a new team is onboarded to Managed Secrets, an admin will need to manually run:

    vault secrets enable -version=2 -path=<team name> -description="<team name> Secrets" kv
    
   
