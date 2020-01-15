# keymaster

[![Status](https://codebuild.us-east-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiV1FnWVg1ZlNiTmg0OCt2Q2RMeEZEQm5HKzFMWTJ1VnRBL2JuZFVRNGg5Nm9TUjlnODJMblpNV2hEeUZheTdSV0dVcm8zbEtQZ0g5L0hzcmJXQVd4ZUlBPSIsIml2UGFyYW1ldGVyU3BlYyI6IlZCSWd3ZzF3SmVyR0dtU28iLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)](https://us-east-2.console.aws.amazon.com/codesuite/codebuild/projects/keymaster/history?region=us-east-2)

## Overview
This repo contains a library that configures Hashicorp Vault for something called "Managed Secrets".

The idea behind Managed Secrets is that your secrets are `managed`.  Users do not need to know or care that Vault is backend to store secrets, or where the secrets are stored within Vault, or how Vault is configured.  

They don't need to know anything about Vault at all to use secrets.  What's more, the backend could be swapped out at any time and nobody should notice or care.

Secrets are defined as string values that must be kept from disclosure or discovery to or by unauthorized entities.

Secrets are basically key value pairs that are owned by a Team.  One secret 'key' has multiple values- one for each Environment.  

Users also don't generally need to know or care which Environment they're fetching Secrets for- the system is environmentally aware, and will automatically return the appropriate value for the Environment in which the client is run.

Each Secret has a 'generator' which can create and recreate the value of the Secret in each Environment.  This is used to initially provision a Secret, and to rotate it at need.

One gains access to Secrets via Roles.  The Roles define which Principal (app or person) can access which Secret in a given Environment.  

Again, even though the reference implementation leverages Vault, and Vault stores secrets at paths, you don't need to know or care which path is being used.  You authenticate to a Role- as defined in this repo, and the rest _just works_.

In this manner, developers can create Secrets in a self service fashion, and automatically make the Secrets available to their application in each Environment without needing to specify what the values actually are. The generator populates the actual values in each Environment.

Developers on one Team can also request access to Secrets owned by another Team simply by creating a Role which contains that Secret.  This is a deliberate design feature.  It is also something that could absolutely be used by evil.   

Permission to use Secrets from another Team is controlled by Code Review on the repo containing the config files.  How ever good/bad that's handled will determine how 'safe' cross team secrets access really is.

Managed Secrets then is basically a yaml interface for machine access to Vault.  

## Capabilities

Based on the contents of a config file, hese libs do the following:

* Defines Secrets and their Generators for a Team.

* Generate Secrets for a Team in each Environment, storing the Secrets in Vault. 

* Creates Vault Policies allowing Principals to access the above Secrets in each Environment.

* Creates Roles per Team, generating Vault Auth endpoints allowing the `secrets` client or any other Vault savvy user to authenticate to Vault and get a token.

* Roles have 'Realms' which are computing environments.  Each Realm configures a different flavor of Authentication backend.  Choices are 'k8s', 'iam', and 'tls'.

* Does *not* create the per team secrets engines in Vault.  That has to be done manually by a Vault Admin.  This is deliberate, and allows `keymaster` to run with limited permissions (creating new storage engines would require `keymaster` to run with root permissions).

* At present, CA engines are general purpose - not per Team.

## Other Components

This repo is the libraries behind https://github.com/scribd/keymaster-cli.  `keymaster-cli` would be run against a set of config files as described above to configure Vault for Managed Secrets.

An example client for Managed Secrets is https://github.com/scribd/secrets.  It leverages libraries in https://github.com/scribd/vault-authenticator to attempt parallel login methods to Vault, and then grab secrets from your Role.

Under Managed Secrets, your users take your version of `secrets`, and either bake it into your containers, or use a dynamic binary system such as [dbt](https://github.com/nikogura/dbt) to inject `secrets` into containers at runtime.

With `secrets` providing your access, and `keymaster-cli` configuring Vault for you, you can make Secrets for your organization a self-service proposition while you do more interesting things.

## Manual or Static Secrets

Some Secrets cannot be generated, and must be manually placed.  3rd party API credentials are a good example of this.  

In the case of these 'manual' secrets, the appropriate 'bucket' will be created, but any values will be the empty string.  Static Secrets are no different than any other Secret, but their Generator does precisely _nothing_.

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
      - name: app1                          # A role unimaginatively named 'app1'
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
              - "arn:aws:iam::888888888888:role/vaultadmin-role20191254858394857285048328"
            environment: staging            # each principal auths to a role in a single environment.
        secrets:
          - name: foo                       # These Secrets are defined above.  No 'team' in the config means 'team from this file'
          - name: wip
          - name: baz
            team: test-team2                # This secret is owned by another Team.
            
    environments:                           # Environments are just strings.  Use whatever you want.   Many people would like Scribd to use standardized Environment names.  That's a people problem, not a tech problem.  To the code, they're all just strings.
      - production
      - staging
      - development                         # The 'development' environment is special.  If you have one, anyone who can authenticate can access development secrets.  This is intended to ease/ speed development.
      

## Admin Notes

These cannot create secret engines.  This is a deliberate choice.

Every time a new team is onboarded to Managed Secrets, an admin will need to manually run:

    vault secrets enable -version=2 -path=<team name> -description="<team name> Secrets" kv
    
   