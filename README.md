# psst

Secrets definition and management tool

## Requirements

Define Secrets - and their generators

Define Secret Roles (Vault AppRoles & Policies)

In Memory vault server for testing

Verify CRUD off of definition

Write secrets if not exist in preprod/prod

Backends for dev/preprod/prod

Definitions out of git, or act as front end to whats in vault

Vault itself is the storage medium, Vault AppRole/Policy is definition and enforcement of role


## Stories

* As a Developer, I want to define a Secret for my application and have it made available everywhere it's needed.

* As a Developer, or an Operator, I want to be able to define a Role for my application, and choose what secrets this Role needs access to.

* As a Security Admin, I want to be able to rotate (regenerate) any secret or group of secrets when I deem it necessary (time based, or in response to a suspected breach).

* As an Operator, I want Developers to be able to choose the Name (Key) of a secret, and define a pattern for that secret's generation so that it can be created and populated in all environments/realms where necessary so that the Developer needs no further interaction.

