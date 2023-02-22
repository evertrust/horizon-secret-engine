# horizon-secrets-engine

This plugin allow you to create a secret backend that will use the Horizon API to generate dynamic credentials.

## Setup

Enable the plugin inside vault.
```text
$ vault secrets enable -path=horizon horizon-secrets-engine
```

Setup your administrator profile which will create the temporary users.
```text
$ vault write horizon/config/<instance> \
  horizon_endpoint=... \
  username=... \
  password=...
```

Setup your roles.
```text
$ vault write horizon/roles/<roleName> \
	instance=<instance> \
	roles=... \
	contact=... \
	ttl=1h \
	max_ttl=24h
```

## Usage 

Create dynamic credentials.
```text
$ vault read horizon/creds/<instance>
```