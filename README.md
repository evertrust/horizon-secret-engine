# horizon-secrets-engine

This plugin allow you to create a secret backend that will use the Horizon API to generate dynamic credentials.

## Setup

### Register horizon-secrets-engine in plugin catalog

Start server with the right config setup in `vault/server.hcl`.

    $ vault server -config=vault/server.hcl

In a new terminal, set the VAULT\_ADDR to the local Vault server.

    $ export VAULT_ADDR='http://127.0.0.1:8200'

Initialize Vault with one key. Save the initial root token and unseal
key.

    $ vault operator init -key-shares=1 -key-threshold=1

    Unseal key 1: $VAULT_UNSEAL_KEY
    Initial Root Token: $VAULT_TOKEN

Set the `VAULT_TOKEN` to the root token

    $ export VAULT_TOKEN=$VAULT_TOKEN

Unseal vault with the unseal keys.

    $ vault operator unseal $VAULT_UNSEAL_KEY

Calculate the SHA256 sum of the compiled plugin binary.

    $ SHA256=$(shasum -a 256 /Path/to/vault/plugins/horizon-secrets-engine | cut -d ' ' -f1)

Register the plugin

    $ vault plugin register -sha256=$SHA256 secret horizon-secrets-engine

### Enabling

Enable the horizon secret engine:

    $ vault secrets enable -path=horizon horizon-secrets-engine

### Configure Vault

Configure Vault with the proper plugin and connection

    $ vault write horizon/config/<instance> \
      horizon_endpoint="..." \
      username="..." \
      password="..."

Vault will use the user specified here to create/update/revoke horizon
credentials. That user must have the appropriate permissions to perform
actions upon other horizon users (create, update credentials, delete,
etc.).

### Rotate-root

After configuring the root user, it is highly recommanded you rotate
that user’s password such that the vault user is not accessible by any
users other than Vault itself:

    $ vault write -force horizon/rotate-root/<instance>


## Usage 

### Configure Role

Configure a role that maps a name in Vault to a set of creation
statements to create the horizon credentials:

    $ vault write horizon/roles/<role-name> \
            instance=<instance> \
            roles=... \
            contact=... \
            ttl=1h \
            max_ttl=24h

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<tbody>
<tr class="odd">
<td style="text-align: left;"><p>Parameter</p></td>
<td style="text-align: left;"><p>Description</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>instance</p></td>
<td style="text-align: left;"><p>The horizon instance defined in the
horizon/config (mandatory)</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>roles</p></td>
<td style="text-align: left;"><p>Roles predefined in horizon, which you
want to assign to the new credential</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>contact</p></td>
<td style="text-align: left;"><p>Email address (mandatory)</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>ttl</p></td>
<td style="text-align: left;"><p>Life duration for the
credential</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>max_ttl</p></td>
<td style="text-align: left;"><p>Maximale life duration for the
credential</p></td>
</tr>
<tr class="odd">
<td style="text-align: left;"><p>password_policy</p></td>
<td style="text-align: left;"><p>The password policy used to generate
the password</p></td>
</tr>
<tr class="even">
<td style="text-align: left;"><p>username_policy</p></td>
<td style="text-align: left;"><p>The username policy used to generate
the username</p></td>
</tr>
</tbody>
</table>

### Credential Generation

After the secrets engine is configured and a user/machine has a Vault
token with the proper permission, it can generate credentials.

Generate a new credential by reading from the `/creds` endpoint with the
name of the role:

    $ vault read horizon/creds/<role-name>
