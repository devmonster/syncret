# Syncret

A PowerShell script that syncs your local secrets to an Azure Key Vault Secrets repo by comparing the key/pair values.

## Features
- Syncs your local secret to key vault
- Checks each property values and prompts the for copy/update/delete
- Password-encrypt your secrets so a single keyvault can be shared across different projects and teams

## Usage


```powershell
.\syncret.ps1 -KeyVaultName "<KeyVault Name>" -SecretName "<Secret Name>" -SecretsFileName "<secrets guid or name>"
```

| Parameter | Description | Sample |
|--|--|--|
| `KeyVaultName` | Key vault name to read the secrets from. The logged in user has to have access to the Secrets (Get) | **dev-secrets-kv** |
| `SecretName` | Secret name that contains the encrypted JSON | **local-secrets** |
| `SecretsFileName` | Local secret name or UUID that VS uses to read the secrets from. You can find the SecretsFileName value if you open the *.csproj* file and look for the *\<UserSecretsId\>* tag. This might be a UUID or a custom value | **d9d8264f-795a-4ea3-bac9-64c7002b447c** |

### Important

- Azure CLI is required. You must [install Azure CLI on Windows, Mac, or Linux](https://learn.microsoft.com/en-us/cli/azure/)
- Make sure a user is logged in via the `az login` command and has access to the key vault

## Known Issues
- Seems to be only working fine on flat JSON structure/key pair

## Future Plans
- Nested JSON structure support