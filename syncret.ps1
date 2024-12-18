param (
    [string]$KeyVaultName ,
    [string]$SecretName ,
    [string]$SecretsFileName
)

Write-Host "Syncret ver 1.0"
Write-Host "by devmonster"

$global:isAuthenticated = $false
$global:authenticateCancel = $false
$global:KeyVaultValue = [PSCustomObject]@{}
$global:hasKeyVaultChanges = $false
$global:hasLocalSecretsChanges = $false
$global:key = $null

function Import-Json {
    param (
        [string]$Path
    )
    if (Test-Path $Path) {
        Write-Host "Importing data from $Path"
        
        $content = Get-Content -Path $Path -Raw
        if ($content.Trim()) {
            Write-Host "└─  Done"
            return $content | ConvertFrom-Json
        }
    }
    return [PSCustomObject]@{}
}

function Get-SecretFromKeyVault {
    param (
        [string]$KeyVaultName,
        [string]$SecretName
    )
    try {
        Write-Host "Fetching secret from Key Vault"       

        $secret = az keyvault secret show --vault-name $KeyVaultName --name $SecretName --query value -o tsv

        if ($secret) {
            Write-Host "└─  Done"
            return $secret
        }
    }
    catch {
        Write-Error "└─ ❌ Failed to fetch secret from Key Vault: $_"
    }
    return ""
}

function Convert-SecureStringToByteArray {
    param (
        [System.Security.SecureString]$SecureString
    )
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr))
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function New-Key {
    param (
        [System.Security.SecureString]$Password
    )
    $passwordBytes = Convert-SecureStringToByteArray -SecureString $Password
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    return $sha256.ComputeHash($passwordBytes)
}

function Write-To-KeyVault {
    param (
        [string]$KeyVaultName,
        [string]$SecretName,
        [PSObject]$JsonString        
    )

    Write-Host "Saving data"    

    $jsonStringConvert = $JsonString | ConvertTo-Json -Depth 10
    $secureString = ConvertTo-SecureString $jsonStringConvert -AsPlainText -Force
    $encryptedSecret = $secureString | ConvertFrom-SecureString -Key $global:key
    $base64Secret = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($encryptedSecret))

    $tempFilePath = [System.IO.Path]::GetTempFileName()
    Set-Content -Path $tempFilePath -Value $base64Secret

    az keyvault secret set --vault-name $KeyVaultName --name $SecretName --file $tempFilePath

    Remove-Item -Path $tempFilePath

    return
}



function Show-Menu {

    while ($true) {

        Write-Host
        Write-Host "Options:" 
        Write-Host "1. Copy LocalSecrets to Key Vault"
        Write-Host "2. Copy Key Vault to LocalSecrets"
        Write-Host "3. Manual Compare"
        Write-Host "4. Show LocalSecrets"
        Write-Host "5. Show Key Vault"
        Write-Host "6. Exit"
        Write-Host 
        $action = Read-Host "Select an option [1/2/3/4/5/6]"     

        if ($action -eq "1") {
            $confirm = Read-Host "Are you sure you want to copy everything from LocalSecrets to Key Vault? This will overwrite all values in Key Vault. (yes/no) [y/n]"
            if ($confirm -eq "yes" -or $confirm -eq "y") {              
                Write-Host Values $LocalSecrets                  
                Write-To-KeyVault -KeyVaultName $KeyVaultName -SecretName $SecretName -JsonString $LocalSecrets | Out-Null
                Write-Host "All values from LocalSecrets have been copied to Key Vault."             
            }
            else {
                Write-Host "Operation cancelled."
            }
        }
        elseif ($action -eq "2") {
            $confirm = Read-Host "Are you sure you want to copy everything from Key Vault to LocalSecrets? This will overwrite all values in LocalSecrets. [yes/no]"
            if ($confirm -eq "yes") {
                $LocalSecrets = $KeyVault
                Write-Host "All values from Key Vault have been copied to LocalSecrets."                
            }
            else {
                Write-Host "Operation cancelled."
            }
        }
        elseif ($action -eq "3") {
          Compare-Json -LocalSecrets $LocalSecrets -KeyVault $global:KeyVaultValue
        }
        elseif ($action -eq "4") {
            Write-Host "LocalSecrets: $($LocalSecrets | ConvertTo-Json -Depth 10)"            
        }
        elseif ($action -eq "5") {
            Write-Host "Key Vault: $($global:KeyVaultValue| ConvertTo-Json -Depth 10)"            
        }
        elseif ($action -eq "6") {
            exit 0
        }
        else {
            Write-Host "Invalid option selected. Please try again."            
        }
    }
}


function Authenticate {

    $encryptedSecret = Get-SecretFromKeyVault -KeyVaultName $KeyVaultName -SecretName $SecretName

    do {
        Write-Host
        Write-Host "Decrypting secret from Key Vault"
        $password = Read-Host -AsSecureString "├ Enter the password to decrypt the secret"
        $global:key = New-Key -Password $password

        $isAuthComplete = $false        
        
        if ($encryptedSecret) {
            try {
                $decodedSecret = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encryptedSecret))
                $decryptedSecureString = $decodedSecret | ConvertTo-SecureString -Key $global:key

                if ($decryptedSecureString) {
                    $plainTextSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($decryptedSecureString)
                    )
                    $global:KeyVaultValue = $plainTextSecret | ConvertFrom-Json

                    $isAuthComplete = $true

                    Write-Host "└── Decryption complete"
                    Write-Host
                }
                else {
                    $isAuthComplete = $false                   
                }
            }
            catch {
                 $isAuthComplete = $false
            }
        }
        else {
             $global:KeyVaultValue = [PSCustomObject]@{}
        }

        if ($isAuthComplete -eq $false) {
            Write-Error "│ ❌ Failed to decrypt the secret: $_"
            
            $retry = Read-Host "└── The decryption password is incorrect. Do you want to try again? (yes/no)"
            if ($retry -eq "no") {

                Write-Host
                Write-Host "Do you want to start over with a new secret?"
                Write-Host "│ ⚠ WARNING: This will overwrite the secret on the server. This will affect users who are using the secret. If versioning is enabled on the Key Vault, you can revert to a previous version of the secret."
                Write-Host

                $confirm = Read-Host "├── Are you sure you want to proceed? (yes/no)"

                if ($confirm -eq "yes") {
                    $verifyKeyVaultName = Read-Host "│ Type the Key Vault name ('$KeyVaultName') to verify"
                    if ($verifyKeyVaultName -eq $KeyVaultName) {                           

                        do {
                            $password = Read-Host -AsSecureString "├── Enter a new password to encrypt the secret"
                            $confirmPassword = Read-Host -AsSecureString "└── Confirm the new password"

                            if ([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)) -eq [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword))) {
                                $global:key = New-Key -Password $password
                                $global:KeyVaultValue  = [PSCustomObject]@{}
                                break
                            }
                            else {
                                Write-Host "├ ❌ Passwords do not match. Please try again."
                            }
                        } while ($true)
                    }
                    else {
                        Write-Host "└ ❌ Key Vault name does not match. Exiting."
                        exit
                    }
                }
                else {
                    exit
                }
            }
            
        }
    } while ($isAuthComplete -eq $false)
}

function Compare-Json {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$LocalSecrets,
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$KeyVault
    )
        
    $global:hasKeyVaultChanges = $false
    $global:hasLocalSecretsChanges = $false        

    Write-Host "Starting Manual Compare"

    if ($LocalSecrets -eq $KeyVault) {
        Write-Host "└─  The Local and Key Vault versions are the same."
        Write-Host 
        Write-Host         
    }

    foreach ($property in $LocalSecrets.PSObject.Properties) {
        $name = $property.Name
        $value1 = $property.Value
        $value2 = if ($KeyVault.PSObject.Properties[$name]) { $KeyVault.$name } else { $null }

        if ($null -eq $value2) {
            Write-Host
            Write-Host "Property '$name' exists in LocalSecrets but not in Key Vault."
            Write-Host "│ LocalSecrets: $value1"
            Write-Host "│ Key Vault: null"
            Write-Host "│ "
            Write-Host "│ What do you want to do?"
            Write-Host "├─ Add this property to Key Vault : [add or a]"
            Write-Host "├─ Delete this property from LocalSecrets : [delete or d]"
            Write-Host "├─ Skip this property : [skip or s]"
            Write-Host "│"
            $action = Read-Host "└──  Do you want to add this property to Key Vault, delete it from LocalSecrets, or skip? (add/delete/skip) [a/d/s]"
            if ($action -eq "add" -or $action -eq "a") {
                $KeyVault | Add-Member -MemberType NoteProperty -Name $name -Value $value1
                $global:hasKeyVaultChanges = $true
                Write-Host "Added property '$name' to Key Vault."                
            }
            elseif ($action -eq "delete" -or $action -eq "d") {
                $LocalSecrets.PSObject.Properties.Remove($name)
                $global:hasLocalSecretsChanges = $true
                Write-Host "Deleted property '$name' from LocalSecrets."
            }
            elseif ($action -eq "skip" -or $action -eq "s") {
                continue
            }        
        }
        elseif ($value1 -ne $value2) {
            Write-Host
            Write-Host "Property '$name' has different values in LocalSecrets and Key Vault."
            Write-Host "│ LocalSecrets: $value1"
            Write-Host "│ Key Vault: $value2"
            Write-Host "│ "
            Write-Host "│ What do you want to update?"
            Write-Host "├─ LocalSecrets (Key Vault -> LocalSecrets) : [l or LocalSecrets]"
            Write-Host "├─ Key Vault (LocalSecrets -> Key Vault) : [k or KeyVault]"
            Write-Host "├─ Skip this property : [s or skip]"
            Write-Host "│"
            $action = Read-Host "└── [l/k/s]"
            if ($action -eq "LocalSecrets" -or $action -eq "l") {
                $LocalSecrets.$name = $value2
                $global:hasLocalSecretsChanges = $true
                Write-Host "Updated LocalSecrets with value from Key Vault for property '$name'."
            }
            elseif ($action -eq "KeyVault" -or $action -eq "k") {
                $KeyVault.$name = $value1
                $global:hasKeyVaultChanges = $true
                Write-Host "Updated Key Vault with value from LocalSecrets for property '$name'."
            }
            elseif ($action -eq "skip" -or $action -eq "s") {
                continue
            }
        }
    }

    foreach ($property in $KeyVault.PSObject.Properties) {
        $name = $property.Name
        if (-not $LocalSecrets.PSObject.Properties[$name]) {
            Write-Host
            Write-Host "Property '$name' exists in Key Vault but not in LocalSecrets."
            Write-Host "│ Key Vault: $($KeyVault.$name)"
            Write-Host "│ LocalSecret: null"
            Write-Host "│"
            Write-Host "│ What do you want to do?"
            Write-Host "├─ Copy this property to LocalSecret : [copy or c]"
            Write-Host "├─ Delete this property from Key Vault : [delete or d]"
            Write-Host "├─ Skip this property : [skip or s]"
            Write-Host "│"
            $action = Read-Host "└──  Do you want to copy this property to LocalSecrets or delete it from Key Vault? (copy/delete/skip) [c/d/s]"
            if ($action -eq "copy" -or $action -eq "c") {
                $LocalSecrets | Add-Member -MemberType NoteProperty -Name $name -Value $KeyVault.$name
                $global:hasLocalSecretsChanges = $true
                Write-Host "Copied property '$name' to LocalSecrets."                
            }
            elseif ($action -eq "delete" -or $action -eq "d") {
                $KeyVault.PSObject.Properties.Remove($name)
                $global:hasKeyVaultChanges = $true
                Write-Host "Deleted property '$name' from Key Vault."
            }
            elseif ($action -eq "skip" -or $action -eq "s") {
                continue
            }
        }
    }
            
    if ($global:hasKeyVaultChanges) {
        try { 
            Write-To-KeyVault -KeyVaultName $KeyVaultName -SecretName $SecretName -JsonString $KeyVault
            Write-Host "Updated secret saved to Key Vault."
     
        }
        catch {
            Write-Error "Failed to encrypt and save the secret: $_"
        }
    }
    else {
        Write-Host "LocalSecrets and Key vault are the same. No changes were made."
    }

    
    if ($global:hasLocalSecretsChanges) {
        try {
            $LocalSecrets | ConvertTo-Json -Depth 10 | Set-Content -Path $userSecretsPath
            Write-Host "Local secrets saved to $userSecretsPath."
        }
        catch {
            Write-Error "Failed to save local secrets: $_"
        }
    }

    return
}

$userSecretsPath = "$env:APPDATA\Microsoft\UserSecrets\$SecretsFileName\secrets.json"
$LocalSecrets = Import-Json -Path $userSecretsPath

Authenticate
Show-Menu

