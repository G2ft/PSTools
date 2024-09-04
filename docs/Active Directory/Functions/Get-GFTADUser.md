# Get-GFTADUser

## Definition
This function allow you to get user from all DC in your AD. Resolve replication delay.

## Usage

```powershell

#For default properties:
Get-GFTADUser myuser

#For others properties:
Get-GFTADUser myuser -Properties mail,LastLogonDate

```

## Default options

```powershell

# This function cannot be run without samaccountname
[Parameter(Mandatory)]
[ValidateNotNullOrEmpty()]
[string]$SamAccountName

```
