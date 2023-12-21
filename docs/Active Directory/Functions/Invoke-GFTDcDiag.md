# Invoke-GFTDcDiag

## Definition
This function allow you to invoke DCDiag on one or multiple domain controller.

## Usage

```powershell

#For one domain controller:
Invoke-GFTDcDiag -DomainControllers AD01

#For Multiple domain controllers:
Invoke-GFTDcDiag -DomainControllers AD01,AD02

#For each DC in your Farm:
$DCs = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | % { $_.Servers } | select Name).Name
Invoke-GFTDcDiag -DomainControllers $DCs

```

## Default options

```powershell

# This function cannot be run without DC Name
[Parameter(Mandatory)]
[ValidateNotNullOrEmpty()]
[string[]]$DomainControllers

```