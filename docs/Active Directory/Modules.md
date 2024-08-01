# Active Directory

## Prerequisites

* ActiveDirectory PowerShell module
* This module is tested in PowerShell 7.3

## Description
These modules allow you to manage Active Directory objects.

You can : 

* Launch DCDiag

* Generate Username / Password

## Usage

Usage depends on the module you import

### Import Module

```powershell
# To Import DCDiag module : 
Import-Module ".\ActiveDirectory\Invoke-GFTDCDiag.psm1"
```

## List of function

* [**Invoke-GFTDCDiag**](../Functions/Invoke-GFTDcDiag.psm1)
  * Invoke an DCDiag on your Domain Controllers
* [**New-GFTUsername**](./Functions/New-GFTUsername.md)
  * Generate Username for your users
* [**New-GFTPassword**](./Functions/New-GFTPassword.md)
  * Generate Password
