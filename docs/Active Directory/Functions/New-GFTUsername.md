# New-GFTUsername

## Definition

This function allow you to generate username.

It check in Active Directory if username is already present and create another if it the case.

## Usage

```powershell

# Simple example
New-GFTUsername Dorian Irsi

# No Check in Active Directory
New-GFTUsername -FirstName Dorian -LastName Irsi -NoADCheck

# Add prefix (ex: service account)
# If you add prefix, firstname isn't truncate
New-GFTUsername -FirstName opnsense -LastName connect -Prefix svc_

# Remove 15 characters limitation
New-GFTUsername -FirstName Dorian -LastName IrsiTheBestHRInthePlace -NumberOfLetters 25

```


## Default options

```powershell

# Firstname is mandatory
[parameter(Mandatory=$true, Position=0)]
[string]$FirstName

# Lastname is not mandatory, if you want generate an specific account (firstname will be not truncate)
[parameter(Mandatory=$false, Position=1)]
[string]$LastName

# NumbersOfLetters is not mandatory but it's fixed at 15. This parameter truncate username.
[parameter(Mandatory=$false, Position=2)]
[int]$NumberOfLetters = 15

# NoADCheck allow you to bypass AD Check
[parameter(Mandatory=$false, Position=3)]
[switch]$NoADCheck

# Prefix add prefix to username (firstname will be not truncate)
[parameter(Mandatory=$false, Position=4)]
[String]$Prefix

```