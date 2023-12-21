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
# Lenght is your password lenght
[parameter(Mandatory=$false, Position=0)]
[int]$Lenght = 18

# NoComplexity remove complex characters
[parameter(Mandatory=$false, Position=1)]
[switch]$NoComplexity

```