# New-GFTPassword

## Definition

This function allow you to generate passwords.
Lenght is limited to 62.

## Usage

```powershell

# Simple example
New-GFTPassword

# Remove complexity
New-GFTPassword -NoComplexity

# Password not complex with 29 characters
New-GFTPassword -NoComplexity -Lenght 29

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