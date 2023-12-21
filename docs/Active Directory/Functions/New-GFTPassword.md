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
# Lenght is your password lenght
[parameter(Mandatory=$false, Position=0)]
[int]$Lenght = 18

# NoComplexity remove complex characters
[parameter(Mandatory=$false, Position=1)]
[switch]$NoComplexity

```