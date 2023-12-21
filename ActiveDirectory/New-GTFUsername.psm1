function New-GFTUsername {
    <#
    .SYNOPSIS
        Create username (pnom)

    .DESCRIPTION
        Create username with firstname and lastname
        Check in Active Directory if username exist, if it's the case, generate another username with the second letter of firstname

    .NOTES
        Filename: New-GFTUsername.psm1

    .Example
        # Simple example
        New-GFTUsername Dorian Irsi
    .Example
        # No Check in Active Directory
        New-GFTUsername -FirstName Dorian -LastName Irsi -NoADCheck
    .Example
        # Add prefix (ex: service account)
        # If you add prefix, firstname isn't truncate
        New-GFTUsername -FirstName opnsense -LastName connect -Prefix svc_
    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, Position=0)]
        [string]$FirstName,
        [parameter(Mandatory=$false, Position=1)]
        [string]$LastName,
        [parameter(Mandatory=$false, Position=2)]
        [int]$NumberOfLetters = 15,
        [parameter(Mandatory=$false, Position=3)]
        [switch]$NoADCheck,
        [parameter(Mandatory=$false, Position=4)]
        [String]$Prefix
    )
    if(!($Prefix)) {
        if (!($LastName)) {
            $FirstLetterName = $FirstName -replace "é","e" -replace "è","e" -replace "ê","e" -replace "â","a" -replace "à","a" -replace " ",""
            $xlettersofLastname = $FirstName[0..$NumberOfLetters] -join ''
            $LoginName = "$xlettersofLastname"
        } else {
            $LastName = $LastName -replace "é","e" -replace "è","e" -replace "ê","e" -replace "â","a" -replace "à","a" -replace " ",""
            if ($LastName.Length -lt 2) {
                $FirstLetterName = ($FirstName.Split(" ") | % { $_[0..2] }) -join ""
            } else {
                $FirstLetterName = ($FirstName.Split(" ") | % { $_[0] }) -join ""
            }
            $xlettersofLastname = $LastName[0..$NumberOfLetters] -join ''
            $LoginName = "$FirstLetterName$xlettersofLastname"
        }
    } else {
        $LoginName = "$Prefix$Firstname$Lastname"
    }
    if (!($NoADCheck)) {
        $TryUser = $(try {Get-ADUser $LoginName} catch {$null})
        if ($TryUser -ne $null) {
            $i=1
            while ($(try {Get-ADUser $LoginName} catch {$null}) -ne $null) {
                if ($Prefix) {                
                    [int]$Com = $NumberOfLetters-$i
                    $LoginName = $LoginName[0..$com] -join ''
                } else {
                    [int]$Com = $NumberOfLetters-$i
                    $FirstLetterName = $FirstName[0..$i] -join ''
                    $lettersofLastname = $LastName[0..$Com] -join ''
                    $LoginName = "$FirstLetterName$lettersofLastname"
                }
                $i++
                if ($Com -eq 0) { Return "Error no loginname found !" }
            }
        }
    }
    $LoginName = $LoginName -replace "é","e" -replace "è","e" -replace "ê","e" -replace "â","a" -replace "à","a" -replace " ",""
    Return $LoginName.ToLower()
}