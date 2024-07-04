function New-GFTPassword {
    <#
    .SYNOPSIS
        Create password

    .DESCRIPTION
        Create password with complexity or not. 
        You can choose number fo characters.

    .NOTES
        Filename: New-GFTPassword.psm1

    .Example
        # Simple example
        New-GFTPassword
    .Example
        # Remove complexity
        New-GFTPassword -NoComplexity
    .Example
        # Password not complex with 29 characters
        New-GFTPassword -NoComplexity -Lenght 29
    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$false, Position=0)]
        [int]$Lenght = 18,
        [parameter(Mandatory=$false, Position=1)]
        [switch]$NoComplexity
    )
    if (!($NoComplexity)) {
        $Lenght = [int]$Lenght-1
        $Password = ([char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) + 0..9 | Sort-Object {Get-Random})[0..$Lenght] -join ''
        Return $Password
    } else {
        $Lenght = [int]$Lenght-1
        $Password = ([char[]]([char]65..[char]90) + ([char[]]([char]97..[char]122)) + 0..9 | Sort-Object {Get-Random})[0..$Lenght] -join ''
        while ($Password -notmatch '\d') {
            $Password = ([char[]]([char]65..[char]90) + ([char[]]([char]97..[char]122)) + 0..9 | Sort-Object {Get-Random})[0..$Lenght] -join ''
        }
        Return $Password
    }

}