function Invoke-GFTDcDiag {    
    <#
    .SYNOPSIS
        Invoke an DCDiag on multiple Domain Controller

    .DESCRIPTION
        This script allow you to invoke an DCDiag on multiple Domain Controller

    .NOTES
        Filename:       Invoke-GFTDCDiag.psm1

    .Example
        Invoke-GFTDcDiag -DomainControllers AD01
    .Example
        Invoke-GFTDcDiag -DomainControllers AD01,AD02 | ? {$_.TestResult -ne "Passed"}
    .Example
        $DCs = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | % { $_.Servers } | select Name).Name
        Invoke-GFTDcDiag -DomainControllers $DCs | ? {$_.TestResult -ne "Passed"} | Export-CSV C:\my\path\csv.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$DomainControllers
    )

    $DCDiagFull = @()
    foreach ($DomainController in $DomainControllers) {
        $result = dcdiag /s:$DomainController /v
        $result | Select-String -pattern '\. (.*) \b(passed|failed)\b test (.*)' | % {
            if ($_.Matches.Groups[2].Value -eq "Failed") {
                $MoreInformations = (dcdiag /s:$DomainController /v /test:$($_.Matches.Groups[3].Value) | Out-String)
                $MoreInformations -match "(?s)starting test: $($_.Matches.Groups[3].Value)(?<content>.*).... $DomainController" | Out-Null
                $MoreInformations = $($Matches['content']).Trim()
            } else {
                $MoreInformations = "N/A"
            }
            $obj = @{
                TestName = $_.Matches.Groups[3].Value
                TestResult = $_.Matches.Groups[2].Value
                Entity = $_.Matches.Groups[1].Value
                Details = $MoreInformations
            }
            $DCDiagFull += [pscustomobject]$obj
        }
    }
    return $DCDiagFull
}