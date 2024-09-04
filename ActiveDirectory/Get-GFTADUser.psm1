function Get-GFTADUser {
    <#
    .SYNOPSIS
        Get user in Active Directory

    .DESCRIPTION
        This function allow you to get user from all DC in your AD Forest.

    .NOTES
        Version:        1.0
        Changelog:      N/A
        Filename:       Get-GFTADUser.psm1

    .Example
        Get-GFTADUser myuser

    .Example
        Get-GFTADUser myuser -Properties mail
    #>
    [CmdletBinding()]
    param(
        [String]$SamAccountName,
        [String[]]$Properties,
        [int]$WaitTime = 2,
        [int]$TestNumber = 3
    )
    $Params = @{}
    if ($Properties) {
        $Params['Properties'] += $Properties 
    }
    $Params['Identity'] = $SamAccountName
    $DCs = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | % { $_.Servers } | Select-Object Name).Name
    $i=1
     while (!($Return) -and $i -le $TestNumber) {
        $DCs | % {
            repadmin /syncall $_ (Get-ADDomain).DistinguishedName /e /A | Out-Null
            $Params['Server'] = "$($_)"
            $Return = try {
                Get-ADUser @Params
            } catch [System.ArgumentException],[Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                if ($i -le $($TestNumber-1)) { 
                    $null 
                } else {
                    throw $_.Exception.Message
                }
            } catch {
                $null
            }
        }
        if (!($Return)) {
            $i++
            Start-Sleep -Seconds $WaitTime
        } else {
            Return $Return
        }
    }
    Return $Return
}
