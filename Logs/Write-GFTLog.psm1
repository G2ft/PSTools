function Write-GFTLog {
<#
.SYNOPSIS
    This function allows you to write logfile.

.DESCRIPTION
    This function allows you to write log in log file.
    You can edit log path with logpath parameter.
    This module is store in PS Modules folder.

.NOTES
    Prerequisite : PowerShell V5
 
.EXAMPLE
    Write-GFTLog -LogPath "C:\MyFolder" -Begin
    Write-GFTLog -Logcontent "MyValue" -LogPath "C:\MyFolder"
    Write-GFTLog -LogPath "C:\MyFolder" -End

.EXAMPLE
    Write-GFTLog -Begin
    Get-LocalUser | Write-GFTLog
    Write-GFTLog -End

.EXAMPLE
    Write-GFTLog -Begin
    Get-LocalUser -Verbose | Write-GFTLog
    Write-GFTLog -End
#>
param (
        [CmdletBinding()]
        [Parameter(Mandatory=$False, ValueFromPipeline=$True)]
        [String[]]$LogContent,
        [String]$LogPath = "$($env:HOMEDRIVE)\PSLogs\",
        [String]$LogTitle,
        [Switch]$Begin,
        [Switch]$End,
        [int]$DayBeforeDelete
    )

    if (!(Test-Path $LogPath)) {
        try {
            Write-Verbose "Create Directory $LogPath" 
            [void](New-Item $LogPath -ItemType Directory -ErrorAction Stop)
        } catch {
            Return "Error when create $LogPath"
        }
    }

    if (!($LogTitle)) {
        $Type = "Function"
        (Get-PSCallStack).FunctionName | Select-String -Pattern "\w+-\w+" | % {
                $PatternMatch = $_.Matches
        }

        if (($PatternMatch.Value | measure).count -gt 1) {
            $FunctionName = $PatternMatch.Value | ? {$_ -ne "Write-GFTLog"}
        } else {
            $FunctionName = $PatternMatch.Value
        }
    } else {
        $FunctionName = $LogTitle
        $Type = ""
    }

    $Verbose = $False
    Get-PSCallStack | % {
        if ($_.Arguments -match "Verbose=true") {
            $Verbose = $True
        }
    }
    Write-Verbose $FunctionName
    $Username = $env:USERNAME
    $Domain = (Get-CimInstance Win32_ComputerSystem).Domain
    if ($Domain) {
        $LogFilePath = "$FunctionName-$Domain_$(Get-Date -Format 'yyyy-MM-dd').GFTlog"
    } else {
        $LogFilePath = "$FunctionName-$(Get-Date -Format 'yyyy-MM-dd').GFTlog"
    }
    

    $LogPath = Join-Path $LogPath $LogFilePath
    if ($DayBeforeDelete) {
        $LogFolder = Split-Path $LogPath
        Get-ChildItem -Filter "*.GFTlog" -Path $LogFolder | ? {$_.LastWriteTime -lt (Get-Date).AddDays(-$DayBeforeDelete)} | % {
            Remove-Item $_.FullName -Confirm:$false -Force 6>&15>&14>&13>&12>&1
            "Remove $($_.FullName)" | Write-GFTLog
        }
    }
    
    
    Write-Verbose $LogPath
    
    if ($Begin) {
        Write-Verbose "$Username : $Type $FunctionName Begin at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Write-Output "$Username : $Type $FunctionName Begin at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $LogPath -Append
    }

    if ($LogContent) {
        Write-Verbose "$Username : $LogContent $Type $Functionname" -Verbose:$Verbose
        Write-Output "$Username : $LogContent $Type $FunctionName -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $LogPath -Append
    }

    if ($End) {
        Write-Verbose "$Username : $Type $FunctionName End at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $LogPath -Append
        Write-Output "$Username : $Type $FunctionName End at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $LogPath -Append
        Write-Output " " | Out-File $LogPath -Append
    }
}
