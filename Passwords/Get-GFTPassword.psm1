function Get-GFTPassword {
    <#
    .SYNOPSIS
        This function allow you to search password in Passbolt

    .DESCRIPTION
        This function allow you to search password in Passbolt with specific account.
        You can filter your search with SearchMethod (uri, name, id) and SearchContent.
        Require Module PSPGP

    .NOTES
        Filename:       Get-GFTPassword.psm1

    .Example
        Get-GFTPassword 
    .Example
        Get-GFTPassword -SearchMethod uri -SearchContent "https://myservice.passbolt"
    .Example
        Get-GFTPassword -SearchMethod name -SearchContent "My Service"
    #>
    param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeLine = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias(
            'PSCredential'
        )]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credentials,
        [string]$Server = "https://mypassbolt.url.local",
        # Take Privatekey and FingerPrint in Windows Registry and manage permissions of keys
        [String]$PrivateKeyContent = (Get-ItemProperty 'HKLM:\Software\Microsoft\APIPassbolt\').PrivateKey,
        [string]$FingerPrint = (Get-ItemProperty 'HKLM:\Software\Microsoft\APIPassbolt\').FingerPrint,
        [ValidateSet("uri","name","id")]
        [String]$SearchMethod,
        [String]$SearchContent,
        [switch]$Direct,
        [string]$ID
    )
    $ProgressPreference = 'SilentlyContinue'
    if (!($Credentials)) {
        $AccountXML = Import-Clixml "passbolt.xml"
        $Credentials = New-Object System.Management.Automation.PSCredential($AccountXML.Username, (ConvertTo-SecureString -String "$($AccountXML.Password)" -Key $($AccountXML.Key)))
    }
    $Password = $Credentials.GetNetworkCredential().Password
    $UriLogin = '/auth/login.json'
    $UriResourse = '/resources.json'

    $Files = New-Item -Path "C:\PowerShell\Temp\" -Name "$([System.IO.Path]::GetRandomFileName())$(Get-Random -Minimum 0 -Maximum 99999)" -ItemType File -Value $PrivateKeyContent 
    $Body = @{
        'data[gpg_auth][keyid]' = $FingerPrint
    }
    $Response1 = Invoke-WebRequest -Uri ($Server+$UriLogin) -Method Post -ContentType 'multipart/form-data' -Form ($Body)
    $Files = $Files.FullName 
    $DecryptedToken = Unprotect-PGP -FilePathPrivate $Files -Password $Password -String ([System.Web.HttpUtility]::UrlDecode($Response1.Headers.'X-GPGAuth-User-Auth-Token').Replace('\ ',' '))
    
    $Body = @{
        'data[gpg_auth][keyid]' = $FingerPrint
        'data[gpg_auth][user_token_result]' = $DecryptedToken
    }
    
    $Response2 = Invoke-WebRequest -Uri ($Server+$UriLogin) -Method Post -ContentType 'multipart/form-data' -Form ($Body) -SessionVariable WebSession
    $Response3 = Invoke-WebRequest -Uri ($Server) -Method Get -WebSession $WebSession 
    $csrfToken = ($WebSession.Cookies.GetAllCookies() | Where-Object {$_.Name -eq 'csrfToken'}).value
    $Headers = @{
        'X-CSRF-Token' = $csrfToken
    }
    $Resources = ((Invoke-WebRequest -Uri ($Server+$UriResourse) -Method Get -Headers $Headers -WebSession $WebSession) |ConvertFrom-Json).Body
    $array = @()
    if ($Direct) {
        $Content = ((Invoke-WebRequest -Uri ($Server+"/resources/$ID.json?api-version=v2&contain[secret]=1") -Method Get -Headers $Headers -WebSession $WebSession) |ConvertFrom-Json).Body 
        $Secret = Unprotect-PGP -FilePathPrivate $Files -Password $Password -String $($Content.Secrets.data)
        if ($Secret -match 'description') {
            $Description = $($Secret -split ",")[0] -replace '^\{"description":"', '' -replace '\"$',''
            $Secret = $($Secret -split ",")[1] -replace '^"password":"', '' -replace '"\}$',''
        } else {
            $Description = ""
        }
        $Obj = @{
            id = $Content.Id
            Name = $Content.name
            Username = $Content.username
            Secret = $Secret
            Description = $Description
            uri = $Content.uri
        }
        $Array += [pscustomobject]$Obj
    } else {
        $Resources | ? {$_."$SearchMethod" -match "$SearchContent"} | % {
            ((Invoke-WebRequest -Uri ($Server+"/resources/$($_.id).json?api-version=v2&contain[secret]=1") -Method Get -Headers $Headers -WebSession $WebSession) |ConvertFrom-Json).Body |%{
                $Secret = Unprotect-PGP -FilePathPrivate $Files -Password $Password -String $($_.Secrets.data)
                if ($Secret -match 'description') {
                    $Description = $($Secret -split ",")[0] -replace '^\{"description":"', '' -replace '\"$',''
                    $Secret = $($Secret -split ",")[1] -replace '^"password":"', '' -replace '"\}$',''
                } else {
                    $Description = ""
                }

                $Obj = @{
                    id = $_.Id
                    Name = $_.name
                    Username = $_.username
                    Secret = $Secret
                    Description = $Description
                    uri = $_.uri
                }
                $Array += [pscustomobject]$Obj
            }
        }
    }
    if (($array | Measure-Object).Count -gt 0) {
        Write-GFTLog -LogContent "$($env:USERNAME) Retreive Password from $Server : $($Array | Select-Object name,username,uri | Out-String)" -LogTitle "APIPassbolt"
    }
    Remove-Item $files -Force -Confirm:$false
    Return $Array
}
