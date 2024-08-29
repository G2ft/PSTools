function Get-GFTPassboltConnection {
    <#
    .SYNOPSIS
        This function is required for all other functions (Connection begin)

    .DESCRIPTION
        This function allow you to connect.
        Stock your privatekey in secure location (registry with controlled acl for example)

    .NOTES
        Version:        1.0
        Changelog:      N/A
        Filename:       MgtPassbolt.psm1

    .Example
        Get-GFTPassboltConnection -Credential (Get-Credential) -PrivateKeyContent (Get-Content MyPrivateKey) -FingerPrint "MyFingerPrint"
    .Example
        Get-GFTPassboltConnection -PrivateKeyContent (Get-Content MyPrivateKey)
    .Example
        Get-GFTPassboltConnection
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
        [string]$Server = "https://yourserver.com",
        [String]$PrivateKeyContent = (Get-ItemProperty 'HKLM:\Software\Microsoft\APIPass\').PrivateKey,
        [string]$FingerPrint = (Get-ItemProperty 'HKLM:\Software\Microsoft\APIPass\').FingerPrint,
        [string]$SecretPath = "C:\PowerShell\Temp\Secret$(Get-Random -Minimum 0 -Maximum 99999)"
    )

    $ProgressPreference = 'SilentlyContinue'
    if (!($Credentials)) {
        $AccountXML = Import-Clixml "<myxmlpass>"
        $Credentials = New-Object System.Management.Automation.PSCredential($AccountXML.Username, (ConvertTo-SecureString -String "$($AccountXML.Password)" -Key $($AccountXML.Key)))
    }
    if (Test-Path $SecretPath) {
        Remove-Item $SecretPath -Recurse -Force -Confirm:$false
    }
    New-Item $SecretPath -ItemType Directory -Force -Confirm:$false | Out-Null

    $ACL = Get-Acl $SecretPath
    $ACL.SetAccessRuleProtection($true, $false)
    $UserToAdd = [System.Security.Principal.NTAccount]$Env:USERNAME
    $Permissions = $UserToAdd,"FullControl","ObjectInherit,ContainerInherit","None","Allow"
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Permissions)
    $ACL.AddAccessRule($Rule)
    $FileInfos = Get-Item $SecretPath
    [System.IO.FileSystemAclExtensions]::SetAccessControl($FileInfos, $ACL)

    $Password = $Credentials.GetNetworkCredential().Password
    $UriLogin = '/auth/login.json'
    $UriResourse = '/resources.json'

    $Files = New-Item -Path $SecretPath -Name "$([System.IO.Path]::GetRandomFileName())$(Get-Random -Minimum 0 -Maximum 99999)" -ItemType File -Value $PrivateKeyContent 
    $Files = $Files.FullName
    $Body = @{
        'data[gpg_auth][keyid]' = $FingerPrint
    }
    $Response1 = Invoke-WebRequest -Uri ($Server+$UriLogin) -Method Post -ContentType 'multipart/form-data' -Form ($Body)
    $DecryptedToken = Unprotect-PGP -FilePathPrivate $Files -Password $Password -String ([System.Web.HttpUtility]::UrlDecode($Response1.Headers.'X-GPGAuth-User-Auth-Token').Replace('\ ',' '))
    
    $Body = @{
        'data[gpg_auth][keyid]' = $FingerPrint
        'data[gpg_auth][user_token_result]' = $DecryptedToken
    }
    
    $Response2 = Invoke-RestMethod -SkipCertificateCheck -UseBasicParsing -Uri ($Server+$UriLogin) -Method Post -ContentType 'multipart/form-data' -Form ($Body) -SessionVariable Session
    $Response3 = Invoke-RestMethod -SkipCertificateCheck -UseBasicParsing -Uri ($Server) -Method Get -WebSession $Session
    $csrfToken = ($Session.Cookies.GetAllCookies() | Where-Object {$_.Name -eq 'csrfToken'}).value
    $Headers = @{
        'X-CSRF-Token' = $csrfToken
    }
    $Session.Headers.Add("X-CSRF-Token","$csrfToken")
    $Session.Headers.Add("SPath","$SecretPath")
    $Session.Headers.Add("SSPath","$Files")
    $Session.Headers.Add("Server","$Server")
    $Session.Headers.Add("URIResources",$UriResourse)

    Return $Session
}

function Stop-GFTPassboltConnection {
    [CmdletBinding()]
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$SecretPath = "C:\PowerShell\Temp\Secret*"
    )
    try {
        if (!($Session)) {
            Get-ChildItem $SecretPath | % {
                Remove-Item $_.FullName -Force -Confirm:$false -Recurse | Out-Null
            }
        } else {
            $Server = $Session.Headers.Server
            $PathToDelete = $Session.Headers.SPath

            Invoke-RestMethod -SkipCertificateCheck -UseBasicParsing -Uri ($Server+'/auth/logout') -Method Get -WebSession $Session | Out-Null
            if (Test-Path $PathToDelete) {
                Remove-Item $PathToDelete -Force -Confirm:$false -Recurse | Out-Null
            } else {
                Write-Verbose "Secret Path not found"
                Stop-GFTPassboltConnection
            }
        }
        Write-Verbose "Disconnected"
    } catch {
        $_.Exception.Message
    }    
}
function Get-GFTPassword {
    <#
    .SYNOPSIS
        This function allow you to search password in Passbolt

    .DESCRIPTION
        This function allow you to search password in Passbolt with specific account.
        You can filter your search with SearchMethod (uri, name, id) and SearchContent.
        Require Module PSPGP

    .NOTES
        Version:        1.0
        Changelog:      N/A
        Filename:       Get-GFTPassword.psm1

    .Example
        Get-GFTPassword 
    .Example
        Get-GFTPassword -SearchMethod uri -SearchContent "http://myservice.password"
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
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [ValidateSet("uri","name","id")]
        [String]$SearchMethod,
        [String]$SearchContent,
        [switch]$Direct,
        [string]$ID
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Credentials)) {
            $AccountXML = Import-Clixml "<myxmlpass>"
            $Credentials = New-Object System.Management.Automation.PSCredential($AccountXML.Username, (ConvertTo-SecureString -String "$($AccountXML.Password)" -Key $($AccountXML.Key)))
        }
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $params = @{}
        if ($Session) {
            $params['Session'] = $Session
        }
        $SecretPath = $Session.Headers.SPath
        if (!($SecretPath)) {
            Return "No secret found !"
        }
        $Files = $Session.Headers.SSPath
        $Server = $Session.Headers.Server
        $UriResourse = $Session.Headers.URIResources
    }
    Process {
        $Password = $Credentials.GetNetworkCredential().Password
        $array = @()
        if ($Direct) {
            $Content = (Invoke-RestMethod -Uri ($Server+"/resources/$ID.json?api-version=v2&contain[secret]=1") -Method Get -WebSession $Session).Body 
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
            $Array = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
            $Resources = (Invoke-RestMethod -UseBasicParsing -SkipCertificateCheck -Uri ($Server+$UriResourse) -Method Get -WebSession $Session).Body
            $Resources | ? {$_."$SearchMethod" -match "$SearchContent"} | % -Parallel {
                $Server = $using:Server
                $Session = $using:Session
                $SecretPath = $using:SecretPath
                $Files = $using:Files
                $Array = $using:Array
                $Password = $using:Password
                (Invoke-RestMethod -UseBasicParsing -Uri ($Server+"/resources/$($_.id).json?api-version=v2&contain[secret]=1") -Method Get -WebSession $Session).Body |% -Parallel {
                    $Server = $using:Server
                    $Array = $using:Array
                    $Password = $using:Password
                    $Files = $using:Files
                    $Secret = Unprotect-PGP -FilePathPrivate $Files -Password $Password -String $($_.Secrets.data)
                    if ($Secret -match 'description') {
                        $Json = $Secret | ConvertFrom-Json
                        $Description = $Json.Description # $($Secret -split ",")[0] -replace '^\{"description":"', '' -replace '\"$',''
                        $Secret = $Json.Password #$($Secret -split ",")[1] -replace '^"password":"', '' -replace '"\}$',''
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
                    $Array.Add([pscustomobject]$Obj) | Out-Null
                } -ThrottleLimit 10
            }
        }
        if (($array | Measure-Object).Count -gt 0) {
            Write-GFTLog -LogContent "$($env:USERNAME) Retreive Password from $Server : $($Array | Select-Object name,username,uri | Out-String)" -LogTitle "APIPass"
        }
        try {
            Stop-GFTPassboltConnection -Session $Session
        } catch {
            Stop-GFTPassboltConnection
        }
        Return $Array
    }
}

function Get-GFTPassboltPGPPubKey {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $params = @{}
        if ($Session) {
            $params['Session'] = $Session
        }
        $SecretPath = $Session.Headers.SPath
        if (!($SecretPath)) {
            Return "No secret found !"
        }
        $Server = $Session.Headers.Server
    }
    Process {
        $Content = (Invoke-RestMethod -Uri ($Server+"/gpgkeys.json") -Method Get -WebSession $Session).Body
        Return $Content
    }
    end {
        Stop-GFTPassboltConnection -Session $Session
    }
}
function New-GFTPassboltPassword {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$PublicKeyContent = (Get-GFTPassboltPGPPubKey | ? { $_.uid -match "APIPass" }).armored_key,
        [String]$UserID = (Get-GFTPassboltPGPPubKey | ? { $_.uid -match "APIPass" }).user_id,
        [String]$PasswordName,
        [String]$PasswordUsername,
        [String]$PasswordUrl,
        [String]$PasswordDescription,
        [String]$NewPassword
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $params = @{}
        if ($Session) {
            $params['Session'] = $Session
        }
        $SecretPath = $Session.Headers.SPath
        if (!($SecretPath)) {
            Return "No secret found !"
        }
        $Files = $Session.Headers.SPath
        $Server = $Session.Headers.Server
        $Files = New-Item -Path $SecretPath -Name "$([System.IO.Path]::GetRandomFileName())$(Get-Random -Minimum 0 -Maximum 99999)" -ItemType File 
        Set-Content -Path $Files.FullName -Value $PublicKeyContent
        $Password = Protect-PGP -FilePathPublic $files.FullName -String $NewPassword
    }
    Process {
        $Json = @{}
        $Secrets = @{}
        $Json['name'] = $PasswordName
        $Json['username'] = $PasswordUsername
        $Json['description'] = $PasswordDescription
        $Json['uri'] = $PasswordUrl
        $Secrets['user_id'] = $UserID
        $Secrets['data'] = "$Password"
        $Json.Add('secrets',@($Secrets))
        $Json = $Json | ConvertTo-Json
        $Content = Invoke-RestMethod -Uri ($Server+"/resources.json") -Method Post -WebSession $Session -Body $Json -ContentType 'application/json'
        return $Content.Body
    }
    End {
        Stop-GFTPassboltConnection -Session $Session
    }
}

function Remove-GFTPassboltPassword {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$PasswordID
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $params = @{}
        if ($Session) {
            $params['Session'] = $Session
        }
        $Server = $Session.Headers.Server
    }
    Process {
        $Content = (Invoke-RestMethod -Uri ($Server+"/resources/$PasswordID.json") -Method Delete -WebSession $Session).Body
        Return $Content
    }
    End {
        Stop-GFTPassboltConnection -Session $Session
    }
}

function Get-GFTPassboltFolders {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$FolderID
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $params = @{}
        if ($Session) {
            $params['Session'] = $Session
        }
        $Server = $Session.Headers.Server
    }
    Process {
        if ($FolderID) {
            $Content = (Invoke-RestMethod -Uri ($Server+"/folders/$FolderID.json?contain[children_folders]=1&contain[children_resources]=1&contain[permission]=1") -Method Get -WebSession $Session).Body
        } else {
            $Content = (Invoke-RestMethod -Uri ($Server+"/folders.json") -Method Get -WebSession $Session).Body
        }
        Return $Content
    }
    End {
        Stop-GFTPassboltConnection -Session $Session
    }
}

function Get-GFTShareInformations {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $params = @{}
        if ($Session) {
            $params['Session'] = $Session
        }
        $Server = $Session.Headers.Server
        $ProgressPreference = 'SilentlyContinue'      
    }
    Process {
        $Content = (Invoke-RestMethod -Uri ($Server+"/share/search-aros.json?contain[children_folders]=1&contain[children_resources]=1&contain[permission]=1") -Method Get -WebSession $Session).Body
        Return $Content
    }
    End {
        Stop-GFTPassboltConnection -Session $Session
    }
}


function Move-GFTPassboltPasswordToFolder {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$PasswordID,
        [String]$FolderID
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $params = @{}
        if ($Session) {
            $params['Session'] = $Session
        }
        $SecretPath = $Session.Headers.SPath
        if (!($SecretPath)) {
            Return "No secret found !"
        }
        $Server = $Session.Headers.Server
    }
    Process {
        $Json = @{}
        $Json['folder_parent_id'] = $FolderID
        $Json = $Json | ConvertTo-Json
        $Content = Invoke-RestMethod -Uri ($Server+"/move/resource/$PasswordID.json") -Method Post -WebSession $Session -Body $Json -ContentType 'application/json'
        Return $Content
    }
    End {
        Stop-GFTPassboltConnection -Session $Session
    }
}

function Get-GFTPassboltUser {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$Username,
        [String]$ID,
        [switch]$NoSessionRemove
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $Server = $Session.Headers.Server
    }
    Process {
        if ($Username) {
            $Content = Invoke-RestMethod -Uri ($Server+"/users.json?filter[search]=$Username") -Method Get -WebSession $Session
        } elseif ($ID) {
            $Content = Invoke-RestMethod -Uri ($Server+"/users.json") -Method Get -WebSession $Session
            $Content = $Content  | ? {$_.id -eq "$ID"}
        } else {
            $Content = Invoke-RestMethod -Uri ($Server+"/users.json") -Method Get -WebSession $Session
        }
        if ($NoSessionRemove) {
            Return $Content.Body
        } else {
            Stop-GFTPassboltConnection -Session $Session
            Return $Content.Body
        }
    }
}

function Set-GFTPassboltPermissions {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$PasswordID,
        [String]$GroupID,
        [String]$UserID,
        [switch]$ReadOnly,
        [switch]$Update,
        [switch]$Owner
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $Server = $Session.Headers.Server
        if ($GroupID) {
            $Rid = try { 
                ((Invoke-RestMethod -Uri ($Server+"/permissions/resource/$PasswordID.json") -Method Get -WebSession $Session).Body |? {$_.aro_foreign_key -eq $GroupID}).id
            } catch {
                $null
            }
        } elseif ($UserID) {
            $Rid = try { 
                ((Invoke-RestMethod -Uri ($Server+"/permissions/resource/$PasswordID.json") -Method Get -WebSession $Session).Body |? {$_.aro_foreign_key -eq $UserID}).id
            } catch {
                $null
            }
        } else {
            Return "You can't have group and user id at the same command !"
        }

    }
    Process {
        if (!($Rid)) {
            Return "Not have access to this resource !"
        }
        $Json = @{}
        $Permissions = @{}
        $Permissions['id'] = "$Rid"
        if ($UserID) {
            $Permissions['delete'] = $false
        }
        if ($GroupID) {
            $Permissions['is_new'] = $false
        }
        $Permissions['aco'] = "Resource"
        $Permissions['aco_foreign_key'] = "$PasswordID"
        if ($ReadOnly) {
            $Permissions['type'] = "1"
        } elseif ($Update) {
            $Permissions['type'] = "7"
        } elseif ($Owner) {
            $Permissions['type'] = "15"
        } else {
            Return "Please choose an permission (ReadOnly, Update, Owner)"
        }
        if ($GroupID) {
            $Permissions['aro'] = "Group"
            $Permissions['aro_foreign_key'] = "$GroupID"
        } elseif ($UserID) {
            $Permissions['aro'] = "User"
            $Permissions['aro_foreign_key'] = "$UserID"
        } else {
            Return "You can't have group and user id at the same command !"
        }

        $Json.Add("permissions",@($Permissions))
        $Json = $Json | ConvertTo-Json -Depth 8
        try {
            $ChangeContent = Invoke-RestMethod -Uri ($Server+"/share/resource/$PasswordID.json") -Method Put -WebSession $Session -Body $Json -ContentType 'application/json'
        } catch { 
            if (($_.ErrorDetails.Message | ConvertFrom-Json).Body.permissions.aco_foreign_key.permission_unique) {
                Return "Permissions already fix !"
            }
        }
        Return $ChangeContent.Body
    }
}

function New-GFTPassboltGroup {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [String]$GroupName,
        [parameter(Mandatory=$true)]
        [String]$GroupAdmin,
        [parameter(Mandatory=$true)]
        [String[]]$Users
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }

        $Server = $Session.Headers.Server
        $Group = Get-GFTPassboltGroup -GroupName $GroupName
    }
    Process {
        if ($Group) {
            Return "This group $GroupName already exist !"
        }
        $Json = @{}
        $Json['name'] = "$GroupName"
        $Temp = @()
        $Users | % {
            $TestUser = Get-GFTPassboltUser -Username $_
            if ($TestUser) {
                if ($GroupAdmin -contains $_) {
                    $Admin = $true
                } else {
                    $Admin = $false
                }
            } else {
                Write-Output "$($_) does not exist"
            }
            $Temp +=  @{
                'user_id' = "$($TestUser.id)"
                'is_admin' = $Admin
            }
            if ($TestUser) {
                Remove-Variable TestUser
            }
            if ($Admin) {
                Remove-Variable Admin
            }
        }
        $Json.Add("groups_users",$Temp)
        $Json = $Json | ConvertTo-Json
        try {
            $AddGroup = Invoke-RestMethod -Uri ($Server+"/groups.json") -Method Post -WebSession $Session -Body $Json -ContentType 'application/json'
        } catch { 
            Return "$($_.Exception)"
        }
        Return $AddGroup
    }
}
function Set-GFTPassboltShare {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$PasswordID,
        [String]$GroupID,
        [String]$UserID = (Get-GFTPassboltUser -Username "apipass").id,
        [String]$PublicKeyContent = (Get-GFTPassboltPGPPubKey | ? { $_.uid -match "APIPass" }).armored_key,
        [Switch]$Selfdelete,
        [switch]$SelfReadOnly
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $Files = $Session.Headers.SPath
        $SecretPath = $Session.Headers.SPath

        $Server = $Session.Headers.Server
        $NewPass = (Get-GFTPassword -Direct -ID $PasswordID).Secret
        if ($Selfdelete -or $SelfReadOnly) {
            $Rid = try { 
                ((Invoke-RestMethod -Uri ($Server+"/permissions/resource/$PasswordID.json") -Method Get -WebSession $Session).Body |? {$_.aro_foreign_key -eq $UserID}).id
            } catch {
                $null
            }
        }
    }
    Process {
        if (($Selfdelete -or $SelfReadOnly) -and (!($Rid))) {
            Return "Have you the necessary permissions for this ?"
        }
        $Json = @{}
        $Permissions = @{}
        $Permissions['is_new'] = "true"
        $Permissions['aro'] = "Group"
        $Permissions['aro_foreign_key'] = "$GroupID"
        $Permissions['aco'] = "Resource"
        $Permissions['aco_foreign_key'] = "$PasswordID"
        $Permissions['type'] = "15"
        
        $Temp = @()
        (Get-GFTPassboltUser -NoSessionRemove | ? {$_.Groups_users.group_id -eq $GroupID}) | %  {
            $Files = New-Item -Path $SecretPath -Name "$([System.IO.Path]::GetRandomFileName())$(Get-Random -Minimum 0 -Maximum 99999)" -ItemType File 
            Set-Content -Path $Files.FullName -Value $_.gpgkey.armored_key
            $Temp +=  @{
                'user_id' = "$($_.id)"
                'data' = "$(Protect-PGP -FilePathPublic $files.FullName -String $NewPass)"
            }
        }

        $Json.Add("secrets",$Temp)
        $Json.Add("permissions",@($Permissions))
        
        $Json = $Json | ConvertTo-Json -Depth 8

        try {
            $Content = Invoke-RestMethod -Uri ($Server+"/share/resource/$PasswordID.json") -Method Put -WebSession $Session -Body $Json -ContentType 'application/json'
        } catch { 
            if (($_.ErrorDetails.Message | ConvertFrom-Json).Body.permissions.aco_foreign_key.permission_unique) {
                if ($Selfdelete -or $SelfReadOnly) {
                    $AlreadyExist = $true
                } else {
                    Return "Share already exist !"
                }
            }
        }
        if ($Selfdelete){
            $Json = @{}
            $Permissions = @{}

            $Permissions['id'] = "$Rid"
            $Permissions['delete'] = $true
            $Permissions['aro'] = "User"
            $Permissions['aro_foreign_key'] = "$UserID"
            $Permissions['aco'] = "Resource"
            $Permissions['aco_foreign_key'] = "$PasswordID"
            $Permissions['type'] = "1"

            $Json.Add("permissions",@($Permissions))
            $Json = $Json | ConvertTo-Json -Depth 8
            try {
                $ContentDelete = Invoke-RestMethod -Uri ($Server+"/share/resource/$PasswordID.json") -Method Put -WebSession $Session -Body $Json -ContentType 'application/json'
            } catch { 
                if (($_.ErrorDetails.Message | ConvertFrom-Json).Body.permissions.aco_foreign_key.permission_unique) {
                    Return "Share already exist !"
                }
            }
            if ($AlreadyExist) {
                Write-Output "Share already exist but $UserID has been delete from share"
                Return $ContentDelete.Body
            } else {
                $ContentDelete.Body
                $Content.Body
            }
        }
        if ($SelfReadOnly) {
            $Json = @{}
            $Permissions = @{}

            $Permissions['id'] = "$Rid"
            $Permissions['delete'] = $false
            $Permissions['aro'] = "User"
            $Permissions['aro_foreign_key'] = "$UserID"
            $Permissions['aco'] = "Resource"
            $Permissions['aco_foreign_key'] = "$PasswordID"
            $Permissions['type'] = "1"

            $Json.Add("permissions",@($Permissions))
            $Json = $Json | ConvertTo-Json -Depth 8
            try {
                $ContentDelete = Invoke-RestMethod -Uri ($Server+"/share/resource/$PasswordID.json") -Method Put -WebSession $Session -Body $Json -ContentType 'application/json'
            } catch { 
                if (($_.ErrorDetails.Message | ConvertFrom-Json).Body.permissions.aco_foreign_key.permission_unique) {
                    Return "Share already exist !"
                }
            }
            if ($AlreadyExist) {
                Write-Output "Share already exist but $UserID has been change to read-only from share"
                Return $ContentDelete.Body
            } else {
                $ContentDelete.Body
                $Content.Body
            }
        }
        Return $Content.Body
    }
    End {
        Stop-GFTPassboltConnection -Session $Session
    }
}

function Get-GFTPassboltGroup {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$GroupName
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $Server = $Session.Headers.Server
    }
    Process {
        if ($GroupName) {
            $Content = Invoke-RestMethod -Uri ($Server+"/groups.json") -Method Get -WebSession $Session
            $Content = $Content.Body | ? {$_.Name -eq "$GroupName"}
        } else {
            $Content = (Invoke-RestMethod -Uri ($Server+"/groups.json") -Method Get -WebSession $Session).Body
        }
        Return $Content
    }
    End {
        Stop-GFTPassboltConnection -Session $Session
    }
}

function Get-GFTPassboltResource {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$ResourceID
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $Server = $Session.Headers.Server
    }
    Process {
            $URL = "$Server/resources.json?filter[is-shared-with-group]=$ResourceID&contain[permissions]=1"
            $Content = Invoke-RestMethod -Uri $Url -Method Get -WebSession $Session
            Return $Content.Body
    }
    End {
        Stop-GFTPassboltConnection -Session $Session
    }
}
function Get-GFTPassboltResourceTest {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$ResourceID
    )
    Begin {
        $ProgressPreference = 'SilentlyContinue'
        if (!($Session)) {
            $Session = Get-GFTPassboltConnection
        }
        $Server = $Session.Headers.Server
    }
    Process {
        $UrlToChecks = @(
            "$Server/resources/$ResourceID.json",
            "$Server/resource-types/$ResourceID.json",
            "$Server/permissions/resource/$ResourceID.json",
            "$Server/users/$ResourceID.json",
            "$Server/groups/$ResourceID.json",
            "$Server/gpgkeys/$ResourceID.json",
            "$Server/comments/resource/$ResourceID.json",
            "$Server/favorites/resource/$ResourceID.json",
            "$Server/folders/$ResourceID.json"
        )

        foreach ($Url in $UrlToChecks) {
            try {
                $Content = Invoke-RestMethod -Uri $Url -Method Get -WebSession $Session
            } catch {
                $ResourcesError = $_.Exception.Message
            }
            if (!($ResourcesError)) {
                Return $Content.Body
            }
            Remove-Variable ResourcesError
        }
    }
    End {
        Stop-GFTPassboltConnection -Session $Session
    }
}
