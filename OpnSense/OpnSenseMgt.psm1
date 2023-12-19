function Get-GFTOpnSenseCSRFToken {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$Path = "/ui/openvpn/export"
    )
    $ProgressPreference = "SilentlyContinue"
    $Init = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri "$RTRUrl$Path" -WebSession $Session
    $CsrfToken = (($Init.RawContent | Select-String -Pattern "x-csrftoken(.+)" | % { $_.matches.value }) -split "," -replace '\"','' -replace "\);","")[1].Trim()
    Return $CsrfToken
}
function Open-GFTOpnSenseConnection {
    param (
        $RTRUrl = ""
    )
    $ProgressPreference = "SilentlyContinue"
    $Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $Init = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri "$RTRUrl" -WebSession $Session
    $CookiePHPSESSIDName = (((($init | Select-Object -ExpandProperty Headers)."Set-Cookie")[0]) -Replace('\;(.+)','') -Split('='))[0]
    $CookiePHPSESSIDValue = (((($init | Select-Object -ExpandProperty Headers)."Set-Cookie")[0]) -Replace('\;(.+)','') -Split('='))[1]
    $Cookiecookie_testName = (((($init | Select-Object -ExpandProperty Headers)."Set-Cookie")[2]) -Replace('\;(.+)','') -Split('='))[0]
    $Cookiecookie_testValue = (((($init | Select-Object -ExpandProperty Headers)."Set-Cookie")[2]) -Replace('\;(.+)','') -Split('='))[1]
    $RTRQN = [System.Uri]"$RTRUrl"
    $HiddenName = ($Init | Select-Object -ExpandProperty InputFields | ? {$_ -match "autocomplete"}).Name
    $HiddenValue = ($Init | Select-Object -ExpandProperty InputFields | ? {$_ -match "autocomplete"}).Value
    $Session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
    $Session.Cookies.Add((New-Object System.Net.Cookie("$Cookiecookie_testName", "$Cookiecookie_testValue", "/", "$($($RTRQN.Authority).Split(':')[0])")))
    $Session.Cookies.Add((New-Object System.Net.Cookie("$CookiePHPSESSIDName", "$CookiePHPSESSIDValue", "/", "$($($RTRQN.Authority).Split(':')[0])")))
    
    $Session.Headers.Add("authority","$($RTRQN.Authority)")
    $Session.Headers.Add("scheme","https")
    $Session.Headers.Add("origin","$RTRUrl")
    $CsrfToken = Get-GFTOpnSenseCSRFToken -Session $Session
    $Session.Headers.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
    $Session.Headers.Add("accept-encoding","gzip, deflate, br")
    $Session.Headers.Add("accept-language","fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7")
    $Session.Headers.Add("HiddenName","$HiddenName")
    $Session.Headers.Add("HiddenValue","$HiddenValue")
    $Session.Headers.Add("x-csrftoken","$CsrfToken")
    $Session.Headers.Add("x-requested-with","XMLHttpRequest")
    return $Session
}

function Get-GFTOpnSenseCSRFToken {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$Path = "/"
    )
    $ProgressPreference = "SilentlyContinue"
    $Init = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri ($RTRUrl+"ui/openvpn/export") -WebSession $Session
    $CsrfToken = (($Init.RawContent | Select-String -Pattern "x-csrftoken(.+)" | % { $_.matches.value }) -split "," -replace '\"','' -replace "\);","")[1].Trim()
    Return $CsrfToken
}

function Get-GFTOpnSenseLogin {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        $Login = "",
        $Password = ''
    )
    $ProgressPreference = "SilentlyContinue"
    $PasswordEncoded = [System.Web.HttpUtility]::UrlEncode($Password)
    $HiddenName = $Session.Headers.HiddenName
    $HiddenValue = $Session.Headers.HiddenValue
    $LoginTry = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri "$RTRUrl" -Method Post -WebSession $Session -ContentType "application/x-www-form-urlencoded" -Body "$HiddenName=$HiddenValue&usernamefld=$Login&passwordfld=$PasswordEncoded&login=1"
}

function Get-GFTOpnSenseLDAPUsers {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User
    )
    $ProgressPreference = "SilentlyContinue"
    if ($User) {
        $ADAccount = try { (Get-ADUser -filter "SamAccountName -eq '$User'" | Select-Object Givenname,Surname,DistinguishedName,SamAccountName) } catch { $null }

        if ($ADAccount) {
            $DN = $ADAccount.DistinguishedName
            $Content =((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ("$RTRUrl"+"system_usermanager_import_ldap.php") -WebSession $Session | Select-Object -ExpandProperty InputFields).Value) | ? {$_ -match "$DN"}
        } else {
            $Content =((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ("$RTRUrl"+"system_usermanager_import_ldap.php") -WebSession $Session | Select-Object -ExpandProperty InputFields).Value) | ? {$_ -match "CN="}
        }
    } else {
        $Content =((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ("$RTRUrl"+"system_usermanager_import_ldap.php") -WebSession $Session | Select-Object -ExpandProperty InputFields).Value) | ? {$_ -match "CN="}
    }
    $ArrayUsers = @()
    
    foreach ($Item in $Content) {
        if ($ADAccount) {
            $ObjUsers = @{
                Firstname = $ADAccount.GivenName
                Lastname = $ADAccount.Surname
                DN = $ADAccount.DistinguishedName
                Sam = $ADAccount.SamAccountname 
            }
            $ArrayUsers += [PSCustomObject]$ObjUsers            
        } else {
            $CheckFirstname = try { $($($Item | % { $_.Split(',')[0].Replace('CN=','').Split(' ')[0] })) } catch { $null }
            if ($CheckFirstname) {
                $ObjUsers = @{
                    Firstname = $($Item | % { $_.Split(',')[0].Replace('CN=','').Split(' ')[0] })
                    Lastname = "$($Item | % { $_.Split(',')[0].Replace('CN=','').Split(' ')[1..3] })"
                    DN = $Item
                    Sam = (Get-ADUser -filter "DistinguishedName -eq '$Item'" | Select-Object SamAccountName).SamAccountname 
                }
                $ArrayUsers += [PSCustomObject]$ObjUsers
            }
        }
    }
    if ($User) {
        return $ArrayUsers | ? { $User -in $_.Sam}
    } else {
        return $ArrayUsers 
    }
    
}

function Import-GFTOpnSenseLDAPUser {
    [CmdletBinding()]
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User
    )
    $ProgressPreference = "SilentlyContinue"
    Write-Verbose "$RTRUrl * $User"
    $UserDN = (Get-GFTOpnSenseLDAPUsers -User "$User" -Session $Session).DN
    $UserDN = [System.Web.HttpUtility]::UrlEncode($UserDN)
    $HiddenName = $Session.Headers.HiddenName
    $HiddenValue = $Session.Headers.HiddenValue
    $Session.Headers.Remove("path") | Out-Null
    $Session.Headers.Remove("referer") | Out-Null

    $Session.Headers.Add("path","/system_usermanager_import_ldap.php")
    $Session.Headers.Add("referer","$RTRUrl"+"system_usermanager_import_ldap.php")
    $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri ($RTRUrl+"system_usermanager_import_ldap.php") -Method "POST" -WebSession $Session -ContentType "application/x-www-form-urlencoded"  -Body "$HiddenName=$HiddenValue&user_dn%5B%5D=$UserDN"
    if ($Content.StatusCode -ne "200") {
        Return $Content.StatusCode
        Write-Verbose "$($Content.Content | Out-String)"
    }
}

function Get-GFTOpnSenseUserID {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User
    )
    $ProgressPreference = "SilentlyContinue"
    #Get-GFTOpnSenseLogin -Session $Session
    $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Method Get -Uri ("$RTRUrl"+"system_usermanager.php") -WebSession $Session
    $Content = (Select-String -InputObject $Content -Pattern "(?smi)<table class=""table table-striped"">(.*?)$User.*?(\d+)""" -AllMatches  |  %{ $_.Matches } |%{ $_.Groups[2]})[0].Value
    Return $Content
}

function Get-GFTOpnSenseUserDN {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User      
    )
    $ProgressPreference = "SilentlyContinue"
    $UserID = Get-GFTOpnSenseUserID -User $User -Session $Session
    $Content = ((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ($RTRUrl+"system_usermanager.php?act=edit&userid=$UserID") -WebSession $Session).Content)
    $Content = ((Select-String -InputObject $Content -Pattern '<input name="user_dn" type="text" id="user_dn" size="20" value="(.*?)"(.*?)' -AllMatches | %{ $_.Matches.Groups[1] }).Value).Trim()
    return $Content 
}

function Get-GFTOpnSenseGroup {
    [CmdletBinding()]
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [Switch]$VPNWord,
        [String]$Name
    )
    if ($VPNWord) {
        $ProgressPreference = "SilentlyContinue"
        $Content =((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ("$RTRUrl"+"system_groupmanager.php") -WebSession $Session).Content)
        $Content = ((Select-String -InputObject $Content -Pattern '(?smi)<span class="fa fa-user text-info"></span>(.*?)</td>' -AllMatches | %{ $_.Matches } |%{ $_.Groups[1]}).Value).trim() | ? { $_ -match "VPN"}
        return $Content
    } elseif ($Name) {
        $Content =((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ("$RTRUrl" + "system_groupmanager.php") -WebSession $Session).Content)
        $Content = ((Select-String -InputObject $Content -Pattern '(?smi)<span class="fa fa-user text-info"></span>(.*?)</td>' -AllMatches | %{ $_.Matches } |%{ $_.Groups[1]}).Value).trim()
        return $Content | ? {$_ -eq "$Name"}
    } else {
        $Content =((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ("$RTRUrl" + "system_groupmanager.php") -WebSession $Session).Content)
        $Content = ((Select-String -InputObject $Content -Pattern '(?smi)<span class="fa fa-user text-info"></span>(.*?)</td>' -AllMatches | %{ $_.Matches } |%{ $_.Groups[1]}).Value).trim()
        return $Content
    }
}

function Get-GFTOpnSenseUserGroup {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User
    )
    $ProgressPreference = "SilentlyContinue"
    $UserID = Get-GFTOpnSenseUserID -User $User -Session $Session
    $WebContent = ((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ($RTRUrl+"system_usermanager.php?act=edit&userid=$UserID") -WebSession $Session).Content)
    $TempContent = (Select-String -InputObject $WebContent -Pattern '(?smi)<select size="\d{0,2}" name="groups\[\]" id="groups" onchange=".*?" multiple="multiple">(.*?)</select>' | % {$_.Matches.Groups[0]} ).Value
    $Groups = @()
    (Select-String -InputObject $TempContent -Pattern '<option value="(.*?)">' -AllMatches | % { $_.Matches.Groups }).Value | ? { $_ -notmatch '^<' } | % {
        $Obj = @{
            Group = $_
        }
        $Groups += [pscustomobject]$Obj
    }
    return $Groups 
}

function Get-GFTOpnSenseUserTOTP {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User
    )
    $ProgressPreference = "SilentlyContinue"
    $UserID = Get-GFTOpnSenseUserID -User $User -Session $Session
    $Content = ((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ($RTRUrl+"system_usermanager.php?act=edit&userid=$UserID") -WebSession $Session).Content)
    $Content = ((Select-String -InputObject $Content -Pattern '(?smi)<input name="otp_seed" type="text" value="(.*?)"' -AllMatches | %{ $_.Matches.Groups[1] }).Value).Trim()
    return $Content 
}

function Get-GFTOpnSenseRouters {
    param (
        [String]$CSVFilePath = "C:\Powershell\routers.csv"
    )
    if (!(Test-Path $CSVFilePath)) {
        Get-GFTPassword | Select-Object name,uri,id
    } else {
        Import-CSV $CSVFilePath
    }
}

function Add-GFTOpnSenseTOTP {
    [CmdletBinding()]
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User,
        [string]$UserEmail,
        [string]$TOTP
    )
    $ProgressPreference = "SilentlyContinue"
    $UserDN = (Get-GFTOpnSenseUserDN -Session $Session -User $User)
    $UserDN = [System.Web.HttpUtility]::UrlEncode($UserDN)
    $UserID = Get-GFTOpnSenseUserID -User $User -Session $Session
    $UserDescription = "$User"
    if (!($UserEmail)) {
        $UserEmail = Get-ADUser $User -Properties email | Select-Object -ExpandProperty email
    }
    $UserEmail = [System.Web.HttpUtility]::UrlEncode($UserEmail)
    $HiddenName = $Session.Headers.HiddenName
    $HiddenValue = $Session.Headers.HiddenValue

    if ($TOTP) {
        $OTP_Chain = "&otp_seed=$TOTP" 
    } else {
        $OTP_Chain = "&otp_seed=&gen_otp_seed=on"
    }
    $GroupExist = try { Get-GFTOpnSenseUserGroup -User $User -Session $Session } catch { $null }
    if ($GroupExist) {
        $GroupExist | % {
            $Group_Chain += "&groups%5B%5D=$($_.Group)"
        }
    } else {
        $Group_Chain = "&groups%5B%5D="
    }
    $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri ($RTRUrl+"system_usermanager.php?act=edit&userid=$UserID") `
    -Method "POST" `
    -WebSession $Session `
    -ContentType "application/x-www-form-urlencoded" `
    -Body "$HiddenName=$HiddenValue&act=edit&userid=$UserID&priv_delete=&api_delete=&certid=&scope=user&usernamefld=$User&oldusername=&user_dn=&passwordfld1=&passwordfld2=&descr=$UserDescription&email=$UserEmail&comment=&landing_page=&language=Default&shell=&expires=$Group_Chain$OTP_Chain&authorizedkeys=&save_close=save_close&id=$UserID"
    if ($Content.StatusCode -ne "200") {
        Return $Content.StatusCode
        Write-Verbose "$($Content.Content | Out-String)"
    }
}

function Add-GFTOpnSenseGroupToUser {
    [CmdletBinding()]
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User,
        [string]$UserEmail,
        [string]$Name
    )
    $ProgressPreference = "SilentlyContinue"
    $UserID = Get-GFTOpnSenseUserID -User $User -Session $Session
    $UserDescription = "$User"
    if (!($UserEmail)) {
        $UserEmail = Get-ADUser $User -Properties email | Select-Object -ExpandProperty email
    }
    $UserEmail = [System.Web.HttpUtility]::UrlEncode($UserEmail)
    if ($Name) {
        $VPNGroup = Get-GFTOpnSenseGroup -Session $Session -Name $Name
    } else {
        $VPNGroup = Get-GFTOpnSenseGroup -Session $Session -VPNWord
    }
    $HiddenName = $Session.Headers.HiddenName
    $HiddenValue = $Session.Headers.HiddenValue
    $Totp = try { Get-GFTOpnSenseUserTOTP -User $User -Session $Session } catch { $null }
    if ($Totp) {
        $Totp_Chain = "&otp_seed=$(Get-GFTOpnSenseUserTOTP -User $User -Session $Session)"
    } else {
       $Totp_Chain = "&otp_seed="
    }
    $GroupExist = try { Get-GFTOpnSenseUserGroup -User $User -Session $Session } catch { $null }
    if ($GroupExist) {
        $GroupExist | % {
            $VPNGroup += "&groups%5B%5D=$($_.Group)"
        }
    }
    $UserDN = [System.Web.HttpUtility]::UrlEncode((Get-GFTOpnSenseUserDN -Session $Session -User $User))
    $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri ($RTRUrl+"system_usermanager.php?act=edit&userid=$UserID") -Method "POST" -WebSession $Session -ContentType "application/x-www-form-urlencoded" -Body "$HiddenName=$HiddenValue&act=edit&userid=$UserID&priv_delete=&api_delete=&certid=&scope=user&usernamefld=$User&oldusername=$User&user_dn=$UserDN&passwordfld1=&passwordfld2=&descr=$UserDescription&email=$UserEmail&comment=&landing_page=&language=Default&shell=&expires=&groups%5B%5D=$VPNGroup$Totp_Chain&authorizedkeys=&save_close=save_close&id=$UserID"
    if ($Content.StatusCode -ne "200") {
        Return $Content.StatusCode
        Write-Verbose "$($Content.Content | Out-String)"
    }
}

function Get-GFTOpnSenseCAID {
    param(
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin)
    )
    # You have to create certificate one time with this CA and link certificate to root user (id:0)
    $ProgressPreference = "SilentlyContinue"
    $Content = ((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ($RTRUrl+"system_camanager.php") -WebSession $Session).Content)
    $Content2 = ((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ($RTRUrl+"system_usermanager.php?act=edit&userid=0") -WebSession $Session).Content)
    $Caref = ((Select-String -InputObject $Content2 -Pattern '(?smi)caref=(.*?)"' -AllMatches | %{ $_.Matches.Groups[1] }).Value).Trim() 
    $Array = @()
    ((Select-String -InputObject $Content -Pattern '(?smi)<table (.*?)>(.*?)<thead>(.*?)</thead>(.*?)<td>(.*?)</td>(.*?)<td>(.*?)</td>(.*?)</tbody>' -AllMatches | %{ $_.Matches } | % { 
        $Obj = @{
            CAName = $_.Groups[5].Value.trim()
            CAID = $Caref
            CAInternal = $_.Groups[7].Value.trim() -replace "&nbsp;",""
        }
        $array += [pscustomobject]$Obj
    }))
    return $Array | ? { $_.CAInternal -eq "YES"}
}
function New-GFTOpnSenseUserCertificate {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User,
        [string]$DNMail = "mail@example.com",
        [string]$DNOrg = "mycompagny",
        [string]$DNCountry = "FR",
        [string]$DNState = "Lorraine",
        [string]$DNCity = "Metz"
    )
    $ProgressPreference = "SilentlyContinue"
    $DNMail = [System.Web.HttpUtility]::UrlEncode($DNMail)
    $DNOrg = [System.Web.HttpUtility]::UrlEncode($DNOrg)
    $DNCountry = [System.Web.HttpUtility]::UrlEncode($DNCountry)
    $DNState = [System.Web.HttpUtility]::UrlEncode($DNState)
    $DNCity = [System.Web.HttpUtility]::UrlEncode($DNCity)
    $UserID = Get-GFTOpnSenseUserID -User $User -Session $Session
    $HiddenName = $Session.Headers.HiddenName
    $HiddenValue = $Session.Headers.HiddenValue
    $CA = (Get-GFTOpnSenseCAID -Session $Session)
    $CAName = $CA.CAName
    $CAID = $CA.caid
    Remove-GFTOpnSenseUserCertificate -User $User -Session $Session
    Remove-GFTOpnSenseCertificate -User $User -Session $Session
    $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri ($RTRUrl+"system_certmanager.php?act=new&userid=$UserID") `
    -Method "POST" `
    -WebSession $Session `
    -ContentType "application/x-www-form-urlencoded" `
    -Body "$HiddenName=$HiddenValue&act=new&userid=$UserId&certmethod=internal&descr=$User&cert=&key=&caref_sign_csr=$CAName&digest_alg_sign_csr=sha256&lifetime_sign_csr=397&csr=&basic_constraints_path_len_sign_csr=&caref=$CAID&cert_type=usr_cert&keytype=RSA&keylen=4096&curve=prime256v1&digest_alg=sha256&lifetime=397&private_key_location=firewall&dn_country=$DNCountry&dn_state=$DNState&dn_city=$DNCity&dn_organization=$DNOrg&dn_email=$DNMail&dn_commonname=$User&altname_type%5B%5D=DNS&altname_value%5B%5D=&csr_keytype=RSA&csr_keylen=2048&csr_curve=prime256v1&csr_digest_alg=sha256&csr_dn_country=AD&csr_dn_state=&csr_dn_city=&csr_dn_organization=&csr_dn_organizationalunit=&csr_dn_email=&csr_dn_commonname=&certref=&save=Save"
    if ($Content.StatusCode -ne "200") {
        Return $Content.StatusCode
    } else {
        Return $False
    }
}

function Remove-GFTOpnSenseUserCertificate {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User
    )
    $ProgressPreference = "SilentlyContinue"
    $UserID = try {
        Get-GFTOpnSenseUserID -Session $Session -User $User
    } catch {
        $null
    }
    if ($UserID) {
        $HiddenName = $Session.Headers.HiddenName
        $HiddenValue = $Session.Headers.HiddenValue
        $Session.Headers.Remove("path") | Out-Null
        $Session.Headers.Remove("referer") | Out-Null
    
        $Session.Headers.Add("path","/system_usermanager.php")
        $Session.Headers.Add("referer","$RTRUrl"+"system_usermanager.php")
        $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri ($RTRUrl+"system_usermanager.php") -Method "POST" -WebSession $Session -ContentType "application/x-www-form-urlencoded" -Body "$HiddenName=$HiddenValue&act=delcert&userid=$UserID&certid=0&username=$User&usernamefld=$User&oldusername=$User"
    }
}

function Get-GFTOpnSenseOpenVPNProviders {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$Name
    )
    $ProgressPreference = "SilentlyContinue"
    Get-GFTOpnSenseLogin -Session $Session
    $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Method Get -Uri ($RTRUrl+"api/openvpn/export/providers/") -WebSession $Session
    $Providers = $Content | Select-Object -ExpandProperty Content | ConvertFrom-Json
    $ProvidersArray = @()
    $Providers | Get-Member | Select-Object name | ? {$_ -match '\d'} | % {
        $ProvidersArray += (($Providers)."$($_.Name)")
    }
    if ($Name) {
        Return $ProvidersArray | ? {$_.Name -eq "$Name"}
    } else {
        Return $ProvidersArray
    }
}

function Get-GFTOpnSenseOpenVPNUsers {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User
    )
    $ProgressPreference = "SilentlyContinue"
    $ContentRequest = @()
    $array = @()
    Get-GFTOpnSenseOpenVPNProviders -Session $Session | % {
        $ContentRequest += Invoke-RestMethod -SkipCertificateCheck -UseBasicParsing -Method Get -Uri ($RTRUrl+"api/openvpn/export/accounts/$($_.vpnid)/") -WebSession $Session | ConvertFrom-Json -AsHashtable
    }

    $ContentRequest = ($ContentRequest | ConvertTo-Json).Replace('""','"EmptyString"')
    $ContentRequest = $ContentRequest | ConvertFrom-Json

    $ContentRequest.PSObject.Properties | % {
        $Obj = @{
            Id = $_.Name
            User = $_.Value.users
            Description = $_.Value.description
        }
        $array += [pscustomobject]$Obj
    }

    if ($User) {
        Return $array | ? {$_.User -eq "$User"}
    } else {
        Return $array
    }
}

function Get-GFTOpnSenseOpenVPNFiles {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User,
        [string]$DestFolder = "C:\Powershell\",
        [string]$ProviderName
    )
    $ProgressPreference = "SilentlyContinue"
    #Get-GFTOpnSenseLogin -Session $Session
    Write-GFTLog -LogTitle "OpnSense" -Logcontent "$User $DestFolder $ProviderName"
    $parms = @{
        Session = $Session
    }
    if ($ProviderName) {
        $parms["Name"] = $ProviderName
    }
    $OpenVPNID = (Get-GFTOpnSenseOpenVPNUsers -User $User -Session $Session).Id
    $ProviderInfos = Get-GFTOpnSenseOpenVPNProviders @parms
    $ProviderID =  $ProviderInfos | Select-Object -ExpandProperty "vpnid"
    $Template = $ProviderInfos | Select-Object -ExpandProperty "template"
    $LocalPort = $ProviderInfos | Select-Object -ExpandProperty "local_port"
    $VPNHost = $ProviderInfos | Select-Object -ExpandProperty "hostname"

    $jSON = @{
        "openvpn_export" = @{
          "servers" = "1"
          "template" = "$Template"
          "hostname"= "$VPNHost"
          "local_port"= "$LocalPort"
          "random_local_port"= "1"
          "p12_password" = ""
          "p12_password_confirm"= ""
          "validate_server_cn"= "1"
          "cryptoapi"= "0"
          "auth_nocache"= "0"
          "plain_config" = "auth-nocache
auth-user-pass
--providers legacy default"
        }
    }
    $JSON = $JSON | ConvertTo-Json
    $CsrfToken = Get-GFTOpnSenseCSRFToken -Session $Session
    $Session.Headers.Remove("referer")
    $Session.Headers.Add("referer","$RTRUrl"+"ui/openvpn/export")
    $Session.Headers.Remove("x-csrftoken")
    $Session.Headers.Add("x-csrftoken","$CsrfToken")
    $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri ($RTRUrl+"api/openvpn/export/download/$ProviderID/$OpenVPNID/") -Method "POST" -WebSession $Session -ContentType "application/json" -Body $JSON 
    $JsonFormat = $Content.Content | ConvertFrom-Json
    $Filename = $JsonFormat.Filename
    $Destination = Join-Path $DestFolder $Filename
    $Bytes = [Convert]::FromBase64String($JsonFormat.Content)
    [IO.File]::WriteAllBytes($Destination, $Bytes)
}

function Test-GFTOpnSenseUserCertificates {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [String]$User
    )
    $ProgressPreference = "SilentlyContinue"
    $UserID = Get-GFTOpnSenseUserID -User $User -Session $Session
    $Content = ((Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ($RTRUrl+"system_usermanager.php?act=edit&userid=$UserID") -WebSession $Session).Content)
    if ($Content | Select-String -Pattern 'unlink certificate') { 
        "Certificate Present" 
    }
}
function Get-GFTOpnSenseCertificates {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [Switch]$Expire
    )
    $ProgressPreference = "SilentlyContinue"
    Get-GFTOpnSenseLogin -Session $Session
    $array = @()
    $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Method Get -Uri ("$RTRUrl"+"system_certmanager.php") -WebSession $Session
    $Content = ((Select-String -InputObject $Content -Pattern '(?smi)<table class="table table-striped">(.*?)<thead>(.*?)</thead>(.*?)</div>' -AllMatches | %{ $_.Matches } |%{ $_.Groups[3]}).Value).trim()
    ((Select-String -InputObject $Content -Pattern '(?smi)<i class="fa fa-certificate"></i>(.*?)<br/><br/>(.*?)</a>(.*?)</td>'-AllMatches | %{ $_.Matches } | % { 
        $CertTypePattern = '(?smi)(.*?)CA: (.*?),(.*?)Server: (.*?)</td>(.*?)<td>(.*?)</td>(.*?)<td>(.*?)&nbsp;<br />(.*?)'
        $CertChainPattern = '(?smi)(.*?)CA: (.*?),(.*?)Server: (.*?)</td>(.*?)<td>(.*?)</td>(.*?)<td>(.*?)&nbsp;<br />(.*?)'
        $CertDateFromPattern = '(?smi)(.*?)CA: (.*?),(.*?)Server: (.*?)</td>(.*?)<td>(.*?)</td>(.*?)<td>(.*?)&nbsp;<br />(.*?)<table>(.*?)<tr>(.*?)<td(.*?)</td>(.*?)<td(.*?)</td>(.*?)<td(.*?)>(.*?)</td>'
        $CertDateEndPattern = '(?smi)(.*?)CA: (.*?),(.*?)Server: (.*?)</td>(.*?)<td>(.*?)</td>(.*?)<td>(.*?)&nbsp;<br />(.*?)<table>(.*?)<tr>(.*?)<td(.*?)</td>(.*?)<td(.*?)</td>(.*?)<td(.*?)>(.*?)</td>(.*?)</tr>(.*?)<tr>(.*?)<td>(.*?)</td>(.*?)<td>(.*?)</td>(.*?)<td>(.*?)</td>'
        $CertID = '(?smi)data-id="(.*?)"'
        $IsRemovable = '(?smi)<a id="del_(.*?)"'
        $Removable = try {
            (((Select-String -InputObject $($_.Groups[3].Value.trim()) -Pattern $IsRemovable -AllMatches -ErrorAction SilentlyContinue | %{ $_.Matches } |%{ $_.Groups[1]}).Value).trim())
        } catch {
            $null
        }
        $Obj = @{
            ID = ((Select-String -InputObject $($_.Groups[2].Value.trim()) -Pattern $CertID -AllMatches | %{ $_.Matches } |%{ $_.Groups[1]}).Value).trim()
            Certname = $_.Groups[1].Value.trim()
            CertType = if (((Select-String -InputObject $($_.Groups[2].Value.trim()) -Pattern $CertTypePattern | %{ $_.Matches } |%{ $_.Groups[4]}).Value).trim() -eq "Yes") { "Server" } else { "Client"}
            CertChain = ((Select-String -InputObject $($_.Groups[2].Value.trim()) -Pattern $CertChainPattern -AllMatches | %{ $_.Matches } |%{ $_.Groups[8]}).Value).trim()
            CertFromDate = Get-Date "$(((Select-String -InputObject $($_.Groups[2].Value.trim()) -Pattern $CertDateFromPattern -AllMatches | %{ $_.Matches } |%{ $_.Groups[17]}).Value).trim())" -Format "dd/MM/yyyy hh:mm"
            CertEndDate = Get-Date "$(((Select-String -InputObject $($_.Groups[2].Value.trim()) -Pattern $CertDateEndPattern -AllMatches | %{ $_.Matches } |%{ $_.Groups[25]}).Value).trim())" -Format "dd/MM/yyyy hh:mm"
            IsRemovable = if ($Removable) { "Yes" } else { "No" }
        }
        $array += [pscustomobject]$Obj
    }))

    Return $array
}

function Remove-GFTOpnSenseCertificate {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User
    )
    $ProgressPreference = "SilentlyContinue"
    $HiddenName = $Session.Headers.HiddenName
    $HiddenValue = $Session.Headers.HiddenValue
    $Session.Headers.Remove("path") | Out-Null
    $Session.Headers.Remove("referer") | Out-Null

    $Session.Headers.Add("path","/system_certmanager.php")
    $Session.Headers.Add("referer","$RTRUrl"+"system_certmanager.php")
    $UserCertificate = Get-GFTOpnSenseCertificates -Session $Session | ? {$_.CertName -eq $User -and $_.IsRemovable -eq 'Yes'}
    $NumberOfCertificate = ($UserCertificate | Measure-Object).Count
    for ($i=1;$i -le $NumberOfCertificate;$i++) {
        $UserCertificateID = (Get-GFTOpnSenseCertificates -Session $Session | ? {$_.CertName -eq $User -and $_.IsRemovable -eq 'Yes'}).ID | Select-Object -First 1
        Write-GFTLog -LogTitle "OpnSense" -LogContent "DELETE Certificate : $($UserCertificateID)"
        $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri ($RTRUrl+"system_certmanager.php") -Method "POST" -WebSession $Session -ContentType "application/x-www-form-urlencoded" -Body "$HiddenName=$HiddenValue&id=$($UserCertificateID)&act=del" -Verbose
    }
}

function Remove-GFTOpnSenseUser {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin),
        [string]$User
    )
    $ProgressPreference = "SilentlyContinue"

    $UserID = try {
        Get-GFTOpnSenseUserID -Session $Session -User $Username
    } catch {
        $null
    }
    if ($UserID) {
        $HiddenName = $Session.Headers.HiddenName
        $HiddenValue = $Session.Headers.HiddenValue
        $Session.Headers.Remove("path") | Out-Null
        $Session.Headers.Remove("referer") | Out-Null
    
        $Session.Headers.Add("path","/system_usermanager.php")
        $Session.Headers.Add("referer","$RTRUrl"+"system_usermanager.php")
        $Content = Invoke-WebRequest -SkipCertificateCheck -UseBasicParsing -Uri ($RTRUrl+"system_usermanager.php") -Method "POST" -WebSession $Session -ContentType "application/x-www-form-urlencoded" -Body "$HiddenName=$HiddenValue&act=deluser&userid=$UserID&username="
    }
}

function Get-GFTOpnSenseUserList {
    param (
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $RTRUrl = $($Session.Headers.origin)
    )
    $RawContent = (Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri ("$RTRUrl"+"system_usermanager.php") -WebSession $Session).Content 
    Select-String -Pattern '(?smi)<span class="fa fa-user text-(info|danger)"></span>(.*?)</td>' -InputObject $RawContent -AllMatches | % {$_.Matches.Groups}
}

function New-GFTOpnSenseUser {
    [CmdletBinding()]
    param (
        [string]$RTRUrl,
        [string]$Username,
        [string]$UserEmail,
        [string]$TOTP,
        [switch]$VPNCreate,
        [string]$ProviderName,
        [string]$Group
    )
    $Creds = Get-GFTPassword -SearchMethod uri -SearchContent "$RTRUrl"
    $User = $Creds.Username
    $Password = $Creds.Secret
    $Uri = $Creds.Uri
    if (!($UserEmail)) {
        $UserEmail = ((Get-ADuser $Username -Properties mail).mail)
    }
    $Session = (Open-GFTOpnSenseConnection -RTRUrl $Uri)
    Get-GFTOpnSenseLogin -Session $Session -Login $User -Password $Password

    try {
        $UserID = Get-GFTOpnSenseUserID -Session $Session -User $Username
        $UserCertificate = Test-GFTOpnSenseUserCertificates -Session $Session -User $Username
    } catch {
        $NotExist = 1
    }
    # Import User from LDAP
    if ($NotExist) {
        try {
            $LDAPUser = Get-GFTOpnSenseLDAPUsers -Session $Session -User $Username
            Write-GFTLog -LogTitle "OpnSense" -LogContent "LDAP DN : $($LDAPUser.DN)"
            Import-GFTOpnSenseLDAPUser -Session $Session -User $Username -Verbose
        } catch {
            Write-GFTLog -LogTitle "OpnSense" -LogContent "Username : $Username not exist or error in program failed : $($_.Exception.Message)"
            Return "ERROR : Username - $Username not exist or error in program failed"
        }
    }

    # Add to group VPN
    try {
        $gparams = @{
            User = $Username
            Session = $Session
            UserEmail = $UserEmail
        }
        if ($Group) {
            $gparams['Name'] = $Group
        }
        Write-GFTLog -LogTitle "OpnSense" -LogContent "Add-GFTOpnSenseGroupToUser -User $Username -Session $($Session.Headers.origin) -UserEmail $UserEmail ($Group)"
        Add-GFTOpnSenseGroupToUser @gparams
    } catch {
        Write-GFTLog -LogTitle "OpnSense" -LogContent "Group : $Username not add to Group failed : $($_.Exception.Message)"
        Return "ERROR : Group - $Username not add to Group failed $($gparams | Out-String)"
    }

    # Add certificate to user
    if ($UserCertificate) {
        if ((Get-Date).AddDays(-15) -lt $UserCertificate.CertEndDate) {
            # Certificat expiré à 15 jours
            try {
                Write-GFTLog -LogTitle "OpnSense" -LogContent "Certificate : create certificate for $Username"
                New-GFTOpnSenseUserCertificate -User $Username -Session $Session
            } catch {
                Write-GFTLog -LogTitle "OpnSense" -LogContent "Certificate : create certificate for $Username failed : $($_.Exception.Message)"
            }
        } else {
            # on conserve l'actuel et on ne créer pas
        }
    } else {
        try {
            Write-GFTLog -LogTitle "OpnSense" -LogContent "Certificate : create certificate for $Username"
            New-GFTOpnSenseUserCertificate -User $Username -Session $Session
        } catch {
            Write-GFTLog -LogTitle "OpnSense" -LogContent "Certificate : create certificate for $Username failed : $($_.Exception.Message)"
        }
    }
    if ($NotExist) {
        try {
            Write-GFTLog -LogTitle "OpnSense" -LogContent "Certificate : create certificate for $Username"
            New-GFTOpnSenseUserCertificate -User $Username -Session $Session
        } catch {
            Write-GFTLog -LogTitle "OpnSense" -LogContent "Certificate : create certificate for $Username failed : $($_.Exception.Message)"
        }
    }
    # Add TOTP to user
    try {
        if ($TOTP) {
            Write-GFTLog -LogTitle "OpnSense" -LogContent "ADD TOTP $TOTP"
            Add-GFTOpnSenseTOTP -User $Username -UserEmail $UserEmail -Session $Session -TOTP $TOTP
        } else {
            Write-GFTLog -LogTitle "OpnSense" -LogContent "ADD TOTP - New generation"
            Add-GFTOpnSenseTOTP -User $Username -UserEmail $UserEmail -Session $Session
        }
    } catch {
        Write-GFTLog -LogTitle "OpnSense" -LogContent "TOTP : create TOTP for $Username failed : $($_.Exception.Message)"
    }

    if ($VPNCreate) {
        Write-GFTLog -LogTitle "OpnSense" -LogContent "Send File to $Username"
        Get-GFTOpnSenseOpenVPNFiles -Session $Session -User $Username -ProviderName $ProviderName
    }
}
