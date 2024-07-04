function Get-GFTAWXLogin {
    [CmdletBinding()]
    param(
        [string]$AWXAPIUrl = "https://YourAwxURL",
        [string]$User,
        [string]$Passfile = "awx.xml"
    )

    $AccountXML = Import-Clixml -Path $Passfile
    $Account = New-Object System.Management.Automation.PSCredential($AccountXML.Username, (ConvertTo-SecureString -String "$($AccountXML.Password)" -Key $($AccountXML.Key)))

    $Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $Init = Invoke-WebRequest -UseBasicParsing -Uri "$AWXAPIUrl/api/login/" -Method Get -WebSession $Session
    $Session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    $AWXQN = [System.Uri]"$AWXAPIUrl"
    $Session.Cookies.Add((New-Object System.Net.Cookie("$((((($init | Select-Object -ExpandProperty Headers)."Set-Cookie")[0]) -Replace('\;(.+)','') -Split('='))[0])", "$((((($init | Select-Object -ExpandProperty Headers)."Set-Cookie")[0]) -Replace('\;(.+)','') -Split('='))[1])", "/", "$($AWXQN.Authority)")))
    $Session.Cookies.Add((New-Object System.Net.Cookie("$((((($init | Select-Object -ExpandProperty Headers)."Set-Cookie")[1]) -Replace('\;(.+)','') -Split('='))[0])", "$((((($init | Select-Object -ExpandProperty Headers)."Set-Cookie")[0]) -Replace('\;(.+)','') -Split('='))[1])", "/", "$($AWXQN.Authority)")))

    $Session.Cookies.Add((New-Object System.Net.Cookie("userLoggedIn", "true", "/", "$($AWXQN.Authority)")))
    $CSRFTokenMiddleWare = (($Init.RawContent | Select-String -Pattern "csrfmiddlewaretoken(.+)" ) | % {$_.Matches.Value } | Out-String).Split('=').Replace('"','').Replace('>','')[1].Trim()
    $CSRFToken = ($Session.Cookies.GetAllCookies() | ? {$_.name -eq 'csrftoken'}).Value
    $LoginTry = Invoke-WebRequest -UseBasicParsing -Uri "$AWXAPIUrl/api/login/" -Method "POST" -WebSession $Session -Headers @{
        "Origin"="$AWXAPIUrl"
        "Pragma"="no-cache"
        "Referer"="$AWXAPIUrl/api/login/?next=/api/v2/"
        "X-CSRFTOKEN"="$CSRFToken"
        "csrfmiddlewaretoken"="$CSRFTokenMiddleWare"
    } -ContentType "application/x-www-form-urlencoded" -Body "csrfmiddlewaretoken=$CSRFTokenMiddleWare&next=%2Fapi%2Fv2%2F&username=$($Account.UserName)&password=$($Account.GetNetworkCredential().Password)"
    if ($?) {
        Return $Session
    } else {
        Return $False
    }
}

function Get-GFTAWXInventories {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventories/" -WebSession $Session
    Return $Result.Results | Select-Object id, name, url, type
}

function Get-GFTAWXTemplates {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [int]$ID
    )
    if ($ID) {
        $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/job_templates/$ID/" -WebSession $Session
    } else {
        $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/job_templates/" -WebSession $Session).Results
    }
    Return $Result | Select-Object id, name, url, playbook, inventory, @{N='Variables';E={(Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/job_templates/$($_.ID)/survey_spec/" -WebSession $Session).spec.variable}},@{N='DefaultValue';E={(Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/job_templates/$($_.ID)/survey_spec/" -WebSession $Session).spec.default}}
}

function Add-GFTAWXHostToInventory {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [ipaddress]$IPAddress,
        $Inventory
    )

    $InventoryID = try { 
        [int]$Inventory = $Inventory
        $Inventory
      } catch {  
        (Get-GFTAWXInventories -Session $Session | ? {$_.Name -eq "$Inventory" }).ID
    }
    if (!($InventoryID)) {
        Return "Error no ID Found with inventory name : $Inventory"
    }

    $ExistingHost = Get-GFTAWXHosts -Session $Session -Hostname $IPAddress.IPAddressToString
    if (!($ExistingHost)) {
        $OSTry = try { Get-GFTNetboxVMInformations -VMIP $IPAddress.IPAddressToString -TestDomain } catch { $null }
        if ($OSTry) {
            $Variables = @{}
            $Variables['ansible_host'] = $IPAddress.IPAddressToString
            if ($OSTry.AnsibleUpdate -eq "Yes") {
                $Variables['update'] = 'update'
            }
            if ($OSTry.Status -eq "Offline") {
                $Variables['offline'] = 1
            }
            if ($OSTry.Domain -eq "No") {
                $Variables['notindomain'] = 1
                if ($OSTry.OS -eq "Windows") {
                    $Variables['ansible_user'] = "{{ win_user_ood }}" 
                    $Variables['ansible_password'] = "{{ win_pass_ood }}"
                } elseif ($OSTry.Tenant -match "bnp-dev") {
                    $Variables['ansible_user'] = "{{ win_user_bnp_dev }}"
                    $Variables['ansible_password'] = "{{ win_pass_bnp_dev }}"
                } else {
                    $Variables['ansible_user'] = "{{ lin_user_ood }}"
                    $Variables['ansible_password'] = "{{ lin_pass_ood }}"
                }
            } else {
                if ($OSTry.OS -eq "Windows") {
                    $Variables['ansible_user'] = "{{ win_user }}"
                    $Variables['ansible_password'] = "{{ win_pass }}"
                }
            }
            if ($OSTry.OS -eq "Windows") {
                $Variables['windows'] = 1
                $Variables['ansible_connection'] = "winrm"
                $Variables['ansible_winrm_cert_validation'] = "ignore"
                $Variables['ansible_become'] = "false"
                $Variables['ansible_port'] = 5985
                $Variables['ansible_winrm_transport'] = "ntlm"
            } else {
                $Variables['linux'] = 1
                $Variables['ansible_ssh_common_args'] = '-o StrictHostKeyChecking=no'
            }
        }
    }
    $PostUrl = "$($Session.Headers.Origin)/api/v2/inventories/$InventoryID/hosts/"
    if ($ExistingHost) {
        $Json = @{
            "name" = $ExistingHost.Name
            "description" = ""
            "enabled" = "true"
            "instance_id" = ""
            "variables" = $ExistingHost.variables
        } | ConvertTo-Json
    } elseif (!($ExistingHost) -and $OSTry) {
        $Json = @{
            "name" = $OSTry.Name
            "description" = ""
            "enabled" = "true"
            "instance_id" = ""
            "variables" = $Variables | ConvertTo-Json
        } | ConvertTo-Json
    } else {
        $Json = @{
            "name" = "$IPAddress"
            "description"= ""
            "enabled"= "true"
            "instance_id"= ""
            "variables"= "ansible_host: $IPAddress"
        } | ConvertTo-Json
    }
    $Request = Invoke-RestMethod -Uri $PostUrl -WebSession $Session -Method Post -ContentType 'application/json' -Body $Json
    if ($?) {
        Return "$IPAddress add to $((Get-GFTAWXInventories -Session $Session | ? {$_.id -eq $InventoryID }).name)"
    } else {
        Return $False
    }
}

function Get-GFTAWXHosts {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$Hostname
    )
    if ($Hostname) {
        $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/hosts/?search=$Hostname" -WebSession $Session
    } else {
        $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/hosts/?page_size=9990" -WebSession $Session
    }
    Return $Result.Results | Select-Object id,name,url,type,variables
}
function Remove-GFTAWXHost {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [String]$Hostname
    )

#    $Session = Get-GFTAWXLogin
    $ToDelete = Get-GFTAWXHosts -Session $session -Hostname $Hostname
    $DeleteUrl = "$($Session.Headers.Origin)/api/v2/hosts/$($ToDelete.id)/"
    $Json = @{
        'name' = "$(($ToDelete).Name)"
    } | ConvertTo-Json
    $Request = Invoke-RestMethod -Uri $DeleteUrl -WebSession $Session -Method Delete -ContentType 'application/json' -Body $Json
    if ($?) {
        Return "$Hostname remove successfully"
    } else {
        Return $false
    }
}

function Get-GFTAWXInventories {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventories/" -WebSession $Session
    Return $Result.Results | Select-Object id, name, url, type
}

function Get-GFTAWXInventory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [int]$ID
    )
    $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventories/$ID" -WebSession $Session
    Return $Result | Select-Object id, name, url, type
}

function Get-GFTAWXHostsInInventory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [int]$ID
    )
    $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventories/$ID/hosts" -WebSession $Session).Results
    Return $Result | Select-Object id, name, url, type
}

function Get-GFTAWXGroupsInInventory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [int]$ID
    )
    $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventories/$ID/groups" -WebSession $Session).Results
    Return $Result | Select-Object id, name, url, type
}

function Get-GFTAWXCredentialTypes {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/credential_types/" -WebSession $Session).Results
    
    Return $Result | Select-Object id, name
}

function Get-GFTAWXCredentials {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/credentials/" -WebSession $Session).Results
    Return $Result | Select-Object id, name, @{N="Username";E={$_.inputs.username}}
}

function Get-GFTAWXJobs {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [switch]$All
    )
    if (!($All)) {
        $PageSize = "&page_size=30"
    }
    $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/jobs/?order_by=-id$PageSize" -WebSession $Session
    Return $Result.Results | Select-Object id, name, launch_type, inventory, limit, status, started, finished
}

function Get-GFTAWXJob {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [int]$ID,
        [switch]$Inventory,
        [switch]$Project
    )
    if ($Inventory) {
        $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventory_updates/$ID/" -WebSession $Session
    } elseif ($Project) {
        $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/project_updates/$ID/" -WebSession $Session
    } else {
        $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/jobs/$ID" -WebSession $Session
    }
    Return $Result
}

function Get-GFTAWXJobStream {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [int]$ID,
        [parameter(Mandatory=$false)]
        [string]$Format = "txt"
    )
    ## Example for PLIK URL : (Get-GFTAWXJobStream -Session $Session -ID 37 | Select-String '(.*?)\"msg\":(.*)\s+' | % { $_.Matches.Groups[2].Value }).Replace('"','').Trim()
    # Example for PLIK URL :(Get-GFTAWXJobStream -Session $Session -ID $test.job | Select-String '(.*?)\"msg\":(.*)\s+' || Select-String '(.*?)\"msg\":(.*)\s+' | % { $_.Matches.Groups[2].Value }).Replace('"','').Split('url:')[1].Replace('}','').Trim()
    $Result = Invoke-RestMethod -ContentType 'application/json; charset=windows-1252' -Uri "$($Session.Headers.origin)/api/v2/jobs/$ID/stdout/?format=$Format" -WebSession $Session
    $ResultPattern = $Result
    Return $ResultPattern
}

function Get-GFTAWXJobEvents {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [int]$ID
    )
    # Example for PLIK URL : (Get-GFTAWXJobStream -Session $Session -ID 37 | Select-String '(.*?)\"msg\":(.*)\s+' | % { $_.Matches.Groups[2].Value }).Replace('"','').Trim()
    $Result = Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/jobs/$ID/job_events/" -WebSession $Session
    $Array = @()
    
    $ResultPattern = $Result.Results | % {
        $Obj = [PSCustomObject]@{
            ID = $_.id
            Status = $_.event_display
            Failed = $_.failed
        }
        $Array += $Obj
    }
    Return $Array
}

function Get-GFTAWXJobStatus {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [int]$ID,
        [switch]$Inventory,
        [switch]$Project
    )
    if ($Inventory) {
        $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventory_updates/$ID/" -WebSession $Session).Status
    } elseif ($Project) {
        $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/project_updates/$ID/" -WebSession $Session).Status
    } else {
        $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/jobs/$ID" -WebSession $Session).Status
    }
    Return $Result
}

function Wait-GFTAWXStatus {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [int]$ID,
        [switch]$Inventory,
        [switch]$Project
    )
    $params = @{}
    $params['ID'] = $ID

    if ($Inventory) {
        $params['Inventory'] = $true
    }
    if ($Project) {
        $params['Project'] = $true
    }
    $Status = Get-GFTAWXJobStatus -Session $Session @params
    while ($Status -match 'waiting|Pending|running') {
        Start-Sleep -Seconds 1
        $Status = Get-GFTAWXJobStatus -Session $Session @params
    }
}

function Get-GFTAWXJsonUpdate {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [int]$ID
    )

    Wait-GFTAWXStatus -Session $Session -ID $ID

    $Request = (Get-GFTAWXJobStream -Session $Session -ID $ID)
    $JobInfos = (Get-GFTAWXJob -Session $Session -id $ID)
    $AvailbaleRequest = $Request -match "(?smi)TASK \[Gathering Facts\](.*?)PLAY RECAP"
    if ($AvailbaleRequest) {
        $Status = $Matches[0] | Select-String -Pattern '(?smi)(ok|fatal):(.*?)\]' -AllMatches | % { $_.Matches.Value }
        #$Hosts = ($Status | Select-String -Pattern '(?smi)\[(.*?)\]' -AllMatches | % { $_.Matches.Value }) -replace '(\[|\])',''

        $JobBlock = $Matches[0] | Select-String -Pattern '(?smi)TASK \[Security Update\](.*?)(PLAY RECAP|TASK)' -AllMatches | % { $_.Matches.Value }
        $JobBlockWin = $Matches[1] | Select-String -Pattern '(?smi)TASK \[Windows Server Security update\](.+.)(changed|failed|ignored|ok): \[(.*?)\] => (.+.)$' -AllMatches | % { $_.Matches }

        $Array = @()
        # Add fatal to array
        $Status | ? { $_ -match "fatal"} | % {
            $FatalObj = [PSCustomObject]@{
                HostStatus = ($_).Split(":")[0]
                Status = "Error"
                IP = (($_).Split(":")[1] -replace '(\[|\])','').Trim()
                Json = "{}"
                Results = "{}"
            }
            $Array += $FatalObj
        }
        if ($JobBlockWin) {
            $JobBlockWin | % {
            
#            ).Value -replace 'TASK','' -replace '(changed|failed|skipped|rescued|ignored|ok):(.*?)\] =>','').Trim() | % {
                $IP = ($_.Groups[3].Value).Trim()
                $JobStatus = if ($JobInfos.job_type -eq "check") {
                    "Check - No change"
                } else {
                    $_.Groups[2].Value
                }
                $Update = @()
                
                $JsonForThis = $_.Groups[4].Value | ConvertFrom-Json
                $JsonForThis.Updates.psobject.Properties.Name | % {
                    $UpdateObj = [PSCustomObject]@{
                        TitleUpdate = $JsonForThis.Updates."$($_)".title
                        Installed = $JsonForThis.Updates."$($_)".installed
                        Categories = $JsonForThis.Updates."$($_)".categories | Out-String
                    }
                    $Update += $UpdateObj
                }
                
                $Obj = [PSCustomObject]@{
                    HostStatus = ($Status | ? {$_ -match $IP}).Split(":")[0]
                    Status = $JobStatus
                    IP = $IP
                    Json = $_.Groups[4].Value | ConvertFrom-Json
                    Display = $($Update | % {$_.TitleUpdate }) -join ','
                    Results = $Update
                }
                $Array += $Obj
            }
        }
        if ($JobBlock) {
            $JobBlock | Select-String -Pattern '(?smi)(changed|failed|skipped|rescued|ignored|ok):(.*?)\] => (.*?)\}' -AllMatches | % { $_.Matches } | % {
            $IP = ($_.Groups[2].Value -replace '(\[|\])','').Trim()
            $JobStatus = if ($JobInfos.job_type -eq "check") {
                "Check - No change"
            } else {
                $_.Groups[1].Value
            }
            $Obj = [PSCustomObject]@{
                HostStatus = ($Status | ? {$_ -match $IP}).Split(":")[0]
                Status = $JobStatus
                IP = ($_.Groups[2].Value -replace '(\[|\])','').Trim()
                Json = "$($_.Groups[3].Value)}"
                Results = ("$($_.Groups[3].Value)}" | ConvertFrom-Json).Results
            }
            $Array += $Obj
        }
        }
    }
    Return $Array
}

function Get-GFTAWXGroups {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/groups" -WebSession $Session).Results
    $Array = @()
    $Result | % {
        $Inventory = Get-GFTAWXInventory -Session $Session -ID $_.Inventory
        $Obj = [PSCustomObject]@{
            ID = $_.ID
            Name = $_.Name
            Inventory = $Inventory.Name
            Inventory_ID = $Inventory.ID
        }
    $Array += $Obj
    }
    Return $Array
}

function New-GFTAWXInventory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [String]$Name,
        [switch]$LinuxKeyVariables,
        [switch]$WindowsKeyVariables
    )
    $Json = @{}
    $Json.Add('name', $Name)
    $Json.Add('organization',2)
    if ($LinuxKeyVariables) {
        $Json.Add('variables',"ansible_ssh_common_arg: '-o StrictHostKeyChecking=no'")
    }
    if ($WindowsKeyVariables) {
        $Variables = @{}
        $Variables['ansible_user'] = "{{ win_user_ood }}"
        $Variables['ansible_password'] = "{{ win_pass_ood }}"
        $Variables['ansible_port'] = 5985
        $Variables['ansible_connection'] = "winrm"
        $Variables['ansible_winrm_cert_validation'] = "ignore"
        $Variables['ansible_winrm_transport'] = "ntlm"
    #    $Variables['ansible_become'] = "true"
        $Variables['windows'] = 1
        $Json.Add('variables', ($Variables | ConvertTo-Json))
    }
    $Json = $Json | ConvertTo-Json
    $PostUrl = "$($Session.Headers.Origin)/api/v2/inventories/"
    $Result = Invoke-RestMethod -Method Post -Uri $PostUrl -WebSession $Session -Body $Json -ContentType 'application/json'
    Return $Result.Results
}

function Remove-GFTAWXInventory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [String]$Name
    )
    $Json = @{}
    $Json.Add('name', $Name)
    $Json.Add('organization',2)
    $InventoryID = (Get-GFTAWXInventories -Session $Session | ? { $_.Name -eq "$Name"}).ID
    $PostUrl = "$($Session.Headers.Origin)/api/v2/inventories/$InventoryID/"
    $Result = Invoke-RestMethod -Method Delete -Uri $PostUrl -WebSession $Session
    Return $Result.Results
}

function Start-GFTAWXJob {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [int]$ID,
        [parameter(Mandatory=$false)]
        [String]$Limit,
        [String[]]$VariableName,
        [String[]]$VariableValue,
        [String]$Hostname,
        $Inventory,
        [string]$HostID,
        [Int]$Credentials,
        [switch]$StreamResult,
        [switch]$NewLinux,
        [switch]$NewWindows
    )

    $Session = Get-GFTAWXLogin
    $Json = @{}
    if ($Limit) {
        $Json.Add('limit',$Limit)
    }
    if ($VariableName -and $VariableValue) {
        $ExtraArray = New-GFTArrayFromValue -VarName $VariableName -Varvalue $VariableValue
        if (!($ExtraArray)) {
            Return $false
        }
        $ExtraVars = @{}
        $ExtraArray | % {
            $ExtraVars += @{"$($_.Varname)"="$($_.VarValue)"}
        }
        $Json.Add("extra_vars", $ExtraVars)
    }
    if ($Credentials) {
        $Json.Add("credentials", @($Credentials))
    }

    if ($HostID) {

    }
    if ($Hostname -and (-not $Inventory)) {
        # Create inventory
        $Inventory = Generate-GFTPassword -lenght 6 -NoComplexity
        if ($NewLinux) {
            $NewInventory = New-GFTAWXInventory -Session $Session -Name $Inventory -LinuxKeyVariables
        } elseif ($NewWindows) {
            $NewInventory = New-GFTAWXInventory -Session $Session -Name $Inventory -WindowsKeyVariables
        } else {
            $NewInventory = New-GFTAWXInventory -Session $Session -Name $Inventory
        }
        # Add host to inventory
        $AddTo = Add-GFTAWXHostToInventory -Session $Session -IPAddress $Hostname -Inventory $Inventory
        $Inventories = Get-GFTAWXInventories -Session $Session | ? {$_.Name -eq $Inventory}
        $RemoveInventory = $true
    } elseif ($Inventory -and (-not $Hostname)) {
        if ($Inventory -is [int]) {
            $Inventories = Get-GFTAWXInventories -Session $Session | ? {$_.Id -eq $Inventory}
        } else {
            $Inventories = Get-GFTAWXInventories -Session $Session | ? {$_.Name -eq $Inventory}
        }
        #$NoPatch = $true
    } else {
        $Template = Get-GFTAWXTemplates -Session $Session -ID $ID
        $Inventories = Get-GFTAWXInventories -Session $Session | ? {$_.ID -eq $Template.inventory}
    }
    $PatchUrl = "$($Session.Headers.origin)$((Get-GFTAWXTemplates -Session $Session | ? {$_.ID -eq $ID}).Url)/"

    if (!($NoPatch)) {
        $JsonPatch = @{}
        $JsonPatch.Add('inventory', $Inventories.id)
        $JsonPatch = $JsonPatch | ConvertTo-Json
        $PatchInventory = Invoke-RestMethod -Uri $PatchUrl -WebSession $Session -Method Patch -Body $JsonPatch -ContentType 'application/json'
    }
    
    $Json = $Json | ConvertTo-Json
    $URLToLaunch = "$($Session.Headers.origin)$((Get-GFTAWXTemplates -Session $Session | ? {$_.ID -eq $ID}).Url)launch/"
    $Result = try { 
        Invoke-RestMethod -Uri "$($URLToLaunch)" -Method Post -ContentType 'application/json' -Body $Json -WebSession $Session
    } catch {
        "HTTP Error: $($_.Exception.Message)"
    }

    if ($Result.job) {
        Wait-GFTAWXStatus -Session $Session -ID $Result.job
    }
    $JobResult = Get-GFTAWXJob -Session $Session -ID $Result.job
    if ($StreamResult) {
        $JobResult = Get-GFTAWXJobStream -Session $Session -ID $Result.job
    }
    # Delete temporary inventory
    if ($RemoveInventory) {
        $ToRemove = try { Get-GFTAWXInventories -Session $Session | ? {$_.Name -eq $Inventory} } catch { $null }
        
        while ($ToRemove) {
            $ToRemove = try { Get-GFTAWXInventories -Session $Session | ? {$_.Name -eq $Inventory} } catch { $null }
            try { Remove-GFTAWXInventory -Session $Session -Name $ToRemove.name } catch { $null }
            Start-Sleep -Seconds 1
        }
    }
    Return $JobResult
}

function Start-GFTAWXUpdate {
    param(
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [switch]$Emulate,
        [string]$ClientName,
        [parameter(Mandatory=$true)]
        [string[]]$Environment,
        [switch]$Notification,
        [String]$TemplateMail = "yourpath.txt"
    )

    if ($Environment.count -gt 1) {
        $EnvironmentMatching = $Environment -join '|'
        $EnvironmentSubject = $Environment -join ','
        if ($Environment -contains "dev") {
            $EnvironmentGrp = "DEV"
        }
        if ($Environment -contains "uat") {
            $EnvironmentGrp = "UAT"
        }        
        if ($Environment -contains "prod") {
            $EnvironmentGrp = "PROD"
        }
    } else {
        $EnvironmentMatching = $Environment
        $EnvironmentSubject = $Environment
        $EnvironmentGrp = $Environment
    }

    if ($Emulate) {
        $Template = try { Get-GFTAWXTemplates -Session $Session | ? {$_.Name -match "Check Update"} } catch { throw "Template not found" }
    } else {
        $Template = try { Get-GFTAWXTemplates -Session $Session | ? {$_.Name -match "Security Update"} } catch { throw "Template not found" }
    }

    if ($ClientName) {
        $ClientInventory = Get-GFTAWXInventories -Session $Session | ? {$_.Name -eq "$ClientName"}
    } else {
        $ClientInventory = Get-GFTAWXInventories -Session $Session 
    }
    if (-not($ClientInventory)) {
        Throw "Client $ClientName not found"
    }
    $GroupD = @()
    $ClientInventory | ? {$_.name -notmatch 'All|Local|temp|demo'} | % {
        $params = @{}
        $TemplateID = [int]$Template.ID
        $params['ID'] = $TemplateID
        $LimitGroup = @()
        $GroupD += (Get-GFTAWXGroupsInInventory -Session $Session -ID $_.ID).Name | ? {$_ -match "$EnvironmentMatching"}
        if ($ClientName) {
            if (-not($GroupD)) {
                Throw "Group $EnvironmentMatching not found"
            }
        }
        $GroupD | ? { $_ -notmatch "offline" } | % {
            $LimitGroup += $_
        }
        #$LimitGroup
        $params['limit'] = $LimitGroup -join ':'
        
        $params['Inventory'] = $_.name
        if ($Notification -and (!($Emulate))) {
            $NotifMembers = @()
            $NotifMembers += try {(Get-ADGroupMember -Identity "GG_NOTIFICATION_UPDATE_$($_.name)" | Get-ADUser -Properties mail).mail} catch {$null}
            $NotifMembers += try {(Get-ADGroupMember -Identity "GG_NOTIFICATION_UPDATE_$($_.name)_$($EnvironmentGrp)" | Get-ADUser -Properties mail).mail} catch {$null}
            $Subject = "Security update"
            $TemplateMail = Get-Content $TemplateMail -Raw
            $TemplateMail = $TemplateMail -replace "ENCustomerName", "$($_.name) Users" -replace "FRCustomerName", "utilisateurs $($_.name)" -replace 'UPDATEENV',"$EnvironmentSubject"
            $NotifMembers = $NotifMembers | Sort-Object -Unique
            $NotifMembers | % {
                Send-GFTMail -SMTPSender "your@mail.com" -ToAddress $_ -Body "$TemplateMail" -Azure -Subject $Subject
            }
            $DateBegin = Get-Date
        }
        $Job = Start-GFTAWXJob -Session $Session @params
        if ($Notification -and (!($Emulate))) {
            $DateEnd = Get-Date
            $Duration = $DateEnd - $DateBegin
            $Duration = "$($Duration.Hours) hours $($Duration.Minutes) mins. $($Duration.Seconds) sec."
            $CSV = Get-GFTAWXJsonUpdate -Session $Session -ID $Job.id | Select-Object IP,HostStatus,Status,@{N='Result';E={if ($_.Display) { $_.Display } else { ($_.json | ConvertFrom-Json).Results }}} | ConvertTo-Csv | Out-File -Path "$($_.name).csv" -Force -Confirm:$false
            $CheckOrNot = if ($Emulate) { "Check mode (no real update)"} else { "Update with real modification" }
            $Subject = "Security update"
            $Resume = Get-GFTAWXJsonUpdate -Session $Session -ID $Job.id | Select-Object IP,Status | ConvertTo-Html -Fragment
            $TemplateMail = Get-Content $TemplateMail -Raw
            $TemplateMail = $TemplateMail -replace "ENCustomerName", "$($_.name) Users" -replace "FRCustomerName", "utilisateurs $($_.name)" -replace 'MDURATION',"$Duration" -replace "ENDDATE", $(Get-Date $DateEnd -format "yyyy-MM-dd HH:mm:ss")
            $NotifMembers = $NotifMembers | Sort-Object -Unique
            $ClN = $_.name
            $NotifMembers | % {
                Send-GFTMail -SMTPSender "your@mail.com" -ToAddress $_ -Body "$TemplateMail" -Attachment "$($ClN).csv" -Azure -Subject $Subject
            }
        }
        if ($Notification -and $Emulate) {
            $NotifMembers = @()
            $NotifMembers += try {(Get-ADGroupMember -Identity "GG_NOTIFICATION_UPDATE_$($_.name)" | Get-ADUser -Properties mail).mail} catch {$null}
            $NotifMembers += try {(Get-ADGroupMember -Identity "GG_NOTIFICATION_UPDATE_$($_.name)_$($EnvironmentGrp)" | Get-ADUser -Properties mail).mail} catch {$null}
            $Subject = "Update"
            $Resume = Get-GFTAWXJsonUpdate -Session $Session -ID $Job.id | Select-Object IP,Status,@{N='Result';E={if ($_.Display) { $_.Display } elseif (($_.json | ConvertFrom-Json).Results) { ($_.json | ConvertFrom-Json).Results } else { "Status not send"}}} | ConvertTo-Html -Fragment
            $TemplateMail = Get-Content $TemplateMail -Raw
            $TemplateMail = $TemplateMail -replace "ENCustomerName", "$($_.name) Users" -replace "FRCustomerName", "utilisateurs $($_.name)" -replace 'ARRAYRESUME',"$Resume" -replace 'Installed: (.*?) ','<span style="color: green;">$1</span><br />' -replace 'Removed: (.*?) ','<span style="color: red;">$1</span><br />'
            $NotifMembers = $NotifMembers | Sort-Object -Unique
            $NotifMembers | % {
                Send-GFTMail -SMTPSender "your@mail.com" -ToAddress $_ -Body "$TemplateMail" -Azure -Subject $Subject
            }
            $DateBegin = Get-Date
        }
        if ($GroupD) {
            Remove-Variable GroupD -Force -Confirm:$false
        }
        $Job
    }
}

function Set-GFTAWXHostsUpdate {
    param (
        [String]$Hostname,
        [String]$IP,
        [switch]$Enabled,
        [switch]$Disabled
    )
    $params = @{}
    if ($Hostname -and -not $IP) {
        $params['Hostname'] = $Hostname
    } elseif ($IP -and -not $Hostname) {
        $params['IP'] = $IP
    } else {
        throw 'Incorrect choice, choose IP or Hostname'
    }
    $params['TagName'] = "No-Update"

    if ($Enabled -and $Disabled) {
        throw 'Incorrect choice, choose Enabled or Disabled'
    } elseif ($Enabled) {
        Remove-GFTNetboxVMTag @params
    } elseif ($Disabled) {
        Add-GFTNetboxVMTag @params
    } else {
        Throw "Incorrect choice ... choose Enabled or Disabled"
    }
}

function Get-GFTAWXProjects {
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/projects" -WebSession $Session).Results
    Return $Result
}

function Get-GFTAWXInventorySource {
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Result = (Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventory_sources/" -WebSession $Session).Results
    Return $Result
}
function Add-GFTAWXInventorySource {
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [String]$GitPath,
        [parameter(Mandatory=$true)]
        [String]$Name,
        [parameter(Mandatory=$true)]
        [String]$Inventory,
        [String]$SourceProject = "Local GitLab"
    )
    $InventoryID = (Get-GFTAWXInventories -Session $Session | ? { $_.Name -eq "$Inventory"}).ID
    $ProjectID = (Get-GFTAWXProjects -Session $session | ? { $_.Name -eq "$SourceProject" }).ID
    $Json = @{}
    $Json['name'] = $Name
    $Json['source'] = "scm"
    $Json['source_project'] = $ProjectID
    $Json['source_path'] = $GitPath
    $Json['overwrite'] = $true
    $Json['overwrite_vars'] = $true
    $Json['update_on_launch'] = $true
    $Json['inventory'] = $InventoryID
    $Body = $Json | ConvertTo-Json
    Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventory_sources/" -Method Post -ContentType "application/json" -Body $Body -WebSession $Session
}

function Remove-GFTAWXInventorySource {
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [int]$SourceID
    )
    $Result = Try { Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventory_sources/$SourceID/" -Method Delete -WebSession $Session } catch { "Error" }
    Return $Result
}

function Update-GFTAWXInventorySource {
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [parameter(Mandatory=$true)]
        [int]$SourceID
    )
    $Result = Try { Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/inventory_sources/$SourceID/update/" -Method Post -ContentType 'application/json' -Body "{}" -WebSession $Session } catch { "Error" }
    Wait-GFTAWXStatus -Session $Session -ID $Result.id -Inventory
    $Result = Get-GFTAWXJob -Session $Session -ID $Result.id -Inventory
    Return $Result
}

function Update-GFTAWXProject {
    param (
        [parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [String]$Project = "Local GitLab"
    )
    [int]$ProjectID = (Get-GFTAWXProjects -Session $Session | ? { $_.Name -eq $Project }).ID
    $Result = Try { Invoke-RestMethod -Uri "$($Session.Headers.origin)/api/v2/projects/$ProjectID/update/" -Method Post -ContentType 'application/json' -Body "{}" -WebSession $Session } catch { "Error" }
    [int]$IDResult = $Result.ID
    Wait-GFTAWXStatus -Session $Session -ID $IDResult -Project
    $Result = Get-GFTAWXJob -Session $Session -ID $Result.id -Project
    Return $Result
}
