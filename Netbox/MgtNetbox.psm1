function Get-NetworkIPv4 {
    param(
        [string]$ipAddress,
        [int]$cidr
    )
    $parsedIpAddress = [System.Net.IPAddress]::Parse($ipAddress)
    $shift = 64 - $cidr
    
    [System.Net.IPAddress]$subnet = 0

    if ($cidr -ne 0) {
        $subnet = [System.Net.IPAddress]::HostToNetworkOrder([int64]::MaxValue -shl $shift)
    }

    [System.Net.IPAddress]$network = $parsedIpAddress.Address -band $subnet.Address

    return [PSCustomObject]@{
        Network = $network
        SubnetMask = $subnet
    }
}
function Get-GFTNetboxConnection {
    param(
        [string]$APIURL = "https://netboxurl/api",
        [string]$XMLCreds = "netbox.xml",
        [string]$Token
    )
    
    # Set API Headers
    if ($XMLCreds) {
        $AccountXML = Import-Clixml $XMLCreds
        $Credentials = New-Object System.Management.Automation.PSCredential($AccountXML.Username, (ConvertTo-SecureString -String "$($AccountXML.token)" -Key $($AccountXML.Key)))
        $Token = $Credentials.GetNetworkCredential().Password
    }
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Token $Token")
    $headers.Add("Content-Type", 'application/json')
    $headers.Add("Accept", 'application/json')
    $headers.Add("URL", "$APIURL")
    Return $headers
}

function Get-GFTNetboxClientGroup {
    param (
        [string]$ClientName
    )
    $headers = Get-GFTNetboxConnection
    $URL = (($headers).GetEnumerator() | ? {$_.Key -eq "URL"}).Value
    $GetGroups = Invoke-RestMethod -Uri $URL/tenancy/tenant-groups/?limit=0 -Method Get -Headers $headers
    if ($ClientName) {
        $ClientGroup = $GetGroups.results | ? {$_.Name -match "$ClientName"}
    } else {
        $ClientGroup = $GetGroups.results
    }
    Return $ClientGroup
}

function Get-GFTNetboxClientTenant {
    param (
        [string]$ClientName
    )
    $headers = Get-GFTNetboxConnection
    $URL = (($headers).GetEnumerator() | ? {$_.Key -eq "URL"}).Value
    if ($ClientName) {
        $ClientID = (Get-GFTNetboxClientGroup -ClientName $ClientName).id
        $GetTenant = Invoke-RestMethod -Uri $URL/tenancy/tenants/?group_id=$ClientID -Method Get -Headers $headers
    } else {
        $GetTenant = Invoke-RestMethod -Uri $URL/tenancy/tenants/?limit=0 -Method Get -Headers $headers
    }
    $ClientTenant = $GetTenant.results 
    Return $ClientTenant
}

function Get-GFTNetboxClientVM {
    param (
        [string]$ClientName
    )
    $headers = Get-GFTNetboxConnection
    $URL = (($headers).GetEnumerator() | ? {$_.Key -eq "URL"}).Value
    if ($ClientName) {
        $ClientTenant = Get-GFTNetboxClientTenant -ClientName $ClientName
    } else {
        $ClientTenant = Get-GFTNetboxClientTenant
    }
    $Array = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    foreach ($Tenant in $ClientTenant) {
        $Nav = (Invoke-RestMethod -Uri $URL/virtualization/virtual-machines/?tenant_id=$($Tenant.id) -Method Get -Headers $headers).Results
        if ($ClientName) {
            $ClientGroup = (Get-GFTNetboxClientGroup -ClientName $ClientName).name
        } else {
            $ClientGroup = (Invoke-RestMethod -Uri "$URL/tenancy/tenants/$($Tenant.Id)/?limit=0" -Method Get -Headers $headers).Group.Display
        }

        $Nav | % -Parallel {
            $Array = $using:Array
            $ClientGroup = $using:ClientGroup
            $TestDomain = try { Get-ADComputer -Filter "name -like '$($_.Name | % { $($_)[0..14] -join '' })*'" } catch { $null }
            $DataToReturn = New-Object -TypeName psobject 
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.name
            if ($_.primary_ip.display) {
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "IP" -Value ($_.primary_ip.display -split "/")[0]
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "CIDR" -Value ($_.primary_ip.display -split "/")[1]
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "Netmak" -Value (Get-NetworkIPv4 -ipAddress ($_.primary_ip.display -split "/")[0] -cidr ($_.primary_ip.display -split "/")[1]).SubnetMask
            } else {
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "IP" -Value "NaN"
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "CIDR" -Value "NaN"
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "Netmak" -Value "NaN"
            }
            
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "Tenant" -Value $_.Tenant.name
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "Client" -Value $ClientGroup
            if ("No-Update" -in $_.tags.name) {
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "AnsibleUpdate" -Value "No"
            } else {
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "AnsibleUpdate" -Value "Yes"
            }
            if ($_.platform.name -match "Microsoft|Windows") {
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "OS" -Value "Windows"
            } else {
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "OS" -Value "Linux"
            }
            if ($_.status.value -eq "Offline") {
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "Status" -Value "Offline"
            } else {
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "Status" -Value "Online"
            }
            if ($TestDomain) {
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "Domain" -Value "Yes"
            } else {
                $DataToReturn | Add-Member -MemberType NoteProperty -Name "Domain" -Value "No"
            }
            $Array.Add($DataToReturn) | Out-Null
            if ($TestDomain) {
                Remove-Variable TestDomain
            }
        } -ThrottleLimit 30
    }
    $Array
}

function New-GFTNetboxClientIniFile {
    param (
        [String]$FolderPath = "Path\to\folder",
        [String[]]$AcceptedIPRange = @("10.0.0.0/8","172.16.0.0/16","192.168.0.0/16")        
    )

    if (!(Test-Path $FolderPath)) {
        New-Item $FolderPath -ItemType Directory -Force
    }
    Get-GFTNetboxClientVM | Sort-Object Tenant | % {
        $IniFile = "$FolderPath\$($_.Client).ini"
        if (Test-Path $IniFile) { 
            Remove-Item $IniFile -Force
        }
    }
    $ClientVM = Get-GFTNetboxClientVM | Sort-Object Tenant 
    $ClientVM | ? { $_.Status -ne 'Offline' } | % {
        if ($_.IP -match "10\.") { $ip = "10.0.0.0/8" } elseif ($_.IP -match "172\.16\.") { $ip = "172.16.0.0/16"} elseif ($_.IP -match "192\.168\.") { $ip = "192.168.0.0/16"} else { $ip = "192.168.0.0/24" }
        if ("$ip" -in $AcceptedIPRange) {
            $IniFile = "$FolderPath\$($_.Client).ini"
            if (!(Test-Path $IniFile)) {
                if ($_.Client) {
                    New-Item $IniFile -ItemType File -Force
                }
            }
            if ($_.Client -and ($_.IP -ne "NaN")) {
                $IniContent = Get-Content $IniFile -Raw

                if ($IniContent | Select-String -Pattern "\[$([Regex]::Escape($_.Tenant))\]") {
                    "nothin to do"
                } else {
                    Add-Content -Value "[$($_.Tenant)]" -Path $IniFile
                }

                    if ($_.AnsibleUpdate -eq "Yes") {
                        $VariableNotUpdate = " update=update"
                    } else {
                        $VariableNotUpdate = ""
                    }
                    if ($_.Status -eq "Offline") {
                        $VariableStatus = " offline=1"
                    } else {
                        $VariableStatus = ""
                    }
                    if ($_.Domain -eq "No") {
                        $VariableDomain = " notindomain=1"
                        if (($_.Tenant -match 'Client1-.*-dev') -and ($_.OS -eq "Windows")) {
                            $VariableCreds = " ansible_user=""{{ win_user_Client1_dev }}"" ansible_password=""{{ win_pass_Client1_dev }}"""
                        } elseif (($_.Tenant -match "Client1-.*-dev") -and ($_.OS -eq "Linux")) {
                            $VariableCreds = " ansible_user=""{{ lin_user_Client1_dev }}"" ansible_password=""{{ lin_pass_Client1_dev }}"""
                        } elseif (($_.Tenant -match 'Client1-.+-uat') -and ($_.OS -eq "Windows")) {
                            $VariableCreds = " ansible_user=""{{ win_user_Client1_uat }}"" ansible_password=""{{ win_pass_Client1_uat }}"""
                        } elseif (($_.Tenant -match 'Client1-.*-uat') -and ($_.OS -eq "Linux")) {
                            $VariableCreds = " ansible_user=""{{ lin_user_Client1_dev }}"" ansible_password=""{{ lin_pass_Client1_dev }}"""
                        } elseif (($_.Tenant -match 'Client1-.*-prod') -and ($_.OS -eq "Windows")) {
                            $VariableCreds = " ansible_user=""{{ win_user_Client1_prod }}"" ansible_password=""{{ win_pass_Client1_prod }}"""
                        } elseif (($_.Tenant -match 'Client1-.*-prod') -and ($_.OS -eq "Linux")) {
                            $VariableCreds = " ansible_user=""{{ lin_user_Client1_dev }}"" ansible_password=""{{ lin_pass_Client1_dev }}"""
                        } elseif ($_.OS -eq "Windows") {
                            $VariableCreds = " ansible_user=""{{ win_user_ood }}"" ansible_password=""{{ win_pass_ood }}"""
                        } else {
                            $VariableCreds = " ansible_user=""{{ lin_user_ood }}"" ansible_password=""{{ lin_pass_ood }}"""
                        }
                    } else {
                        if ($_.OS -eq "Windows") {
                            $VariableCreds = " ansible_user=""{{ win_user }}"" ansible_password=""{{ win_pass }}"""
                        } else {
                            $VariableCreds = ""
                        }
                        $VariableDomain = ""
                    }
                    if ($_.OS -eq "Windows") {
                        $VariableOS = " windows=1 ansible_connection=winrm ansible_winrm_cert_validation=ignore ansible_become=false ansible_port=5985 ansible_winrm_transport=ntlm"
                    } else {
                        $VariableOS = " linux=1 ansible_ssh_common_args='-o StrictHostKeyChecking=no'"
                    }
                    Add-Content -Value "$($_.IP)$($VariableNotUpdate)$($VariableOS)$($VariableStatus)$($VariableDomain)$($VariableCreds)" -Path $IniFile -Force
            }
        }
    }
    $ClientVM | ? { $_.Status -eq 'Offline' } | % {
        if ($_.IP -match "10\.") { $ip = "10.0.0.0/8" } elseif ($_.IP -match "172\.16\.") { $ip = "172.16.0.0/16"} elseif ($_.IP -match "192\.168\.") { $ip = "192.168.0.0/16"} else { $ip = "192.168.0.0/24" }
        if ("$ip" -in $AcceptedIPRange) {
            $IniFile = "$FolderPath\$($_.Client).ini"
            if (!(Test-Path $IniFile)) {
                if ($_.Client) {
                    New-Item $IniFile -ItemType File -Force
                }
            }
            if ($_.Client -and ($_.IP -ne "NaN")) {
                $IniContent = Get-Content $IniFile -Raw

                if ($IniContent | Select-String -Pattern "\[$([Regex]::Escape($_.Tenant))\-offline]") {
                    "nothin to do"
                } else {
                    Add-Content -Value "[$($_.Tenant)-offline]" -Path $IniFile
                }
                if ($_.Status -eq "Offline") {
                    $VariableStatus = " offline=1"
                } else {
                    $VariableStatus = ""
                }
                Add-Content -Value "$($_.IP)$($VariableStatus)" -Path $IniFile -Force
            }
        }
    }
}

function Get-GFTNetboxIPInformations {
    param (
        [String]$IPAddress
    )
    $headers = Get-GFTNetboxConnection
    $URL = (($headers).GetEnumerator() | ? {$_.Key -eq "URL"}).Value
    $GetIPInfos = try { Invoke-RestMethod -Uri $URL/ipam/ip-addresses/?q=$IPAddress/ -Method Get -Headers $headers } catch { $_.Exception.Message }
    if ($GetIPInfos.Count -eq 1 -and $GetIPInfos.Results) {
        Return $GetIPInfos.Results
    } elseif (!($GetIPInfos.Results)) {
        throw 'No result found'
    } else {
        throw "Error : $($GetIPInfos)"
    }
}

function Get-GFTNetboxVMInformations {
    param (
        [String]$VMName,
        [String]$VMIP,
        [Switch]$TestDomain
    )
    $headers = Get-GFTNetboxConnection

    if ($VMIP) {
        $VMUrl = (((Get-GFTNetboxIPInformations -IPAddress $VMIP).assigned_object).virtual_machine).url
        if ($VmUrl) {
            $VMUrl = $VMUrl -replace "http","https"
            $GetVMInfos = try { Invoke-RestMethod -Uri $VMUrl -Method Get -Headers $headers } catch { $_.Exception.Message }
        }
        $DataToReturn = New-Object -TypeName psobject
        $DataToReturn | Add-Member -MemberType NoteProperty -Name "ID" -Value $GetVMInfos.id
        $DataToReturn | Add-Member -MemberType NoteProperty -Name "Name" -Value $GetVMInfos.name
        $DataToReturn | Add-Member -MemberType NoteProperty -Name "TagsID" -Value $(($GetVMInfos.tags.id) -join ',')
        if ($GetVMInfos.primary_ip.display) {
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "IP" -Value ($GetVMInfos.primary_ip.display -split "/")[0]
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "CIDR" -Value ($GetVMInfos.primary_ip.display -split "/")[1]
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "Netmak" -Value (Get-NetworkIPv4 -ipAddress ($GetVMInfos.primary_ip.display -split "/")[0] -cidr ($GetVMInfos.primary_ip.display -split "/")[1]).SubnetMask
        } else {
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "IP" -Value "NaN"
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "CIDR" -Value "NaN"
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "Netmak" -Value "NaN"
        }
        
        $DataToReturn | Add-Member -MemberType NoteProperty -Name "Tenant" -Value $GetVMInfos.Tenant.name
        if ("No-Update" -in $GetVMInfos.tags.name) {
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "AnsibleUpdate" -Value "No"
        } else {
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "AnsibleUpdate" -Value "Yes"
        }
        if ($GetVMInfos.platform.name -match "Microsoft|Windows") {
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "OS" -Value "Windows"
        } else {
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "OS" -Value "Linux"
        }
        if ($GetVMInfos.status.value -eq "Offline") {
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "Status" -Value "Offline"
        } else {
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "Status" -Value "Online"
        }
        if ($TestDomain) {
            $TestDomain = try { Get-ADComputer -Filter "name -like '$((([system.Net.Dns]::GetHostByAddress("$(($GetVMInfos.primary_ip.display -split "/")[0])").Hostname).Split("."))[0] | % { $($_)[0..14] -join '' })*'" } catch { $null }
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "Domain" -Value "Yes"
        } else {
            $DataToReturn | Add-Member -MemberType NoteProperty -Name "Domain" -Value "No"
        }
        Return $DataToReturn
    } elseif ($VMName) {

    } elseif ($VMName -and $VMIP) {
        throw "One choice authorized"
    } else {
        throw "Error, no choice (VMIP or VMName required)"
    }
}

function Get-GFTNetboxTags {
    param (
        [String]$TagName
    )
    $headers = Get-GFTNetboxConnection
    $URL = (($headers).GetEnumerator() | ? {$_.Key -eq "URL"}).Value
    if ($TagName) {
        $Result = Invoke-RestMethod -Uri $URL/extras/tags/?name=$TagName -Method Get -Headers $headers
    } else {
        $Result = Invoke-RestMethod -Uri $URL/extras/tags/ -Method Get -Headers $headers        
    }
    if ($Result.Count -eq 0) {
        Throw "Tag not found"
    } else {
        Return $Result.results
    }
}

function Add-GFTNetboxVMTag {
    param (
        [String]$Hostname,
        [String]$IP,
        [String]$TagName
    )
    $headers = Get-GFTNetboxConnection
    $URL = (($headers).GetEnumerator() | ? {$_.Key -eq "URL"}).Value
    $params = @{}
    if ($Hostname -and -not $IP) {
        $params['VMName'] = $Hostname
    } elseif ($IP -and -not $Hostname) {
        $params['VMIP'] = $IP
    } else {
        throw 'Incorrect choice, choose IP or Hostname'
    }
    $params['TestDomain'] = $true
    $VMInfos = Get-GFTNetboxVMInformations @params
    $VMID = $VMInfos.id
    $TagInfos = Get-GFTNetboxTags -TagName $TagName
    $Json = @{}
    $Json['tags'] = $VMInfos.TagsID -split ','
    $Json['tags'] += $TagInfos.id
    $Body = $Json | ConvertTo-Json
    Invoke-RestMethod -Uri $URL/virtualization/virtual-machines/$VMID/ -Method Patch -Headers $headers -Body $Body -ContentType 'application/json'
}

function Remove-GFTNetboxVMTag {
    param (
        [String]$Hostname,
        [String]$IP,
        [String]$TagName
    )
    $headers = Get-GFTNetboxConnection
    $URL = (($headers).GetEnumerator() | ? {$_.Key -eq "URL"}).Value
    $params = @{}
    if ($Hostname -and -not $IP) {
        $params['VMName'] = $Hostname
    } elseif ($IP -and -not $Hostname) {
        $params['VMIP'] = $IP
    } else {
        throw 'Incorrect choice, choose IP or Hostname'
    }
    $params['TestDomain'] = $true
    $VMInfos = Get-GFTNetboxVMInformations @params
    $VMID = $VMInfos.id
    $TagInfos = Get-GFTNetboxTags -TagName $TagName
    $Json = @{}
    $Json['tags'] = ($VMInfos.TagsID -split ',' | ? {$_ -ne $TagInfos.id})
    $Body = $Json | ConvertTo-Json
    Invoke-RestMethod -Uri $URL/virtualization/virtual-machines/$VMID/ -Method Patch -Headers $headers -Body $Body -ContentType 'application/json'
}
