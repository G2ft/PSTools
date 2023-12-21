# Get-GFTOpnSenseLogin

## Definition
This function log PowerShell session to firewall web interface and initialize connection.
You must have credentials.

## Usage

```powershell
$Creds = (Get-Credential)
$Session = (Open-GFTOpnSenseConnection -RTRUrl "https://myfirewall.url")
Get-GFTOpnSenseLogin -Login $Creds.Username -Password $Creds.GetNetworkCredential().Password -Session $Session

```

## Default options

```powershell

# You have session with : Open-GFTOpnSenseConnection
# Store it in $Session Variable
[Microsoft.PowerShell.Commands.WebRequestSession]$Session
# Router URL ($RTRUrl) can be automaticaly set with Open-GFTOpnSenseConnection function, you can put your custom URL
$RTRUrl = $($Session.Headers.origin)
$Login = ""
$Password = ''

```