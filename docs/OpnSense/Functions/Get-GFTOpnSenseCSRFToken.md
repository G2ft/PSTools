# Get-GFTOpnSenseCSRFToken

## Definition
This function allow you to get the CSRF token. It's mandatory to navigate on the web interface.

## Usage

```powershell

$Session = (Open-GFTOpnSenseConnection -RTRUrl "https://myfirewall.url")
Get-GFTOpnSenseCSRFToken -Session $Session

```

## Default options

```powershell

# You have session with : Open-GFTOpnSenseConnection
# Store it in $Session Variable
[Microsoft.PowerShell.Commands.WebRequestSession]$Session
# Router URL ($RTRUrl) can be automaticaly set with Open-GFTOpnSenseConnection function, you can put your custom URL
$RTRUrl = $($Session.Headers.origin)
[string]$Path = "/ui/openvpn/export"

```