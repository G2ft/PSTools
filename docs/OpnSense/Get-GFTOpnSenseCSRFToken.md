# Get-GFTOpnSenseCSRFToken

## Definition
This function allow you to get the CSRF token. It's mandatory to navigate on the web interface.

## Default options

```powershell
# You have session with : Open-GFTOpnSenseConnection
# Store it in $Session Variable
[Microsoft.PowerShell.Commands.WebRequestSession]$Session
# Router URL ($RTRUrl) can be automaticaly set with previous cmdlet
$RTRUrl = $($Session.Headers.origin)
[string]$Path = "/ui/openvpn/export"

```

