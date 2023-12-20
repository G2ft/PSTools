# Open-GFTOpnSenseConnection

## Definition
This function open the first connection to OpnSense Firewall
It add necessary Cookies and Headers

## Usage

```powershell

$Session = (Open-GFTOpnSenseConnection -RTRUrl "https://myfirewall.url")
# Variable session content
$Session | ConvertTo-Json
{
  "Headers": {
    "authority": "https://myfirewall.url",
    "scheme": "https",
    "origin": "https://myfirewall.url",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "accept-encoding": "gzip, deflate, br",
    "accept-language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "HiddenName": "eml1L25zZjhWT1ZtYjVwLzUycFd2UT09",
    "HiddenValue": "NEVocUlFbDNnc21WTHc1Z1I2YVJadz09",
    "x-csrftoken": "NEVocUlFbDNnc21WTHc1Z1I2YVJadz09",
    "x-requested-with": "XMLHttpRequest"
  },
  "Cookies": {
    "Capacity": 300,
    "Count": 4,
    "MaxCookieSize": 4096,
    "PerDomainCapacity": 20
  },
  "UseDefaultCredentials": false,
  "Credentials": null,
  "Certificates": null,
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
  "Proxy": null,
  "MaximumRedirection": -1,
  "MaximumRetryCount": 0,
  "RetryIntervalInSeconds": 0
}

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