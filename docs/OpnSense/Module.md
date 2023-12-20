# OpnSense

## Description
This module allow you to manage Users in OpnSense firewall.

You can : 

* Import from LDAP

* Create & delete certificate

* Create & generate OTP Code

* Create VPN File (OpenVPN)

## Usage

### Connect

```powershell
$User = "myuser"
$Password = "MyPassword"
$RTRUrl = "https://myfirewall.local/"
$Session = (Open-GFTOpnSenseConnection -RTRUrl $RTRUrl)
Get-GFTOpnSenseLogin -Session $Session -Login $User -Password $Password
```

### Administration

Test if user exist : 

```powershell
# Connect with connection example
$Username = "MyUser"
if (Get-GFTOpnSenseUserID -Session $Session -User $Username) {
  "Exist"
} else {
  "Not"
}
```

Create certificate for user :

```powershell
# Connect with connection example
$Username = "MyUser"
New-GFTOpnSenseUserCertificate -User $Username -Session $Session
```

