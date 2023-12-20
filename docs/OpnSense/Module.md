# OpnSense

## Prerequisites

* ActiveDirectory PowerShell module
* This module is tested in PowerShell 7.3

```powershell
# If you use Passbolt module and function
Install-Module -Name PSPGP -AllowClobber -Force -Scope AllUsers
```

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


## List of function

* **Get-GFTOpnSenseCSRFToken**
  * Allows you to retrieve the CSRF Token
* **Open-GFTOpnSenseConnection**
  * Open first connection to OpnSense Firewall
  * Add necessary Cookie and Headers 
* **Get-GFTOpnSenseLogin**
  * Login to Firewall web interface to initialize connection
* **Get-GFTOpnSenseLDAPUsers**
  * Return array from Import LDAP page
  * Check samaccountname in Active Directory with Get-ADUser cmdlet
* **Import-GFTOpnSenseLDAPUser**
  * Import user from Import LDAP page
* **Get-GFTOpnSenseUserID**
  * Return User ID if exist
* **Get-GFTOpnSenseUserDN**
  * Return User DN if exist
* **Get-GFTOpnSenseGroup**
  * Return existing groups in OpnSense 
* **Get-GFTOpnSenseUserGroup**
  * Return groups from existing user
* **Get-GFTOpnSenseUserTOTP**
  * Return user OTP
* **Get-GFTOpnSenseRouters**
  * This function is Passbolt PowerShell and OpnSense and creates a password-free csv (cache).
  * Passbolt needs to store information from different firewalls
* **Add-GFTOpnSenseTOTP**
  * Add OTP to user
* **Add-GFTOpnSenseGroupToUser**
  * Add group to user
* **Get-GFTOpnSenseCAID**
  * Return CA ID for create certificate
  * You have to create certificate one time with this CA and link certificate to root user (id:0)
* **New-GFTOpnSenseUserCertificate**
  * Create certificate for an exisiting user
* **Remove-GFTOpnSenseUserCertificate**
  * Delete certificate for an existing user
* **Get-GFTOpnSenseOpenVPNProviders**
  * Return OpenVPN Providers
* **Get-GFTOpnSenseOpenVPNUsers**
  * Return OpenVPN Users
* **Get-GFTOpnSenseOpenVPNFiles**
  * Construct VPN File for an user to Path
* **Test-GFTOpnSenseUserCertificates**
  * Test if an certificate exist
* **Get-GFTOpnSenseCertificates**
  * Retreive all OpnSense Certificates
* **Remove-GFTOpnSenseCertificate**
  * Remove OpnSense Certificate
* **Remove-GFTOpnSenseUser**
  * Remove OpnSense user
* **Get-GFTOpnSenseUserList**
  * Return list of OpnSense Users
* **New-GFTOpnSenseUser**
  * This function allows you to follow the complete path from import to VPN file creation.