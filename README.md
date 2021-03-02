# TrueNAS-Administration
This is a Powershell Module that provides command-lines and automation for the TrueNAS API.
With this module, you can manage your TrueNAS server from a computer with Powershell (Windows or Linux).
* This module only works over HTTPS.
* This module only works with [TrueNAS API Key](https://www.truenas.com/docs/hub/additional-topics/api/#creating-api-keys).

## Requirements
* **Powershell 7.1 Minimum** (for a better experience) but works on Powershell 5.1 Minimum
* TrueNAS RESTful API 2.0

### How to install Powershell 7 ?
* [Installing Powershell 7 on Windows](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-windows?view=powershell-7.1)
* [Installing Powershell 7 on Debian 10](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7.1#debian-10)
* [Installing Powershell 7 on Ubuntu 20.04](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7.1#ubuntu-2004)


## Import the module in Powershell
#### 1. Run Powershell

#### 2. Clone the repository or download the project :
```bash
git clone https://github.com/kevinjjworld/TrueNAS-Powershell-Module.git

```
#### 3. Import the Module in Powershell :
```Powershell
Import-Module -Name ".\TrueNAS-Powershell-Module\TrueNAS-Administration" -Force
```

#### 4. List all module's Cmdlets :
```Powershell
Get-Command -Module "TrueNAS-Administration"
```

## Usage
#### 1. Get a session and store it in a variable
* If you have a valid certificate :
```Powershell
$Session = Get-TrueNasSession -Server "truenas" -APIToken "1-xxxxxxxxxxx"
```
* If you don't have a valid certificate, use the parameter `-SkipCertificateCheck` :
```Powershell
$Session = Get-TrueNasSession -Server "truenas" -APIToken "1-xxxxxxxxxxx" -SkipCertificateCheck
```
#### 2. Run Cmdlets using the previous variable containing the session. For example :
```Powershell
Get-TrueNasInfo -TrueNasSession $Session
```

## Examples
#### List TrueNAS users
```Powershell
Get-TrueNasUser -TrueNasSession $Session
```

#### Create a new user
* Example 1 :
```Powershell
New-TrueNasUser -TrueNasSession $Session -Credential "userName" -FullName "My New User" `
                -MicrosoftAccount -SambaAuthentification
```
You will be prompted for the users's password. If you need a **non-interactive** command, see **Example 2**.

* Example 2 :
```Powershell
$Cred = New-Object System.Management.Automation.PSCredential -ArgumentList @(
        "userName", $(ConvertTo-SecureString -String "userPassword" -AsPlainText -Force)
)

New-TrueNasUser -TrueNasSession $Session -Credential $Cred -FullName "My New User" `
                -MicrosoftAccount -SambaAuthentification
```
This method is less secure because the password is written in clear text in the command line history.

#### List TrueNAS groups :
```Powershell
Get-TrueNasGroup -TrueNasSession $Session
```

#### Create a new group :
```Powershell
New-TrueNasGroup -TrueNasSession $Session -GroupName "groupName" -SambaGroup
```