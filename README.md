# TrueNAS-Administration
This is a Powershell Module that provides command-lines and automation for the TrueNAS API.
With this module, you can manage your TrueNAS server from a computer with Powershell (Windows or Linux).
* This module only works over HTTPS.
* This module only works with [TrueNAS API Key](https://www.truenas.com/docs/hub/additional-topics/api/#creating-api-keys).

## Requirements
* **[Powershell 7.1](https://github.com/PowerShell/PowerShell/releases/latest)** Minimum
* TrueNAS RESTful API 2.0

## Import the module in Powershell
#### 1. Run Powershell 7

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
$Session = Get-TrueNasSeesion -Server "truenas" -APIToken "1-xxxxxxxxxxx"
```
* If you don't have a valid certificate, use the `-SkipCertificateCheck` parameter :
```Powershell
$Session = Get-TrueNasSeesion -Server "truenas" -APIToken "1-xxxxxxxxxxx" -SkipCertificateCheck
```
#### 2. Execute Cmdlets using the previous variable contains the session
* Get TrueNAS informations :
```Powershell
Get-TrueNasInfo -TrueNasSession $Session
```
* Get TrueNAS users :
```Powershell
Get-TrueNasUser -TrueNasSession $Session
```

* Create new TrueNAS User (Example 1) :
```Powershell
New-TrueNasUser -TrueNasSession $Session -Credential myNewUserName -FullName "My New User" -MicrosoftAccount -SambaAuthentification
```
You will be prompted for the users's password. If you need a `non-interactive` command, see `Example 2`.

* Create new TrueNAS User (Example 2) :
```Powershell
$Cred = New-Object System.Management.Automation.PSCredential -ArgumentList "userName", $(ConvertTo-SecureString -String "userPassword" -AsPlainText -Force)

New-TrueNasUser -TrueNasSession $Session -Credential $Cred -FullName "My New User" -MicrosoftAccount -SambaAuthentification
```
