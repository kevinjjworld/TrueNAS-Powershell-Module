# TrueNAS-Administration
This is a Powershell Module that provides command-lines and automation for the TrueNAS API.

### Compatibilities
* **Powershell 7.1** Minimum
* TrueNAS RESTful API 2.0

### Import the module in Powershell
#### 1. Clone the repository or download the project :
```bash
git clone 

```
#### 2. Import the Module in Powershell :
```Powershell
Import-Module -Name ".\TrueNAS-Administration" -Force
```

#### 3. List all module's command-lines :
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
Get-TrueNasUser -TrueNasSession $TrueSession
```