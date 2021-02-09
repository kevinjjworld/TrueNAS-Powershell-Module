# TrueNAS-Administration functions
function Invoke-RestMethodOnFreeNAS {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [string]$ApiSubPath,
        [Parameter(Mandatory = $true)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [String]$Body,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateSet("GET", "PUT", "POST", "DELETE")]
        [String]$Method = "GET",
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    if(!$Body){
        $Body = [string]::Empty
    }

    # Variables
    $headers = @{ "Content-type" = "application/json"; "Authorization" = "Bearer " + $apiToken }
    [string]$apiBaseURI = "https://${Server}"
    if ($Port) {
        $apiBaseURI = "https://${Server}:${Port}"
    }
    [string]$apiRootPath = "/api/v2.0"

    $apiFullUri = $($apiBaseURI + $apiRootPath + $ApiSubPath)

    # Lancement de la requête
    $result = Invoke-RestMethod -Uri $apiFullUri -Method $Method -Headers $headers -SkipCertificateCheck:$SkipCertificateCheck -Body $Body

    return $result
}

function Get-TrueNasInfos {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/system/info"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasPools {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasPoolAttachements {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/id/$id/attachments"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasPoolProcesses {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/id/$id/processes"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasPoolDisks {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/id/$id/get_disks"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasPoolFileSystems {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/filesystem_choices"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasDatasets {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/dataset"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasDatasetAttachments {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/dataset"
    $ApiSubPath += "/id/" + $Id + "/attachments"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasDatasetProcesses {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/dataset"
    $ApiSubPath += "/id/" + $Id + "/processes"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasServices {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/service"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasSharing {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $true)]
        [ValidateSet("afp", "nfs", "smb", "webdav")]
        [string]$Type,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/sharing/$Type"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasSMBConfig {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/smb"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasSMBStatus {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/smb/status"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasSSHConfig {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/ssh"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}
function Get-TrueNasUpdateTrains {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/update/get_trains"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}
function Get-TrueNasUpdateStatus {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/update/check_available"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasGeneralConfig {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/system/general"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasNTPServers {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/system/ntpserver"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasSystemDataset {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/systemdataset"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasTunable {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/tunable"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasUsers {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )
    

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/user"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasGroups {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )
    

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/group"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasVM {

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )
    

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/vm"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasVMMemoryUsage {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )
    

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/vm/get_vmemory_in_use"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasVMDevices {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )
    

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/vm/device"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }
    
    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function New-TrueNasUser {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [String]$APIToken,
        [Parameter(Mandatory = $true)]
        [pscredential]$Credential,
        [Parameter(Mandatory = $true)]
        [string]$FullName,
        [Parameter(Mandatory = $false)]
        [string]$email,
        [Parameter(Mandatory = $false)]
        [switch]$MicrosoftAccount,
        [Parameter(Mandatory = $false)]
        [switch]$SambaAuthentification,
        [Parameter(Mandatory = $false)]
        [switch]$PermitSudo,
        [Parameter(Mandatory = $false)]
        [string]$SSHPubKey,
        [Parameter(Mandatory = $false)]
        [switch]$LockUser,
        [Parameter(Mandatory = $false)]
        [string]$HomeDirectory,
        [Parameter(Mandatory = $false)]
        [string]$HomeDirectoryMode,
        [Parameter(Mandatory = $false)]
        [string]$Shell,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )
    

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/user"

    # Création de l'objet
    $newObject = @{
        username = $Credential.UserName;
        group_create = $true;
        full_name = $FullName;
    }

    #region Ajout des paramètres supplémentaires
        if(![string]::IsNullOrEmpty($SSHPubKey)){
            $newObject.Add("sshpubkey", $SSHPubKey)
        }
        if(![string]::IsNullOrEmpty($email)){
            $newObject.Add("email", $email)
        }
        if([string]::IsNullOrEmpty($Credential.GetNetworkCredential().Password)){
            $newObject.Add("password_disabled", $true)
        }
        else {
            $newObject.Add("password", $Credential.GetNetworkCredential().Password)
        }
        if($MicrosoftAccount.IsPresent){
            $newObject.Add("microsoft_account", $true)
        }
        if($SambaAuthentification.IsPresent){
            $newObject.Add("smb", $true)
        }
        if($PermitSudo.IsPresent){
            $newObject.Add("sudo", $true)
        }
        if($LockUser.IsPresent){
            $newObject.Add("locked", $true)
        }
        if(![string]::IsNullOrEmpty($HomeDirectory)){
            $newObject.Add("home", $HomeDirectory)
        }
        if(![string]::IsNullOrEmpty($Shell)){
            $newObject.Add("shell", $Shell)
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken -Body $body

    return $result
}
function Remove-TrueNasUser {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [String]$APIToken,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$DeleteUserPrimaryGroup,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )
    
    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/user"
    $ApiSubPath += "/id/" + $Id

    # Création de l'objet
    $newObject = @{
    }

    #region Ajout des paramètres supplémentaires
        if($DeleteUserPrimaryGroup.IsPresent){
            $newObject.Add("delete_group", $true)
        }
    #endregion
    $body = $newObject | ConvertTo-Json
    

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method DELETE -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken -Body $body

    return $result
}




