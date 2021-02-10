# TrueNAS-Administration functions

function Get-TrueNasSeesion {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port,
        [Parameter(Mandatory = $true)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )

    if (!$port) {
        $Port = 443
    }

    $apiFullUri = "https://$Server`:$Port/api/v2.0/"

    $headers = @{ "Content-type" = "application/json"; "Authorization" = "Bearer " + $apiToken }

    # Connexion à l'API
    try {
        $result = Invoke-RestMethod -Uri $apiFullUri -Method Get -Headers $headers -SkipCertificateCheck:$SkipCertificateCheck `
                      -SessionVariable CurrentSession
    }
    catch {
        throw $_
    }
    
    #Write-Verbose -Message "Connecté à $($result.info.title) $($result.info.version)"
    Write-Host -ForegroundColor Cyan -Message "Connecté à $apiFullUri - $($result.info.title) $($result.info.version)"
    
    return $CurrentSession
}
function Invoke-RestMethodOnFreeNAS {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [string]$ApiSubPath,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
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

    if ([string]::IsNullOrEmpty($APIToken) -and $null -eq $WebSession) {
        throw New-Object System.Exception -ArgumentList "Un des paramètres APIToken ou WebSession doit être spécifié."
    }

    if (![string]::IsNullOrEmpty($APIToken) -and $null -ne $WebSession) {
        throw New-Object System.Exception -ArgumentList "APIToken et WebSession ne doivent pas être utilisés en même temps."
    }

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

    if($null -eq $WebSession) {
        $otherParams = @{ Headers = $headers }
    }else {
        $otherParams = @{ WebSession = $WebSession }
    }

    # Lancement de la requête
    #$result = Invoke-RestMethod -Uri $apiFullUri -Method $Method -Headers $headers -SkipCertificateCheck:$SkipCertificateCheck -Body $Body
    $result = Invoke-RestMethod -Uri $apiFullUri -Method $Method -SkipCertificateCheck:$SkipCertificateCheck -Body $Body `
                                @otherParams

    return $result
}

function Get-TrueNasInfo {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if ([string]::IsNullOrEmpty($APIToken) -and $null -eq $WebSession) {
        throw New-Object System.Exception -ArgumentList "Un des paramètres APIToken ou WebSession doit être spécifié."
    }

    if (![string]::IsNullOrEmpty($APIToken) -and $null -ne $WebSession) {
        throw New-Object System.Exception -ArgumentList "APIToken et WebSession ne doivent pas être utilisés en même temps."
    }

    if (!$port) {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/system/info"

    if($null -eq $WebSession) {
        $otherParams = @{ APIToken = $APIToken }
    }else {
        $otherParams = @{ WebSession = $WebSession }
    }

    # Lancement de la requête
    #$result = Invoke-RestMethodOnFreeNAS -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    $result = Invoke-RestMethodOnFreeNAS -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath `
                                         @otherParams
    

    return $result
}

function Get-TrueNasPool {
    
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

function Get-TrueNasPoolAttachement {
    
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

function Get-TrueNasPoolProcess {
    
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

function Get-TrueNasPoolDisk {
    
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

function Get-TrueNasPoolFileSystem {
    
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

function Get-TrueNasDataset {
    
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

function Get-TrueNasDatasetAttachment {
    
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

function Get-TrueNasDatasetProcess {
    
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

function Get-TrueNasService {
    
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
function Get-TrueNasUpdateTrain {
    
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

function Get-TrueNasNTPServer {
    
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



function Get-TrueNasAvailableShell {
    
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
    $ApiSubPath = "/user/shell_choices"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    
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


function Get-TrueNasUser {
    
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
        if(![string]::IsNullOrEmpty($HomeDirectoryMode)){
            $newObject.Add("home_mode", $HomeDirectoryMode)
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

function Set-TrueNasUser {
    
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
        [string]$Username,
        [Parameter(Mandatory = $false)]
        [securestring]$SecurePassword,
        [Parameter(Mandatory = $false)]
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
    $ApiSubPath = "/user/id/$Id"
    
    # Création de l'objet
    $newObject = @{
    }

    #region Ajout des paramètres supplémentaires
        if(![string]::IsNullOrEmpty($UserName)){
            $newObject.Add("username", $Username)
        }
        if(![string]::IsNullOrEmpty($FullName)){
            $newObject.Add("full_name", $FullName)
        }
        if(![string]::IsNullOrEmpty($SSHPubKey)){
            $newObject.Add("sshpubkey", $SSHPubKey)
        }
        if(![string]::IsNullOrEmpty($email)){
            $newObject.Add("email", $email)
        }
        if(![string]::IsNullOrEmpty($SecurePassword)){
                $Cred = (New-Object System.Management.Automation.PSCredential -ArgumentList "None", $SecurePassword)
                $newObject.Add("password", $Cred.GetNetworkCredential().Password)
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
    $result = Invoke-RestMethodOnFreeNAS -Method PUT -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken -Body $body

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
        [switch]$KeepPrimaryGroup,
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
    $ApiSubPath = "/user/id/$Id"
    
    # Création de l'objet
    $newObject = @{
    }

    #region Ajout des paramètres supplémentaires
        if($KeepPrimaryGroup.IsPresent){
            $newObject.Add("delete_group", $false)
        }else {
            $newObject.Add("delete_group", $true)
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method DELETE -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken -Body $body

    return $result
}

function Get-TrueNasGroup {
    
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
function New-TrueNasGroup {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [String]$APIToken,
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [Parameter(Mandatory = $false)]
        [switch]$SambaGroup,
        [Parameter(Mandatory = $false)]
        [switch]$PermitSudo,
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
    
    # Création de l'objet
    $newObject = @{
        name = $GroupName;
    }

    #region Ajout des paramètres supplémentaires
        if($SambaGroup.IsPresent){
            $newObject.Add("smb", $true)
        }else {
            $newObject.Add("smb", $false)
        }
        if($PermitSudo.IsPresent){
            $newObject.Add("sudo", $true)
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken -Body $body

    return $result
}

function Set-TrueNasGroup {
    
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
        [string]$GroupName,
        [Parameter(Mandatory = $false)]
        [switch]$SambaGroup,
        [Parameter(Mandatory = $false)]
        [switch]$PermitSudo,
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
    $ApiSubPath = "/group/id/$Id"
    
    # Création de l'objet
    $newObject = @{
    }

    #region Ajout des paramètres supplémentaires
        if(![string]::IsNullOrEmpty($GroupName)){
            $newObject.Add("name", $GroupName)
        }
        if($SambaGroup.IsPresent){
            $newObject.Add("smb", $true)
        }else {
            $newObject.Add("smb", $false)
        }
        if($PermitSudo.IsPresent){
            $newObject.Add("sudo", $true)
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method PUT -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken -Body $body

    return $result
}

function Remove-TrueNasGroup {
    
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
        [switch]$RemoveUsersIfPrimaryGroup,
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
    $ApiSubPath = "/group/id/$Id"
    
    # Création de l'objet
    $newObject = @{
    }

    #region Ajout des paramètres supplémentaires
        if($RemoveUsersIfPrimaryGroup.IsPresent){
            $newObject.Add("delete_users", $true)
        }else {
            $newObject.Add("delete_users", $false)
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method DELETE -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken -Body $body

    return $result
}