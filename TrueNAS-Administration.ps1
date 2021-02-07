function Invoke-RestMethodOnFreeNAS
{
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
        [switch]$SkipCertificateCheck,
        [Parameter(Mandatory = $false)]
        [ValidateSet("GET", "PUT", "POST", "DELETE")]
        [String]$Method = "GET",
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $headers = @{ "Content-type" = "application/json"; "Authorization" = "Bearer " + $apiToken }
    [string]$apiBaseURI = "https://${Server}"
    if ($Port)
    {
        $apiBaseURI = "https://${Server}:${Port}"
    }
    [string]$apiRootPath = "/api/v2.0"

    $apiFullUri = $($apiBaseURI + $apiRootPath + $ApiSubPath)

    # Lancement de la requête
    $result = Invoke-RestMethod -Uri $apiFullUri -Method $Method -Headers $headers -SkipCertificateCheck:$SkipCertificateCheck

    return $result
}

function Get-TrueNasInfos
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/system/info"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasPools
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool"

    if ($Id)
    {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasPoolAttachements
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/id/$id/attachments"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasPoolProcesses
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/id/$id/processes"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasPoolDisks
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/id/$id/get_disks"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasPoolFileSystems
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/filesystem_choices"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasDatasets
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/dataset"

    if ($Id)
    {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasDatasetAttachments
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/dataset"
    $ApiSubPath += "/id/" + $Id + "/attachments"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasDatasetProcesses
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/pool/dataset"
    $ApiSubPath += "/id/" + $Id + "/processes"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasServices
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/service"

    if ($Id)
    {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasSharing
{
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
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/sharing/$Type"

    if ($Id)
    {
        $ApiSubPath += "/id/" + $Id
    }

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasSMBConfig
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/smb"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasSMBStatus
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/smb/status"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

function Get-TrueNasSSHConfig
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/ssh"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}
function Get-TrueNasUpdateTrains
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/update/get_trains"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method GET -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}
function Get-TrueNasUpdateStatus
{
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

    if (!$port)
    {
        $Port = 443
    }

    # Variables
    $ApiSubPath = "/update/check_available"

    # Lancement de la requête
    $result = Invoke-RestMethodOnFreeNAS -Method POST -Server $Server -Port $Port -SkipCertificateCheck:$SkipCertificateCheck -ApiSubPath $ApiSubPath -APIToken $APIToken
    

    return $result
}

