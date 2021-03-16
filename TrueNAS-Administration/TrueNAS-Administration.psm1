class TrueNasSession {
    # Properties
    [String] $Server
    [int] $Port
    [System.Object] $WebSession
    [bool] $SkipCertificateCheck
    [String] $ApiName
    [String] $Version

    # Constructor
    TrueNasSession ([String] $Server, [int] $Port, [System.Object] $WebSession, [bool] $SkipCertificateCheck, [String] $ApiName, [string] $Version) {
        $this.Server = $Server
        $this.Port = $Port
        $this.WebSession = $WebSession
        $this.SkipCertificateCheck = $SkipCertificateCheck
        $this.ApiName = $ApiName
        $this.Version = $Version
    }

    # Method
    [String] GetApiUri() {
       return [string]::Format("https://{0}:{1}/api/v2.0/", $this.Server, $this.Port)
    }

    # ToString Method
    [String] ToString() {
        return [string]::Format("{0} - {1} {2}", $this.getApiUri(), $this.ApiName, $this.Version)
    }
}

function Get-TrueNasSession {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Port=443,
        [Parameter(Mandatory = $true)]
        [String]$APIToken,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )

    
    $apiFullUri = [string]::Format("https://{0}:{1}/api/v2.0/", $Server, $Port)

    $params = @{
        Uri = $apiFullUri;
        Method = "Get";
        Headers = @{ "Authorization" = "Bearer " + $apiToken };
        SkipCertificateCheck = $SkipCertificateCheck.IsPresent;
        ContentType = "Application/Json";
        SessionVariable = "CurrentSession"
    }


    try {
        
        # Some specifications depending on Powershell version
        switch ($PSVersionTable.PSVersion.Major) {
            {$_ -le 5} {
                $params.Remove("SkipCertificateCheck")
                if ($SkipCertificateCheck.IsPresent) {
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                }
                break
            }

            Default {}
        }

        # API Connection
        $result = Invoke-RestMethod @params
        
    }
    catch {
        throw $_
    }
    
    
    Write-Verbose -Message "Connected to $apiFullUri - $($result.info.title) $($result.info.version)"
    $TrueNasSession = New-Object -TypeName TrueNasSession -ArgumentList @($Server, $Port, $CurrentSession, $SkipCertificateCheck, $result.info.title, $result.info.version)

    return $TrueNasSession
}

function Invoke-RestMethodOnFreeNAS {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$ApiSubPath,
        [Parameter(Mandatory = $false)]
        [String]$Body,
        [Parameter(Mandatory = $false)]
        [ValidateSet("GET", "PUT", "POST", "DELETE")]
        [String]$Method = "GET"
    )
    
    
    $ApiSubPath = $ApiSubPath -replace("^/","")
    $apiFullUri = [System.IO.Path]::Combine($TrueNasSession.GetApiUri(), $ApiSubPath)

    $params = @{
        Uri = $apiFullUri;
        SkipCertificateCheck = $TrueNasSession.SkipCertificateCheck;
        Method = $Method;
        Body = $Body;
        WebSession = $TrueNasSession.WebSession
    }

    if([string]::IsNullOrEmpty($params.Body)) {
        $params.Remove("Body")
    }

    # Some specifications depending on Powershell version
    switch ($PSVersionTable.PSVersion.Major) {
        {$_ -le 5} {
            $params.Remove("SkipCertificateCheck")
            if ($Method -eq "Get" -and ![string]::IsNullOrEmpty($Body)) {
                $params.Remove("Body")
                Write-Warning -Message "Body parameters for GET are not supported on your version of Powershell. Powershell 7.1 minimum required."
            }

            if ($TrueNasSession.SkipCertificateCheck) {
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            }

            break
        }

        Default {}
    }

    
    $result = Invoke-RestMethod @params

    return $result
}

function Get-TrueNasState {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/system/state"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasActiveSession {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/auth/sessions"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Stop-TrueNas {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Delay
    )

    
    $ApiSubPath = "/system/shutdown"

    
    $newObject = @{
    }
    
    #region Adding additional parameters
        if($Delay -gt 0){
            $newObject.Add( "delay", $Delay )
        }
    #endregion
    
    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Restart-TrueNas {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Delay,
        [Parameter(Mandatory = $false)]
        [switch]$Wait
    )

    
    $ApiSubPath = "/system/reboot"

    
    $newObject = @{
    }
    
    #region Adding additional parameters
        if($Delay -gt 0){
            $newObject.Add( "delay", $Delay )
        }
    #endregion
    
    $body = $newObject | ConvertTo-Json

    
    Write-Verbose "$($TrueNasSession.Server) will restart in $Delay seconde(s)"
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath -ErrorAction Stop
    
    if($Wait.IsPresent){
        
        Start-Sleep -Seconds ($Delay + 5)
        while($curState -ne "READY"){
            
            try {
                $curState = Get-TrueNasState -TrueNasSession $TrueNasSession
            }
            catch {
                $curState = $_.Exception.Message
            }
            
            Write-Verbose "$($TrueNasSession.Server) state : $curState"
            Start-Sleep -Seconds 10
        }

    }

    return $result
}

function Get-TrueNasVersion {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/system/version"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasInfo {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/system/info"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasAlert {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/alert/list"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasAlertCategories {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/alert/list_categories"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasAlertPolicies {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/alert/list_policies"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Unregister-TrueNasAlert {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
         [Parameter(Mandatory = $true)]
        [string]$Id
    )

    
    $ApiSubPath = "/alert/dismiss"

    
    $newObject = $Id

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Restore-TrueNasAlert {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
         [Parameter(Mandatory = $true)]
        [string]$Id
    )

    
    $ApiSubPath = "/alert/restore"

    
    $newObject = $Id

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasDisk {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id
    )

    
    $ApiSubPath = "/disk"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }
    
    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasDiskTemperature {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    
    $ApiSubPath = "/disk/temperatures"

    
    $newObject = @{
        names = $Names
    }
    
    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasPool {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id
    )

    
    $ApiSubPath = "/pool"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasPoolAttachement {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [int]$Id
    )

    
    $ApiSubPath = "/pool/id/$id/attachments"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    

    return $result
}

function Get-TrueNasPoolProcess {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [int]$Id
    )
    
    
    $ApiSubPath = "/pool/id/$id/processes"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Get-TrueNasPoolDisk {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [int]$Id
    )

    
    $ApiSubPath = "/pool/id/$id/get_disks"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasDataset {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [string]$Id
    )

    $Id = $Id -replace("/","%2F")

    
    $ApiSubPath = "/pool/dataset"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

New-Alias -Name Get-TrueNasZvol -Value Get-TrueNasDataset -Force

function New-TrueNasDataset {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [ValidateSet("GENERIC", "SMB")]
        [string]$ShareType,
        [Parameter(Mandatory = $false)]
        [string]$Comments,
        [Parameter(Mandatory = $false)]
        [ValidateSet("PASSTHROUGH", "RESTRICTED")]
        [string]$AclMode,
        [Parameter(Mandatory = $false)]
        [switch]$ReadOnly
    )

    
    $ApiSubPath = "/pool/dataset"

    
    $newObject = @{
        type = "FILESYSTEM";
        name = $Name
    }

    #region Adding additional parameters
        if(![string]::IsNullOrEmpty($ShareType)){
            $newObject.Add("share_type", $ShareType)
        }
        if(![string]::IsNullOrEmpty($Comments)){
            $newObject.Add("comments", $Comments)
        }
        if(![string]::IsNullOrEmpty($AclMode)){
            $newObject.Add("aclmode", $AclMode)
        }
        if($ReadOnly.IsPresent){
            $newObject.Add("readonly", "ON")
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Set-TrueNasDataset {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [string]$Comments,
        [Parameter(Mandatory = $false)]
        [ValidateSet("PASSTHROUGH", "RESTRICTED")]
        [string]$AclMode,
        [Parameter(Mandatory = $false)]
        [ValidateSet("True", "False", "ON", "OFF")]
        [string]$ReadOnly
    )
    
    $Id = $Id -replace("/","%2F")

    
    $ApiSubPath = "/pool/dataset/id/$Id"

    switch ($ReadOnly) {
        "True" { $ReadOnly = "ON" }
        "False" { $ReadOnly = "OFF" }
    }

    
    $newObject = @{
    }

    #region Adding additional parameters
        if(![string]::IsNullOrEmpty($Comments)){
            $newObject.Add("comments", $Comments)
        }
        if(![string]::IsNullOrEmpty($AclMode)){
            $newObject.Add("aclmode", $AclMode)
        }
        if($ReadOnly -eq "ON"){
            $newObject.Add("readonly", "ON")
        }
        if($ReadOnly -eq "OFF"){
            $newObject.Add("readonly", "OFF")
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Put -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function New-TrueNasZvol {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [long]$VolumeSize,
        [Parameter(Mandatory = $false)]
        [string]$Comments,
        [Parameter(Mandatory = $false)]
        [switch]$ForceSize,
        [Parameter(Mandatory = $false)]
        [switch]$ReadOnly
    )

    
    $ApiSubPath = "/pool/dataset"

    
    $newObject = @{
        type = "VOLUME";
        name = $Name
        volsize = $VolumeSize
    }

    #region Adding additional parameters
        if(![string]::IsNullOrEmpty($Comments)){
            $newObject.Add("comments", $Comments)
        }
        if($ForceSize.IsPresent){
            $newObject.Add("force_size", $true)
        }
        if($ReadOnly.IsPresent){
            $newObject.Add("readonly", "ON")
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Set-TrueNasZvol {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$id,
        [Parameter(Mandatory = $false)]
        [long]$VolumeSize,
        [Parameter(Mandatory = $false)]
        [string]$Comments,
        [Parameter(Mandatory = $false)]
        [switch]$ForceSize
    )

    $Id = $Id -replace("/","%2F")

    
    $ApiSubPath = "/pool/dataset/id/$Id"

    
    $newObject = @{
    }

    #region Adding additional parameters
        if($VolumeSize -gt 0){
            $newObject.Add("volsize", $VolumeSize)
        }    
        if(![string]::IsNullOrEmpty($Comments)){
            $newObject.Add("comments", $Comments)
        }
        if($ForceSize.IsPresent){
            $newObject.Add("force_size", $true)
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Put -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Remove-TrueNasDataset {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$Recurse,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    $Id = $Id -replace("/","%2F")
    
    
    $ApiSubPath = "/pool/dataset/id/$Id"
    
    
    $newObject = @{
    }

    #region Adding additional parameters
        if($Recurse.IsPresent){
            $newObject.Add("recursive", $true)
        }
        if($Force.IsPresent){
            $newObject.Add("force", $true)
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Delete -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

New-Alias -Name Remove-TrueNasZvol -Value Remove-TrueNasDataset -Force


function Get-TrueNasDatasetAttachment {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    $Id = $Id -replace("/","%2F")

    
    $ApiSubPath = "/pool/dataset"
    $ApiSubPath += "/id/" + $Id + "/attachments"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasDatasetProcess {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    $Id = $Id -replace("/","%2F")

    
    $ApiSubPath = "/pool/dataset"
    $ApiSubPath += "/id/" + $Id + "/processes"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasSnapshot {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [ValidateSet("id", "name", "pool", "type", "properties", "holds", "dataset", "snapshot_name", "mountpoint")]
        [string]$OrderBy,
        [Parameter(Mandatory = $false)]
        [ValidateSet("id", "name", "pool", "type", "properties", "holds", "dataset", "snapshot_name", "mountpoint")]
        [string[]]$Select
    )

    $Id = $Id -replace("/","%2F")
    $ApiSubPath = "/zfs/snapshot"
    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }
    
    $newObject = @{
        "query-filters" = @();
        "query-options" = @{};
    }

    #region Adding additional parameters
        if(![string]::IsNullOrEmpty($OrderBy)){
            $newObject.'query-options'.Add( "order_by", @($OrderBy.ToLower()) )
        }
        if(![string]::IsNullOrEmpty($Select)){
            $newObject.'query-options'.Add( "select", @($Select.ToLower()) )
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function New-TrueNasSnapshot {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Dataset,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$AddDateToSnapshotName,
        [Parameter(Mandatory = $false)]
        [switch]$Recurse
    )

    
    $ApiSubPath = "/zfs/snapshot"
    
    $newObject = @{
        "dataset" = $Dataset;
        "name" = $Name;
    }

    #region Adding additional parameters
        if ($AddDateToSnapshotName.IsPresent) {
            $newObject.Remove("name")
            $newObject.Add("naming_schema", $($Name + "-%Y-%m-%d_%H-%M"))
        }
        if ($Recurse.IsPresent) {
            $newObject.Add("recursive", $true)
        } 
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Remove-TrueNasSnapshot {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$Defer
    )

    $Id = $Id -replace("/","%2F")
    $ApiSubPath = "/zfs/snapshot/id/$Id"
    
    $newObject = @{
    }

    #region Adding additional parameters
        if ($Defer.IsPresent) {
            $newObject.Add("defer", $true)
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Delete -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function New-TrueNasSnapshotClone {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Snapshot,
        [Parameter(Mandatory = $false)]
        [string]$Destination
    )

    # $Destination = $Destination -replace("/","%2F") # Destination is not in the URI, so this line is useless
    $ApiSubPath = "/zfs/snapshot/clone"
    
    $newObject = @{
        snapshot = $Snapshot;
        dataset_dst = $Destination;
    }

    #region Adding additional parameters

    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Invoke-TrueNasSnapshotRollback {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$RemoveNewerSnapshots,
        [Parameter(Mandatory = $false)]
        [switch]$RemoveNewerSnapshotsAndClones,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if ($RemoveNewerSnapshots.IsPresent -and $RemoveNewerSnapshotsAndClones.IsPresent) {
        throw "-RemoveNewerSnapshots and -RemoveNewerSnapshotsAndClones cannot be used in the same command line."
    }

    #$Id = $Id -replace("/","%2F") # Id is not in the URI, so this line is useless
    $ApiSubPath = "/zfs/snapshot/rollback"
    
    $newObject = @{
        id = $Id;
        options = @{};
    }

    #region Adding additional parameters
        if($RemoveNewerSnapshots.IsPresent) {
            $newObject.options.Add("recursive", $true)
        }
        if($RemoveNewerSnapshotsAndClones.IsPresent) {
            $newObject.options.Add("recursive_clones", $true)
        }
        if($Force.IsPresent) {
            $newObject.options.Add("force", $true)
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

New-Alias -Name Restore-TrueNasSnapshot -Value Invoke-TrueNasSnapshotRollback -Force

function Get-TrueNasChildItem {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [ValidateSet("name", "path", "realpath", "type", "size", "mode", "acl", "uid", "gid")]
        [string]$OrderBy,
        [Parameter(Mandatory = $false)]
        [ValidateSet("name", "path", "realpath", "type", "size", "mode", "acl", "uid", "gid")]
        [string[]]$Select
    )

    
    $ApiSubPath = "/filesystem/listdir"

    
    $newObject = @{
        path = $Path;
        "query-filters" = @();
        "query-options" = @{};
    }

    #region Adding additional parameters
        if(![string]::IsNullOrEmpty($OrderBy)){
            $newObject.'query-options'.Add( "order_by", @($OrderBy.ToLower()) )
        }
        if(![string]::IsNullOrEmpty($Select)){
            $newObject.'query-options'.Add( "select", @($Select.ToLower()) )
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasPathAcl {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [switch]$Simplified
    )

    
    $ApiSubPath = "/filesystem/getacl"

    
    $newObject = @{
        path = $Path
    }

    #region Adding additional parameters
        if($Simplified.IsPresent){
            $newObject.Add( "simplified", $true )
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Set-TrueNasPathAcl {
    # TODO
}

function Set-TrueNasPathPerm {
    # TODO UNIX Permissions
}

function Set-TrueNasPathOwner {
    # TODO
}

function Get-TrueNasService {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id
    )

    
    $ApiSubPath = "/service"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Set-TrueNasService {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$EnableAtStartup,
        [Parameter(Mandatory = $false)]
        [switch]$DisableAtStartup
    )

    if($EnableAtStartup.IsPresent -and $DisableAtStartup.IsPresent){
        throw "-EnableAtStartup and -DisableAtStartup cannot be used in the same command line."
    }

    
    $ApiSubPath += "/service/id/$Id"

     
     $newObject = @{
    }

    #region Adding additional parameters
        if($EnableAtStartup.IsPresent) {
            $newObject.Add("enable", $true)
        }
        if($DisableAtStartup.IsPresent) {
            $newObject.Add("enable", $false)
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Put -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Enable-TrueNasService {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [int]$Id
    )

    return (Set-TrueNasService -TrueNasSession $TrueNasSession -Id $Id -EnableAtStartup)
}

function Disable-TrueNasService {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [int]$Id
    )

    return (Set-TrueNasService -TrueNasSession $TrueNasSession -Id $Id -DisableAtStartup)
}

function Start-TrueNasService {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [Parameter(Mandatory = $false)]
        [switch]$HaPropagate
    )

    
    $ApiSubPath += "/service/start"

     
     $newObject = @{
        service = $ServiceName
    }

    #region Adding additional parameters
        if($HaPropagate.IsPresent) {
            $newObject.Add(
                "service-control",
                @{ ha_propagate = $true }
            )
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Stop-TrueNasService {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [Parameter(Mandatory = $false)]
        [switch]$HaPropagate
    )

    
    $ApiSubPath += "/service/stop"

     
     $newObject = @{
        service = $ServiceName
    }

    #region Adding additional parameters
        if($HaPropagate.IsPresent) {
            $newObject.Add(
                "service-control",
                @{ ha_propagate = $true }
            )
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Restart-TrueNasService {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [Parameter(Mandatory = $false)]
        [switch]$HaPropagate
    )

    
    $ApiSubPath += "/service/restart"

     
     $newObject = @{
        service = $ServiceName
    }

    #region Adding additional parameters
        if($HaPropagate.IsPresent) {
            $newObject.Add(
                "service-control",
                @{ ha_propagate = $true }
            )
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasSharing {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [ValidateSet("afp", "nfs", "smb", "webdav")]
        [string]$Type,
        [Parameter(Mandatory = $false)]
        [int]$Id
    )

    
    $Type = $Type.ToLower()
    $ApiSubPath = "/sharing/$Type"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasSMBConfig {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/smb"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Get-TrueNasSMBStatus {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/smb/status"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Get-TrueNasSSHConfig {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/ssh"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Get-TrueNasUpdate {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )
    
    
    $ApiSubPath = "/update/download"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasUpdateTrain {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/update/get_trains"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasUpdateAutoDownload {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/update/get_auto_download"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Set-TrueNasUpdateAutoDownload {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [bool]$Value
    )

    
    $ApiSubPath = "/update/set_auto_download"

    
    $newObject = $Value

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Enable-TrueNasUpdateAutoDownload {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    return Set-TrueNasUpdateAutoDownload -TrueNasSession $TrueNasSession -Value $true
}

function Disable-TrueNasUpdateAutoDownload {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    return Set-TrueNasUpdateAutoDownload -TrueNasSession $TrueNasSession -Value $false
}

function Get-TrueNasUpdateAvailable {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )
    
    
    $ApiSubPath = "/update/check_available"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

New-Alias -Name Get-TrueNasUpdateStatus -Value Get-TrueNasUpdateAvailable -Force

function Update-TrueNas {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [switch]$RestartAfter
    )
    
    
    $ApiSubPath = "/update/update"

    
    $newObject = @{
    }

    #region Adding additional parameters
        if($RestartAfter.IsPresent){
            $newObject.Add("reboot", $true)
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasGeneralConfig {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/system/general"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Restart-TrueNasWebUIService {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/system/general/ui_restart"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasNTPServer {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/system/ntpserver"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Get-TrueNasSystemDataset {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/systemdataset"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Get-TrueNasTunable {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    
    $ApiSubPath = "/tunable"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}



function Get-TrueNasAvailableShell {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )
    
    
    $ApiSubPath = "/user/shell_choices"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Get-TrueNasVM {

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [string]$Name
    )
    
    if ($Id -gt 0 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }

    $ApiSubPath = "/vm"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    if(![string]::IsNullOrEmpty($Name)) {
        $result =  $result | Where-Object { $_.Name -eq $Name }

        if($null -eq $result) {
            throw "VM $Name was not found."
        }
    }

    # Add properties state, pid and domain_state to parent objet for more readability
    foreach ($curItem in $result) {
        $curItem | Add-Member -MemberType NoteProperty -Name state -Value $curItem.status.state
        $curItem | Add-Member -MemberType NoteProperty -Name pid -Value $curItem.status.pid
        $curItem | Add-Member -MemberType NoteProperty -Name domain_state -Value $curItem.status.domain_state
    }
    
    return $result
}

function Start-TrueNasVM {

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    if ($Id -gt 0 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }
    
    # Get VM Id
    if(![string]::IsNullOrEmpty($Name)) {
        $Id =  (Get-TrueNasVM -TrueNasSession $TrueNasSession -Name $Name).Id

        if(($null -eq $Id) -and ($Id -eq 0)) {
            throw "VM $Name was not found."
        }
    }

    $ApiSubPath = "/vm/id/$id/start"

    
    $newObject = @{
    }

    #region Adding additional parameters
        if($Force.IsPresent){
            $newObject.Add( "overcommit", $true )
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Stop-TrueNasVM {

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    if ($Id -gt 0 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }
    
    # Get VM Id
    if(![string]::IsNullOrEmpty($Name)) {
        $Id =  (Get-TrueNasVM -TrueNasSession $TrueNasSession -Name $Name).Id

        if(($null -eq $Id) -and ($Id -eq 0)) {
            throw "VM $Name was not found."
        }
    }

    $ApiSubPath = "/vm/id/$id/stop"

    
    $newObject = @{
    }

    #region Adding additional parameters
        if($Force.IsPresent){
            $newObject.Add( "force", $true )
            $newObject.Add( "force_after_timeout", $true )
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Restart-TrueNasVM {

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [string]$Name
    )
    
    if ($Id -gt 0 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }
    
    # Get VM Id
    if(![string]::IsNullOrEmpty($Name)) {
        $Id =  (Get-TrueNasVM -TrueNasSession $TrueNasSession -Name $Name).Id

        if(($null -eq $Id) -and ($Id -eq 0)) {
            throw "VM $Name was not found."
        }
    }

    $ApiSubPath = "/vm/id/$id/restart"
    
    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Get-TrueNasVMCPUFlag {

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )
    
    
    $ApiSubPath = "/vm/flags"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Get-TrueNasVMMemoryUsage {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id
    )
    
    
    $ApiSubPath = "/vm/get_vmemory_in_use"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}

function Get-TrueNasVMDevices {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id
    )
    
    
    $ApiSubPath = "/vm/device"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }
    
    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}


function Get-TrueNasUser {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDSCache
    )
    
    
    $ApiSubPath = "/user"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    
    $newObject = @{
        "query-filters" = @();
        "query-options" = @{};
    }

    #region Adding additional parameters
        if($IncludeDSCache.IsPresent){
            $newObject.'query-options'.Add( "extra", @{"search_dscache" = $true} )
        }
    #endregion

    $body = $newObject | ConvertTo-Json


    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    
    return $result
}
function New-TrueNasUser {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
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
        [string]$Shell
    )

    
    $ApiSubPath = "/user"
    
    
    $newObject = @{
        username = $Credential.UserName;
        group_create = $true;
        full_name = $FullName;
    }

    #region Adding additional parameters
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
    
    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Set-TrueNasUser {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
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
        [string]$Shell
    )
    
    
    $ApiSubPath = "/user/id/$Id"
    
    
    $newObject = @{
    }

    #region Adding additional parameters
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
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Put -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Remove-TrueNasUser {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$KeepPrimaryGroup
    )
    
    
    $ApiSubPath = "/user/id/$Id"
    
    
    $newObject = @{
    }

    #region Adding additional parameters
        if($KeepPrimaryGroup.IsPresent){
            $newObject.Add("delete_group", $false)
        }else {
            $newObject.Add("delete_group", $true)
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Delete -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasGroup {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDSCache
    )
    
    
    $ApiSubPath = "/group"

    if ($Id) {
        $ApiSubPath += "/id/" + $Id
    }

    
    $newObject = @{
        "query-filters" = @();
        "query-options" = @{};
    }

    #region Adding additional parameters
        if($IncludeDSCache.IsPresent){
            $newObject.'query-options'.Add( "extra", @{"search_dscache" = $true} )
        }
    #endregion

    $body = $newObject | ConvertTo-Json


    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    

    return $result
}
function New-TrueNasGroup {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [Parameter(Mandatory = $false)]
        [switch]$SambaGroup,
        [Parameter(Mandatory = $false)]
        [switch]$PermitSudo
    )
    
    
    $ApiSubPath = "/group"
    
    
    $newObject = @{
        name = $GroupName;
    }

    #region Adding additional parameters
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
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Set-TrueNasGroup {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [string]$GroupName,
        [Parameter(Mandatory = $false)]
        [switch]$SambaGroup,
        [Parameter(Mandatory = $false)]
        [switch]$PermitSudo
    )
    
    
    $ApiSubPath = "/group/id/$Id"
    
    
    $newObject = @{
    }

    #region Adding additional parameters
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
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Put -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Remove-TrueNasGroup {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $false)]
        [switch]$RemoveUsersIfPrimaryGroup
    )
    
    
    $ApiSubPath = "/group/id/$Id"
    
    
    $newObject = @{
    }

    #region Adding additional parameters
        if($RemoveUsersIfPrimaryGroup.IsPresent){
            $newObject.Add("delete_users", $true)
        }else {
            $newObject.Add("delete_users", $false)
        }
    #endregion

    $body = $newObject | ConvertTo-Json
    

    
    $result = Invoke-RestMethodOnFreeNAS -Method Delete -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasActiveDirectoryConfig {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )
    
    
    $ApiSubPath = "/activedirectory"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasActiveDirectoryDomainInfo {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )
    
    
    $ApiSubPath = "/activedirectory/domain_info"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasActiveDirectoryServiceState {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )
    
    
    $ApiSubPath = "/activedirectory/get_state"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Test-TrueNasActiveDirectory {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )
    
    
    $ApiSubPath = "/activedirectory/started"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}