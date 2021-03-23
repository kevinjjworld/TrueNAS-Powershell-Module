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

    # 
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
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeExpired,
        [Parameter(Mandatory = $false)]
        [switch]$WithPoolName,
        [Parameter(Mandatory = $false)]
        [switch]$WithPasswords
    )

    if (![string]::IsNullOrEmpty($Id) -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }

    $ApiSubPath = "/disk"

    if (![string]::IsNullOrEmpty($Id)) {
        $ApiSubPath += "/id/" + $Id
    }
    
    $newObject = @{
        "query-filters" = @();
        "query-options" = @{ extra = @{} };
    }

    #region Adding additional parameters
        if($IncludeExpired.IsPresent){
            $newObject.'query-options'.extra.Add("include_expired", $true )
        }
        if($WithPoolName.IsPresent){
            $newObject.'query-options'.extra.Add("pools", $true )
        }
        if($WithPasswords.IsPresent){
            $newObject.'query-options'.extra.Add("passwords", $true )
        }
    #endregion

    $body = $newObject | ConvertTo-Json

    $result = Invoke-RestMethodOnFreeNAS -Method Get -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    if(![string]::IsNullOrEmpty($Name)) {
        if ($IgnoreCase.IsPresent) {
            $result =  $result | Where-Object { $_.name -like $Name }    
        }
        else {
            $result =  $result | Where-Object { $_.name -clike $Name }
        }

        if($null -eq $result) {
            throw "Disk $Name was not found."
        }
    }

    return $result
}

function Get-TrueNasDiskTemperature {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [string[]]$Names
    )

    if (![string]::IsNullOrEmpty($Name) -and $Names.Count -gt 0) {
        throw "-Name and -Names cannot be used in the same command line."
    }
    
    $ApiSubPath = "/disk/temperature"    

    if ($Names.Count -gt 0) {
        $ApiSubPath = "/disk/temperatures"
    }

    
    $newObject = @{
    }
    
    #region Adding additional parameters
        if(![string]::IsNullOrEmpty($Name)){
            $newObject.Add("name", $Name )
        }
        if($Names.Count -gt 0){
            $newObject.Add("names", $Names )
        }
    #endregion
    
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
        [int]$Id=-1,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$IgnoreCase
    )

    if ($Id -gt -1 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }
    
    $ApiSubPath = "/pool"

    if ($Id -gt -1) {
        $ApiSubPath += "/id/" + $Id
    }

    
    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    if(![string]::IsNullOrEmpty($Name)) {
        if ($IgnoreCase.IsPresent) {
            $result =  $result | Where-Object { $_.name -like $Name }    
        }
        else {
            $result =  $result | Where-Object { $_.name -clike $Name }
        }

        if($null -eq $result) {
            throw "Pool $Name was not found."
        }
    }

    return $result
}

function Get-TrueNasPoolAttachement {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [int]$Id=-1,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$IgnoreCase
    )

    if ($Id -gt -1 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }

    # Get Pool Id
    if(![string]::IsNullOrEmpty($Name)) {
        if($Name -match "\*") {
            throw "The * wildcard character is not allowed for this command line."
        }

        if($IgnoreCase.IsPresent) {
            $Pool = Get-TrueNasPool -TrueNasSession $TrueNasSession | Where-Object { $_.Name -like $Name }
        }
        else {
            $Pool = Get-TrueNasPool -TrueNasSession $TrueNasSession | Where-Object { $_.Name -clike $Name }
        }
        
        if($null -ne $Pool) {
            $Id = $Pool.id
        }
        else {
            throw "Pool $Name was not found."
        }
    }

    
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
        [Parameter(Mandatory = $false)]
        [int]$Id=-1,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$IgnoreCase
    )
    
    if ($Id -gt -1 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }

    # Get Pool Id
    if(![string]::IsNullOrEmpty($Name)) {
        if($Name -match "\*") {
            throw "The * wildcard character is not allowed for this command line."
        }

        if($IgnoreCase.IsPresent) {
            $Pool = Get-TrueNasPool -TrueNasSession $TrueNasSession | Where-Object { $_.Name -like $Name }
        }
        else {
            $Pool = Get-TrueNasPool -TrueNasSession $TrueNasSession | Where-Object { $_.Name -clike $Name }
        }
        
        if($null -ne $Pool) {
            $Id = $Pool.id
        }
        else {
            throw "Pool $Name was not found."
        }
    }

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

function Private_GetAllDatasets {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession
    )

    $ApiSubPath = "/pool/dataset"

    
    $newObject = @{
        "query-filters" = @();
        "query-options" = @{};
    }

    #region Adding additional parameters
        $newObject.'query-options'.Add( "extra", @{"flat" = $true} )
    #endregion
    
    $body = $newObject | ConvertTo-Json

    $result = Invoke-RestMethodOnFreeNAS -Method Get -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasDataset {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [Alias('Id')]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$Recurse,
        [Parameter(Mandatory = $false)]
        [switch]$IgnoreCase
    )

    $ApiSubPath = "/pool/dataset"

    
    if ($Name -notmatch "\*" -and !$IgnoreCase.IsPresent -and !$Recurse.IsPresent) {
        Write-Verbose "Fast - Call Api Path : $ApiSubPath"
        if ([string]::IsNullOrEmpty($Name)) {
            $newObject = @{
                "query-filters" = @();
                # 2021/03/23 - The query-options.extra.flat attribute don't work with "/pool/dataset/id/$Id"
                "query-options" = @{ extra = @{flat = $false} };
            }

            $body = $newObject | ConvertTo-Json
        }
        else {
            $ApiSubPath += "/id/" + $($Name -replace("/","%2F"))
        }

        $result =  Invoke-RestMethodOnFreeNAS -Method Get -Body $body -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath
    }
    else {
        Write-Verbose "Slow - Call Api Path : $ApiSubPath"
        $result = Private_GetAllDatasets -TrueNasSession $TrueNasSession

        if(![string]::IsNullOrEmpty($Name)) {
            if (!$Recurse.IsPresent) {
                $count = ($Name -split "\/").Count
                $parent = $((Split-Path $Name) -replace("\\","/") -replace("\/$",""))
                
                if(![string]::IsNullOrEmpty($parent) -and $parent -match "\*") {
                    $result = $result | Where-Object { $_.name -like $parent }
                }
                
                $result = $result | Where-Object { ($_.name -split "\/").Count -eq $count }
            }
        
            if ($IgnoreCase.IsPresent) {
                $result = $result | Where-Object { $_.name -like $Name }
            }
            else {
                $result = $result | Where-Object { $_.name -clike $Name }
            }
        }
    }

    return $result
}

New-Alias -Name Get-TrueNasZvol -Value Get-TrueNasDataset -Force

function Get-TrueNasDatasetChildren {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $true)]
        [Alias('Id')]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$Recurse,
        [Parameter(Mandatory = $false)]
        [switch]$IgnoreCase
    )
    
    
    if($Name -match "\*") {
        throw "The * wildcard character is not allowed for this command line."
    }

    if($Recurse.IsPresent) {
        $result = Get-TrueNasDataset -TrueNasSession $TrueNasSession -Name "$Name*" -Recurse -IgnoreCase:$IgnoreCase
    }
    else {
        $result = Get-TrueNasDataset -TrueNasSession $TrueNasSession -Name $Name -IgnoreCase:$IgnoreCase
        $result = $result.children
    }

    return $result
}

New-Alias -Name Get-TrueNasChildDataset -Value Get-TrueNasDatasetChildren -Force

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
        [Parameter(Mandatory = $false)]
        [Alias('Id')]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [string]$Comments,
        [Parameter(Mandatory = $false)]
        [ValidateSet("PASSTHROUGH", "RESTRICTED")]
        [string]$AclMode,
        [Parameter(Mandatory = $false)]
        [ValidateSet("True", "False", "ON", "OFF")]
        [string]$ReadOnly
    )
    
    $Name = $Name -replace("/","%2F")

    
    $ApiSubPath = "/pool/dataset/id/$Name"

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
        [Parameter(Mandatory = $false)]
        [Alias('Id')]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [long]$VolumeSize=-1,
        [Parameter(Mandatory = $false)]
        [string]$Comments,
        [Parameter(Mandatory = $false)]
        [switch]$ForceSize
    )

    $Name = $Name -replace("/","%2F")

    
    $ApiSubPath = "/pool/dataset/id/$Name"

    
    $newObject = @{
    }

    #region Adding additional parameters
        if($VolumeSize -gt -1){
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
        [Parameter(Mandatory = $false)]
        [Alias('Id')]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$Recurse,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    $Name = $Name -replace("/","%2F")
    
    $ApiSubPath = "/pool/dataset/id/$Name"
    
    
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
        [Parameter(Mandatory = $false)]
        [Alias('Id')]
        [string]$Name
    )

    $Name = $Name -replace("/","%2F")

    
    $ApiSubPath = "/pool/dataset"
    $ApiSubPath += "/id/" + $Name + "/attachments"

    
    $result = Invoke-RestMethodOnFreeNAS -Method Post -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    return $result
}

function Get-TrueNasDatasetProcess {
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [TrueNasSession]$TrueNasSession,
        [Parameter(Mandatory = $false)]
        [Alias('Id')]
        [string]$Name
    )

    $Name = $Name -replace("/","%2F")

    
    $ApiSubPath = "/pool/dataset"
    $ApiSubPath += "/id/" + $Name + "/processes"

    
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
        [Alias('Id')]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [string]$Dataset,
        [Parameter(Mandatory = $false)]
        [ValidateSet("id", "name", "pool", "type", "properties", "holds", "dataset", "snapshot_name", "mountpoint")]
        [string]$OrderBy,
        [Parameter(Mandatory = $false)]
        [ValidateSet("id", "name", "pool", "type", "properties", "holds", "dataset", "snapshot_name", "mountpoint")]
        [string[]]$Select
    )

    if (![string]::IsNullOrEmpty($Name) -and ![string]::IsNullOrEmpty($Dataset)) {
        throw "-Name and -Dataset cannot be used in the same command line."
    }

    $Name = $Name -replace("/","%2F")
    $ApiSubPath = "/zfs/snapshot"
    if (![string]::IsNullOrEmpty($Name)) {
        $ApiSubPath += "/id/" + $Name
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

    if (![string]::IsNullOrEmpty($Dataset)) {
        $result = $result | Where-Object { $_.dataset -like "$Dataset*" }
    }

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
        [int]$Id=-1
    )

    
    $ApiSubPath = "/service"

    if ($Id -gt -1) {
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
        [int]$Id=-1
    )

    
    $Type = $Type.ToLower()
    $ApiSubPath = "/sharing/$Type"

    if ($Id -gt -1) {
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
        [int]$Id=-1,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$IgnoreCase
    )
    
    if ($Id -gt -1 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }

    $ApiSubPath = "/vm"

    if ($Id -gt -1) {
        $ApiSubPath += "/id/" + $Id
    }

    $result = Invoke-RestMethodOnFreeNAS -Method Get -TrueNasSession $TrueNasSession -ApiSubPath $ApiSubPath

    if(![string]::IsNullOrEmpty($Name)) {

        if($IgnoreCase.IsPresent) {
            $result =  $result | Where-Object { $_.Name -like $Name }
        }
        else {
            $result =  $result | Where-Object { $_.Name -clike $Name }
        }
        
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
        [int]$Id=-1,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    if ($Id -gt -1 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }
    
    # Get VM Id
    if(![string]::IsNullOrEmpty($Name)) {
        if($Name -match "\*") {
            throw "The * wildcard character is not allowed for this command line."
        }

        $VM = Get-TrueNasVM -TrueNasSession $TrueNasSession | Where-Object { $_.Name -ceq $Name }
        
        if($null -ne $VM) {
            $Id = $VM.id
        }
        else {
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
        [int]$Id=-1,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    if ($Id -gt -1 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }
    
    # Get VM Id
    if(![string]::IsNullOrEmpty($Name)) {
        if($Name -match "\*") {
            throw "The * wildcard character is not allowed for this command line."
        }

        $VM = Get-TrueNasVM -TrueNasSession $TrueNasSession | Where-Object { $_.Name -ceq $Name }
        
        if($null -ne $VM) {
            $Id = $VM.id
        }
        else {
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
        [int]$Id=-1,
        [Parameter(Mandatory = $false)]
        [string]$Name
    )
    
    if ($Id -gt -1 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }
    
    # Get VM Id
    if(![string]::IsNullOrEmpty($Name)) {
        if($Name -match "\*") {
            throw "The * wildcard character is not allowed for this command line."
        }

        $VM = Get-TrueNasVM -TrueNasSession $TrueNasSession | Where-Object { $_.Name -ceq $Name }
        
        if($null -ne $VM) {
            $Id = $VM.id
        }
        else {
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
        [int]$Id=-1
    )
    
    
    $ApiSubPath = "/vm/device"

    if ($Id -gt -1) {
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
        [int]$Id=-1,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDSCache,
        [Parameter(Mandatory = $false)]
        [switch]$IgnoreCase
    )
    

    if ($Id -gt -1 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }

    $ApiSubPath = "/user"

    if ($Id -gt -1) {
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
    
    if(![string]::IsNullOrEmpty($Name)) {
        if ($IgnoreCase.IsPresent) {
            $result =  $result | Where-Object { $_.username -like $Name }    
        }
        else {
            $result =  $result | Where-Object { $_.username -clike $Name }
        }

        if($null -eq $result) {
            throw "User $Name was not found."
        }
    }

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
        [int]$Id=-1,
        [Parameter(Mandatory = $false)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDSCache,
        [Parameter(Mandatory = $false)]
        [switch]$IgnoreCase
    )
    
    if ($Id -gt -1 -and ![string]::IsNullOrEmpty($Name)) {
        throw "-Id and -Name cannot be used in the same command line."
    }
    
    $ApiSubPath = "/group"

    if ($Id -gt -1) {
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
    

    if(![string]::IsNullOrEmpty($Name)) {
        if ($IgnoreCase.IsPresent) {
            $result =  $result | Where-Object { $_.group -like $Name }    
        }
        else {
            $result =  $result | Where-Object { $_.group -clike $Name }
        }

        if($null -eq $result) {
            throw "User $Name was not found."
        }
    }

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


# Registers a custom argument completer for parameter "Name" without command line name but conditions in script block
Register-ArgumentCompleter -ParameterName Name -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

    switch -Regex ($commandName) {
        "^Get-TrueNasPool"
        {
            (Get-TrueNasPool -TrueNasSession $fakeBoundParameter.TrueNasSession -Name "$wordToComplete*").name
            break
        }
        "^Get-TrueNasDisk"
        {
            (Get-TrueNasDisk -TrueNasSession $fakeBoundParameter.TrueNasSession -Name "$wordToComplete*" -WarningAction SilentlyContinue).name
            break
        }
        "^Get-TrueNasDataset|^New-TrueNasDataset"
        {
            (Get-TrueNasDataset -TrueNasSession $fakeBoundParameter.TrueNasSession -Name "$wordToComplete*" -IgnoreCase -Recurse:$fakeBoundParameter.Recurse -WarningAction SilentlyContinue).name
            break
        }
        
        Default {}
    }

}

# Registers a custom argument completer for parameter "Name" without command line name but conditions in script block
Register-ArgumentCompleter -ParameterName Dataset -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

    switch -Regex ($commandName) {
        "^Get-TrueNasSnapshot|^New-TrueNasSnapshot"
        {
            (Get-TrueNasDataset -TrueNasSession $fakeBoundParameter.TrueNasSession -Name "$wordToComplete*" -IgnoreCase -Recurse:$fakeBoundParameter.Recurse -WarningAction SilentlyContinue).name
            break
        }
        
        Default {}
    }

}

Export-ModuleMember -Function "*-TrueNAS*" -Alias "*"
