<#
.SYNOPSIS
  Collect OEM BIOS verson information from HP, Dell and Lenovo based on querying Log Analytics for excisting models in your environment. 

.DESCRIPTION
  Collect OEM BIOS verson information from HP, Dell and Lenovo based on querying Log Analytics for excisting models in your environment. 
  This script is to run in Azure Automation - verfied on Powershell 5.1 and Powershell 7.1 

.NOTES
    Purpose/Change: Initial script development
    Author:      Jan Ketil Skanke & Maurice Daly
    Contact:     @JankeSkanke @Modaly_IT
    Created:     2020-10-11
    Updated:     2021-09-08
    Version history:
    1.0.0 - (2021-Nov-3) Initial version
    1.0.1 - (2021-Dec-01) Fixed issue with Dell BIOS version sorting and more than one entry pr SKU in OEMs XML file and catering for older format (ex: A15)
    1.0.2 - (2021-Dec-01) Fixed issue with missing HP BIOS info and improved version matching
.EXAMPLE
#>
#Requires -Modules 7Zip4Powershell, Az.Accounts, Az.OperationalInsights
#region Initialisations
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#endregion Initialisations
#Region Decalarations
#Define WorkspaceID
$WorkspaceID = Get-AutomationVariable -Name 'WorkspaceID'
$SharedKey = Get-AutomationVariable -Name 'WSSharedKey'
#Define Log Analytics Workspace Subscription ID
$SubscriptionID = Get-AutomationVariable -Name 'LASubscriptionID'
#Define OEM BIOS information Log Name
$BIOSLogType = "OEMBIOSInformation"
#Define Intune Custom Inventory Log Name
$InventoryLog = "DeviceInventory_CL"
# DO NOT DELETE TimeStampField - IT WILL BREAK LA Injection
$TimeStampField = "" 
#EndRegion Declarations 

#region functions
Function New-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
    return $authorization
}#endfunction
Function Send-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = New-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    
    #validate that payload data does not exceed limits
    if ($body.Length -gt (31.9 *1024*1024))
    {
        throw("Upload payload is too big and exceed the 32Mb limit for a single upload. Please reduce the payload size. Current payload size is: " + ($body.Length/1024/1024).ToString("#.#") + "Mb")
    }

    $payloadsize = ("Upload payload size is " + ($body.Length/1024).ToString("#.#") + "Kb ")
    
    $headers = @{
        "Authorization"        = $signature;
        "Log-Type"             = $logType;
        "x-ms-date"            = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing 
    $statusmessage = "$($response.StatusCode) : $($payloadsize)"
    return $statusmessage 
}#endfunction
function Get-XMLData ($XMLUrl) {
    $xml = New-Object xml
    $resolver = New-Object -TypeName System.Xml.XmlUrlResolver
    $resolver.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    $reader = New-Object -TypeName System.Xml.XmlReaderSettings
    $reader.XmlResolver = $resolver
    $reader = [System.Xml.XmlReader]::Create($XMLUrl, $reader) 
    $xml.Load($reader)
    [xml]$response = $xml
    return $response
}#endfunction
#endregion functions

#region script
#Connecting Using Managed Service Identity with defined subscription
$Connecting = Connect-AzAccount -Identity -Subscription $SubscriptionID

#region Dell
#Query Log Analytics for models in Intune Inventory
$DellSystemSKUsQuery = "$($InventoryLog) | where Manufacturer_s contains `"Dell`" | distinct SystemSKU_s"
$DellSystemSKUs = Invoke-AZOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $DellSystemSKUsQuery
#Query OEM, Process and inject to LA
Invoke-WebRequest -Uri "https://downloads.dell.com/catalog/CatalogPC.cab" -OutFile (Join-Path -Path $env:TEMP -ChildPath "CatalogPC.cab")
if (Test-Path -Path (Join-Path -Path $env:TEMP -ChildPath "CatalogPC.xml")){
    Remove-Item (Join-Path -Path $env:TEMP -ChildPath "CatalogPC.xml")
    }
Expand-7Zip -ArchiveFileName (Join-Path -Path $env:TEMP -ChildPath "CatalogPC.cab") -TargetPath $env:TEMP 
[xml]$DellBIOSXML = Get-Content -Path (Join-Path -Path $env:TEMP -ChildPath "CatalogPC.xml")
foreach($SKU in $DellSystemSKUs.Results.SystemSKU_s){
    if (-not([string]::IsNullOrEmpty($Sku))){
        $AllBIOSVersions = ($DellBiosXML.Manifest.SoftwareComponent | Where-Object {($_.name.display."#cdata-section" -match "BIOS") -and ($_.SupportedSystems.Brand.Model.SystemID -match $SKU)}).vendorVersion
        Write-Verbose "Testing $($AllBIOSVersions) on $($SKU)"
        $VersionBIOSVersion = @()
        if ($AllBIOSVersions -match "[a-zA-Z][0-9]{2}"){
            Write-Verbose "Using older BIOS version format $($AllBIOSVersions)"
            $DellBIOSLatest = $DellBiosXML.Manifest.SoftwareComponent | Where-Object {($_.name.display."#cdata-section" -match "BIOS") -and ($_.SupportedSystems.Brand.Model.SystemID -match $SKU)} | Sort-Object -Property vendorVersion -Descending | Select-Object -First 1            
        } 
        else {
            foreach ($BIOSVersion in $AllBIOSVersions){   
                [Version]$BIOSVersion = $BIOSVersion
                $VersionBIOSVersion += $BIOSVersion
            }
            $VersionBIOSVersionLatest = $VersionBIOSVersion | Sort-Object -Descending | Select-Object -First 1
            $DellBIOSLatest = $DellBiosXML.Manifest.SoftwareComponent | Where-Object {($_.name.display."#cdata-section" -match "BIOS") -and ($_.SupportedSystems.Brand.Model.SystemID -match $SKU)} | Where-Object {[Version]$_.vendorVersion -match $VersionBIOSVersionLatest}
        }
        $CurrentDellBIOSVersion = $DellBIOSLatest.dellVersion
        [DateTime]$CurrentDellBIOSDate = $DellBIOSLatest.releaseDate
        #Write-Output "SKU:$($sku),Version:$($BiosLatest.ver),Date:$($BiosLatest.date)"
        $BIOSInventory = New-Object System.Object
        $BIOSInventory | Add-Member -MemberType NoteProperty -Name "SKU" -Value "$SKU" -Force   
        $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEMVersion" -Value "$CurrentDellBIOSVersion" -Force   
        $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEMDate" -Value "$CurrentDellBIOSDate" -Force      
        $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEM" -Value "Dell" -Force  
        $BIOSJson = $BIOSInventory | ConvertTo-Json
        #write-output $BIOSJson
        try {
            $ResponseBIOSInventory = Send-LogAnalyticsData -customerId $WorkspaceID -sharedKey $SharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($BIOSJson)) -logType $BIOSLogType -ErrorAction Stop
            Write-Output "BIOS Information injected for SKU $($SKU)"
        } catch {
            $ResponseBIOSInventory = "Error Code: $($_.Exception.Response.StatusCode.value__)"
            $ResponseBIOSMessage = $_.Exception.Message
            Write-Output "Error $($ResponseBIOSInventory), Message $($ResponseBIOSMessage)"
        }
    }      
}
#endregion Dell

#region HP
#Query Log Analytics for models in Intune Inventory
$HPSystemSKUsQuery = "$($InventoryLog) | where Manufacturer_s contains `"HP`" or Manufacturer_s contains `"Hewlett`" | distinct SystemSKU_s"
$HPSystemSKUs = Invoke-AZOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $HPSystemSKUsQuery
# Fetching latest HP BIOS release info from HP
foreach($SKU in $HPSystemSKUs.Results.SystemSKU_s){
    if (-not([string]::IsNullOrEmpty($Sku))){
        $BIOSXML = $null
        try{
            $Request = Invoke-WebRequest -uri "https://ftp.ext.hp.com/pub/pcbios/$($SKU)/$($SKU).xml" 
            $URLStatus = $Request.StatusCode
         } catch{
            $URLStatus = $($_.Exception.Response.StatusCode.Value__)
            Write-Output "Unable to find BIOS Information from HP for SKU $($SKU) - Error $($URLStatus)"
         }
        
        if ($URLStatus -ne "404"){
            $BIOSXML = Get-XMLData -XMLUrl "https://ftp.ext.hp.com/pub/pcbios/$($SKU)/$($SKU).xml" 
            $AllHPBIOSVersions = $BIOSXML.BIOS.Rel
            
            $VersionHPBIOSVersion = @()
            foreach ($HPBIOSVersion in $AllHPBIOSVersions.ver){   
                [Version]$HPBIOSVersion = $HPBIOSVersion
                $VersionHPBIOSVersion += $HPBIOSVersion
            }
            $VersionHPBIOSVersionLatest = ($VersionHPBIOSVersion | Sort-Object -Descending | Select-Object -First 1)#.ToString()
            $BIOSLatest = $BIOSXML.BIOS.Rel | Where-Object {[Version]$_.Ver -match $VersionHPBIOSVersionLatest}
            $CurrentBIOSVersion = $BIOSLatest.ver
            [DateTime]$CurrentBIOSDate = $BIOSLatest.date
            
            #Write-Output "SKU:$($sku),Version:$($BiosLatest.ver),Date:$($BiosLatest.date)"
            $BIOSInventory = New-Object System.Object
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "SKU" -Value "$SKU" -Force   
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEMVersion" -Value "$CurrentBIOSVersion" -Force   
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEMDate" -Value "$CurrentBIOSDate" -Force 
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEM" -Value "HP" -Force             
            $BIOSJson = $BIOSInventory | ConvertTo-Json
            #write-output $BIOSJson
        }
        else{
            $BIOSInventory = New-Object System.Object
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "SKU" -Value "$SKU" -Force   
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEMVersion" -Value "NA" -Force   
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEMDate" -Value "NA" -Force       
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEM" -Value "HP" -Force       
            $BIOSJson = $BIOSInventory | ConvertTo-Json
        }    
        try {
            $ResponseBIOSInventory = Send-LogAnalyticsData -customerId $WorkspaceID -sharedKey $SharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($BIOSJson)) -logType $BIOSLogType -ErrorAction Stop
            Write-Output "BIOS Information injected for SKU $($SKU)"
        } catch {
            $ResponseBIOSInventory = "Error Code: $($_.Exception.Response.StatusCode.value__)"
            $ResponseBIOSMessage = $_.Exception.Message
            Write-Output "Error $($ResponseBIOSInventory), Message $($ResponseBIOSMessage)"
        }        
    }
}
#endregion HP

#region Lenovo
#Query Log Analytics for models in Intune Inventory
$LenovoSystemSKUsQuery = "$($InventoryLog) | where Manufacturer_s contains `"Lenovo`" | distinct SystemSKU_s"
$LenovoSystemSKUs = Invoke-AZOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $LenovoSystemSKUsQuery
# Fetching latest Lenovo BIOS release info
# Define Lenovo Download Sources
$LenovoBiosBase = "https://download.lenovo.com/catalog/"
foreach($SKU in $LenovoSystemSKUs.Results.SystemSKU_s){
    if (-not([string]::IsNullOrEmpty($Sku))){
        Write-Output "Trying Lenovo $SKU"
        try{
            $Request = Invoke-WebRequest -uri ($LenovoBiosBase + "$SKU" + "_Win10.xml")
            $URLStatus = $Request.StatusCode
         } catch{
            $URLStatus = $($_.Exception.Response.StatusCode.Value__)
            Write-Output "Unable to find BIOS Information from Lenovo for SKU $($SKU) - Error $($URLStatus)"
         }
        if ($URLStatus -ne "404"){
        [xml]$ValidBIOSLocationXML = Get-XMLData -XMLUrl ($LenovoBiosBase + "$SKU" + "_Win10.xml")
        $LenovoModelBIOSInfo = $ValidBIOSLocationXML.Packages.Package | Where-Object {$_.Category -match "BIOS" } | Sort-Object Location -Descending | Select-Object -First 1
            $LenovoBIOSLocationInfo = $LenovoModelBIOSInfo.location
            $LatestOEMBIOSInfo = (Get-XMLData -XMLUrl $LenovoBIOSLocationInfo).Package

            $CurrentBIOSVersion = $LatestOEMBIOSInfo.version
            [DateTime]$CurrentBIOSDate = $LatestOEMBIOSInfo.ReleaseDate
            
            #Write-Output "SKU:$($sku),Version:$($BiosLatest.ver),Date:$($BiosLatest.date)"
                $BIOSInventory = New-Object System.Object
                $BIOSInventory | Add-Member -MemberType NoteProperty -Name "SKU" -Value "$SKU" -Force   
                $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEMVersion" -Value "$CurrentBIOSVersion" -Force   
                $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEMDate" -Value "$CurrentBIOSDate" -Force  
                $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEM" -Value "Lenovo" -Force       
                $BIOSJson = $BIOSInventory | ConvertTo-Json
        }
        else {
            $BIOSInventory = New-Object System.Object
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "SKU" -Value "$SKU" -Force   
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEMVersion" -Value "NA" -Force   
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEMDate" -Value "NA" -Force       
            $BIOSInventory | Add-Member -MemberType NoteProperty -Name "OEM" -Value "Lenovo" -Force       
            $BIOSJson = $BIOSInventory | ConvertTo-Json
        }
        try {
            $ResponseBIOSInventory = Send-LogAnalyticsData -customerId $WorkspaceID -sharedKey $SharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($BIOSJson)) -logType $BIOSLogType -ErrorAction Stop
            Write-Output "BIOS Information injected for SKU $($SKU)"
        } catch {
            $ResponseBIOSInventory = "Error Code: $($_.Exception.Response.StatusCode.value__)"
            $ResponseBIOSMessage = $_.Exception.Message
            Write-Output "Error $($ResponseBIOSInventory), Message $($ResponseBIOSMessage)"
        }
        $ValidBIOSLocationXML = $null
        $URLStatus = $null
    }
}
#endregion Lenovo
#endregion Script