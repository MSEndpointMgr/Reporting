<#
.SYNOPSIS
Collects Delivery Optimization settings and uploads to Log Analytics for further processing.

.DESCRIPTION
This script will collect Delivery Optimization settings from the local device and upload the data to an Azure Function for further processing. The script will check if the device is running a supported operating system version and if the Delivery Optimization registry key exists. If the registry key does not exist, the script will create the registry key and value. The script will then restart the Delivery Optimization service and exit with an exit code of 0 if successful.

.EXAMPLE
Invoke-DeliveryOptimizationDataGather.ps1 (Required to run as System or Administrator)

.PARAMETER 
Note the following variables 
$RandomiseCollectionInt - if this is true the randomizer to spread load over X minutes is enabled 
$RandomizeMinutes - the number of minutes to randomize load over. Max 50 minutes to avoid PR timeouts 

.NOTES
FileName:    Invoke-DeliveryOptimizationDataGather.ps1
Author:      Maurice Daly
Contributor: Sandy Zeng / Jan Ketil Skanke
Contact:     @MoDaly_IT 
Created:     30-05-2024
Updated:     30-05-2024 by @modaly_it

Version history:
1.0.0 - (30-05-2024) Script created
1.0.1 - (30-05-2024) Script updates
1.0.2 - (30-05-2024) Script updates
#>

#region initialize
# Define your azure function URL: 
# Example 'https://<appname>.azurewebsites.net/api/<functioname>'

$AzureFunctionURL = "YOURFUNCTIONURLHERE"

# Enable TLS 1.2 support 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Control if you want to collect (True = Collect)
$CollectDORegistrySettings = $true
$CollectDOPerfStats = $true
$CollectDOConfig = $true
$CollectDOMonthlyPerfStats = $true
$CollectDOContentStats = $false

#Set Log Analytics Log Name
$DORegistryLog = "DeliveryOptimizationSettings"
$DORegistryStatsLog = "DeliveryOptimizationPerfStats"
$DORegistryMonthlyStatsLog = "DeliveryOptimizationMonthlyPerfStats"
$DOConfigLog = "DeliveryOptimizationConfig"
$DOContentStatsLog = "DeliveryOptimizationContentStats"

$Date = (Get-Date)
# Enable or disable randomized running time to avoid azure function to be overloaded in larger environments 
# Set to true only if needed 
$RandomiseCollectionInt = $false
# Time to randomize over, max 50 minutes to avoid PR timeout. 
$RandomizeMinutes = 30

#endregion initialize

#region functions
# Function to get Azure AD DeviceID
function Get-AzureADDeviceID {
    <#
    .SYNOPSIS
        Get the Azure AD device ID from the local device.
    
    .DESCRIPTION
        Get the Azure AD device ID from the local device.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-05-26
        Updated:     2021-05-26
    
        Version history:
        1.0.0 - (2021-05-26) Function created
		1.0.1 - (2022-15.09) Updated to support CloudPC (Different method to find AzureAD DeviceID)
    #>
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoKey = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        if ($AzureADJoinInfoKey -ne $null) {
            # Retrieve the machine certificate based on thumbprint from registry key
            
            if ($AzureADJoinInfoKey -ne $null) {
                # Match key data against GUID regex
                if ([guid]::TryParse($AzureADJoinInfoKey, $([ref][guid]::Empty))) {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($AzureADJoinInfoKey)" }
                }
                else {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoKey }    
                }
            }
            if ($AzureADJoinCertificate -ne $null) {
                # Determine the device identifier from the subject name
                $AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
                # Handle return value
                return $AzureADDeviceID
            }
        }
    }
} #endfunction 
function Get-AzureADJoinDate {
    <#
    .SYNOPSIS
        Get the Azure AD Join Date from the local device.
    
    .DESCRIPTION
        Get the Azure AD Join Date from the local device.
    
    .NOTES
        Author:      Jan Ketil Skanke (and Nickolaj Andersen)
        Contact:     @JankeSkanke
        Created:     2021-05-26
        Updated:     2021-05-26
    
        Version history:
        1.0.0 - (2021-05-26) Function created
		1.0.1 - (2022-15.09) Updated to support CloudPC (Different method to find AzureAD DeviceID)
    #>
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoKey = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        if ($AzureADJoinInfoKey -ne $null) {
            # Retrieve the machine certificate based on thumbprint from registry key
            
            if ($AzureADJoinInfoKey -ne $null) {
                # Match key data against GUID regex
                if ([guid]::TryParse($AzureADJoinInfoKey, $([ref][guid]::Empty))) {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($AzureADJoinInfoKey)" }
                }
                else {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoKey }    
                }
            }
            if ($AzureADJoinCertificate -ne $null) {
                # Determine the device identifier from the subject name
                $AzureADJoinDate = ($AzureADJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
                # Handle return value
                return $AzureADJoinDate
            }
        }
    }
} #endfunction 
#Function to get AzureAD TenantID
function Get-AzureADTenantID {
    # Cloud Join information registry path
    $AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
    # Retrieve the child key name that is the tenant id for AzureAD
    $AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
    return $AzureADTenantID
}                          
#endregion functions

#region script
#region common
# ***** DO NOT EDIT IN THIS REGION *****
# Check if device is in "provisioning day" and skip inventory until next day if true
$JoinDate = Get-AzureADJoinDate
$DelayDate = $JoinDate.AddDays(1)
$CompareDate = ($Date - $DelayDate)
if ($CompareDate.TotalDays -ge 0){
	# Randomize over X minutes to spread load on Azure Function if enabled
	if ($RandomiseCollectionInt -eq $true){
		Write-Output "Randomzing execution time"
		$RandomizerSeconds = $RandomizeMinutes * 60
		$ExecuteInSeconds = (Get-Random -Maximum $RandomizerSeconds -Minimum 1)
		Start-Sleep -Seconds $ExecuteInSeconds
	}
} else {
	Write-Output "Device recently added, inventory not to be runned before $Delaydate"
    Exit 0  
}
 
#Get Intune DeviceID and ManagedDeviceName
if (@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
    $MSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq 'MS DM Server' }
    $ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)" -ErrorAction SilentlyContinue
}
$ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
$ManagedDeviceID = $ManagedDeviceInfo.EntDMID
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

#Get Computer Info
$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$ComputerName = $ComputerInfo.Name
#endregion common

#region DeliveryOptimizationSettings
if ($CollectDORegistrySettings) {
	
    #Get Delivery Optimization settings from registry
    $DOSettingsRegKey = "HKLM:\SOFTWARE\Microsoft\PolicyManager\Current\Device\DeliveryOptimization"
    $ExcludedProperties = "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSPath"
    $DOSettingsRegSettings = Get-Item -Path $DOSettingsRegKey -ErrorAction SilentlyContinue |  Get-ItemProperty -ErrorAction SilentlyContinue
    $DOSettings = $DOSettingsRegSettings.PSObject.Properties | Select-Object -Property Name, Value | Where-Object { $_.Name -notin $ExcludedProperties }
	
    # Create array for DO settings
    $DOSettingsArray = @()
    $DOSetting = New-Object -TypeName PSObject
    foreach ($Setting in $DOSettings) {
        try {
            $DOSetting | Add-Member -MemberType NoteProperty -Name "ManagedDeviceId" -Value "$ManagedDeviceId" -Force
            $DOSetting | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ComputerName" -Force
            $DOSetting | Add-Member -MemberType NoteProperty -Name "$($Setting.Name)" -Value "$($Setting.Value)" -Force
        }
        catch [System.Exception] {
            Write-Output "[Warning] - Unable to add $($App.DisplayName) to DO registry array. Error message: $($_.Exception.Message)"
        }
    }
    # Add to full settings array
    $DOSettingsArray += $DOSetting
	
    # Constuct object for reporting
    $DOSettingsOutput = $DOSettingsArray
}
#endregion DeliveryOptimizationSettings

#region DeliveryOptimizationPerfStats
if ($CollectDOPerfStats) {
	
    try {
        #Get Delivery Optimization performance stats
        $DOPerfSnapRawValues = Get-DeliveryOptimizationPerfSnap | Select-Object -Property *
        $ExcludedProperties = "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSPath"
        $DOPerfSnapValues = $DOPerfSnapRawValues.PSObject.Properties | Select-Object -Property Name, Value | Where-Object { $_.Name -notin $ExcludedProperties }

        # Create array for DO settings
        $DOPerfSnapArray = @()
        $DOPerfSnapEntry = New-Object -TypeName PSObject
        foreach ($Value in $DOPerfSnapValues) {
            try {
                $DOPerfSnapEntry | Add-Member -MemberType NoteProperty -Name "ManagedDeviceId" -Value "$ManagedDeviceId" -Force
                $DOPerfSnapEntry | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ComputerName" -Force
                $DOPerfSnapEntry | Add-Member -MemberType NoteProperty -Name "$($Value.Name)" -Value "$($Value.Value)" -Force
            }
            catch [System.Exception] {
                Write-Output "[Warning] - Unable to add $($App.DisplayName) to DO performance array. Error message: $($_.Exception.Message)"
            }
        }
        # Add to full settings array
        $DOPerfSnapArray += $DOPerfSnapEntry
	
        # Constuct object for reporting
        $DOPerfSnapOutput = $DOPerfSnapArray
    }
    catch {
        Write-Output "[Warning] - Unable to get Delivery Optimization performance stats. Error message: $($_.Exception.Message)"
    }
}
#endregion DeliveryOptimizationPerfStats

#region DeliveryOptimizationMonthlyPerfStats
if ($CollectDOMonthlyPerfStats) {
	
    try {
        #Get Delivery Optimization monthly performance stats
        $DOMonthlyPerfSnapRawValues = Get-DeliveryOptimizationPerfSnapThisMonth | Select-Object -Property *
        $ExcludedProperties = "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSPath"
        $DOMonthlyPerfSnapValues = $DOMonthlyPerfSnapRawValues.PSObject.Properties | Select-Object -Property Name, Value | Where-Object { $_.Name -notin $ExcludedProperties }

        # Create array for DO settings
        $DOMonthlyPerfSnapArray = @()
        $DOMonthlyPerfSnapEntry = New-Object -TypeName PSObject
        foreach ($Value in $DOMonthlyPerfSnapValues) {
            try {
                $DOMonthlyPerfSnapEntry | Add-Member -MemberType NoteProperty -Name "ManagedDeviceId" -Value "$ManagedDeviceId" -Force
                $DOMonthlyPerfSnapEntry | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ComputerName" -Force
                $DOMonthlyPerfSnapEntry | Add-Member -MemberType NoteProperty -Name "$($Value.Name)" -Value "$($Value.Value)" -Force
            }
            catch [System.Exception] {
                Write-Output "[Warning] - Unable to add $($App.DisplayName) to app array list. Error message: $($_.Exception.Message)"
            }
        }
        # Add to full settings array
        $DOMonthlyPerfSnapArray += $DOMonthlyPerfSnapEntry
	
        # Constuct object for reporting
        $DOMonthlyPerfSnapOutput = $DOMonthlyPerfSnapArray
    }
    catch {
        Write-Output "[Warning] - Unable to get Delivery Optimization performance stats. Error message: $($_.Exception.Message)"
    }
}
#endregion DeliveryOptimizationMonthlyPerfStats

#region DeliveryOptimizationConfig
if ($CollectDOConfig) {
	
    try {
        #Get Delivery Optimization performance stats
        $DOConfigRawValues = Get-DOConfig | Select-Object -Property *
        $ExcludedProperties = "PSParentPath", "PSChildName", "PSDrive", "PSProvider", "PSPath"
        $DOConfigValues = $DOConfigRawValues.PSObject.Properties | Select-Object -Property Name, Value | Where-Object { $_.Name -notin $ExcludedProperties }

        # Create array for DO settings
        $DOConfigArray = @()
        $DOConfigEntry = New-Object -TypeName PSObject
        foreach ($Value in $DOConfigValues) {
            try {
                $DOConfigEntry | Add-Member -MemberType NoteProperty -Name "ManagedDeviceId" -Value "$ManagedDeviceId" -Force
                $DOConfigEntry | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ComputerName" -Force
                $DOConfigEntry | Add-Member -MemberType NoteProperty -Name "$($Value.Name)" -Value "$($Value.Value)" -Force
            }
            catch [System.Exception] {
                Write-Output "[Warning] - Unable to add $($App.DisplayName) to DO config array. Error message: $($_.Exception.Message)"
            }
        }
        # Add to full settings array
        $DOConfigArray += $DOConfigEntry
	
        # Constuct object for reporting
        $DOConfigOutput = $DOConfigArray
    }
    catch {
        Write-Output "[Warning] - Unable to get Delivery Optimization configuration. Error message: $($_.Exception.Message)"
    }
}
#endregion DeliveryOptimizationConfig

#region DeliveryOptimizationStats
if ($CollectDOContentStats) {
	
    try {
        #Get Delivery Optimization performance stats
        $DOContentStatsRawValues = Get-DeliveryOptimizationStatus

        # Create array for DO settings
        $DOContentStatsArray = @()
        $DOContentStatEntry = New-Object -TypeName PSObject
        foreach ($Value in $DOContentStatsRawValues) {
            try {
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "ManagedDeviceId" -Value "$ManagedDeviceId" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ComputerName" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "FileId" -Value "$($Value.FileId)" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "Status" -Value "$($Value.Status)" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "SourceURL" -Value "$($Value.SourceURL)" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "DownloadMode" -Value "$($Value.DownloadMode)" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "CacheHost" -Value "$($Value.CacheHost)" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "NumPeers" -Value "$($Value.NumPeers)" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "ExpireOn" -Value "$($Value.ExpireOn)" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "Priority" -Value "$($Value.Priority)" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "DownloadDuration" -Value "$($Value.DownloadDuration)" -Force
                $DOContentStatEntry | Add-Member -MemberType NoteProperty -Name "PredefinedCallerApplication" -Value "$($Value.PredefinedCallerApplication)" -Force

                # Add to full settings array
                $DOContentStatsArray += $DOContentStatEntry
            }
            catch [System.Exception] {
                Write-Output "[Warning] - Unable to add $($App.DisplayName) to content stats array. Error message: $($_.Exception.Message)"
            }
        }
	
        # Constuct object for reporting
        $DOContentStatsOutput = $DOContentStatsArray
    }
    catch {
        Write-Output "[Warning] - Unable to get Delivery Optimization configuration. Error message: $($_.Exception.Message)"
    }
}
#endregion DeliveryOptimizationStats

#region compose
# Start composing logdata
# If additional logs is collected, remember to add to main payload 
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

# Adding every log payload into PSObject for main payload - Additional logs can be added 
$LogPayLoad = New-Object -TypeName PSObject 
if ($CollectDORegistrySettings) {
    $LogPayLoad | Add-Member -NotePropertyMembers @{$DORegistryLog = $DOSettingsOutput }
}
if ($CollectDOPerfStats) {
    $LogPayLoad | Add-Member -NotePropertyMembers @{$DORegistryStatsLog = $DOPerfSnapOutput }
}
if ($CollectDOMonthlyPerfStats) {
    $LogPayLoad | Add-Member -NotePropertyMembers @{$DORegistryMonthlyStatsLog = $DOMonthlyPerfSnapOutput }
}
if ($CollectDOConfig) {
    $LogPayLoad | Add-Member -NotePropertyMembers @{$DOConfigLog = $DOConfigOutput }
}
if ($CollectDOContentStats) {
    $LogPayLoad | Add-Member -NotePropertyMembers @{$DOContentStatslog = $DOContentStatsOutput }
}
 
# Construct main payload to send to LogCollectorAPI
$MainPayLoad = [PSCustomObject]@{
    AzureADTenantID = $AzureADTenantID
    AzureADDeviceID = $AzureADDeviceID
    LogPayloads     = $LogPayLoad
}
$MainPayLoadJson = $MainPayLoad | ConvertTo-Json -Depth 10	

#endregion compose

#region ingestion 
# NO NEED TO EDIT BELOW THIS LINE 
# Requires functionapp version 1.2 
# Set default exit code to 0 
$ExitCode = 0

# Attempt to send data to API
try {
    $ResponseInventory = Invoke-RestMethod $AzureFunctionURL -Method 'POST' -Headers $headers -Body $MainPayLoadJson
    foreach ($response in $ResponseInventory) {
        if ($response.response -match "200") {
            $OutputMessage = $OutPutMessage + "OK: $($response.logname) $($response.response) "
        }
        else {
            $OutputMessage = $OutPutMessage + "FAIL: $($response.logname) $($response.response) "
            $ExitCode = 1
        }
    }
} 
catch {
    $ResponseInventory = "Error Code: $($_.Exception.Response.StatusCode.value__)"
    $ResponseMessage = $_.Exception.Message
    $OutputMessage = $OutPutMessage + "Inventory:FAIL " + $ResponseInventory + $ResponseMessage
    $ExitCode = 1
}
# Exit script with correct output and code

Write-Output $OutputMessage
Exit $ExitCode																							
#endregion ingestion 

#endregion script