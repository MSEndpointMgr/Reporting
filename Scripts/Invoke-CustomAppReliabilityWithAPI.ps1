<#
.SYNOPSIS
Collect application reliability and upload to Log Analytics for further processing.

.DESCRIPTION
This script will audit reliability events and upload this to a Log Analytics Workspace. This allows you to easily search in device hardware and installed apps inventory.
The script is meant to be runned on a daily schedule either via Proactive Remediations (RECOMMENDED) in Intune or manually added as local schedule task on your Windows 10 Computer.

.EXAMPLE
Invoke-CustomAppReliabilityWithAPI.ps1 (Required to run as System or Administrator)

.NOTES
FileName:    Invoke-CustomAppReliabilityWithAPI.ps1
Author:      Maurice Daly
Contributor: Jan Ketil Skanke / Sandy Zeng
Contact:     @modaly_it
Created:     2022-01-05
Updated:     2022-20-05

Version history:
1.0.0 - (2022 - 01 - 05) Script created
#>

#region initialize
# Define your azure function URL: 
# Example 'https://<appname>.azurewebsites.net/api/<functioname>'

$AzureFunctionURL = "https://<YOUR FUNCTION APP URL>/api/LogCollectorAPI"

# Enable TLS 1.2 support 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Set Log Analytics Log Name
$AppReliabilityLogName = "AppReliability"
$Date = (Get-Date)
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
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
		if ($AzureADJoinInfoThumbprint -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
			$AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
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
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
		if ($AzureADJoinInfoThumbprint -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
			$AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
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
# Function to get all Installed Application
function Get-InstalledApplications() {
	param (
		[string]$UserSid
	)
	
	New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
	$regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
	$regpath += "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
	if (-not ([IntPtr]::Size -eq 4)) {
		$regpath += "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
		$regpath += "HKU:\$UserSid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
	}
	$propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallString'
	$Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, PSPath | Sort-Object DisplayName
	Remove-PSDrive -Name "HKU" | Out-Null
	Return $Apps
}
#endregion functions

#region script

#Get Common data for App and Device Inventory: 
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
$ComputerManufacturer = $ComputerInfo.Manufacturer

if ($ComputerManufacturer -match "HP|Hewlett-Packard") {
	$ComputerManufacturer = "HP"
}

#region APPRELIABILITY
if ($CollectAppReliability) {
	# Obtain reliability data
	$AppReliabilityInventory = @()
	$ReliabilityEvents = Get-CimInstance win32_ReliabilityRecords | Where-Object { $_.EventIdentifier -match "1000|1002" -and $_.TimeGenerated -ge (Get-Date).AddHours(-24) }
	
	# Loop and process reliability events
	foreach ($ReliabilityEvent in $ReliabilityEvents) {
		
		$ApplicationName = $ReliabilityEvent.ProductName
		$ReliabilityEventId = $ReliabilityEvent.EventIdentifier
		$ReliabilityEventType = $ReliabilityEvent.SourceName
		[datetime]$ReliabilityEventTime = $ReliabilityEvent.TimeGenerated
		
		$ApplicationPath = $ReliabilityEvent.InsertionStrings | Where-Object { $_ -like "*\$ApplicationName" } | Select-Object -Unique
		
		if (-not ([string]::IsNullOrEmpty($ApplicationPath)) -and (Test-Path -Path $ApplicationPath)) {
			$ApplicationDetails = Get-ItemProperty -Path $ApplicationPath
			
			# Get file siging details
			$ApplicationSigningDetails = Get-AuthenticodeSignature -FilePath $ApplicationDetails.FullName
			$ApplicationSigningCert = $ApplicationSigningDetails.SignerCertificate
			
			# Get application publisher details
			$ApplicationPublisher = $ApplicationDetails.VersionInfo | Select-Object -ExpandProperty CompanyName
			if ([string]::IsNullOrEmpty($ApplicationPublisher)) {
				$ApplicationPublisher = "Unknown"
			}
			
			# Get version information
			$ApplicationVersion = $ApplicationDetails.VersionInfo.FileVersionRaw
			if ([string]::IsNullOrEmpty($ApplicationVersion)) {
				$ApplicationVersion = "Unavailable"
			}
			
			# Get faulting module
			if ($ReliabilityEvent.Message -match "module name") {
				$ApplicationFaultingModule = ((($ReliabilityEvent.Message.Split(",")) | Where-Object { $_ -match "Faulting module name:" }).Split(":") | Select-Object -Last 1).Trim()
				$ApplicationFaultingModulePath = $($ReliabilityEvent.Message).Split() | Where-Object { $_ -like "*\$ApplicationFaultingModule" }
			} else {
				$ApplicationFaultingModule = $null
				$ApplicationFaultingModulePath = $null
			}
			
			# Create JSON to Upload to Log Analytics
			$ReliabilityEventPayload = New-Object System.Object
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "Application" -Value "$ApplicationName" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "EventType" -Value "$ReliabilityEventType" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "EventId" -Value "$ReliabilityEventId" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "ApplicationPublisher" -Value "$ApplicationPublisher" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "ApplicationPath" -Value "$ApplicationPath" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "ApplicationSignatureCert" -Value "$ApplicationSigningCert" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "ApplicationVersion" -Value "$ApplicationVersion" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "FaultingModule" -Value "$ApplicationFaultingModule" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "FaultingModulePath" -Value "$ApplicationFaultingModulePath" -Force
			$ReliabilityEventPayload | Add-Member -MemberType NoteProperty -Name "EventGenerated" -Value "$ReliabilityEventTime" -Force
			
			# Add event to array
			$AppReliabilityInventory += $ReliabilityEventPayload
		}
	}
}

#endregion APPRELIABILITY

#Randomize over 50 minutes to spread load on Azure Function - disabled on date of enrollment 
$JoinDate = Get-AzureADJoinDate
$DelayDate = $JoinDate.AddDays(1)
$CompareDate = ($DelayDate - $JoinDate)
if ($CompareDate.Days -ge 1) {
	Write-Output "Randomzing execution time"
	#$ExecuteInSeconds = (Get-Random -Maximum 3000 -Minimum 1)
	#Start-Sleep -Seconds $ExecuteInSeconds
}
#Start sending logs
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

$LogPayLoad = New-Object -TypeName PSObject
$LogPayLoad | Add-Member -NotePropertyMembers @{ $AppReliabilityLogName = $AppReliabilityInventory }

# Construct main payload to send to LogCollectorAPI
$MainPayLoad = [PSCustomObject]@{
	AzureADTenantID = $AzureADTenantID
	AzureADDeviceID = $AzureADDeviceID
	LogPayloads	    = $LogPayLoad
}

$MainPayLoadJson = $MainPayLoad | ConvertTo-Json -Depth 9

# Sending data to API
try {
	$ResponseInventory = Invoke-RestMethod $AzureFunctionURL -Method 'POST' -Headers $headers -Body $MainPayLoadJson
	$OutputMessage = $OutPutMessage + "Inventory:OK " + $ResponseInventory
} catch {
	$ResponseInventory = "Error Code: $($_.Exception.Response.StatusCode.value__)"
	$ResponseMessage = $_.Exception.Message
	$OutputMessage = $OutPutMessage + "Inventory:Fail " + $ResponseInventory + $ResponseMessage
}

# Check status and report to Proactive Remediations
if ($ResponseInventory -match "200") {
	$AppResponse = $ResponseInventory.Split(",") | Where-Object { $_ -match "App:" }
	$DeviceResponse = $ResponseInventory.Split(",") | Where-Object { $_ -match "Device:" }
	$AppReliabilityResponse = $ResponseInventory.Split(",") | Where-Object { $_ -match "AppReliability:" }
	if ($AppResponse -match "App:200") {
		
		$OutputMessage = $OutPutMessage + " AppReliability:OK " + $AppResponse
	} else {
		$OutputMessage = $OutPutMessage + " AppReliability:Fail " + $AppResponse
	}
	Write-Output $OutputMessage
	if (($DeviceResponse -notmatch "Device:200") -or ($AppResponse -notmatch "App:200")) {
		Exit 1
	} else {
		Exit 0
	}
} else {
	Write-Output "Error: $($ResponseInventory), Message: $($ResponseMessage)"
	Exit 1
}
#endregion script
