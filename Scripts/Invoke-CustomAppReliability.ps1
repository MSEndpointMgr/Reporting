<#
.SYNOPSIS
    Collect custom application reliability monitor events and upload to Log Analytics for further processing. 

.DESCRIPTION
    This script will audit reliability events and upload this to a Log Analytics Workspace. This allows you to easily identify applications which are causing stability issues. 
    The script is meant to be runned on a daily schedule either via Proactive Remediations (RECOMMENDED) in Intune or manually added as local schedule task on your Windows 10 Computer. 

.EXAMPLE
    Invoke-CustomAppReliability.ps1.ps1(Required to run as System or Administrator)      

.NOTES
    FileName:    Invoke-CustomAppReliability.ps1
    Author:      Jan Ketil Skanke / Maurice Daly
    Contact:     @JankeSkanke / @MoDaly_IT
    Created:     2022-05-16
    Updated:     2022-05-16

    Version history:
    1.0.0 - (2022-05-16) Script created

#>
#region initialize
# Enable TLS 1.2 support 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Replace with your Log Analytics Workspace ID
$CustomerId = "<YOUR LOG ANALYTICS WORKSPACE ID>"

# Replace with your Primary Key
$SharedKey = "<YOUR PRIMARY KEY>"

# You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
# DO NOT DELETE THIS VARIABLE. Recommened keep this blank. 
$TimeStampField = ""

#endregion initialize

#region functions

# Function to create the authorization signature
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
}

# Function to create and post the request
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
	if ($body.Length -gt (31.9 * 1024 * 1024)) {
		throw ("Upload payload is too big and exceed the 32Mb limit for a single upload. Please reduce the payload size. Current payload size is: " + ($body.Length/1024/1024).ToString("#.#") + "Mb")
	}
	
	$payloadsize = ("Upload payload size is " + ($body.Length/1024).ToString("#.#") + "Kb ")
	
	$headers = @{
		"Authorization"	       = $signature;
		"Log-Type"			   = $logType;
		"x-ms-date"		       = $rfc1123date;
		"time-generated-field" = $TimeStampField;
	}
	
	$response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
	$statusmessage = "$($response.StatusCode) : $($payloadsize)"
	return $statusmessage
}

function Start-PowerShellSysNative {
	param (
		[parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the sysnative PowerShell process.")]
		[ValidateNotNull()]
		[string]$Arguments
	)
	
	# Get the sysnative path for powershell.exe
	$SysNativePowerShell = Join-Path -Path ($PSHOME.ToLower().Replace("syswow64", "sysnative")) -ChildPath "powershell.exe"
	
	# Construct new ProcessStartInfo object to run scriptblock in fresh process
	$ProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
	$ProcessStartInfo.FileName = $SysNativePowerShell
	$ProcessStartInfo.Arguments = $Arguments
	$ProcessStartInfo.RedirectStandardOutput = $true
	$ProcessStartInfo.RedirectStandardError = $true
	$ProcessStartInfo.UseShellExecute = $false
	$ProcessStartInfo.WindowStyle = "Hidden"
	$ProcessStartInfo.CreateNoWindow = $true
	
	# Instatiate the new 64-bit process
	$Process = [System.Diagnostics.Process]::Start($ProcessStartInfo)
	
	# Read standard error output to determine if the 64-bit script process somehow failed
	$ErrorOutput = $Process.StandardError.ReadToEnd()
	if ($ErrorOutput) {
		Write-Error -Message $ErrorOutput
	}
} #endfunction
#endregion functions

#region script

#Get Intune DeviceID and ManagedDeviceName
if (@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
	$MSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' }
	$ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)"
}
$ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
$ManagedDeviceID = $ManagedDeviceInfo.EntDMID

#Get ComputerName
$ComputerName = Get-ComputerInfo | Select-Object -ExpandProperty CsName

#region APPRELIABILITY

# Set Name of Log
$LogName = "AppReliability"

$ReliabilityPayload = @()
$ReliabilityEvents = Get-CimInstance win32_ReliabilityRecords | Where-Object { $_.EventIdentifier -match "1000|1002" -and $_.TimeGenerated -ge (Get-Date).AddHours(-24) }


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
		Write-Warning -Message "- $($ReliabilityEvent.Message)"
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
		$ReliabilityPayload += $ReliabilityEventPayload
	}
}

if ($ReliabilityEventPayload.Count -ge 1) {
	
	# Convert array data to JSON format
	$ReliabilityJson = $ReliabilityEventPayload | ConvertTo-Json
	
	# Submit the data to the API endpoint
	$ResponseAppReliability = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($ReliabilityJson)) -logType $LogName
}

#endregion APPRELIABILITY

#Report back status
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "

if ($ReliabilityEventPayload.Count -ge 1) {
	if ($ResponseAppReliability -match "200 :") {
		
		$OutputMessage = $OutPutMessage + "AppReliability:OK " + $ResponseAppReliability
	} else {
		$OutputMessage = $OutPutMessage + "AppReliability:Fail "
	}
} else {
	$OutputMessage = ""
}

Write-Output $OutputMessage
Exit 0

#endregion script
