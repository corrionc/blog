+++
date = '2026-12-29T10:08:29-05:00'
draft = true
title = 'Cleaning SEoL dotnet Frameworks with Sysmon'
[build]
	list = 'always'
+++

A problem: We need to remove a great many unsupported .Net Core frameworks from  the fleet, but we have no idea what's using them.  And randomly breaking things isn't an option.

Starting with detection, we have 3 pieces:
1. A Sysmon config that detects dotnet dll loads and logs them to the eventlog.
2. A scheduled task that fires whenever a Sysmon event is created, which launches a Powershell script that logs the details of that event to a text file.
3. Finally, a way to collect all of those text files.

## Sysmon

The sysmon config needs to detect both 32 & 64-bit dll loads from the dotnet directories.  To do this, detect any loads that have dotnet\shared in the path.  The configuration will also detect usage of in-support frameworks.  This is okay, we'll filter this after collection.

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Detect" groupRelation="or">
      <ImageLoad onmatch="include">
      <!--Include images that match all of the conditions in this group-->
        <Rule groupRelation="or">
        <!--Only log images that are in the dotnet core directories-->
          <ImageLoaded condition="contains">dotnet\shared</ImageLoaded>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Package Sysmon & the eventlog creation script with your usual packaging tool.  If you don't have one, [PSAppDeployToolkit](https://psappdeploytoolkit.com/) is rather good.

## Scheduled Tasks
### SOME WORDS ABOUT SCHEDULED TASKS GOES HERE
This is the trigger of the scheduled task, firing whenever Event 7 (Image Loaded) occurs.  

```powershell
# Create Trigger via Sysmon Event 7
$CimSplat = @{
	ClassName = MSFT_TaskEventTrigger
	Namespace = Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger
}
$cimTriggerClass = Get-CimClass @CimSplat
$Trigger = New-CimInstance -CimClass $cimTriggerClass -ClientOnly

$qry = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=7)]]</Select>
  </Query>
</QueryList>
"@
```

Because Windows events are just XML, we can extract the individual fields out of the event and pass them to our function.  Practically speaking, that looks like this.

```powershell
$eventData = @{
	EventID          = 'Event/System/EventID'
    ComputerName     = 'Event/System/Computer'
    RuleName         = 'Event/EventData/Data[@Name="RuleName"]'
    UtcTime          = 'Event/EventData/Data[@Name="UTCTime"]'
    ProcessGuid      = 'Event/EventData/Data[@Name="ProcessGuid"]'
    ProcessId        = 'Event/EventData/Data[@Name="ProcessID"]'
    Image            = 'Event/EventData/Data[@Name="Image"]'
    ImageLoaded      = 'Event/EventData/Data[@Name="ImageLoaded"]'
    FileVersion      = 'Event/EventData/Data[@Name="FileVersion"]'
    Description      = 'Event/EventData/Data[@Name="Description"]'
    Product          = 'Event/EventData/Data[@Name="Product"]'
    Company          = 'Event/EventData/Data[@Name="Company"]'
    OriginalFileName = 'Event/EventData/Data[@Name="OriginalFileName"]'
    Hashes           = 'Event/EventData/Data[@Name="Hashes"]'
    Signed           = 'Event/EventData/Data[@Name="Signed"]'
    Signature        = 'Event/EventData/Data[@Name="Signature"]'
    SignatureStatus  = 'Event/EventData/Data[@Name="SignatureStatus"]'
    User             = 'Event/EventData/Data[@Name="User"]'
    }

    $data = $eventData.keys | ForEach-Object {
    [CimInstance]$cim = $(Get-CimClass -ClassName MSFT_TaskNamedValue -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskNamedValue)
    $cim.Name = $_
    $cim.value = $eventData["$_"]
    $cim
    }
    $Trigger.ValueQueries = $data
```




Finally, we have a Powershell script that logs the events.  It's a pretty straightforward function, logging all the bits of data out of the eventlog.  I ended up inventing my own logline format.  Be smarter than me, and log in CMTrace or json.

```powershell
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$EventID, 
        
    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$ComputerName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$RuleName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$UtcTime,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$ProcessGuid,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$ProcessId,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$Image,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$ImageLoaded,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$FileVersion,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$Description,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$Product,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$Company,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$OriginalFileName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$Hashes,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$Signed,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$Signature,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$SignatureStatus,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$User
)
    
$logLine = "$(Get-Date) - EventID: $EventID, ComputerName: $ComputerName, RuleName: $RuleName, UtcTime: $UtcTime, ProcessGuid: $ProcessGuid, ProcessId: $ProcessId, Image: $Image, ImageLoaded: $ImageLoaded, FileVersion: $FileVersion, Description: $Description, Product: $Product, Company: $Company, OriginalFileName: $OriginalFileName, Hashes: $Hashes, Signed: $Signed, Signature: $Signature, SignatureStatus: $SignatureStatus, User: $User"
Write-Output $logLine | Out-File C:\ProgramData\DotnetLog\dotnetEvents.log -Append
```

After this is deployed, wait a minute 

At a high level, we deployed Sysmon to every PC that had a dotnet runtime, with a configuration that detected dll loads from .net directories.  This was paired with a scheduled task that fired every time an event was written to the Sysmon log, converting it to a file.  

We then collected these events to a central location, and recorded what apps were using the outdated .net frameworks.  We made device collections for each app installed, and used those to exclude the the devices from the final removal collection.

Once we had accumulated enough usage data that we were confident that there were no surprise applications, we deployed the uninstaller.  The initial uninstaller used the dotnet uninstall tool, but this failed to actually remove things.  A second tool that used PSAppDeployToolkit to remove the runtimes worked much better.