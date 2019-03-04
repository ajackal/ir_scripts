<#
.SYNOPSIS
Correltas Sysmon events to assist in threat hunting and incident response.
.PARAMETER StartTime
An optional parameter; defines how far back in history (in minutes) to correlate logs. Default is five (5) minutes.
.PARAMETER GeneratingEvent
An optional parameter; defines which event type generates an event for correlation. Default is Event ID 3, Network Connection Event
.PARAMETER CorrelatingEvent
An optional parameter; defines which event to correlate to the generating event. Default is Event ID 1, Process Creation Event.
.PARAMETER OutputFilePath
An optional parameter; defines the output file path to save the results. Default is "C:\temp\"
.PARAMETER OutputFileType
An optional parameter; defines the output file type. Options: JSON (default), TXT.
.EXAMPLE
CorrelateSysmonEvents.ps1 -StartTime 10 -GeneratingEvent 3 -CorrelatingEvent 1 -OutputFilePath "C:\temp\correlation_results"
.NOTES
.DESCRIPTION
This script retrieves Sysmon logs from the host and correlates the defined event types.
Default configuration will correlate Event ID 3 (Network Connection) with
Event ID 1 (Process Creation) with the purpose of identifying new processes that connect 
to the internet. With appropriate whitelisting in the Sysmon configuration this can be
high fidelity alerting. This behavior could indicate a reverse shell being launched and
connecting to Command and Control infrastructure (C2).

This script was inspired by the work done by Robert Rodriguez (@Cyb3rWard0g) of SpectreOps with his 3 part post "Real-Time Sysmon Processing via KSQL and HELK"

https://posts.specterops.io/real-time-sysmon-processing-via-ksql-and-helk-part-1-initial-integration-88c2b6eac839

Author: Chris Miller
Date Created: 20190115
Date Updated: 20190304

#>

Param(
        [DateTime]$StartTime = (Get-Date) - (New-TimeSpan -Minutes 5),
        [int]$GeneratingEvent = 3,
        [int]$CorrelatingEvent = 1,
        [string]$OutputFilePath = "C:\temp\",
        [string]$OutputFileType = "JSON"
)

Write-Host "Looking as far back as " $StartTime
Write-Host "Correlating Event ID " $GeneratingEvent "with Event ID " $CorrelatingEvent
Write-Host "Output file can be foud at: " $OutputFilePath

# The Message field in the event is a string by default. This parses the string into a PSObject
# which can then be searched and formatted into a JSON object.
function ParseMessageEvents($RawEvents)
{
    $ParsedEventsMessage = $RawEvents | Select-Object -Property Message | ForEach-Object{$_ -replace ": ", "= "} | ForEach-Object {$_ -replace "\\", "\\\\"} | ConvertFrom-StringData
    return $ParsedEventsMessage
}

function CreateUniqueEvents($ParsedMessages)
{
    $global:ProcessGuids = @($ParsedMessages.ProcessGuid | Select-Object -Unique)
    Write-Host "Number of unique generating events found: " $ProcessGuids.Count
    $ParsedMessages | ForEach-Object{$GeneratingEventsMessage += @{$_.ProcessGuid= $_}}
    return $GeneratingEventsMessage
}

# Gets Generating Events and creates a list of unique Process GUIDs.
function GetSysmonGeneratingEvents()
{
    try
    {
        $RawGeneratingEvents = Get-WinEvent -FilterHashTable @{
                                LogName = "Microsoft-Windows-Sysmon/Operational";
                                StartTime = $StartTime;
                                ID = $GeneratingEvent
                            }
    
    }
    catch [System.Exception]
    {
        Write-Error "No generating events found." -ErrorAction Stop
    }
    $ParsedGeneratingEventsMessage = ParseMessageEvents $RawGeneratingEvents
    return CreateUniqueEvents $ParsedGeneratingEventsMessage
    
}

function GetSysmonCorrelatingEvents()
{
    try
    {
        $RawCorrelatingEvents = Get-WinEvent -FilterHashTable @{
                                LogName = "Microsoft-Windows-Sysmon/Operational";
                                StartTime = $StartTime;
                                ID = $CorrelatingEvent
                            }
    
    }
    catch [System.Exception]
    {
        Write-Error "No Correlating events found." -ErrorAction Stop
    }

    $ParsedCorrelatingEventsMessage = ParseMessageEvents $RawCorrelatingEvents
    $ParsedCorrelatingEventsMessage | ForEach-Object{$ParsedCorrelatingEventsMessageIndex += @{$_.ProcessGuid= $_}}
    $ParsedCorrelatingEventsMessage | ForEach-Object{if($_.ProcessGuid -in $ProcessGuids){
            $ChildProcessGuid = $_.ProcessGuid
            $ParentProcessInfo = $_.ParentProcessGuid
            $ParentParentProcessGuid = $ParsedCorrelatingEventsMessageIndex.$ParentProcessInfo.ParentProcessGuid

            $EventTimeUtc = [DateTime]$_.UtcTime
            $PowerShellCorrelatingEvents = GetPowerShellCorrelatingEvents $EventTimeUtc

            $ChildProcessInfo = @{
                "ChildProcess" = $_;
                "ParentProcess" = $ParsedCorrelatingEventsMessageIndex.$ParentProcessInfo
                "ParentParentProcess" = $ParsedCorrelatingEventsMessageIndex.$ParentParentProcessGuid
                "PowerShellEvents" = $PowerShellCorrelatingEvents
            }
            $CorrelatedEvents += @{$ChildProcessGuid=$ChildProcessInfo}

        }
    }
    if ($CorrelatingEvents.Count -eq 0)
    {
        Write-Host "No correlating events found."
        exit(0)
    }
    else 
    {
        Write-Host "Number of correlating events found: " $CorrelatingEvents.Count
        return $CorrelatingEvents
    }
}

function GetPowerShellCorrelatingEvents($SysmonUtcTime)
{
    $TimeZone = Get-TimeZone
    $StartTimeLocal = $SysmonUtcTime + (New-TimeSpan -Hour $TimeZone.BaseUtcOffset.Hours)
    $EndTimeLocal = $StartTimeLocal + (New-TimeSpan -Minutes 2)
    try
    {
        $PSCorrelatingEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-PowerShell/Operational";
            StartTime = $StartTimeLocal;
            EndTime = $EndTimeLocal;
            ID = 4104
        }
        return $PSCorrelatingEvents
    }
    catch [System.Excpetion]
    {
        Write-Error "No PowerShell Events found for the given timespan."
    }
}

function CorrelateAllMessages($GeneratingEvents, $CorrelatingEvents)
{
    Write-Host "Combining all relevant event data."
    $ProcessGuids | ForEach-Object{if($CorrelatingEvents.$_){$CorrelatedEvents += @{$_= @($GeneratingEvents.$_, $CorrelatingEvents.$_)}}}
    Write-Host "Number of Sysmon Events with correlation match: " $CorrelatedEvents.Count
    return $CorrelatedEvents
}

function WriteCorrelatedEventsToJson($CorrelatedEvents)
{
    Write-Host "Saving results to JSON file."
    ConvertTo-Json -InputObject $CorrelatedEvents -Depth 4 | Out-File -Append $OutputFilePath"\SysmonCorrelatedEventLog.json"
}


function WriteCorrelatedEventsToTxt($CorrelatedEvents)
{
    Write-Host "Saving results to TXT file."
    $CorrelatedEvents | Out-File -Append $OutputFilePath"\SysmonCorrelatedEventLog.txt"
}

function main ()
{
    $GeneratingEvents = GetSysmonGeneratingEvents
    $CorrelatingEvents = GetSysmonCorrelatingEvents
    $CorrelatedEvents = CorrelateAllMessages $GeneratingEvents $CorrelatingEvents
    if("JSON" -in $OutputFileType)
    {
        WriteCorrelatedEventsToJson $CorrelatedEvents
    }
    elseif("TXT" -in $OutputFileType)
    {
        WriteCorrelatedEventsToTxt $CorrelatedEvents
    }
}

main