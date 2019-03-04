# ir_scripts
Scripts to aid in incident response and threat hunting.

## Get-CorrelatedSysmonEvents

Get-CorrelatedSysmonEvents is used to build context around an event to provide threat hunters a better picture of what is happening. The original intent was to correlate Network Connection events (Event ID 3) with the process that spawned them (Process Creation, Event ID 1). However, its built to be flexible so that you can correlate any two Event IDs based on the unique Process GUID that Sysmon assigns.

This script was inspired by the work done by Robert Rodriguez (@Cyb3rWard0g) of SpectreOps with his 3 part post "Real-Time Sysmon Processing via KSQL and HELK"

https://posts.specterops.io/real-time-sysmon-processing-via-ksql-and-helk-part-1-initial-integration-88c2b6eac839

## IR-Triage_compatible.ps1

Uses available PowerShell modules to collect forensic data from a host. The data is used to triage the machine, determine if there is a true incident and if further investigation is required on that host.
