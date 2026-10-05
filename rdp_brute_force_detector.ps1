<#
.SYNOPSIS
    RDP Brute Force Detector - designed to be triggered by Windows Task Scheduler
    via a Custom View filtered on Event ID 4625 (failed logon).

.DESCRIPTION
    Checks the Windows Security log for failed RDP logons (Event ID 4625,
    Logon Type 10 = RemoteInteractive) from the same source IP within a
    defined time window. If the count meets/exceeds the threshold, logs an
    alert to a local file and optionally shows a popup (useful for live
    demos and for proving to yourself the detection actually fired).

.NOTES
    Author: Coleman04
    Project: RDP brute-force detection engineering lab
    Pair with: Event Viewer Custom View (Security log, Event ID 4625) ->
        "Attach a Task to This Custom View" -> run this script.

    Revision history:
    - LogonTypeFilter widened from 10 only to 10 and 3. Testing showed
      xfreerdp/Hydra failed attempts can log as Logon Type 3 (Network)
      depending on the negotiated security layer, not just Type 10
      (RemoteInteractive). See README Section 5, item 1.
    - Task must run as SYSTEM with "Run with highest privileges" and with
      -ExecutionPolicy Bypass passed as an argument - a standard user-context
      task cannot reliably read the Security log, and SYSTEM has its own
      separate execution-policy scope. See README Section 5, item 5.
#>

# ---- Config (this is what you'll change during the "tuning" step) ----
$ThresholdCount    = 5                 # number of failed logons that triggers an alert
$TimeWindowMinutes = 5                 # lookback window in minutes
$LogonTypeFilter   = @(10, 3)          # 10 = RemoteInteractive (RDP), 3 = Network
$AlertLogPath      = "C:\rdp_brute_force_detector\rdp_bruteforce_alerts.log"
$DebugLogPath      = "C:\rdp_brute_force_detector\debug.log"
$ShowPopup         = $true             # set to $false once you're past live testing

# Ensure the alert/debug log folder exists
$logDir = Split-Path -Path $AlertLogPath
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

function Write-DebugLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Out-File -FilePath $DebugLogPath -Append -Encoding utf8
}

function Write-AlertLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Out-File -FilePath $AlertLogPath -Append -Encoding utf8
}

# Time window to look back from "now"
$startTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)

Write-DebugLog "Run start. Total 4625 events in window: (querying...)"

# ---- Pull failed logon events (4625) from the Security log in the time window ----
$filter = @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $startTime
}

try {
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
} catch {
    # Get-WinEvent throws if there are zero matching events - treat that as "none found"
    # rather than a real error, since that's the normal state between attacks.
    $events = @()
}

Write-DebugLog "Run start. Total 4625 events in window: $($events.Count)"

if ($events.Count -eq 0) {
    return
}

# ---- Parse the XML for each event to pull LogonType, source IP, and target account ----
$parsed = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }

    [PSCustomObject]@{
        TimeCreated        = $event.TimeCreated
        LogonType           = [int]$data['LogonType']
        SourceNetworkAddress = $data['IpAddress']
        TargetUserName      = $data['TargetUserName']
    }
}

# ---- Filter to the logon types that matter for RDP ----
$matched = $parsed | Where-Object { $LogonTypeFilter -contains $_.LogonType }

Write-DebugLog "Matched logon-type events: $($matched.Count)"

if ($matched.Count -eq 0) {
    return
}

# ---- Group by source IP and check against the threshold ----
$groups = $matched | Group-Object -Property SourceNetworkAddress

foreach ($group in $groups) {
    Write-DebugLog "  Group: '$($group.Name)' -> Count: $($group.Count)"

    if ($group.Count -ge $ThresholdCount) {
        $accounts = ($group.Group | Select-Object -ExpandProperty TargetUserName -Unique) -join ', '
        $alertMessage = "ALERT: RDP brute-force suspected from $($group.Name) - $($group.Count) failed logons in the last $TimeWindowMinutes minute(s) against account(s): $accounts"

        Write-AlertLog $alertMessage
        Write-DebugLog $alertMessage

        if ($ShowPopup) {
            try {
                $wshell = New-Object -ComObject Wscript.Shell
                $wshell.Popup($alertMessage, 0, "RDP Brute-Force Alert", 48) | Out-Null
            } catch {
                Write-DebugLog "Popup failed to display: $($_.Exception.Message)"
            }
        }
    }
}
