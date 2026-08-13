<#
.SYNOPSIS
Creates or previews a Microsoft Sentinel scheduled analytics rule for a LogSeeder scenario.

.DESCRIPTION
Reads a generated runtime scenario file and builds a KQL query from the scenario
phase templates. The rule creates Sentinel incidents when matching logs are
found. This script uses Azure Resource Manager through Azure CLI.

.PARAMETER ScenarioFile
Path to a runtime scenario JSON file.

.PARAMETER WorkspaceConfig
Path to workspace.json. Default: config/workspace.json relative to project root.

.PARAMETER RuleName
Optional display name for the analytics rule.

.PARAMETER LookbackHours
How far back the scheduled rule should query. Default: 6 hours.

.PARAMETER QueryFrequencyMinutes
How often the scheduled rule should run. Default: 5 minutes.

.PARAMETER Severity
Sentinel alert severity. Default: Medium.

.PARAMETER FreshDemoRun
Creates a run-specific analytics rule ID and removes older rules with the same
display name. Use this after ingesting scenario data so each scenario run can
create one fresh incident without leaving duplicate active rules.

.PARAMETER PreviewOnly
Prints the REST target and JSON body without creating or updating the rule.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScenarioFile,

    [string]$WorkspaceConfig,

    [string]$RuleName,

    [ValidateRange(1, 168)]
    [int]$LookbackHours = 6,

    [ValidateRange(5, 20160)]
    [int]$QueryFrequencyMinutes = 5,

    [ValidateSet("Informational", "Low", "Medium", "High")]
    [string]$Severity = "Medium",

    [switch]$FreshDemoRun,

    [switch]$PreviewOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$basePath = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { (Get-Location).Path }
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Join-Path $basePath "scripts" }

if (-not $WorkspaceConfig) {
    $WorkspaceConfig = Join-Path $basePath "config" "workspace.json"
}

. (Join-Path $scriptDir "_WorkspaceContext.ps1")

function ConvertTo-SafeName {
    param([Parameter(Mandatory = $true)][string]$Value)

    $safe = ($Value -replace '[^A-Za-z0-9-]', '-').Trim('-')
    $safe = ($safe -replace '-{2,}', '-')
    if ([string]::IsNullOrWhiteSpace($safe)) { return "logseeder-scenario" }
    if ($safe.Length -gt 64) { return $safe.Substring(0, 64).Trim('-') }
    return $safe
}

function ConvertTo-RuleResourceName {
    param([Parameter(Mandatory = $true)][string]$DisplayName)

    return ConvertTo-SafeName -Value $DisplayName
}

function ConvertTo-RunStamp {
    param([AllowNull()][object]$Scenario)

    $stamp = $null
    if ($Scenario -and $Scenario.PSObject.Properties["generatedAtUtc"]) {
        if ($Scenario.generatedAtUtc -is [datetime]) {
            $stamp = $Scenario.generatedAtUtc.ToUniversalTime()
        } else {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse([string]$Scenario.generatedAtUtc, [ref]$parsed)) {
                $stamp = $parsed.ToUniversalTime()
            }
        }
    }
    if ($null -eq $stamp) {
        $stamp = (Get-Date).ToUniversalTime()
    }

    return ConvertTo-SafeName -Value $stamp.ToString("yyyyMMddTHHmmssZ", [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-RunRuleResourceName {
    param(
        [Parameter(Mandatory = $true)][string]$BaseRuleId,
        [Parameter(Mandatory = $true)][string]$RunStamp
    )

    $reservedLength = $RunStamp.Length + 1
    $maxBaseLength = 64 - $reservedLength
    $safeBase = $BaseRuleId
    if ($safeBase.Length -gt $maxBaseLength) {
        $safeBase = $safeBase.Substring(0, $maxBaseLength).Trim('-')
    }
    return "$safeBase-$RunStamp"
}

function ConvertTo-ScenarioDisplayName {
    param([Parameter(Mandatory = $true)][string]$Value)

    $name = $Value -replace '-openai-runtime$', ''
    $name = $name -replace '-runtime$', ''
    $name = $name -replace '[_-]+', ' '
    $name = $name.Trim()

    if ([string]::IsNullOrWhiteSpace($name)) {
        return "Security scenario"
    }

    return (Get-Culture).TextInfo.ToTitleCase($name.ToLowerInvariant())
}

function ConvertTo-ScenarioKey {
    param([Parameter(Mandatory = $true)][string]$Value)

    $key = $Value.ToLowerInvariant()
    $key = $key -replace '-openai-runtime$', ''
    $key = $key -replace '-runtime$', ''
    return $key
}

function Get-ScenarioDetectionProfile {
    param(
        [Parameter(Mandatory = $true)][string]$ScenarioKey,
        [Parameter(Mandatory = $true)][string]$FallbackName
    )

    $profiles = @{
        "brute-force-lateral-movement" = [pscustomobject]@{
            DisplayName = "RDP brute force followed by lateral movement"
            Description = "Detects repeated failed RDP authentication attempts followed by a successful remote logon, an internal RDP connection, and discovery command execution. This pattern can indicate credential compromise followed by hands-on-keyboard lateral movement. Investigate the source IP, validate the account activity with the user, review RDP exposure, and isolate affected hosts if the activity is unauthorized."
            Summary = "A sequence of RDP failures, successful authentication, lateral RDP activity, and discovery commands was observed."
            RecommendedActions = "Confirm whether the sign-in and RDP activity were expected. Reset the affected account if unauthorized, revoke sessions, inspect the source and destination hosts, review command execution, and restrict exposed RDP access."
        }
        "credential-theft-privesc" = [pscustomobject]@{
            DisplayName = "LSASS credential dumping and account creation"
            Description = "Detects process activity consistent with LSASS credential access together with local administrator account creation and follow-on elevated access. This pattern can indicate credential theft, privilege escalation, and persistence. Review process command lines, validate the account creation, collect endpoint evidence, and rotate credentials for impacted users."
            Summary = "Credential dumping behavior, administrator account changes, and elevated follow-on activity were observed."
            RecommendedActions = "Validate the new or modified account, disable it if unauthorized, collect endpoint triage data, review LSASS access, reset impacted credentials, and hunt for lateral movement using the elevated account."
        }
        "data-exfiltration" = [pscustomobject]@{
            DisplayName = "Sensitive data collection and exfiltration"
            Description = "Detects sensitive resource discovery, bulk file access, large outbound network transfers, and DNS queries consistent with data staging or exfiltration. This pattern can indicate an insider threat or a compromised privileged account. Review accessed objects and files, inspect outbound destinations, and preserve evidence for data exposure assessment."
            Summary = "Sensitive data access, bulk file activity, outbound transfer volume, and DNS activity were observed."
            RecommendedActions = "Validate the user activity, review accessed files and audit objects, block or investigate outbound destinations, inspect DNS queries, contain the source host if unauthorized, and assess possible data exposure."
        }
        "ransomware-deployment" = [pscustomobject]@{
            DisplayName = "Ransomware behavior with file encryption"
            Description = "Detects a chain of suspicious script or payload execution, recovery deletion commands, high-volume file rename or modification activity, and registry persistence changes. This pattern can indicate ransomware execution or preparation for impact. Prioritize endpoint isolation, process containment, and recovery validation."
            Summary = "Payload execution, recovery tampering, file encryption activity, and registry persistence were observed."
            RecommendedActions = "Isolate impacted hosts, stop malicious processes, preserve forensic evidence, validate backups, review encrypted or renamed files, check registry persistence, and begin incident response escalation."
        }
    }

    if ($profiles.ContainsKey($ScenarioKey)) {
        return $profiles[$ScenarioKey]
    }

    return [pscustomobject]@{
        DisplayName = $FallbackName
        Description = "Detects a correlated sequence of security events across multiple data sources that may indicate unauthorized activity. Review the involved accounts, hosts, IP addresses, commands, files, and network destinations to determine whether the activity is expected."
        Summary = "A correlated sequence of security events was observed across multiple telemetry sources."
        RecommendedActions = "Validate the activity owner, review the involved entities, inspect supporting telemetry, contain affected assets if unauthorized, and document the investigation outcome."
    }
}

function New-EntityMapping {
    param(
        [Parameter(Mandatory = $true)][string]$EntityType,
        [Parameter(Mandatory = $true)][hashtable[]]$FieldMappings
    )

    return @{
        entityType = $EntityType
        fieldMappings = @($FieldMappings | ForEach-Object {
            @{
                identifier = $_.Identifier
                columnName = $_.ColumnName
            }
        })
    }
}

function Get-ScenarioEntityMappings {
    param([Parameter(Mandatory = $true)][string]$ScenarioKey)

    $account = New-EntityMapping -EntityType "Account" -FieldMappings @(
        @{ Identifier = "FullName"; ColumnName = "AccountCustomEntity" }
    )
    $hostEntity = New-EntityMapping -EntityType "Host" -FieldMappings @(
        @{ Identifier = "FullName"; ColumnName = "HostCustomEntity" }
    )
    $ip = New-EntityMapping -EntityType "IP" -FieldMappings @(
        @{ Identifier = "Address"; ColumnName = "IPCustomEntity" }
    )
    $dns = New-EntityMapping -EntityType "DNS" -FieldMappings @(
        @{ Identifier = "DomainName"; ColumnName = "DNSCustomEntity" }
    )
    $file = New-EntityMapping -EntityType "File" -FieldMappings @(
        @{ Identifier = "Name"; ColumnName = "FileNameCustomEntity" },
        @{ Identifier = "Directory"; ColumnName = "FileDirCustomEntity" }
    )
    $process = New-EntityMapping -EntityType "Process" -FieldMappings @(
        @{ Identifier = "CommandLine"; ColumnName = "ProcessCmdCustomEntity" },
        @{ Identifier = "ProcessId"; ColumnName = "ProcessIdCustomEntity" },
        @{ Identifier = "CreationTimeUtc"; ColumnName = "ProcessTimeCustomEntity" }
    )
    $registryKey = New-EntityMapping -EntityType "RegistryKey" -FieldMappings @(
        @{ Identifier = "Hive"; ColumnName = "RegistryHiveCustomEntity" },
        @{ Identifier = "Key"; ColumnName = "RegistryKeyCustomEntity" }
    )

    switch ($ScenarioKey) {
        "data-exfiltration" { return @($account, $hostEntity, $ip, $dns, $file) }
        "ransomware-deployment" { return @($account, $hostEntity, $ip, $file, $process) }
        "credential-theft-privesc" { return @($account, $hostEntity, $ip, $process, $registryKey) }
        "brute-force-lateral-movement" { return @($account, $hostEntity, $ip, $process) }
        default { return @($account, $hostEntity, $ip, $file, $process) }
    }
}

function Get-ConfigValue {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) { return $null }
    if (-not $Object.PSObject.Properties[$Name]) { return $null }
    $value = $Object.$Name
    if ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) { return $null }
    return $value
}

function Resolve-DetectionWorkspaceContext {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    if (-not (Test-Path $ConfigPath)) {
        throw "Workspace config not found: $ConfigPath"
    }

    $cfg = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    $subscriptionId = Get-ConfigValue -Object $cfg -Name "subscriptionId"
    $resourceGroup = Get-ConfigValue -Object $cfg -Name "resourceGroup"
    $workspaceName = Get-ConfigValue -Object $cfg -Name "workspaceName"

    if ($subscriptionId -and $resourceGroup -and $workspaceName) {
        return @{
            SubscriptionId = $subscriptionId
            ResourceGroup = $resourceGroup
            WorkspaceName = $workspaceName
        }
    }

    $resolved = Resolve-WorkspaceContext -ConfigPath $ConfigPath
    return @{
        SubscriptionId = $resolved.SubscriptionId
        ResourceGroup = $resolved.ResourceGroup
        WorkspaceName = $resolved.WorkspaceName
    }
}

function ConvertTo-KqlString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return "@''" }
    $text = [string]$Value
    $text = $text -replace "(`r`n|`n|`r)", " "
    $text = $text -replace "'", "''"
    return "@'$text'"
}

function ConvertTo-KqlColumnNameString {
    param([Parameter(Mandatory = $true)][string]$Value)

    $text = $Value -replace "'", "''"
    return "'$text'"
}

function Test-KqlTemplateField {
    param(
        [string]$Name,
        [AllowNull()][object]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -in @("EventCount", "EventStartTime", "EventEndTime", "EventProduct", "EventVendor", "EventSchema", "EventSchemaVersion")) { return $false }
    if ($null -eq $Value) { return $false }
    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -is [string] -and $Value -match '\{\{.+?\}\}') { return $false }
    if ($Value -is [System.Management.Automation.PSCustomObject] -or $Value -is [hashtable]) { return $false }
    return $true
}

function ConvertTo-KqlCondition {
    param(
        [string]$Name,
        [AllowNull()][object]$Value
    )

    $stringColumn = "tostring(column_ifexists($(ConvertTo-KqlColumnNameString -Value $Name), ''))"

    if ($Value -is [System.Array]) {
        $items = @($Value | Where-Object {
            $null -ne $_ -and
            -not [string]::IsNullOrWhiteSpace([string]$_) -and
            ([string]$_ -notmatch '\{\{.+?\}\}') -and
            ($_ -is [string] -or $_ -is [int] -or $_ -is [long] -or $_ -is [double] -or $_ -is [decimal] -or $_ -is [bool])
        })
        if ($items.Count -eq 0) { return $null }
        $literals = @($items | ForEach-Object { ConvertTo-KqlString -Value $_ })
        return ("{0} in~ ({1})" -f $stringColumn, ($literals -join ", "))
    }

    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return ("toreal(column_ifexists({0}, real(null))) == {1}" -f (ConvertTo-KqlColumnNameString -Value $Name), $Value)
    }

    if ($Value -is [bool]) {
        return ("tobool(column_ifexists({0}, bool(null))) == {1}" -f (ConvertTo-KqlColumnNameString -Value $Name), ([string]$Value).ToLowerInvariant())
    }

    return ("{0} =~ {1}" -f $stringColumn, (ConvertTo-KqlString -Value $Value))
}

function New-ScenarioDetectionQuery {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][int]$LookbackHours,
        [Parameter(Mandatory = $true)]$DetectionProfile
    )

    $tableNames = @($Scenario.tables.PSObject.Properties.Name | Sort-Object -Unique)
    if ($tableNames.Count -eq 0) {
        throw "Scenario contains no tables."
    }

    $phasePredicates = @()
    foreach ($phase in @($Scenario.timeline)) {
        $conditions = @("LogTable == $(ConvertTo-KqlString -Value $phase.table)")
        if ($phase.PSObject.Properties["eventTemplate"] -and $phase.eventTemplate) {
            foreach ($prop in $phase.eventTemplate.PSObject.Properties) {
                if (-not (Test-KqlTemplateField -Name $prop.Name -Value $prop.Value)) { continue }
                $condition = ConvertTo-KqlCondition -Name $prop.Name -Value $prop.Value
                if ($condition) { $conditions += $condition }
            }
        }

        if ($conditions.Count -gt 1) {
            $phasePredicates += ("(" + ($conditions -join " and ") + ")")
        }
    }

    if ($phasePredicates.Count -eq 0) {
        $phasePredicates += @("LogTable in~ (" + (@($tableNames | ForEach-Object { ConvertTo-KqlString -Value $_ }) -join ", ") + ")")
    }

    $unionLines = @("union isfuzzy=true withsource=LogTable")
    for ($i = 0; $i -lt $tableNames.Count; $i++) {
        $suffix = if ($i -lt ($tableNames.Count - 1)) { "," } else { "" }
        $unionLines += ("    {0}{1}" -f $tableNames[$i], $suffix)
    }

    $query = @()
    $query += "let Lookback = ${LookbackHours}h;"
    $query += $unionLines
    $query += "| where TimeGenerated > ago(Lookback)"
    if ($Scenario.PSObject.Properties['runId'] -and -not [string]::IsNullOrWhiteSpace($Scenario.runId)) {
        $query += "| where tostring(column_ifexists('EventOriginalUid', '')) startswith $(ConvertTo-KqlString -Value $Scenario.runId)"
    }
    $query += "| where " + ($phasePredicates -join " or`n    ")
    $query += "| extend AccountCandidate = tostring(column_ifexists('TargetUsername', ''))"
    $query += "| extend AccountCandidate = iff(isempty(AccountCandidate), tostring(column_ifexists('ActorUsername', '')), AccountCandidate)"
    $query += "| extend AccountCandidate = iff(isempty(AccountCandidate), tostring(column_ifexists('SrcUsername', '')), AccountCandidate)"
    $query += "| extend AccountCandidate = iff(isempty(AccountCandidate), tostring(column_ifexists('DstUsername', '')), AccountCandidate)"
    $query += "| extend HostCandidate = tostring(column_ifexists('DvcHostname', ''))"
    $query += "| extend HostCandidate = iff(isempty(HostCandidate), tostring(column_ifexists('TargetHostname', '')), HostCandidate)"
    $query += "| extend HostCandidate = iff(isempty(HostCandidate), tostring(column_ifexists('SrcHostname', '')), HostCandidate)"
    $query += "| extend HostCandidate = iff(isempty(HostCandidate), tostring(column_ifexists('DstHostname', '')), HostCandidate)"
    $query += "| extend HostCandidate = iff(isempty(HostCandidate), tostring(column_ifexists('DvcFQDN', '')), HostCandidate)"
    $query += "| extend SrcIpCandidate = tostring(column_ifexists('SrcIpAddr', ''))"
    $query += "| extend DstIpCandidate = tostring(column_ifexists('DstIpAddr', ''))"
    $query += "| extend ProcessNameCandidate = tostring(column_ifexists('TargetProcessName', ''))"
    $query += "| extend ProcessNameCandidate = iff(isempty(ProcessNameCandidate), tostring(column_ifexists('ActingProcessName', '')), ProcessNameCandidate)"
    $query += "| extend ProcessCommandLineCandidate = tostring(column_ifexists('TargetProcessCommandLine', ''))"
    $query += "| extend ProcessCommandLineCandidate = iff(isempty(ProcessCommandLineCandidate), tostring(column_ifexists('ActingProcessCommandLine', '')), ProcessCommandLineCandidate)"
    $query += "| extend ProcessIdCandidate = tostring(column_ifexists('TargetProcessId', ''))"
    $query += "| extend ProcessCreationCandidate = todatetime(column_ifexists('TargetProcessCreationTime', datetime(null)))"
    $query += "| extend FilePathCandidate = tostring(column_ifexists('TargetFilePath', ''))"
    $query += "| extend FileNameCandidate = tostring(column_ifexists('TargetFileName', ''))"
    $query += "| extend FileNameCandidate = iff(isempty(FileNameCandidate) and isnotempty(FilePathCandidate), extract(@'([^\\\\/]+)$', 1, FilePathCandidate), FileNameCandidate)"
    $query += "| extend FileDirectoryCandidate = iff(isnotempty(FilePathCandidate), replace_regex(FilePathCandidate, @'[\\\\/][^\\\\/]*$', ''), '')"
    $query += "| extend DnsCandidate = tostring(column_ifexists('DnsQuery', ''))"
    $query += "| extend UrlCandidate = tostring(column_ifexists('TargetUrl', ''))"
    $query += "| extend RegistryKeyCandidate = tostring(column_ifexists('RegistryKey', ''))"
    $query += "| extend RegistryValueNameCandidate = tostring(column_ifexists('RegistryValue', ''))"
    $query += "| extend RegistryValueDataCandidate = tostring(column_ifexists('RegistryValueData', ''))"
    $query += "| extend RegistryHiveShort = extract(@'^(HKLM|HKCU|HKCR|HKU|HKCC)\\\\', 1, RegistryKeyCandidate)"
    $query += "| extend RegistryHiveCandidate = case(RegistryHiveShort == 'HKLM', 'HKEY_LOCAL_MACHINE', RegistryHiveShort == 'HKCU', 'HKEY_CURRENT_USER', RegistryHiveShort == 'HKCR', 'HKEY_CLASSES_ROOT', RegistryHiveShort == 'HKU', 'HKEY_USERS', RegistryHiveShort == 'HKCC', 'HKEY_CURRENT_CONFIG', '')"
    $query += "| extend RegistryPathCandidate = extract(@'^(?:HKLM|HKCU|HKCR|HKU|HKCC)\\\\(.+)$', 1, RegistryKeyCandidate)"
    $query += "| extend RegistryPathCandidate = iff(isempty(RegistryPathCandidate), RegistryKeyCandidate, RegistryPathCandidate)"
    $query += "| extend SrcBytesValue = tolong(column_ifexists('SrcBytes', 0))"
    $query += "| summarize EventCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), HighSeverityEvents=countif(tostring(column_ifexists('EventSeverity', '')) =~ 'High'), MediumSeverityEvents=countif(tostring(column_ifexists('EventSeverity', '')) =~ 'Medium'), FailureEvents=countif(tostring(column_ifexists('EventResult', '')) =~ 'Failure'), SuccessEvents=countif(tostring(column_ifexists('EventResult', '')) =~ 'Success'), TotalBytesOut=sum(SrcBytesValue), Tables=make_set(LogTable, 10), Accounts=make_set_if(AccountCandidate, isnotempty(AccountCandidate), 10), Hosts=make_set_if(HostCandidate, isnotempty(HostCandidate), 10), SrcIPs=make_set_if(SrcIpCandidate, isnotempty(SrcIpCandidate), 10), DstIPs=make_set_if(DstIpCandidate, isnotempty(DstIpCandidate), 10), Processes=make_set_if(ProcessNameCandidate, isnotempty(ProcessNameCandidate), 10), ProcessCommands=make_set_if(ProcessCommandLineCandidate, isnotempty(ProcessCommandLineCandidate), 10), ProcessIds=make_set_if(ProcessIdCandidate, isnotempty(ProcessIdCandidate), 10), ProcessTimes=make_set_if(ProcessCreationCandidate, isnotnull(ProcessCreationCandidate), 10), FileNames=make_set_if(FileNameCandidate, isnotempty(FileNameCandidate), 10), FileDirs=make_set_if(FileDirectoryCandidate, isnotempty(FileDirectoryCandidate), 10), DnsQueries=make_set_if(DnsCandidate, isnotempty(DnsCandidate), 10), Urls=make_set_if(UrlCandidate, isnotempty(UrlCandidate), 10), RegistryHives=make_set_if(RegistryHiveCandidate, isnotempty(RegistryHiveCandidate), 10), RegistryKeys=make_set_if(RegistryPathCandidate, isnotempty(RegistryPathCandidate), 10), RegistryValueNames=make_set_if(RegistryValueNameCandidate, isnotempty(RegistryValueNameCandidate), 10), RegistryValueData=make_set_if(RegistryValueDataCandidate, isnotempty(RegistryValueDataCandidate), 10)"
    $query += "| where EventCount > 0"
    $query += "| extend DetectionName = $(ConvertTo-KqlString -Value $DetectionProfile.DisplayName)"
    $query += "| extend RecommendedActions = $(ConvertTo-KqlString -Value $DetectionProfile.RecommendedActions)"
    $query += "| extend AccountCustomEntity = tostring(Accounts[0]), HostCustomEntity = tostring(Hosts[0])"
    $query += "| extend SrcIPCustomEntity = tostring(SrcIPs[0]), DstIPCustomEntity = tostring(DstIPs[0])"
    $query += "| extend IPCustomEntity = iff(isnotempty(SrcIPCustomEntity), SrcIPCustomEntity, DstIPCustomEntity)"
    $query += "| extend DNSCustomEntity = tostring(DnsQueries[0]), UrlCustomEntity = tostring(Urls[0])"
    $query += "| extend FileNameCustomEntity = tostring(FileNames[0]), FileDirCustomEntity = tostring(FileDirs[0])"
    $query += "| extend ProcessCmdCustomEntity = tostring(ProcessCommands[0]), ProcessIdCustomEntity = tostring(ProcessIds[0]), ProcessTimeCustomEntity = todatetime(ProcessTimes[0])"
    $query += "| extend RegistryHiveCustomEntity = tostring(RegistryHives[0]), RegistryKeyCustomEntity = tostring(RegistryKeys[0]), RegistryValueCustomEntity = tostring(RegistryValueNames[0]), RegistryDataCustomEntity = tostring(RegistryValueData[0])"
    $query += "| extend AccountList = iff(array_length(Accounts) == 0, 'n/a', strcat_array(Accounts, ', ')), HostList = iff(array_length(Hosts) == 0, 'n/a', strcat_array(Hosts, ', '))"
    $query += "| extend SrcIPList = iff(array_length(SrcIPs) == 0, 'n/a', strcat_array(SrcIPs, ', ')), DstIPList = iff(array_length(DstIPs) == 0, 'n/a', strcat_array(DstIPs, ', '))"
    $query += "| extend ProcessList = iff(array_length(Processes) == 0, 'n/a', strcat_array(Processes, ', ')), ProcessCommandList = iff(array_length(ProcessCommands) == 0, 'n/a', strcat_array(ProcessCommands, ' | '))"
    $query += "| extend FileList = iff(array_length(FileNames) == 0, 'n/a', strcat_array(FileNames, ', ')), DomainList = iff(array_length(DnsQueries) == 0, 'n/a', strcat_array(DnsQueries, ', '))"
    $query += "| extend RegistryList = iff(array_length(RegistryKeys) == 0, 'n/a', strcat_array(RegistryKeys, ', ')), TableList = strcat_array(Tables, ', ')"
    $query += "| extend AlertSummary = strcat($(ConvertTo-KqlString -Value $DetectionProfile.Summary), ' Count=', tostring(EventCount), '; firstSeen=', format_datetime(FirstSeen, 'yyyy-MM-dd HH:mm:ss'), ' UTC; lastSeen=', format_datetime(LastSeen, 'yyyy-MM-dd HH:mm:ss'), ' UTC.')"
    $query += "| extend AlertEvidence = strcat('Accounts: ', AccountList, '; Hosts: ', HostList, '; Source IPs: ', SrcIPList, '; Destination IPs: ', DstIPList, '; Processes: ', ProcessList, '; Commands: ', ProcessCommandList, '; Files: ', FileList, '; DNS: ', DomainList, '; Registry: ', RegistryList, '; Outbound bytes: ', tostring(TotalBytesOut), '; Tables: ', TableList)"
    $query += "| project TimeGenerated=LastSeen, DetectionName, AlertSummary, AlertEvidence, RecommendedActions, EventCount, FirstSeen, LastSeen, HighSeverityEvents, MediumSeverityEvents, FailureEvents, SuccessEvents, TotalBytesOut, TableList, AccountList, HostList, SrcIPList, DstIPList, ProcessList, ProcessCommandList, FileList, DomainList, RegistryList, AccountCustomEntity, HostCustomEntity, IPCustomEntity, SrcIPCustomEntity, DstIPCustomEntity, DNSCustomEntity, UrlCustomEntity, FileNameCustomEntity, FileDirCustomEntity, ProcessCmdCustomEntity, ProcessIdCustomEntity, ProcessTimeCustomEntity, RegistryHiveCustomEntity, RegistryKeyCustomEntity, RegistryValueCustomEntity, RegistryDataCustomEntity"
    return ($query -join "`n")
}

function Get-ScenarioTactics {
    param([Parameter(Mandatory = $true)]$Scenario)

    $allowed = @(
        "InitialAccess", "Execution", "Persistence", "PrivilegeEscalation",
        "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
        "Collection", "Exfiltration", "CommandAndControl", "Impact"
    )

    $mapped = @()
    if ($Scenario.PSObject.Properties["mitreTactics"]) {
        foreach ($tactic in @($Scenario.mitreTactics)) {
            $normalized = ([string]$tactic) -replace '[^A-Za-z]', ''
            if ($allowed -contains $normalized) { $mapped += $normalized }
        }
    }
    return @($mapped | Sort-Object -Unique)
}

function Remove-ExistingScenarioRules {
    param(
        [Parameter(Mandatory = $true)][string]$ListUri,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$BaseRuleId,
        [Parameter(Mandatory = $true)][string]$KeepRuleId
    )

    Write-Host ""
    Write-Host "Removing older enabled rules for this scenario..." -ForegroundColor Cyan
    $listJson = az rest --method get --uri $ListUri 2>&1
    if ($LASTEXITCODE -ne 0) {
        $listJson | Write-Host
        throw "az rest failed while listing existing Sentinel analytics rules."
    }

    $rules = ($listJson | Out-String) | ConvertFrom-Json
    foreach ($rule in @($rules.value)) {
        if ($rule.name -eq $KeepRuleId) { continue }
        if ($rule.name -notlike "$BaseRuleId*") { continue }
        if ($rule.properties.displayName -ne $DisplayName) { continue }

        Write-Host "  Deleting old rule resource '$($rule.name)'." -ForegroundColor DarkCyan
        $deleteOutput = az rest --method delete --uri "$($rule.id)?api-version=2025-09-01" 2>&1
        if ($LASTEXITCODE -ne 0 -and (($deleteOutput | Out-String) -notmatch "NotFound")) {
            $deleteOutput | Write-Host
            throw "az rest failed while deleting old Sentinel analytics rule '$($rule.name)'."
        }
    }
}

if (-not (Test-Path $ScenarioFile)) {
    throw "Scenario file not found: $ScenarioFile"
}

try { $null = Get-Command az -ErrorAction Stop } catch {
    throw "Azure CLI (az) is required to create Sentinel analytics rules."
}

$scenario = Get-Content -Path $ScenarioFile -Raw | ConvertFrom-Json
$workspace = Resolve-DetectionWorkspaceContext -ConfigPath $WorkspaceConfig
$scenarioKey = ConvertTo-ScenarioKey -Value $scenario.name
$fallbackDisplayName = ConvertTo-ScenarioDisplayName -Value $scenario.name
$detectionProfile = Get-ScenarioDetectionProfile -ScenarioKey $scenarioKey -FallbackName $fallbackDisplayName

$displayName = if ([string]::IsNullOrWhiteSpace($RuleName)) {
    $detectionProfile.DisplayName
} else {
    $RuleName
}

$baseRuleId = ConvertTo-RuleResourceName -DisplayName $displayName
$ruleId = if ($FreshDemoRun) {
    ConvertTo-RunRuleResourceName -BaseRuleId $baseRuleId -RunStamp (ConvertTo-RunStamp -Scenario $scenario)
} else {
    $baseRuleId
}
$query = New-ScenarioDetectionQuery -Scenario $scenario -LookbackHours $LookbackHours -DetectionProfile $detectionProfile
$tactics = @(Get-ScenarioTactics -Scenario $scenario)
$apiVersion = "2025-09-01"
$listUri = "https://management.azure.com/subscriptions/$($workspace.SubscriptionId)/resourceGroups/$($workspace.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($workspace.WorkspaceName)/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"
$uri = "https://management.azure.com/subscriptions/$($workspace.SubscriptionId)/resourceGroups/$($workspace.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($workspace.WorkspaceName)/providers/Microsoft.SecurityInsights/alertRules/${ruleId}?api-version=$apiVersion"

$body = [ordered]@{
    kind = "Scheduled"
    properties = [ordered]@{
        displayName = $displayName
        description = $detectionProfile.Description
        severity = $Severity
        enabled = $true
        query = $query
        queryFrequency = "PT${QueryFrequencyMinutes}M"
        queryPeriod = "PT${LookbackHours}H"
        triggerOperator = "GreaterThan"
        triggerThreshold = 0
        suppressionDuration = "PT${LookbackHours}H"
        suppressionEnabled = $true
        eventGroupingSettings = @{
            aggregationKind = "SingleAlert"
        }
        incidentConfiguration = @{
            createIncident = $true
            groupingConfiguration = @{
                enabled = $false
                reopenClosedIncident = $false
                lookbackDuration = "PT${LookbackHours}H"
                matchingMethod = "AnyAlert"
                groupByEntities = @()
                groupByAlertDetails = @()
                groupByCustomDetails = @()
            }
        }
        customDetails = @{
            Detection = "DetectionName"
            EventCount = "EventCount"
            FirstSeen = "FirstSeen"
            LastSeen = "LastSeen"
            Accounts = "AccountList"
            Hosts = "HostList"
            SrcIPs = "SrcIPList"
            DstIPs = "DstIPList"
            Processes = "ProcessList"
            Commands = "ProcessCommandList"
            Files = "FileList"
            Domains = "DomainList"
            RegistryKeys = "RegistryList"
            BytesOut = "TotalBytesOut"
            Tables = "TableList"
            Evidence = "AlertEvidence"
            Response = "RecommendedActions"
            HighEvents = "HighSeverityEvents"
            Failures = "FailureEvents"
            Successes = "SuccessEvents"
        }
        alertDetailsOverride = @{
            alertDisplayNameFormat = "{{DetectionName}} - {{AccountCustomEntity}} / {{HostCustomEntity}}"
            alertDescriptionFormat = "{{AlertSummary}} Evidence: {{AlertEvidence}} Recommended response: {{RecommendedActions}}"
        }
        entityMappings = @(Get-ScenarioEntityMappings -ScenarioKey $scenarioKey)
    }
}

if ($tactics.Count -gt 0) {
    $body.properties.tactics = $tactics
}

$jsonBody = $body | ConvertTo-Json -Depth 50

Write-Host ""
Write-Host "Sentinel analytics rule:" -ForegroundColor Cyan
Write-Host "  $displayName"
Write-Host "Rule ID:" -ForegroundColor Cyan
Write-Host "  $ruleId"
Write-Host "Workspace:" -ForegroundColor Cyan
Write-Host "  $($workspace.WorkspaceName) / $($workspace.ResourceGroup) / $($workspace.SubscriptionId)"
Write-Host ""
Write-Host "KQL:" -ForegroundColor Cyan
Write-Host $query -ForegroundColor DarkCyan

if ($PreviewOnly) {
    Write-Host ""
    Write-Host "Preview mode: analytics rule was not created." -ForegroundColor Yellow
    Write-Host "REST target:" -ForegroundColor Cyan
    Write-Host "  $uri" -ForegroundColor DarkCyan
    Write-Host "Request body:" -ForegroundColor Cyan
    Write-Host $jsonBody -ForegroundColor DarkCyan
    return
}

if ($FreshDemoRun) {
    Remove-ExistingScenarioRules -ListUri $listUri -DisplayName $displayName -BaseRuleId $baseRuleId -KeepRuleId $ruleId
}

$tempFile = [System.IO.Path]::GetTempFileName()
try {
    [System.IO.File]::WriteAllText($tempFile, $jsonBody, [System.Text.Encoding]::UTF8)
    Write-Host ""
    Write-Host "Creating/updating Sentinel analytics rule..." -ForegroundColor Cyan
    az rest --method put --uri $uri --headers "Content-Type=application/json" --body "@$tempFile" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "az rest failed while creating/updating the Sentinel analytics rule."
    }
    Write-Host "Detection rule created or updated." -ForegroundColor Green
    Write-Host "Incidents will be created when the scheduled rule finds matching logs." -ForegroundColor Green
} finally {
    Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
}
