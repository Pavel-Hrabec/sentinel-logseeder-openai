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
display name. Use this after ingesting scenario data so each demo run can
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

    return ConvertTo-SafeName -Value "$DisplayName Demo"
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

function ConvertTo-ScenarioDisplayName {
    param([Parameter(Mandatory = $true)][string]$Value)

    $name = $Value -replace '-openai-runtime$', ''
    $name = $name -replace '-runtime$', ''
    $name = $name -replace '[_-]+', ' '
    $name = $name.Trim()

    if ([string]::IsNullOrWhiteSpace($name)) {
        return "Synthetic security scenario"
    }

    return (Get-Culture).TextInfo.ToTitleCase($name.ToLowerInvariant())
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
    if ($Value -is [string] -and $Value -match '^\{\{.+\}\}$') { return $false }
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
        [Parameter(Mandatory = $true)][int]$LookbackHours
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
    $query += "| where " + ($phasePredicates -join " or`n    ")
    $query += "| extend ScenarioName = $(ConvertTo-KqlString -Value $Scenario.name)"
    $query += "| order by TimeGenerated desc"
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
    Write-Host "Removing older enabled demo rules for this scenario..." -ForegroundColor Cyan
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

$displayName = if ([string]::IsNullOrWhiteSpace($RuleName)) {
    ConvertTo-ScenarioDisplayName -Value $scenario.name
} else {
    $RuleName
}

$baseRuleId = ConvertTo-RuleResourceName -DisplayName $displayName
$ruleId = if ($FreshDemoRun) {
    ConvertTo-SafeName -Value "$baseRuleId $(ConvertTo-RunStamp -Scenario $scenario)"
} else {
    $baseRuleId
}
$query = New-ScenarioDetectionQuery -Scenario $scenario -LookbackHours $LookbackHours
$tactics = @(Get-ScenarioTactics -Scenario $scenario)
$apiVersion = "2025-09-01"
$listUri = "https://management.azure.com/subscriptions/$($workspace.SubscriptionId)/resourceGroups/$($workspace.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($workspace.WorkspaceName)/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"
$uri = "https://management.azure.com/subscriptions/$($workspace.SubscriptionId)/resourceGroups/$($workspace.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($workspace.WorkspaceName)/providers/Microsoft.SecurityInsights/alertRules/${ruleId}?api-version=$apiVersion"

$body = [ordered]@{
    kind = "Scheduled"
    properties = [ordered]@{
        displayName = $displayName
        description = "Creates a Sentinel incident when logs matching the synthetic security scenario '$($scenario.name)' are found."
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
            ScenarioName = "ScenarioName"
            SourceTable = "LogTable"
        }
        alertDetailsOverride = @{
            alertDisplayNameFormat = "$displayName"
            alertDescriptionFormat = "Synthetic security scenario '$($scenario.name)' generated matching events."
        }
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
