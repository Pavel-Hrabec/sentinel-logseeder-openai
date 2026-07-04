<#
.SYNOPSIS
Generate randomized sample data and ingest it into a Microsoft Sentinel / Log Analytics
workspace via the Azure Monitor Logs Ingestion API.

.DESCRIPTION
This script creates the required Azure infrastructure (DCE, DCR, custom table) and ingests
AI-generated sample data seeded with entities from entities.json. It supports both built-in
(standard) and custom Log Analytics tables.

.REQUIREMENTS
- Azure CLI (az) installed and authenticated via 'az login'.
- 'Monitoring Metrics Publisher' RBAC role on the DCR for the signed-in user (or the
  service principal if using -ClientId/-ClientSecret). During -Deploy, the script
  attempts to create this assignment automatically; this requires the caller to hold
  'Microsoft.Authorization/roleAssignments/write' (User Access Administrator or Owner)
  on the DCR scope. Use -SkipRoleAssignment to opt out.

.PARAMETER TableName
Target table name. Custom tables should end with '_CL'.

.PARAMETER RowCount
Number of sample rows to generate. Default: 500.

.PARAMETER Schema
Path to a JSON file containing column definitions. Each element should have 'name' and 'type'.

.PARAMETER SampleDataFile
Path to a JSON or CSV file with representative sample rows. When provided, values are
randomly sampled from this file for the most realistic output.

.PARAMETER EntitiesFile
Path to the entities.json configuration file. Default: config/entities.json relative to project root.

.PARAMETER WorkspaceConfig
Path to workspace.json. Default: config/workspace.json relative to project root.

.PARAMETER Deploy
When specified, creates or reuses DCE, DCR, and custom table resources in Azure.

.PARAMETER Ingest
When specified, generates sample data and ingests it via the Logs Ingestion API.

.PARAMETER TimeWindowMinutes
Time spread for generated TimeGenerated timestamps, in minutes. Default: 30 minutes.
Increase this only when the user explicitly requests a wider time window.

.PARAMETER TenantId
Microsoft Entra tenant ID for service principal auth (optional fallback).

.PARAMETER ClientId
Service principal application (client) ID for ingestion auth (optional fallback).

.PARAMETER ClientSecret
Service principal client secret for ingestion auth (optional fallback).

.PARAMETER SkipRoleAssignment
When specified during -Deploy, skips the automatic 'Monitoring Metrics Publisher' role
assignment on the newly created DCR and just prints a reminder instead.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TableName,

    [int]$RowCount = 500,

    [string]$Schema,

    [string]$SampleDataFile,

    [string]$EntitiesFile,

    [string]$WorkspaceConfig,

    [switch]$Deploy,

    [switch]$Ingest,

    [int]$TimeWindowMinutes = 30,

    [string]$TenantId,

    [string]$ClientId,

    [string]$ClientSecret,

    [switch]$SkipRoleAssignment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Resolve default paths relative to project root (parent of scripts/)
# ---------------------------------------------------------------------------
$basePath = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { (Get-Location).Path }
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Join-Path $basePath "scripts" }

if (-not $WorkspaceConfig) {
    $WorkspaceConfig = Join-Path $basePath "config" "workspace.json"
}
if (-not $EntitiesFile) {
    $EntitiesFile = Join-Path $basePath "config" "entities.json"
}

# Load shared workspace-context resolver
. (Join-Path $scriptDir "_WorkspaceContext.ps1")

# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

function Assert-AzCli {
    try {
        $null = Get-Command az -ErrorAction Stop
        return $true
    } catch {
        throw "Azure CLI (az) is required. Install from https://aka.ms/installazurecli"
    }
}

function Get-ManagementAccessToken {
    return (az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv)
}

function Invoke-ArmRest {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$JsonBody
    )

    if ($Method -eq "GET") {
        $prevEA = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = az rest --method get --uri $Uri 2>&1
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $prevEA
        if ($exitCode -ne 0) {
            $errorOutput = ($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"
            throw "az rest GET failed (exit $exitCode) for ${Uri}: $errorOutput"
        }
        $jsonText = ($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
        return $jsonText | ConvertFrom-Json
    }

    if (-not $JsonBody -or -not $JsonBody.Trim()) {
        throw "Request body is empty for PUT $Uri"
    }
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($tempFile, $JsonBody, [System.Text.Encoding]::UTF8)
        $prevEA = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $output = az rest --method put --uri $Uri --headers "Content-Type=application/json" --body "@$tempFile" 2>&1
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $prevEA
        if ($exitCode -ne 0) {
            $errorOutput = ($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"
            throw "az rest PUT failed (exit $exitCode) for ${Uri}: $errorOutput"
        }
        $jsonText = ($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
        if ($jsonText) { return $jsonText | ConvertFrom-Json }
        return $null
    } finally {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-AccessToken {
    param(
        [string]$TokenTenantId,
        [string]$TokenClientId,
        [string]$TokenClientSecret
    )

    if ($TokenTenantId -and $TokenClientId -and $TokenClientSecret) {
        $tokenUri = "https://login.microsoftonline.com/$TokenTenantId/oauth2/v2.0/token"
        $body = @{
            client_id     = $TokenClientId
            client_secret = $TokenClientSecret
            grant_type    = "client_credentials"
            scope         = "https://monitor.azure.com/.default"
        }
        $response = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
        if (-not $response.access_token) {
            throw "Failed to acquire access token using service principal."
        }
        return $response.access_token
    }

    Assert-AzCli | Out-Null
    $token = az account get-access-token --resource "https://monitor.azure.com/" --query accessToken -o tsv
    if (-not $token) {
        throw "Failed to acquire access token. Ensure you're logged in with 'az login' or provide -ClientId/-ClientSecret."
    }
    return $token
}

function Read-WorkspaceConfig {
    param([string]$ConfigPath)
    return Resolve-WorkspaceContext -ConfigPath $ConfigPath
}

function Resolve-WorkspaceLocation {
    param([string]$WorkspaceResourceId)
    $apiVersion = "2022-10-01"
    $uri = "https://management.azure.com${WorkspaceResourceId}?api-version=$apiVersion"
    $ws = Invoke-ArmRest -Method "GET" -Uri $uri
    return $ws.location
}

# ---------------------------------------------------------------------------
# Infrastructure: DCE
# ---------------------------------------------------------------------------
function Initialize-Dce {
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$Location,
        [string]$DceName
    )

    $dceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$DceName"
    $apiVersion = "2022-06-01"
    $dce = $null

    try {
        $dce = Invoke-ArmRest -Method "GET" -Uri "https://management.azure.com${dceId}?api-version=$apiVersion"
        Write-Host "Reusing existing DCE '$DceName'." -ForegroundColor Green
    } catch {
        $dce = $null
    }

    if (-not $dce) {
        Write-Host "Creating Data Collection Endpoint '$DceName'..." -ForegroundColor Cyan
        $body = @{
            location   = $Location
            properties = @{
                description         = "Sample data ingestion endpoint"
                networkAcls         = @{ publicNetworkAccess = "Enabled" }
            }
        } | ConvertTo-Json -Depth 10 -Compress

        $null = Invoke-ArmRest -Method "PUT" -Uri "https://management.azure.com${dceId}?api-version=$apiVersion" -JsonBody $body
        $dce = Invoke-ArmRest -Method "GET" -Uri "https://management.azure.com${dceId}?api-version=$apiVersion"
        Write-Host "DCE '$DceName' created." -ForegroundColor Green
    }

    return $dce
}

# ---------------------------------------------------------------------------
# Infrastructure: Custom table
# ---------------------------------------------------------------------------
function Initialize-CustomTable {
    param(
        [string]$WorkspaceResourceId,
        [string]$CustomTableName,
        [object[]]$ColumnDefinitions
    )

    $apiVersion = "2022-10-01"
    $tableUri = "https://management.azure.com${WorkspaceResourceId}/tables/${CustomTableName}?api-version=$apiVersion"

    $tableExists = $false
    try {
        $table = Invoke-ArmRest -Method "GET" -Uri $tableUri
        if ($table.properties.provisioningState -eq "Succeeded") {
            Write-Host "Custom table '$CustomTableName' already exists." -ForegroundColor Green
            $tableExists = $true
        }
    } catch {
        # Table does not exist.
    }

    if (-not $tableExists) {
        Write-Host "Creating custom table '$CustomTableName'..." -ForegroundColor Cyan

        $schemaColumns = @(
            @{ name = "TimeGenerated"; type = "datetime"; description = "The time at which the data was generated" }
        )
        foreach ($col in $ColumnDefinitions) {
            if ($col.name -eq "TimeGenerated") { continue }
            $schemaColumns += @{
                name        = $col.name
                type        = if ($col.type) { $col.type } else { "string" }
                description = ""
            }
        }

        $body = @{
            properties = @{
                schema = @{
                    name    = $CustomTableName
                    columns = $schemaColumns
                }
            }
        } | ConvertTo-Json -Depth 20 -Compress

        $null = Invoke-ArmRest -Method "PUT" -Uri $tableUri -JsonBody $body

        # Wait for provisioning
        for ($i = 0; $i -lt 12; $i++) {
            Start-Sleep -Seconds 5
            try {
                $table = Invoke-ArmRest -Method "GET" -Uri $tableUri
                if ($table.properties.provisioningState -eq "Succeeded") {
                    Write-Host "Custom table '$CustomTableName' created." -ForegroundColor Green
                    return
                }
            } catch { }
        }
        throw "Custom table '$CustomTableName' did not reach Succeeded state."
    }
}

# ---------------------------------------------------------------------------
# Infrastructure: DCR
# ---------------------------------------------------------------------------
function Test-IsBuiltInTable {
    param([string]$Name)
    return (-not $Name.EndsWith("_CL"))
}

function New-DcrTemplate {
    param(
        [string]$TargetTableName,
        [string]$WorkspaceResourceId,
        [string]$DceResourceId,
        [string]$Location,
        [object[]]$ColumnDefinitions,
        [string]$TransformKql
    )

    $isBuiltIn = Test-IsBuiltInTable -Name $TargetTableName

    if ($isBuiltIn) {
        $streamName   = "Custom-$TargetTableName"
        $outputStream = "Microsoft-$TargetTableName"
    } else {
        $baseName     = $TargetTableName.Substring(0, $TargetTableName.Length - 3)
        $streamName   = "Custom-$baseName"
        $outputStream = "Custom-$TargetTableName"
    }

    $columnDefs = @(
        foreach ($col in $ColumnDefinitions) {
            @{ name = $col.name; type = if ($col.type) { $col.type } else { "string" } }
        }
    )
    # Ensure TimeGenerated is present in stream declarations
    $hasTimeGenerated = $columnDefs | Where-Object { $_.name -eq "TimeGenerated" }
    if (-not $hasTimeGenerated) {
        $columnDefs += @{ name = "TimeGenerated"; type = "datetime" }
    }

    $transform = if ($TransformKql) { $TransformKql } else { "source" }

    $template = @{
        location   = $Location
        kind       = "Direct"
        properties = @{
            dataCollectionEndpointId = $DceResourceId
            streamDeclarations       = @{
                $streamName = @{
                    columns = $columnDefs
                }
            }
            destinations = @{
                logAnalytics = @(
                    @{
                        name                = "la"
                        workspaceResourceId = $WorkspaceResourceId
                    }
                )
            }
            dataFlows = @(
                @{
                    streams      = @($streamName)
                    destinations = @("la")
                    transformKql = $transform
                    outputStream = $outputStream
                }
            )
        }
    }

    return @{
        Template   = $template
        StreamName = $streamName
    }
}

function Initialize-Dcr {
    param(
        [string]$DcrName,
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [hashtable]$Template
    )

    $apiVersion = "2023-03-11"
    $dcrId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionRules/$DcrName"
    $dcrUri = "https://management.azure.com${dcrId}?api-version=$apiVersion"

    # Check if DCR already exists
    $existing = $null
    try {
        $existing = Invoke-ArmRest -Method "GET" -Uri $dcrUri
    } catch { }

    $body = $Template | ConvertTo-Json -Depth 20 -Compress

    if ($existing) {
        $needsUpdate = $false
        $desiredDceId = [string]$Template.properties.dataCollectionEndpointId
        $currentDceId = [string]$existing.properties.dataCollectionEndpointId

        if (-not [string]::Equals($currentDceId, $desiredDceId, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "Existing DCR '$DcrName' is associated with a different DCE. Updating it." -ForegroundColor Yellow
            $needsUpdate = $true
        }

        $desiredWorkspaceId = [string](@($Template.properties.destinations.logAnalytics)[0].workspaceResourceId)
        $currentWorkspaceId = ""
        if ($existing.properties.destinations -and $existing.properties.destinations.logAnalytics) {
            $currentWorkspaceId = [string](@($existing.properties.destinations.logAnalytics)[0].workspaceResourceId)
        }

        if (-not [string]::Equals($currentWorkspaceId, $desiredWorkspaceId, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "Existing DCR '$DcrName' points to a different workspace destination. Updating it." -ForegroundColor Yellow
            $needsUpdate = $true
        }

        $existingStreams = @()
        if ($existing.properties.streamDeclarations) {
            $existingStreams = @($existing.properties.streamDeclarations.PSObject.Properties.Name)
        }
        foreach ($streamName in @($Template.properties.streamDeclarations.Keys)) {
            if ($existingStreams -notcontains $streamName) {
                Write-Host "Existing DCR '$DcrName' is missing stream '$streamName'. Updating it." -ForegroundColor Yellow
                $needsUpdate = $true
                break
            }
        }

        if ($needsUpdate) {
            $null = Invoke-ArmRest -Method "PUT" -Uri $dcrUri -JsonBody $body
            Write-Host "DCR '$DcrName' updated." -ForegroundColor Green
        } else {
            Write-Host "Reusing existing DCR '$DcrName'." -ForegroundColor Green
        }
    } else {
        Write-Host "Creating DCR '$DcrName'..." -ForegroundColor Cyan
        $null = Invoke-ArmRest -Method "PUT" -Uri $dcrUri -JsonBody $body
        Write-Host "DCR '$DcrName' created." -ForegroundColor Green
    }

    return $dcrId
}

function Get-DcrImmutableId {
    param([string]$DcrId)
    $apiVersion = "2023-03-11"
    $dcr = Invoke-ArmRest -Method "GET" -Uri "https://management.azure.com${DcrId}?api-version=$apiVersion"
    return $dcr.properties.immutableId
}

function Get-DcrIngestionEndpoint {
    param([string]$DcrId)
    $apiVersion = "2023-03-11"
    $dcr = Invoke-ArmRest -Method "GET" -Uri "https://management.azure.com${DcrId}?api-version=$apiVersion"
    if ($dcr.properties.endpoints -and $dcr.properties.endpoints.logsIngestion) {
        return $dcr.properties.endpoints.logsIngestion
    }
    return $null
}

function Grant-DcrPublisherRole {
    <#
    Assigns the 'Monitoring Metrics Publisher' role on the DCR to the signed-in
    principal. Idempotent: silently succeeds if the assignment already exists.
    On failure (e.g. caller lacks Microsoft.Authorization/roleAssignments/write),
    falls back to printing the manual az CLI reminder.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DcrId
    )

    # Fixed role definition GUID for 'Monitoring Metrics Publisher' - avoids name-resolution issues.
    $roleDefId = "3913510d-42f4-4e42-8a64-420c390055eb"

    $printReminder = {
        Write-Host "`n[RBAC] Ensure you have 'Monitoring Metrics Publisher' role on the DCR:" -ForegroundColor Yellow
        Write-Host "  az role assignment create --role 'Monitoring Metrics Publisher' ``" -ForegroundColor Yellow
        Write-Host "    --assignee `"`$(az ad signed-in-user show --query id -o tsv)`" ``" -ForegroundColor Yellow
        Write-Host "    --scope '$DcrId'" -ForegroundColor Yellow
    }

    try {
        # Detect caller identity type (user vs service principal).
        $accountJson = az account show -o json 2>$null
        if (-not $accountJson) { throw "az account show failed" }
        $account = $accountJson | ConvertFrom-Json
        $userType = $account.user.type  # 'user' or 'servicePrincipal'

        $principalId = $null
        $principalType = $null
        if ($userType -eq "user") {
            $principalId = (az ad signed-in-user show --query id -o tsv 2>$null).Trim()
            $principalType = "User"
        } elseif ($userType -eq "servicePrincipal") {
            $spAppId = $account.user.name
            $principalId = (az ad sp show --id $spAppId --query id -o tsv 2>$null).Trim()
            $principalType = "ServicePrincipal"
        } else {
            Write-Host "[RBAC] Unrecognized account type '$userType'; skipping auto-assignment." -ForegroundColor Yellow
            & $printReminder
            return
        }

        if (-not $principalId) {
            Write-Host "[RBAC] Could not resolve signed-in principal object ID; skipping auto-assignment." -ForegroundColor Yellow
            & $printReminder
            return
        }

        Write-Host "`n[RBAC] Assigning 'Monitoring Metrics Publisher' on DCR to $principalType $principalId..." -ForegroundColor Cyan
        $createOutput = az role assignment create `
            --role $roleDefId `
            --assignee-object-id $principalId `
            --assignee-principal-type $principalType `
            --scope $DcrId `
            -o json 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "[RBAC] Role assignment succeeded (note: propagation may take up to 5 minutes)." -ForegroundColor Green
            return
        }

        # Non-zero exit: check if it's the benign 'already exists' case.
        $errText = ($createOutput | Out-String)
        if ($errText -match "RoleAssignmentExists" -or $errText -match "already exists") {
            Write-Host "[RBAC] Role assignment already exists - no action needed." -ForegroundColor Green
            return
        }

        Write-Host "[RBAC] Auto-assignment failed: $errText" -ForegroundColor Yellow
        Write-Host "[RBAC] You likely lack 'Microsoft.Authorization/roleAssignments/write' on the DCR/RG." -ForegroundColor Yellow
        & $printReminder
    } catch {
        Write-Host "[RBAC] Auto-assignment error: $($_.Exception.Message)" -ForegroundColor Yellow
        & $printReminder
    }
}

# ---------------------------------------------------------------------------
# Data Generation
# ---------------------------------------------------------------------------
function Read-EntitiesConfig {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Entities config not found: $Path"
    }
    return Get-Content -Path $Path -Raw | ConvertFrom-Json
}

function Read-SchemaFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Schema file not found: $Path"
    }
    $raw = Get-Content -Path $Path -Raw | ConvertFrom-Json
    # Support both flat array and { columns: [...] } formats
    if ($raw.columns) { return @($raw.columns) }
    return @($raw)
}

function Read-SampleData {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $null }
    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($extension -eq ".json") {
        $data = Get-Content -Path $Path -Raw | ConvertFrom-Json
        if ($data -is [System.Array]) { return @($data) }
        return @($data)
    }
    if ($extension -eq ".csv") {
        return @(Import-Csv -Path $Path)
    }
    throw "Unsupported sample data format: $extension (use .json or .csv)"
}

function Get-EntityColumnMapping {
    param([string]$ColumnName)

    $nameLower = $ColumnName.ToLowerInvariant()

    # IP address patterns
    if ($nameLower -match '(ipaddr|ipaddress|sourceip|destip|callerip|clientip|remoteip|srcip|dstip|_ip$|^ip$)') {
        return "ipAddresses"
    }
    # User patterns
    if ($nameLower -match '(username|userid|userupn|accountname|actorname|principalname|userprincipal|initiatedby|caller$|owner$)') {
        return "users"
    }
    # UPN patterns (more specific)
    if ($nameLower -match '(upn|userprincipalname|mail$|email)') {
        return "emailAddresses"
    }
    # Hostname/device patterns
    if ($nameLower -match '(hostname|computername|devicename|machinename|dvcname|workstation|^computer$|^device$|^dvc$|^host$)') {
        return "devices"
    }
    # FQDN patterns
    if ($nameLower -match '(fqdn|fullyqualified)') {
        return "devicesFqdn"
    }
    # URL patterns
    if ($nameLower -match '(^url$|^uri$|requesturl|targeturl|resourceurl|httpurl)') {
        return "urls"
    }
    # Domain patterns
    if ($nameLower -match '(^domain$|domainname|dnsdomain|targetdomain)') {
        return "domains"
    }

    return $null
}

function Get-EntityValue {
    param(
        [string]$EntityType,
        [object]$Entities
    )

    switch ($EntityType) {
        "ipAddresses" {
            $entry = $Entities.ipAddresses | Get-Random
            return $entry.address
        }
        "users" {
            $entry = $Entities.users | Get-Random
            return $entry.username
        }
        "emailAddresses" {
            return ($Entities.emailAddresses | Get-Random)
        }
        "devices" {
            $entry = $Entities.devices | Get-Random
            return $entry.hostname
        }
        "devicesFqdn" {
            $entry = $Entities.devices | Get-Random
            return $entry.fqdn
        }
        "urls" {
            return ($Entities.urls | Get-Random)
        }
        "domains" {
            return ($Entities.domains | Get-Random)
        }
        default { return $null }
    }
}

function New-RandomValueForType {
    param(
        [string]$ColumnType,
        [string]$ColumnName,
        [int]$WindowMinutes
    )

    $nameLower = $ColumnName.ToLowerInvariant()

    switch ($ColumnType.ToLowerInvariant()) {
        "datetime" {
            $offsetSeconds = Get-Random -Minimum 0 -Maximum ($WindowMinutes * 60)
            return (Get-Date).ToUniversalTime().AddSeconds(-$offsetSeconds).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        }
        { $_ -in @("int", "long") } {
            # Heuristic ranges based on column name
            if ($nameLower -match 'port') { return Get-Random -Minimum 1 -Maximum 65535 }
            if ($nameLower -match 'status|code|response') { return (200, 201, 301, 302, 400, 401, 403, 404, 500, 502, 503 | Get-Random) }
            if ($nameLower -match 'count|total') { return Get-Random -Minimum 1 -Maximum 1000 }
            if ($nameLower -match 'duration|latency|elapsed') { return Get-Random -Minimum 1 -Maximum 30000 }
            if ($nameLower -match 'size|length|bytes') { return Get-Random -Minimum 64 -Maximum 1048576 }
            if ($nameLower -match 'severity|level|priority') { return Get-Random -Minimum 0 -Maximum 5 }
            return Get-Random -Minimum 0 -Maximum 10000
        }
        "real" {
            if ($nameLower -match 'percent|ratio|confidence') {
                return [math]::Round((Get-Random -Minimum 0 -Maximum 10000) / 100.0, 2)
            }
            return [math]::Round((Get-Random -Minimum 0 -Maximum 100000) / 100.0, 2)
        }
        { $_ -in @("bool", "boolean") } {
            return ((Get-Random -Minimum 0 -Maximum 100) -lt 70)
        }
        "dynamic" {
            return @{}
        }
        "guid" {
            return [guid]::NewGuid().ToString()
        }
        default {
            # String - generate contextual value based on column name
            if ($nameLower -match 'result|outcome') {
                return ("Success", "Failure", "Partial", "NA" | Get-Random)
            }
            if ($nameLower -match 'action|operation') {
                return ("Create", "Read", "Update", "Delete", "Execute", "Login", "Logout" | Get-Random)
            }
            if ($nameLower -match 'protocol') {
                return ("TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP", "TLS" | Get-Random)
            }
            if ($nameLower -match 'severity') {
                return ("Informational", "Low", "Medium", "High" | Get-Random)
            }
            if ($nameLower -match 'method') {
                return ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD" | Get-Random)
            }
            if ($nameLower -match 'useragent') {
                return ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                        "curl/8.4.0",
                        "python-requests/2.31.0" | Get-Random)
            }
            if ($nameLower -match 'country|region|geo') {
                return ("US", "GB", "DE", "FR", "JP", "AU", "CA", "BR", "IN", "NL" | Get-Random)
            }
            # Generic string
            $chars = "abcdefghijklmnopqrstuvwxyz0123456789"
            $len = Get-Random -Minimum 8 -Maximum 24
            return -join (1..$len | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
        }
    }
}

function New-SampleRecords {
    param(
        [object[]]$ColumnDefinitions,
        [object]$Entities,
        [int]$Count,
        [int]$WindowMinutes,
        [object[]]$SampleData
    )

    # Build per-column value pools from sample data
    $samplePools = @{}
    if ($SampleData -and $SampleData.Count -gt 0) {
        foreach ($col in $ColumnDefinitions) {
            $values = @($SampleData | ForEach-Object {
                $val = $_.PSObject.Properties[$col.name]
                if ($val) { $val.Value }
            } | Where-Object { $null -ne $_ -and $_ -ne "" })
            if ($values.Count -gt 0) {
                $samplePools[$col.name] = $values
            }
        }
    }

    $records = @()
    for ($i = 0; $i -lt $Count; $i++) {
        $record = [ordered]@{}

        foreach ($col in $ColumnDefinitions) {
            $colName = $col.name
            $colType = if ($col.type) { $col.type } else { "string" }

            # Priority 1: TimeGenerated always gets a fresh timestamp
            if ($colName -eq "TimeGenerated") {
                $offsetSeconds = Get-Random -Minimum 0 -Maximum ($WindowMinutes * 60)
                $record[$colName] = (Get-Date).ToUniversalTime().AddSeconds(-$offsetSeconds).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                continue
            }

            # Priority 2: Schema-defined values (enum hints)
            if ($col.PSObject.Properties['values'] -and $col.values.Count -gt 0) {
                $record[$colName] = (Get-Random -InputObject $col.values)
                continue
            }

            # Priority 3: Sample data pool (most realistic)
            if ($samplePools.ContainsKey($colName)) {
                $record[$colName] = ($samplePools[$colName] | Get-Random)
                continue
            }

            # Priority 4: Entity mapping
            $entityType = Get-EntityColumnMapping -ColumnName $colName
            if ($entityType) {
                $entityVal = Get-EntityValue -EntityType $entityType -Entities $Entities
                if ($null -ne $entityVal) {
                    $record[$colName] = $entityVal
                    continue
                }
            }

            # Priority 5: Type-based random generation
            $record[$colName] = New-RandomValueForType -ColumnType $colType -ColumnName $colName -WindowMinutes $WindowMinutes
        }

        $records += [pscustomobject]$record
    }

    return $records
}

# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
function Get-JsonByteCount {
    param([string]$Json)
    return [System.Text.Encoding]::UTF8.GetByteCount($Json)
}

function Split-RecordsBySize {
    param(
        [array]$Records,
        [int]$MaxBytes = 900000
    )

    $current = @()
    $currentSize = 2  # []

    foreach ($record in $Records) {
        $recordJson = $record | ConvertTo-Json -Depth 20 -Compress
        $recordSize = (Get-JsonByteCount -Json $recordJson) + 1

        if (($currentSize + $recordSize) -gt $MaxBytes -and $current.Count -gt 0) {
            , $current
            $current = @()
            $currentSize = 2
        }

        $current += $record
        $currentSize += $recordSize
    }

    if ($current.Count -gt 0) {
        , $current
    }
}

function Get-IngestHttpClient {
    # PowerShell 7.6 ships on .NET 9, which prefers TLS 1.3 for outbound HTTPS.
    # The Azure Monitor Logs Ingestion DCE endpoint has been observed to fail the
    # TLS 1.3 handshake ("Received an unexpected EOF or 0 bytes from the transport
    # stream"). Invoke-RestMethod -SslProtocol Tls12 does not reliably override
    # the underlying handler in .NET 9, so we use a SocketsHttpHandler that
    # explicitly pins SslProtocols to Tls12.
    if (-not (Get-Variable -Scope Script -Name '__ingestHttpClient' -ErrorAction SilentlyContinue) -or -not $script:__ingestHttpClient) {
        $handler = [System.Net.Http.SocketsHttpHandler]::new()
        $sslOpts = [System.Net.Security.SslClientAuthenticationOptions]::new()
        $sslOpts.EnabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
        $handler.SslOptions = $sslOpts
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromMinutes(2)
        $script:__ingestHttpClient = $client
    }
    return $script:__ingestHttpClient
}

function Invoke-IngestionPost {
    param(
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Body
    )
    $client = Get-IngestHttpClient
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $Uri)
    $req.Content = [System.Net.Http.StringContent]::new($Body, [System.Text.Encoding]::UTF8, "application/json")
    foreach ($k in $Headers.Keys) {
        if ($k -ieq 'Content-Type') { continue }
        if ($k -ieq 'Authorization') {
            $req.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::Parse([string]$Headers[$k])
        } else {
            $null = $req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k])
        }
    }
    try {
        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
    } finally {
        $req.Dispose()
    }
    $content = $null
    try { $content = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() } catch { }
    $retryAfter = $null
    try {
        if ($resp.Headers.RetryAfter) {
            if ($resp.Headers.RetryAfter.Delta -and $resp.Headers.RetryAfter.Delta.HasValue) {
                $retryAfter = [int]$resp.Headers.RetryAfter.Delta.Value.TotalSeconds
            } elseif ($resp.Headers.RetryAfter.Date -and $resp.Headers.RetryAfter.Date.HasValue) {
                $retryAfter = [int]($resp.Headers.RetryAfter.Date.Value - [DateTimeOffset]::UtcNow).TotalSeconds
            }
        }
    } catch { }
    $statusCode = [int]$resp.StatusCode
    $isSuccess = $resp.IsSuccessStatusCode
    $resp.Dispose()
    return [pscustomobject]@{
        StatusCode = $statusCode
        IsSuccess  = $isSuccess
        Content    = $content
        RetryAfter = $retryAfter
    }
}

function Send-Records {
    param(
        [string]$IngestionEndpoint,
        [string]$ImmutableId,
        [string]$StreamName,
        [array]$Records,
        [string]$AccessToken
    )

    if (-not $Records -or $Records.Count -eq 0) {
        Write-Host "No records to send." -ForegroundColor Yellow
        return
    }

    $apiVersion = "2023-01-01"
    $uri = "$IngestionEndpoint/dataCollectionRules/$ImmutableId/streams/${StreamName}?api-version=$apiVersion"
    $headers = @{
        Authorization  = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }

    $batches = @(Split-RecordsBySize -Records $Records)
    $totalSent = 0

    foreach ($batch in $batches) {
        $payload = $batch | ConvertTo-Json -Depth 20 -Compress
        # Ensure payload is always a JSON array
        if (-not $payload.StartsWith("[")) {
            $payload = "[$payload]"
        }

        $attempt = 0
        $maxAttempts = 4
        while ($true) {
            $statusCode = $null
            $responseBody = $null
            $retryAfterSeconds = $null
            $isTransportError = $false
            $transportMessage = $null

            try {
                $headers["x-ms-client-request-id"] = [guid]::NewGuid().ToString()
                $result = Invoke-IngestionPost -Uri $uri -Headers $headers -Body $payload
                if ($result.IsSuccess) {
                    $totalSent += $batch.Count
                    break
                }
                $statusCode = $result.StatusCode
                $responseBody = $result.Content
                $retryAfterSeconds = $result.RetryAfter
            } catch {
                $isTransportError = $true
                $transportMessage = $_.Exception.Message
                $inner = $_.Exception.InnerException
                while ($inner) { $transportMessage = "$transportMessage --> $($inner.Message)"; $inner = $inner.InnerException }
            }

            $isInvalidStream = ($responseBody -and $responseBody -match "InvalidStream")
            $isRetryable = ($statusCode -in @(429, 500, 502, 503, 504)) -or $isTransportError

            if (($isInvalidStream -or $isRetryable) -and $attempt -lt ($maxAttempts - 1)) {
                $attempt++
                $delaySeconds = if ($retryAfterSeconds -and $retryAfterSeconds -gt 0) { $retryAfterSeconds } else { [math]::Min(30, [math]::Pow(2, $attempt)) }
                if ($isInvalidStream) {
                    Write-Host "InvalidStream - waiting for DCR propagation (attempt $attempt/$maxAttempts)..." -ForegroundColor Yellow
                } elseif ($isTransportError) {
                    Write-Host "Transport error: $transportMessage. Retrying in $delaySeconds s (attempt $attempt/$maxAttempts)..." -ForegroundColor Yellow
                } else {
                    Write-Host "Transient error (status $statusCode). Retrying in $delaySeconds s (attempt $attempt/$maxAttempts)..." -ForegroundColor Yellow
                }
                Start-Sleep -Seconds $delaySeconds
                continue
            }

            $msg = if ($isTransportError) { $transportMessage } else { "HTTP $statusCode" }
            Write-Host "Ingestion failed: $msg" -ForegroundColor Red
            if ($responseBody) { Write-Host "Response: $responseBody" -ForegroundColor Red }
            throw "Ingestion failed: $msg"
        }
    }

    Write-Host "Successfully ingested $totalSent records in $($batches.Count) batch(es)." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# MAIN ORCHESTRATION
# ---------------------------------------------------------------------------

Assert-AzCli | Out-Null

# --- Read configuration ---
$ws = Read-WorkspaceConfig -ConfigPath $WorkspaceConfig
Write-Host "Workspace: $($ws.WorkspaceName) (subscription $($ws.SubscriptionId))" -ForegroundColor Cyan

$entities = Read-EntitiesConfig -Path $EntitiesFile
Write-Host "Loaded entity pools: $($entities.users.Count) users, $($entities.ipAddresses.Count) IPs, $($entities.devices.Count) devices" -ForegroundColor Cyan

# --- Read schema ---
if (-not $Schema -and -not $SampleDataFile) {
    throw "Provide -Schema (column definitions JSON) or -SampleDataFile (sample rows to infer schema from)."
}

$columnDefs = $null
$sampleData = $null
$schemaTransformKql = $null

if ($Schema) {
    $columnDefs = Read-SchemaFile -Path $Schema
    # Check for transformKql in schema file
    $schemaRaw = Get-Content -Path $Schema -Raw | ConvertFrom-Json
    if ($schemaRaw.PSObject.Properties['transformKql']) {
        $schemaTransformKql = $schemaRaw.transformKql
    }
    Write-Host "Loaded schema: $($columnDefs.Count) columns from $Schema" -ForegroundColor Cyan
}

if ($SampleDataFile) {
    $sampleData = Read-SampleData -Path $SampleDataFile
    Write-Host "Loaded $($sampleData.Count) sample rows from $SampleDataFile" -ForegroundColor Cyan

    # Infer schema from sample data if no explicit schema provided
    if (-not $columnDefs -and $sampleData.Count -gt 0) {
        $columnDefs = @()
        foreach ($prop in $sampleData[0].PSObject.Properties) {
            $inferredType = "string"
            $val = $prop.Value
            if ($val -is [bool]) { $inferredType = "boolean" }
            elseif ($val -is [int] -or $val -is [long]) { $inferredType = "long" }
            elseif ($val -is [double] -or $val -is [decimal]) { $inferredType = "real" }
            elseif ($val -is [datetime]) { $inferredType = "datetime" }
            elseif ($val -is [hashtable] -or $val -is [pscustomobject] -or $val -is [System.Array]) { $inferredType = "dynamic" }
            $columnDefs += @{ name = $prop.Name; type = $inferredType }
        }
        Write-Host "Inferred schema from sample data: $($columnDefs.Count) columns" -ForegroundColor Cyan
    }
}

if (-not $columnDefs) {
    throw "Could not determine column definitions. Provide -Schema or -SampleDataFile."
}

$isBuiltIn = Test-IsBuiltInTable -Name $TableName

# Variables shared between Deploy and Ingest phases
$immutableId       = $null
$ingestionEndpoint = $null
$streamName        = $null

# --- Deploy infrastructure ---
if ($Deploy) {
    Write-Host "`n--- Deploying infrastructure ---" -ForegroundColor Magenta

    $location = Resolve-WorkspaceLocation -WorkspaceResourceId $ws.WorkspaceResourceId
    Write-Host "Workspace location: $location" -ForegroundColor Cyan

    # 1. DCE
    $dce = Initialize-Dce -SubscriptionId $ws.SubscriptionId -ResourceGroupName $ws.ResourceGroup -Location $location -DceName $ws.DceName
    $dceId = $dce.id
    $ingestionEndpoint = $dce.properties.logsIngestion.endpoint

    # 2. Custom table (only for _CL tables)
    if (-not $isBuiltIn) {
        Initialize-CustomTable -WorkspaceResourceId $ws.WorkspaceResourceId -CustomTableName $TableName -ColumnDefinitions $columnDefs
    }

    # 3. DCR
    $dcrName = "sampledata-$($TableName -replace '_CL$', '' -replace '[^A-Za-z0-9-]', '-')"
    $dcrResult = New-DcrTemplate -TargetTableName $TableName -WorkspaceResourceId $ws.WorkspaceResourceId `
        -DceResourceId $dceId -Location $location -ColumnDefinitions $columnDefs -TransformKql $schemaTransformKql
    $dcrId = Initialize-Dcr -DcrName $dcrName -SubscriptionId $ws.SubscriptionId `
        -ResourceGroupName $ws.ResourceGroup -Template $dcrResult.Template
    $streamName = $dcrResult.StreamName

    $immutableId = Get-DcrImmutableId -DcrId $dcrId

    Write-Host "`nInfrastructure ready:" -ForegroundColor Green
    Write-Host "  DCE endpoint : $ingestionEndpoint"
    Write-Host "  DCR name     : $dcrName"
    Write-Host "  DCR immutable: $immutableId"
    Write-Host "  Stream       : $streamName"
    Write-Host "  Table        : $TableName"

    # RBAC: attempt auto-assignment of 'Monitoring Metrics Publisher' on the DCR.
    if ($SkipRoleAssignment) {
        Write-Host "`n[RBAC] -SkipRoleAssignment specified; skipping auto role assignment." -ForegroundColor Yellow
        Write-Host "[RBAC] Ensure you have 'Monitoring Metrics Publisher' role on the DCR:" -ForegroundColor Yellow
        Write-Host "  az role assignment create --role 'Monitoring Metrics Publisher' ``" -ForegroundColor Yellow
        Write-Host "    --assignee `"`$(az ad signed-in-user show --query id -o tsv)`" ``" -ForegroundColor Yellow
        Write-Host "    --scope '$dcrId'" -ForegroundColor Yellow
    } else {
        Grant-DcrPublisherRole -DcrId $dcrId
    }

    # Save deployment info for subsequent -Ingest runs
    $deploymentInfo = @{
        dceEndpoint   = $ingestionEndpoint
        dcrId         = $dcrId
        immutableId   = $immutableId
        streamName    = $streamName
        tableName     = $TableName
    }
    $deployInfoPath = Join-Path $basePath "schemas" "$($TableName).deploy.json"
    $deployInfoDir = Split-Path $deployInfoPath -Parent
    if (-not (Test-Path $deployInfoDir)) {
        New-Item -ItemType Directory -Path $deployInfoDir -Force | Out-Null
    }
    $deploymentInfo | ConvertTo-Json -Depth 5 | Out-File -FilePath $deployInfoPath -Encoding utf8
    Write-Host "Deployment info saved to: $deployInfoPath" -ForegroundColor Cyan
}

# --- Ingest data ---
if ($Ingest) {
    Write-Host "`n--- Generating and ingesting sample data ---" -ForegroundColor Magenta

    # Load deployment info if not already in memory
    if (-not $immutableId -or -not $ingestionEndpoint -or -not $streamName) {
        $deployInfoPath = Join-Path $basePath "schemas" "$($TableName).deploy.json"
        if (-not (Test-Path $deployInfoPath)) {
            throw "No deployment info found for '$TableName'. Run with -Deploy first, or provide deployment info."
        }
        $deployInfo = Get-Content -Path $deployInfoPath -Raw | ConvertFrom-Json
        $ingestionEndpoint = $deployInfo.dceEndpoint
        $immutableId       = $deployInfo.immutableId
        $streamName        = $deployInfo.streamName
    }

    # Get access token
    $token = Get-AccessToken -TokenTenantId $TenantId -TokenClientId $ClientId -TokenClientSecret $ClientSecret
    Write-Host "Access token acquired." -ForegroundColor Green

    # Generate sample records
    Write-Host "Generating $RowCount sample records..." -ForegroundColor Cyan
    $records = New-SampleRecords -ColumnDefinitions $columnDefs -Entities $entities `
        -Count $RowCount -WindowMinutes $TimeWindowMinutes -SampleData $sampleData
    Write-Host "Generated $($records.Count) records." -ForegroundColor Green

    # Send to Log Ingestion API
    Write-Host "Ingesting into '$TableName' via stream '$streamName'..." -ForegroundColor Cyan
    Send-Records -IngestionEndpoint $ingestionEndpoint -ImmutableId $immutableId `
        -StreamName $streamName -Records $records -AccessToken $token

    Write-Host "`nData ingestion complete. It may take 5-10 minutes for data to appear in Log Analytics." -ForegroundColor Green
    $queryWindowMinutes = [Math]::Max(60, $TimeWindowMinutes + 15)
    Write-Host "KQL query for Sentinel Logs:" -ForegroundColor Cyan
    Write-Host $TableName -ForegroundColor DarkCyan
    Write-Host ("| where TimeGenerated > ago(" + $queryWindowMinutes + "m)") -ForegroundColor DarkCyan
    Write-Host "| order by TimeGenerated desc" -ForegroundColor DarkCyan
}

if (-not $Deploy -and -not $Ingest) {
    Write-Host "No action specified. Use -Deploy, -Ingest, or both." -ForegroundColor Yellow
}

Write-Host "`nDone." -ForegroundColor Green
