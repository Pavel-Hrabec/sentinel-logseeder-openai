<#
.SYNOPSIS
Orchestrate multi-table attack scenario ingestion into Microsoft Sentinel.

.DESCRIPTION
Reads an attack scenario definition (JSON) that describes correlated events across
multiple Log Analytics tables with a coherent timeline, shared actors, and realistic
attack phases. Deploys infrastructure (DCE, DCR, custom tables) for each table and
ingests time-correlated, entity-linked sample data.

.REQUIREMENTS
- Azure CLI (az) installed and authenticated via 'az login'.
- 'Monitoring Metrics Publisher' RBAC role on each DCR for the signed-in user.
- The single-table ingestion script (Invoke-SampleDataIngestion.ps1) in the same directory.

.PARAMETER ScenarioFile
Path to the attack scenario JSON definition.

.PARAMETER WorkspaceConfig
Path to workspace.json. Default: config/workspace.json relative to project root.

.PARAMETER EntitiesFile
Path to entities.json. Default: config/entities.json relative to project root.

.PARAMETER Deploy
When specified, creates or reuses DCE, DCR, and custom table resources for all tables in the scenario.

.PARAMETER Ingest
When specified, generates correlated sample data and ingests it across all tables.

.PARAMETER TimeWindowHours
Total time window for the scenario timeline. Default: 4 hours.

.PARAMETER TenantId
Microsoft Entra tenant ID for service principal auth (optional).

.PARAMETER ClientId
Service principal application (client) ID (optional).

.PARAMETER ClientSecret
Service principal client secret (optional).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScenarioFile,

    [string]$WorkspaceConfig,

    [string]$EntitiesFile,

    [switch]$Deploy,

    [switch]$Ingest,

    [int]$TimeWindowHours = 4,

    [string]$TenantId,

    [string]$ClientId,

    [string]$ClientSecret
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
$basePath = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { (Get-Location).Path }
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Join-Path $basePath "scripts" }

if (-not $WorkspaceConfig) {
    $WorkspaceConfig = Join-Path $basePath "config" "workspace.json"
}
if (-not $EntitiesFile) {
    $EntitiesFile = Join-Path $basePath "config" "entities.json"
}

$singleTableScript = Join-Path $scriptDir "Invoke-SampleDataIngestion.ps1"
if (-not (Test-Path $singleTableScript)) {
    throw "Invoke-SampleDataIngestion.ps1 not found at: $singleTableScript"
}

# Load shared workspace-context resolver
. (Join-Path $scriptDir "_WorkspaceContext.ps1")

# ---------------------------------------------------------------------------
# Load scenario definition
# ---------------------------------------------------------------------------
if (-not (Test-Path $ScenarioFile)) {
    throw "Scenario file not found: $ScenarioFile"
}

$scenario = Get-Content -Path $ScenarioFile -Raw | ConvertFrom-Json
Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host " Attack Scenario: $($scenario.name)" -ForegroundColor Magenta
Write-Host " $($scenario.description)" -ForegroundColor DarkGray
Write-Host "========================================`n" -ForegroundColor Magenta

# ---------------------------------------------------------------------------
# Load entities and resolve actors
# ---------------------------------------------------------------------------
if (-not (Test-Path $EntitiesFile)) {
    throw "Entities file not found: $EntitiesFile"
}
$entities = Get-Content -Path $EntitiesFile -Raw | ConvertFrom-Json

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

function Resolve-ActorValue {
    param(
        [string]$ActorType,
        [string]$Value,
        [object]$Entities
    )

    if ($Value -eq "random" -or $Value -eq $null) {
        switch ($ActorType) {
            "ip" {
                return ($Entities.ipAddresses | Get-Random).address
            }
            "username" {
                return ($Entities.users | Get-Random).username
            }
            "upn" {
                return ($Entities.users | Get-Random).upn
            }
            "device" {
                return ($Entities.devices | Get-Random).hostname
            }
            "deviceFqdn" {
                return ($Entities.devices | Get-Random).fqdn
            }
            "domain" {
                return ($Entities.domains | Get-Random)
            }
            "url" {
                return ($Entities.urls | Get-Random)
            }
            default {
                return $Value
            }
        }
    }
    if ($Value -eq "external") {
        $external = $Entities.ipAddresses | Where-Object { $_.type -eq "external" }
        if ($external) { return ($external | Get-Random).address }
        return ($Entities.ipAddresses | Get-Random).address
    }
    if ($Value -eq "internal") {
        $internal = $Entities.ipAddresses | Where-Object { $_.type -eq "internal" }
        if ($internal) { return ($internal | Get-Random).address }
        return ($Entities.ipAddresses | Get-Random).address
    }
    return $Value
}

# Resolve all actors to concrete values for this run
$resolvedActors = @{}
if ($scenario.actors) {
    foreach ($actorProp in $scenario.actors.PSObject.Properties) {
        $actorName = $actorProp.Name
        $actorDef = $actorProp.Value
        $resolved = @{}

        foreach ($fieldProp in $actorDef.PSObject.Properties) {
            $fieldName = $fieldProp.Name
            $fieldValue = $fieldProp.Value
            $resolved[$fieldName] = Resolve-ActorValue -ActorType $fieldName -Value $fieldValue -Entities $entities
        }

        $resolvedActors[$actorName] = $resolved
        Write-Host "Actor '$actorName': $($resolved | ConvertTo-Json -Compress)" -ForegroundColor Cyan
    }
}

# ---------------------------------------------------------------------------
# Phase 1: Deploy infrastructure for each table
# ---------------------------------------------------------------------------
$tableSchemas = @{}
$tableNames = @()

# Collect all tables from the scenario
foreach ($tableProp in $scenario.tables.PSObject.Properties) {
    $tableName = $tableProp.Name
    $tableConfig = $tableProp.Value
    $tableNames += $tableName

    $schemaPath = $tableConfig.schema
    if (-not [System.IO.Path]::IsPathRooted($schemaPath)) {
        $schemaPath = Join-Path $basePath $schemaPath
    }

    if (-not (Test-Path $schemaPath)) {
        Write-Host "WARNING: Schema file not found for '$tableName': $schemaPath" -ForegroundColor Yellow
        Write-Host "  The agent should create this schema file before running the scenario." -ForegroundColor Yellow
        continue
    }

    $tableSchemas[$tableName] = @{
        SchemaPath = $schemaPath
        RowCount   = if ($tableConfig.rowCount) { $tableConfig.rowCount } else { 50 }
        SamplePath = if ($tableConfig.PSObject.Properties['sampleDataFile'] -and $tableConfig.sampleDataFile) {
            $sp = $tableConfig.sampleDataFile
            if (-not [System.IO.Path]::IsPathRooted($sp)) { Join-Path $basePath $sp } else { $sp }
        } else { $null }
    }
}

if ($Deploy) {
    Write-Host "`n--- Phase 1: Deploying infrastructure for $($tableNames.Count) tables ---`n" -ForegroundColor Magenta

    foreach ($tableName in $tableNames) {
        if (-not $tableSchemas.ContainsKey($tableName)) {
            Write-Host "Skipping '$tableName' - no schema file." -ForegroundColor Yellow
            continue
        }

        $tbl = $tableSchemas[$tableName]
        Write-Host "`n>> Deploying infrastructure for: $tableName" -ForegroundColor Cyan

        $deployArgs = @{
            TableName       = $tableName
            Schema          = $tbl.SchemaPath
            WorkspaceConfig = $WorkspaceConfig
            EntitiesFile    = $EntitiesFile
            Deploy          = $true
        }
        if ($tbl.SamplePath -and (Test-Path $tbl.SamplePath)) {
            $deployArgs["SampleDataFile"] = $tbl.SamplePath
        }

        & $singleTableScript @deployArgs
        Write-Host "Infrastructure deployed for '$tableName'.`n" -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# Phase 2: Generate and ingest correlated data per timeline phase
# ---------------------------------------------------------------------------
if ($Ingest) {
    Write-Host "`n--- Phase 2: Generating and ingesting attack scenario data ---`n" -ForegroundColor Magenta

    # Calculate the scenario anchor time (now minus the time window)
    $scenarioStart = (Get-Date).ToUniversalTime().AddHours(-$TimeWindowHours)
    Write-Host "Scenario base TimeGenerated (UTC): $($scenarioStart.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))  (TimeWindowHours=$TimeWindowHours)" -ForegroundColor DarkCyan

    # Group timeline phases by table so we can batch-generate
    $tableRecords = @{}
    foreach ($tableName in $tableNames) {
        $tableRecords[$tableName] = @()
    }

    foreach ($phase in $scenario.timeline) {
        $tableName = $phase.table
        $phaseStart = $scenarioStart.AddMinutes($phase.offsetMinutes)
        $phaseDuration = if ($phase.durationMinutes) { $phase.durationMinutes } else { 5 }
        $phaseCount = if ($phase.count) { $phase.count } else { 10 }

        Write-Host "Phase: $($phase.phase) | Table: $tableName | Events: $phaseCount | Offset: +$($phase.offsetMinutes)m" -ForegroundColor DarkCyan

        if (-not $tableSchemas.ContainsKey($tableName)) {
            Write-Host "  Skipping - no schema for '$tableName'" -ForegroundColor Yellow
            continue
        }

        # Load schema columns
        $schemaRaw = Get-Content -Path $tableSchemas[$tableName].SchemaPath -Raw | ConvertFrom-Json
        $columns = if ($schemaRaw.columns) { @($schemaRaw.columns) } else { @($schemaRaw) }

        # Generate records for this phase
        for ($i = 0; $i -lt $phaseCount; $i++) {
            $record = [ordered]@{}

            # Generate timestamp within the phase window
            $offsetSeconds = Get-Random -Minimum 0 -Maximum ([math]::Max(1, $phaseDuration * 60))
            $eventTime = $phaseStart.AddSeconds($offsetSeconds)
            $record["TimeGenerated"] = $eventTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

            foreach ($col in $columns) {
                $colName = $col.name
                if ($colName -eq "TimeGenerated") { continue }

                $value = $null

                # Check if the event template specifies this field
                if ($phase.eventTemplate -and $phase.eventTemplate.PSObject.Properties[$colName]) {
                    $templateValue = $phase.eventTemplate.$colName

                    # Check for actor references like "{{attacker.ip}}"
                    if ($templateValue -is [string] -and $templateValue -match '^\{\{(\w+)\.(\w+)\}\}$') {
                        $actorName = $Matches[1]
                        $actorField = $Matches[2]
                        if ($resolvedActors.ContainsKey($actorName) -and $resolvedActors[$actorName].ContainsKey($actorField)) {
                            $value = $resolvedActors[$actorName][$actorField]
                        }
                    }
                    # Check for array values (random selection)
                    elseif ($templateValue -is [System.Array]) {
                        $value = $templateValue | Get-Random
                    }
                    else {
                        $value = $templateValue
                    }
                }

                # Fall back to schema-defined values
                if ($null -eq $value -and $col.PSObject.Properties['values'] -and $col.values -and $col.values.Count -gt 0) {
                    $value = $col.values | Get-Random
                }

                # Fall back to entity mapping
                if ($null -eq $value) {
                    $nameLower = $colName.ToLowerInvariant()
                    if ($nameLower -match '(ipaddr|ipaddress|sourceip|destip|callerip|clientip|remoteip|srcip|dstip|_ip$|^ip$)') {
                        $value = ($entities.ipAddresses | Get-Random).address
                    }
                    elseif ($nameLower -match '(username|userid|accountname|actorname|principalname)') {
                        $value = ($entities.users | Get-Random).username
                    }
                    elseif ($nameLower -match '(upn|userprincipalname|mail$|email)') {
                        $value = ($entities.emailAddresses | Get-Random)
                    }
                    elseif ($nameLower -match '(hostname|computername|devicename|machinename|^computer$|^device$|^dvc$)') {
                        $value = ($entities.devices | Get-Random).hostname
                    }
                    elseif ($nameLower -match '(fqdn|fullyqualified)') {
                        $value = ($entities.devices | Get-Random).fqdn
                    }
                    elseif ($nameLower -match '(^url$|^uri$|requesturl|targeturl)') {
                        $value = ($entities.urls | Get-Random)
                    }
                    elseif ($nameLower -match '(^domain$|domainname)') {
                        $value = ($entities.domains | Get-Random)
                    }
                }

                # Fall back to type-based random
                if ($null -eq $value) {
                    $colType = if ($col.type) { $col.type } else { "string" }
                    switch ($colType.ToLowerInvariant()) {
                        "datetime" {
                            $value = $eventTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        }
                        { $_ -in @("int", "long") } {
                            $value = Get-Random -Minimum 0 -Maximum 10000
                        }
                        "real" {
                            $value = [math]::Round((Get-Random -Minimum 0 -Maximum 100000) / 100.0, 2)
                        }
                        { $_ -in @("bool", "boolean") } {
                            $value = ((Get-Random -Minimum 0 -Maximum 100) -lt 70)
                        }
                        "dynamic" {
                            $value = @{}
                        }
                        default {
                            if ($nameLower -match 'result|outcome') {
                                $value = ("Success", "Failure" | Get-Random)
                            }
                            elseif ($nameLower -match 'severity') {
                                $value = ("Informational", "Low", "Medium", "High" | Get-Random)
                            }
                            else {
                                $chars = "abcdefghijklmnopqrstuvwxyz0123456789"
                                $len = Get-Random -Minimum 8 -Maximum 16
                                $value = -join (1..$len | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
                            }
                        }
                    }
                }

                $record[$colName] = $value
            }

            $tableRecords[$tableName] += [pscustomobject]$record
        }
    }

    # Add background noise records for each table
    foreach ($tableName in $tableNames) {
        if (-not $tableSchemas.ContainsKey($tableName)) { continue }

        $tbl = $tableSchemas[$tableName]
        $phaseRecordCount = $tableRecords[$tableName].Count
        $targetTotal = $tbl.RowCount

        if ($phaseRecordCount -lt $targetTotal) {
            $noiseCount = $targetTotal - $phaseRecordCount
            Write-Host "Adding $noiseCount background noise records for '$tableName'..." -ForegroundColor DarkGray

            $schemaRaw = Get-Content -Path $tbl.SchemaPath -Raw | ConvertFrom-Json
            $columns = if ($schemaRaw.columns) { @($schemaRaw.columns) } else { @($schemaRaw) }

            # Load sample data if available
            $sampleData = $null
            if ($tbl.SamplePath -and (Test-Path $tbl.SamplePath)) {
                $extension = [System.IO.Path]::GetExtension($tbl.SamplePath).ToLowerInvariant()
                if ($extension -eq ".json") {
                    $sampleData = Get-Content -Path $tbl.SamplePath -Raw | ConvertFrom-Json
                    if ($sampleData -isnot [System.Array]) { $sampleData = @($sampleData) }
                }
            }

            # Build sample pools
            $samplePools = @{}
            if ($sampleData -and $sampleData.Count -gt 0) {
                foreach ($col in $columns) {
                    $values = @($sampleData | ForEach-Object {
                        $val = $_.PSObject.Properties[$col.name]
                        if ($val) { $val.Value }
                    } | Where-Object { $null -ne $_ -and $_ -ne "" })
                    if ($values.Count -gt 0) { $samplePools[$col.name] = $values }
                }
            }

            for ($i = 0; $i -lt $noiseCount; $i++) {
                $record = [ordered]@{}
                $offsetSeconds = Get-Random -Minimum 0 -Maximum ($TimeWindowHours * 3600)
                $record["TimeGenerated"] = $scenarioStart.AddSeconds($offsetSeconds).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

                foreach ($col in $columns) {
                    if ($col.name -eq "TimeGenerated") { continue }
                    $colName = $col.name
                    $colType = if ($col.type) { $col.type } else { "string" }

                    # Sample pool first
                    if ($samplePools.ContainsKey($colName)) {
                        $record[$colName] = ($samplePools[$colName] | Get-Random)
                        continue
                    }

                    # Schema values
                    if ($col.PSObject.Properties['values'] -and $col.values -and $col.values.Count -gt 0) {
                        $record[$colName] = ($col.values | Get-Random)
                        continue
                    }

                    # Entity mapping
                    $nameLower = $colName.ToLowerInvariant()
                    if ($nameLower -match '(ipaddr|sourceip|destip|callerip|clientip|srcip|dstip|_ip$|^ip$)') {
                        $record[$colName] = ($entities.ipAddresses | Get-Random).address; continue
                    }
                    if ($nameLower -match '(username|userid|accountname|principalname)') {
                        $record[$colName] = ($entities.users | Get-Random).username; continue
                    }
                    if ($nameLower -match '(hostname|computername|devicename|^computer$|^dvc$)') {
                        $record[$colName] = ($entities.devices | Get-Random).hostname; continue
                    }

                    # Type-based fallback
                    switch ($colType.ToLowerInvariant()) {
                        "datetime" { $record[$colName] = $scenarioStart.AddSeconds((Get-Random -Minimum 0 -Maximum ($TimeWindowHours * 3600))).ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
                        { $_ -in @("int", "long") } { $record[$colName] = Get-Random -Minimum 0 -Maximum 10000 }
                        "real" { $record[$colName] = [math]::Round((Get-Random -Minimum 0 -Maximum 10000) / 100.0, 2) }
                        { $_ -in @("bool", "boolean") } { $record[$colName] = ((Get-Random -Minimum 0 -Maximum 100) -lt 70) }
                        "dynamic" { $record[$colName] = @{} }
                        default {
                            if ($nameLower -match 'result') { $record[$colName] = "Success" }
                            elseif ($nameLower -match 'severity') { $record[$colName] = ("Informational", "Low" | Get-Random) }
                            else {
                                $chars = "abcdefghijklmnopqrstuvwxyz0123456789"
                                $len = Get-Random -Minimum 8 -Maximum 16
                                $record[$colName] = -join (1..$len | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
                            }
                        }
                    }
                }

                $tableRecords[$tableName] += [pscustomobject]$record
            }
        }
    }

    # Ingest records table by table
    Write-Host "`n--- Ingesting scenario data ---`n" -ForegroundColor Magenta

    # Read workspace config for token and deployment info
    $wsConfig = Resolve-WorkspaceContext -ConfigPath $WorkspaceConfig

    # Get access token
    $token = $null
    if ($TenantId -and $ClientId -and $ClientSecret) {
        $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $body = @{
            client_id     = $ClientId
            client_secret = $ClientSecret
            grant_type    = "client_credentials"
            scope         = "https://monitor.azure.com/.default"
        }
        $response = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
        $token = $response.access_token
    } else {
        try { $null = Get-Command az -ErrorAction Stop } catch {
            throw "Azure CLI (az) is required. Install from https://aka.ms/installazurecli"
        }
        $token = az account get-access-token --resource "https://monitor.azure.com/" --query accessToken -o tsv
    }

    if (-not $token) {
        throw "Failed to acquire access token."
    }
    Write-Host "Access token acquired." -ForegroundColor Green

    foreach ($tableName in $tableNames) {
        $records = $tableRecords[$tableName]
        if (-not $records -or $records.Count -eq 0) {
            Write-Host "No records for '$tableName' - skipping." -ForegroundColor Yellow
            continue
        }

        # Load deployment info
        $deployInfoPath = Join-Path $basePath "schemas" "$($tableName).deploy.json"
        if (-not (Test-Path $deployInfoPath)) {
            Write-Host "No deployment info for '$tableName' - run with -Deploy first. Skipping." -ForegroundColor Yellow
            continue
        }

        $deployInfo = Get-Content -Path $deployInfoPath -Raw | ConvertFrom-Json

        Write-Host "`nIngesting $($records.Count) records into '$tableName'..." -ForegroundColor Cyan

        # Batch and send
        $apiVersion = "2023-01-01"
        $uri = "$($deployInfo.dceEndpoint)/dataCollectionRules/$($deployInfo.immutableId)/streams/$($deployInfo.streamName)?api-version=$apiVersion"
        $headers = @{
            Authorization  = "Bearer $token"
            "Content-Type" = "application/json"
        }

        # Split into batches under 1MB
        $current = @()
        $currentSize = 2
        $batches = @()

        foreach ($record in $records) {
            $recordJson = $record | ConvertTo-Json -Depth 20 -Compress
            $recordSize = [System.Text.Encoding]::UTF8.GetByteCount($recordJson) + 1

            if (($currentSize + $recordSize) -gt 900000 -and $current.Count -gt 0) {
                $batches += , $current
                $current = @()
                $currentSize = 2
            }
            $current += $record
            $currentSize += $recordSize
        }
        if ($current.Count -gt 0) { $batches += , $current }

        $totalSent = 0
        foreach ($batch in $batches) {
            $payload = $batch | ConvertTo-Json -Depth 20 -Compress
            if (-not $payload.StartsWith("[")) { $payload = "[$payload]" }

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
                        Write-Host "InvalidStream - waiting for DCR propagation ($attempt/$maxAttempts)..." -ForegroundColor Yellow
                    } elseif ($isTransportError) {
                        Write-Host "Transport error: $transportMessage. Retrying in $delaySeconds s ($attempt/$maxAttempts)..." -ForegroundColor Yellow
                    } else {
                        Write-Host "Transient error (status $statusCode). Retrying in $delaySeconds s ($attempt/$maxAttempts)..." -ForegroundColor Yellow
                    }
                    Start-Sleep -Seconds $delaySeconds
                    continue
                }

                $msg = if ($isTransportError) { $transportMessage } else { "HTTP $statusCode" }
                Write-Host "Ingestion failed for '$tableName': $msg" -ForegroundColor Red
                if ($responseBody) { Write-Host "Response: $responseBody" -ForegroundColor Red }
                throw "Ingestion failed for '$tableName': $msg"
            }
        }

        Write-Host "Ingested $totalSent records into '$tableName' ($($batches.Count) batch(es))." -ForegroundColor Green
    }

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host " Scenario '$($scenario.name)' ingestion complete!" -ForegroundColor Green
    Write-Host " Data may take 5-10 minutes to appear." -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Print a KQL query that can be pasted directly into Sentinel Logs.
    Write-Host "KQL query for Sentinel Logs:" -ForegroundColor Cyan
    $queryWindowHours = [Math]::Max(1, $TimeWindowHours + 1)
    Write-Host "union isfuzzy=true withsource=LogTable" -ForegroundColor DarkCyan
    $queryTables = @($tableNames | Sort-Object -Unique)
    for ($i = 0; $i -lt $queryTables.Count; $i++) {
        $suffix = if ($i -lt ($queryTables.Count - 1)) { "," } else { "" }
        Write-Host ("    {0}{1}" -f $queryTables[$i], $suffix) -ForegroundColor DarkCyan
    }
    Write-Host ("| where TimeGenerated > ago(" + $queryWindowHours + "h)") -ForegroundColor DarkCyan
    Write-Host "| order by TimeGenerated desc" -ForegroundColor DarkCyan
}

if (-not $Deploy -and -not $Ingest) {
    Write-Host "`nNo action specified. Use -Deploy, -Ingest, or both." -ForegroundColor Yellow
    Write-Host "`nScenario summary:" -ForegroundColor Cyan
    Write-Host "  Name:   $($scenario.name)" 
    Write-Host "  Tables: $($tableNames -join ', ')"
    Write-Host "  Phases: $($scenario.timeline.Count)"
    foreach ($phase in $scenario.timeline) {
        Write-Host "    [$($phase.phase)] +$($phase.offsetMinutes)m - $($phase.table) ($($phase.count) events)" -ForegroundColor DarkGray
    }
}

Write-Host "`nDone." -ForegroundColor Green
