Set-StrictMode -Version Latest

$script:ModuleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:ProjectRoot = Split-Path -Parent $script:ModuleRoot

$script:DefaultCategoryMap = @{
    Authentication = @{
        TableName = "ASimAuthenticationEventLogs"
        Schema = "schemas/ASimAuthenticationEventLogs.json"
        EventProduct = "Microsoft Entra ID"
        EventVendor = "Microsoft"
        EventSchema = "Authentication"
        EventSchemaVersion = "0.1.4"
    }
    ProcessEvent = @{
        TableName = "ASimProcessEventLogs"
        Schema = "schemas/ASimProcessEventLogs.json"
        EventProduct = "Windows"
        EventVendor = "Microsoft"
        EventSchema = "ProcessEvent"
        EventSchemaVersion = "0.1.4"
    }
    FileEvent = @{
        TableName = "ASimFileEventLogs"
        Schema = "schemas/ASimFileEventLogs.json"
        EventProduct = "Windows"
        EventVendor = "Microsoft"
        EventSchema = "FileEvent"
        EventSchemaVersion = "0.1.4"
    }
    RegistryEvent = @{
        TableName = "ASimRegistryEventLogs"
        Schema = "schemas/ASimRegistryEventLogs.json"
        EventProduct = "Windows"
        EventVendor = "Microsoft"
        EventSchema = "RegistryEvent"
        EventSchemaVersion = "0.1.4"
    }
    NetworkSession = @{
        TableName = "ASimNetworkSessionLogs"
        Schema = "schemas/ASimNetworkSessionLogs.json"
        EventProduct = "Firewall"
        EventVendor = "LogSeeder"
        EventSchema = "NetworkSession"
        EventSchemaVersion = "0.2.6"
    }
    Dns = @{
        TableName = "ASimDnsActivityLogs"
        Schema = "schemas/ASimDnsActivityLogs.json"
        EventProduct = "DNS Server"
        EventVendor = "Microsoft"
        EventSchema = "Dns"
        EventSchemaVersion = "0.1.7"
    }
    AuditEvent = @{
        TableName = "ASimAuditEventLogs"
        Schema = "schemas/ASimAuditEventLogs.json"
        EventProduct = "Azure"
        EventVendor = "Microsoft"
        EventSchema = "AuditEvent"
        EventSchemaVersion = "0.1.3"
    }
    UserManagement = @{
        TableName = "ASimUserManagementActivityLogs"
        Schema = "schemas/ASimUserManagementActivityLogs.json"
        EventProduct = "Microsoft Entra ID"
        EventVendor = "Microsoft"
        EventSchema = "UserManagement"
        EventSchemaVersion = "0.1.3"
    }
    WebSession = @{
        TableName = "ASimWebSessionLogs"
        Schema = "schemas/ASimWebSessionLogs.json"
        EventProduct = "Proxy"
        EventVendor = "LogSeeder"
        EventSchema = "WebSession"
        EventSchemaVersion = "0.2.6"
    }
    DHCP = @{
        TableName = "ASimDhcpEventLogs"
        Schema = "schemas/ASimDhcpEventLogs.json"
        EventProduct = "DHCP Server"
        EventVendor = "Microsoft"
        EventSchema = "Dhcp"
        EventSchemaVersion = "0.1.1"
    }
}

function Get-DefaultWorkspaceConfigPath {
    Join-Path (Join-Path $script:ProjectRoot "config") "workspace.json"
}

function Get-DefaultEntitiesPath {
    Join-Path (Join-Path $script:ProjectRoot "config") "entities.json"
}

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    return Join-Path $script:ProjectRoot $Path
}

function Read-Text {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [string]$Default
    )

    if ([string]::IsNullOrWhiteSpace($Default)) {
        $value = Read-Host $Prompt
    } else {
        $value = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($value)) {
            $value = $Default
        }
    }

    return $value
}

function Read-YesNo {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [bool]$DefaultYes = $true
    )

    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $value = Read-Host "$Prompt $suffix"
        if ([string]::IsNullOrWhiteSpace($value)) {
            return $DefaultYes
        }
        if ($value -match '^(y|yes)$') { return $true }
        if ($value -match '^(n|no)$') { return $false }
        Write-Host "Please enter y or n." -ForegroundColor Yellow
    }
}

function Read-Number {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [int]$Default,
        [int]$Minimum = 1,
        [int]$Maximum = 100000
    )

    while ($true) {
        $value = Read-Text -Prompt $Prompt -Default ([string]$Default)
        $parsed = 0
        if ([int]::TryParse($value, [ref]$parsed) -and $parsed -ge $Minimum -and $parsed -le $Maximum) {
            return $parsed
        }
        Write-Host "Enter a number between $Minimum and $Maximum." -ForegroundColor Yellow
    }
}

function Read-MenuChoice {
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][object[]]$Items,
        [switch]$AllowBack
    )

    Write-Host ""
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("-" * $Title.Length) -ForegroundColor DarkCyan

    for ($i = 0; $i -lt $Items.Count; $i++) {
        $item = $Items[$i]
        $line = "{0}. {1}" -f ($i + 1), $item.Label
        Write-Host $line -ForegroundColor White
        if ($item.PSObject.Properties['Description'] -and -not [string]::IsNullOrWhiteSpace($item.Description)) {
            Write-Host ("   " + $item.Description) -ForegroundColor DarkGray
        }
    }
    if ($AllowBack) {
        Write-Host "0. Back" -ForegroundColor DarkGray
    } else {
        Write-Host "0. Exit" -ForegroundColor DarkGray
    }

    while ($true) {
        $raw = Read-Host "Select"
        $choice = -1
        if ([int]::TryParse($raw, [ref]$choice)) {
            if ($choice -eq 0) { return $null }
            if ($choice -ge 1 -and $choice -le $Items.Count) {
                return $Items[$choice - 1]
            }
        }
        Write-Host "Choose a number from the list." -ForegroundColor Yellow
    }
}

function Get-OptionalPropertyValue {
    param(
        [object]$Object,
        [string]$Name,
        $Default = $null
    )

    if ($null -eq $Object) { return $Default }
    if ($Object.PSObject.Properties[$Name]) {
        return $Object.$Name
    }
    return $Default
}

function ConvertTo-PlainObject {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $hash = [ordered]@{}
        foreach ($prop in $Value.PSObject.Properties) {
            $hash[$prop.Name] = ConvertTo-PlainObject -Value $prop.Value
        }
        return $hash
    }

    if ($Value -is [System.Array]) {
        $items = @()
        foreach ($item in $Value) {
            $items += ,(ConvertTo-PlainObject -Value $item)
        }
        return $items
    }

    return $Value
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -Path $Path -Raw | ConvertFrom-Json
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Depth = 80
    )

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $InputObject | ConvertTo-Json -Depth $Depth | Out-File -FilePath $Path -Encoding utf8
}

function Ensure-WorkspaceConfig {
    param([string]$WorkspaceConfig)

    if ([string]::IsNullOrWhiteSpace($WorkspaceConfig)) {
        $WorkspaceConfig = Get-DefaultWorkspaceConfigPath
    }

    if (Test-Path $WorkspaceConfig) {
        return $WorkspaceConfig
    }

    Write-Host ""
    Write-Host "Workspace config was not found: $WorkspaceConfig" -ForegroundColor Yellow
    if (-not (Read-YesNo -Prompt "Create it now?" -DefaultYes $true)) {
        throw "Workspace config is required before running LogSeeder."
    }

    $workspaceName = Read-Text -Prompt "Log Analytics workspace name"
    $workspaceId = Read-Text -Prompt "Workspace customer ID (optional)"
    $subscriptionId = Read-Text -Prompt "Subscription ID (optional)"
    $resourceGroup = Read-Text -Prompt "Resource group (optional)"
    $dceName = Read-Text -Prompt "DCE name" -Default "sample-data-dce"

    $cfg = [ordered]@{}
    if (-not [string]::IsNullOrWhiteSpace($workspaceName)) { $cfg.workspaceName = $workspaceName }
    if (-not [string]::IsNullOrWhiteSpace($workspaceId)) { $cfg.workspaceId = $workspaceId }
    if (-not [string]::IsNullOrWhiteSpace($subscriptionId)) { $cfg.subscriptionId = $subscriptionId }
    if (-not [string]::IsNullOrWhiteSpace($resourceGroup)) { $cfg.resourceGroup = $resourceGroup }
    if (-not [string]::IsNullOrWhiteSpace($dceName)) { $cfg.dceName = $dceName }

    if (-not $cfg.Contains("workspaceName") -and -not $cfg.Contains("workspaceId")) {
        throw "Provide at least workspaceName or workspaceId."
    }

    Write-JsonFile -InputObject $cfg -Path $WorkspaceConfig -Depth 10
    Write-Host "Workspace config created: $WorkspaceConfig" -ForegroundColor Green
    return $WorkspaceConfig
}

function Get-ScenarioFiles {
    $scenarioDir = Join-Path $script:ProjectRoot "scenarios"
    $files = Get-ChildItem -Path $scenarioDir -Filter "*.json" -Recurse |
        Where-Object {
            $_.Name -ne "_template.json" -and
            $_.Name -notlike "*-runtime.json" -and
            $_.Name -notlike "*-openai-runtime.json"
        } |
        Sort-Object FullName

    return @($files)
}

function Get-ScenarioMenuItems {
    $items = @()
    foreach ($file in Get-ScenarioFiles) {
        try {
            $scenario = Read-JsonFile -Path $file.FullName
            $tables = @()
            if ($scenario.PSObject.Properties['tables']) {
                foreach ($tableProp in $scenario.tables.PSObject.Properties) {
                    $tables += $tableProp.Name
                }
            }
            $items += [pscustomobject]@{
                Label = $scenario.name
                Description = "$($scenario.description) Tables: $($tables -join ', ')"
                Value = $file.FullName
            }
        } catch {
            $items += [pscustomobject]@{
                Label = $file.BaseName
                Description = "Could not parse description."
                Value = $file.FullName
            }
        }
    }

    $items += [pscustomobject]@{
        Label = "Other / describe a scenario"
        Description = "Use OpenAI to turn a short idea into next steps."
        Value = "__other__"
    }
    return $items
}

function Show-ScenarioDetails {
    param([Parameter(Mandatory = $true)]$Scenario)

    Write-Host ""
    Write-Host $Scenario.name -ForegroundColor Cyan
    Write-Host $Scenario.description -ForegroundColor Gray

    if ($Scenario.PSObject.Properties['mitreIds']) {
        Write-Host ("MITRE: " + (@($Scenario.mitreIds) -join ", ")) -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "Tables:" -ForegroundColor Cyan
    foreach ($tableProp in $Scenario.tables.PSObject.Properties) {
        $rowCount = Get-OptionalPropertyValue -Object $tableProp.Value -Name "rowCount" -Default 50
        Write-Host ("  {0}: {1} rows target" -f $tableProp.Name, $rowCount)
    }

    Write-Host ""
    Write-Host "Timeline:" -ForegroundColor Cyan
    foreach ($phase in @($Scenario.timeline)) {
        Write-Host ("  +{0}m {1} -> {2} ({3} events)" -f $phase.offsetMinutes, $phase.phase, $phase.table, $phase.count)
    }
}

function Get-ScaleProfile {
    $items = @(
        [pscustomobject]@{ Label = "Tiny"; Description = "Very low cost. About 20 percent of scenario events, max 25 background rows per table."; Value = "tiny" },
        [pscustomobject]@{ Label = "Small"; Description = "Low cost. About 40 percent of scenario events, max 75 background rows per table."; Value = "small" },
        [pscustomobject]@{ Label = "Original"; Description = "Use the scenario counts from the repository."; Value = "original" }
    )
    $choice = Read-MenuChoice -Title "Volume" -Items $items -AllowBack
    if ($null -eq $choice) { return $null }

    switch ($choice.Value) {
        "tiny" { return @{ Name = "Tiny"; Factor = 0.20; MaxTableRows = 25 } }
        "small" { return @{ Name = "Small"; Factor = 0.40; MaxTableRows = 75 } }
        default { return @{ Name = "Original"; Factor = 1.0; MaxTableRows = 100000 } }
    }
}

function Scale-Count {
    param(
        [int]$Count,
        [double]$Factor,
        [int]$Maximum
    )

    if ($Count -lt 1) { $Count = 1 }
    $scaled = [int][Math]::Ceiling($Count * $Factor)
    if ($scaled -lt 1) { $scaled = 1 }
    if ($scaled -gt $Maximum) { $scaled = $Maximum }
    return $scaled
}

function Get-ManualScenarioMap {
    param([Parameter(Mandatory = $true)]$Scenario)

    $map = @{}
    Write-Host ""
    Write-Host "Manual table mapping" -ForegroundColor Cyan
    Write-Host "Leave values blank to use the default ASIM table where available." -ForegroundColor DarkGray

    foreach ($tableProp in $Scenario.tables.PSObject.Properties) {
        $category = $tableProp.Name
        $default = $script:DefaultCategoryMap[$category]
        $defaultTable = if ($default) { $default.TableName } else { $category }
        $defaultSchema = if ($default) { $default.Schema } else { "schemas/$category.json" }

        $tableName = Read-Text -Prompt "Target table for $category" -Default $defaultTable
        $schema = Read-Text -Prompt "Schema path for $tableName" -Default $defaultSchema

        $map[$category] = @{
            TableName = $tableName
            Schema = $schema
            EventProduct = "LogSeeder"
            EventVendor = "Synthetic"
            EventSchema = $category
            EventSchemaVersion = "1.0"
        }
    }

    return $map
}

function Get-ScenarioTableMap {
    param([Parameter(Mandatory = $true)]$Scenario)

    $items = @(
        [pscustomobject]@{ Label = "Use ASIM defaults"; Description = "Recommended low-friction mode. Uses ingestible ASIM normalized tables."; Value = "asim" },
        [pscustomobject]@{ Label = "Manual mapping"; Description = "Choose the destination table and schema for each scenario category."; Value = "manual" }
    )

    $choice = Read-MenuChoice -Title "Scenario Table Mapping" -Items $items -AllowBack
    if ($null -eq $choice) { return $null }

    if ($choice.Value -eq "manual") {
        return Get-ManualScenarioMap -Scenario $Scenario
    }

    $map = @{}
    foreach ($tableProp in $Scenario.tables.PSObject.Properties) {
        $category = $tableProp.Name
        if ($script:DefaultCategoryMap.ContainsKey($category)) {
            $map[$category] = $script:DefaultCategoryMap[$category]
        } else {
            $map[$category] = @{
                TableName = $category
                Schema = "schemas/$category.json"
                EventProduct = "LogSeeder"
                EventVendor = "Synthetic"
                EventSchema = $category
                EventSchemaVersion = "1.0"
            }
        }
    }
    return $map
}

function Add-MetadataToTemplate {
    param(
        [Parameter(Mandatory = $true)]$Template,
        [Parameter(Mandatory = $true)][hashtable]$MapEntry
    )

    foreach ($key in @("EventProduct", "EventVendor", "EventSchema", "EventSchemaVersion")) {
        if ($MapEntry.ContainsKey($key) -and -not $Template.Contains($key)) {
            $Template[$key] = $MapEntry[$key]
        }
    }
}

function New-RuntimeScenario {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][hashtable]$TableMap,
        [Parameter(Mandatory = $true)][hashtable]$ScaleProfile,
        [Parameter(Mandatory = $true)][string]$SourcePath
    )

    $phaseCountsByCategory = @{}
    $runtimeTimeline = @()

    foreach ($phase in @($Scenario.timeline)) {
        $category = $phase.table
        if (-not $TableMap.ContainsKey($category)) {
            throw "No table mapping for scenario category '$category'."
        }
        $mapEntry = $TableMap[$category]
        $phaseHash = ConvertTo-PlainObject -Value $phase
        $originalCount = [int](Get-OptionalPropertyValue -Object $phase -Name "count" -Default 10)
        $scaledCount = Scale-Count -Count $originalCount -Factor $ScaleProfile.Factor -Maximum $ScaleProfile.MaxTableRows
        $phaseHash["table"] = $mapEntry.TableName
        $phaseHash["count"] = $scaledCount

        if (-not $phaseHash.Contains("eventTemplate") -or $null -eq $phaseHash["eventTemplate"]) {
            $phaseHash["eventTemplate"] = [ordered]@{}
        }
        Add-MetadataToTemplate -Template $phaseHash["eventTemplate"] -MapEntry $mapEntry

        if (-not $phaseCountsByCategory.ContainsKey($category)) {
            $phaseCountsByCategory[$category] = 0
        }
        $phaseCountsByCategory[$category] += $scaledCount
        $runtimeTimeline += ,$phaseHash
    }

    $runtimeTables = [ordered]@{}
    foreach ($tableProp in $Scenario.tables.PSObject.Properties) {
        $category = $tableProp.Name
        if (-not $TableMap.ContainsKey($category)) {
            throw "No table mapping for scenario category '$category'."
        }

        $mapEntry = $TableMap[$category]
        $tableName = $mapEntry.TableName
        $originalRows = [int](Get-OptionalPropertyValue -Object $tableProp.Value -Name "rowCount" -Default 50)
        $scaledRows = Scale-Count -Count $originalRows -Factor $ScaleProfile.Factor -Maximum $ScaleProfile.MaxTableRows
        if ($phaseCountsByCategory.ContainsKey($category) -and $scaledRows -lt $phaseCountsByCategory[$category]) {
            $scaledRows = $phaseCountsByCategory[$category]
        }

        if ($runtimeTables.Contains($tableName)) {
            $runtimeTables[$tableName].rowCount = [int]$runtimeTables[$tableName].rowCount + $scaledRows
        } else {
            $runtimeTables[$tableName] = [ordered]@{
                schema = $mapEntry.Schema
                rowCount = $scaledRows
            }
        }
    }

    $runtimeName = "$($Scenario.name)-openai-runtime"
    $runtime = [ordered]@{
        name = $runtimeName
        description = "$($Scenario.description) Runtime generated by Start-LogSeederOpenAI.ps1 using $($ScaleProfile.Name) volume."
        sourceScenario = (Resolve-Path -Path $SourcePath).Path
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        tables = $runtimeTables
        actors = ConvertTo-PlainObject -Value $Scenario.actors
        timeline = $runtimeTimeline
    }

    if ($Scenario.PSObject.Properties['mitreTactics']) {
        $runtime.mitreTactics = @(ConvertTo-PlainObject -Value $Scenario.mitreTactics)
    }
    if ($Scenario.PSObject.Properties['mitreIds']) {
        $runtime.mitreIds = @(ConvertTo-PlainObject -Value $Scenario.mitreIds)
    }

    $runtimePath = Join-Path (Join-Path $script:ProjectRoot "scenarios") "$runtimeName.json"
    Write-JsonFile -InputObject $runtime -Path $runtimePath -Depth 100
    return $runtimePath
}

function Show-RuntimePlan {
    param([Parameter(Mandatory = $true)][string]$RuntimePath)

    $runtime = Read-JsonFile -Path $RuntimePath
    Write-Host ""
    Write-Host "Runtime scenario created:" -ForegroundColor Green
    Write-Host "  $RuntimePath"

    Write-Host ""
    Write-Host "Destination tables:" -ForegroundColor Cyan
    foreach ($tableProp in $runtime.tables.PSObject.Properties) {
        Write-Host ("  {0}: {1} target rows, schema {2}" -f $tableProp.Name, $tableProp.Value.rowCount, $tableProp.Value.schema)
    }

    Write-Host ""
    Write-Host "Timeline:" -ForegroundColor Cyan
    foreach ($phase in @($runtime.timeline)) {
        Write-Host ("  +{0}m {1} -> {2} ({3} events)" -f $phase.offsetMinutes, $phase.phase, $phase.table, $phase.count)
    }
}

function Build-NativeArgs {
    param([Parameter(Mandatory = $true)][hashtable]$Arguments)

    $nativeArgs = @()
    foreach ($key in $Arguments.Keys) {
        $value = $Arguments[$key]
        if ($value -is [bool]) {
            if ($value) { $nativeArgs += "-$key" }
        } elseif ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            $nativeArgs += "-$key"
            $nativeArgs += [string]$value
        }
    }
    return $nativeArgs
}

function Format-NativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string[]]$NativeArgs
    )

    $parts = @("pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$ScriptPath`"")
    foreach ($arg in $NativeArgs) {
        if ($arg -like "-*") {
            $parts += $arg
        } else {
            $parts += "`"$arg`""
        }
    }
    return ($parts -join " ")
}

function Invoke-LogSeederScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][hashtable]$Arguments,
        [switch]$PreviewOnly
    )

    $nativeArgs = Build-NativeArgs -Arguments $Arguments
    $commandText = Format-NativeCommand -ScriptPath $ScriptPath -NativeArgs $nativeArgs

    Write-Host ""
    Write-Host "Command:" -ForegroundColor Cyan
    Write-Host "  $commandText" -ForegroundColor DarkCyan

    if ($PreviewOnly) {
        Write-Host "Preview mode: command was not executed." -ForegroundColor Yellow
        return
    }

    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwsh) {
        & $pwsh.Source -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @nativeArgs
    } else {
        Write-Host "PowerShell 7 (pwsh) was not found. Falling back to the current PowerShell host." -ForegroundColor Yellow
        & $ScriptPath @Arguments
    }
}

function Get-RunMode {
    $items = @(
        [pscustomobject]@{ Label = "Deploy and ingest"; Description = "Create/reuse DCE, DCR, table resources, then ingest data."; Value = "deployIngest" },
        [pscustomobject]@{ Label = "Deploy only"; Description = "Prepare Azure resources but do not send log data."; Value = "deploy" },
        [pscustomobject]@{ Label = "Ingest only"; Description = "Use existing deployment info in schemas/*.deploy.json."; Value = "ingest" },
        [pscustomobject]@{ Label = "Preview command only"; Description = "Show the command without running Azure changes."; Value = "preview" }
    )
    return Read-MenuChoice -Title "Action" -Items $items -AllowBack
}

function Invoke-PrebuiltScenarioWorkflow {
    param(
        [string]$WorkspaceConfig,
        [string]$EntitiesFile,
        [switch]$PreviewOnly
    )

    $scenarioChoice = Read-MenuChoice -Title "Prebuilt Scenarios" -Items (Get-ScenarioMenuItems) -AllowBack
    if ($null -eq $scenarioChoice) { return }
    if ($scenarioChoice.Value -eq "__other__") {
        Invoke-OtherRequestWorkflow
        return
    }

    $scenario = Read-JsonFile -Path $scenarioChoice.Value
    Show-ScenarioDetails -Scenario $scenario

    $map = Get-ScenarioTableMap -Scenario $scenario
    if ($null -eq $map) { return }

    $scale = Get-ScaleProfile
    if ($null -eq $scale) { return }

    $runtimePath = New-RuntimeScenario -Scenario $scenario -TableMap $map -ScaleProfile $scale -SourcePath $scenarioChoice.Value
    Show-RuntimePlan -RuntimePath $runtimePath

    $mode = Get-RunMode
    if ($null -eq $mode) { return }

    $previewChoice = ($mode.Value -eq "preview")
    $runPreview = $PreviewOnly -or $previewChoice
    $deploy = $previewChoice -or ($mode.Value -eq "deploy" -or $mode.Value -eq "deployIngest")
    $ingest = $previewChoice -or ($mode.Value -eq "ingest" -or $mode.Value -eq "deployIngest")

    if ($ingest -and -not $runPreview) {
        Write-Host ""
        Write-Host "Cost guard: this will ingest billable Log Analytics/Sentinel data." -ForegroundColor Yellow
        if (-not (Read-YesNo -Prompt "Continue?" -DefaultYes $false)) { return }
    }

    $scriptPath = Join-Path $script:ModuleRoot "Invoke-AttackScenarioIngestion.ps1"
    $args = @{
        ScenarioFile = $runtimePath
        WorkspaceConfig = $WorkspaceConfig
        EntitiesFile = $EntitiesFile
        Deploy = $deploy
        Ingest = $ingest
        TimeWindowHours = 4
    }
    Invoke-LogSeederScript -ScriptPath $scriptPath -Arguments $args -PreviewOnly:$runPreview
}

function Get-CommonSchemaItems {
    $schemaDir = Join-Path $script:ProjectRoot "schemas"
    $preferred = @(
        "ASimAuthenticationEventLogs",
        "ASimProcessEventLogs",
        "ASimNetworkSessionLogs",
        "ASimFileEventLogs",
        "ASimRegistryEventLogs",
        "ASimDnsActivityLogs",
        "ASimAuditEventLogs",
        "ASimUserManagementActivityLogs",
        "SecurityEvent",
        "CommonSecurityLog",
        "AWSCloudTrail",
        "AWSGuardDuty",
        "OktaV2_CL"
    )

    $items = @()
    foreach ($name in $preferred) {
        $path = Join-Path $schemaDir "$name.json"
        if (Test-Path $path) {
            $items += [pscustomobject]@{ Label = $name; Description = "Schema: schemas/$name.json"; Value = $path }
        }
    }
    $items += [pscustomobject]@{ Label = "Other table/schema"; Description = "Type a table name and schema path manually."; Value = "__other__" }
    return $items
}

function Invoke-SingleTableWorkflow {
    param(
        [string]$WorkspaceConfig,
        [string]$EntitiesFile,
        [switch]$PreviewOnly
    )

    $choice = Read-MenuChoice -Title "Single Table Sample Data" -Items (Get-CommonSchemaItems) -AllowBack
    if ($null -eq $choice) { return }

    if ($choice.Value -eq "__other__") {
        $tableName = Read-Text -Prompt "Table name"
        $schemaPath = Read-Text -Prompt "Schema path" -Default "schemas/$tableName.json"
        $schemaPath = Resolve-RepoPath -Path $schemaPath
    } else {
        $schemaPath = $choice.Value
        $tableName = [System.IO.Path]::GetFileNameWithoutExtension($schemaPath)
    }

    if (-not (Test-Path $schemaPath)) {
        Write-Host "Schema not found: $schemaPath" -ForegroundColor Red
        return
    }

    $rowCount = Read-Number -Prompt "Rows to generate" -Default 25 -Minimum 1 -Maximum 100000
    $mode = Get-RunMode
    if ($null -eq $mode) { return }

    $previewChoice = ($mode.Value -eq "preview")
    $runPreview = $PreviewOnly -or $previewChoice
    $deploy = $previewChoice -or ($mode.Value -eq "deploy" -or $mode.Value -eq "deployIngest")
    $ingest = $previewChoice -or ($mode.Value -eq "ingest" -or $mode.Value -eq "deployIngest")

    if ($ingest -and -not $runPreview) {
        Write-Host ""
        Write-Host "Cost guard: this will ingest $rowCount billable rows into $tableName." -ForegroundColor Yellow
        if (-not (Read-YesNo -Prompt "Continue?" -DefaultYes $false)) { return }
    }

    $scriptPath = Join-Path $script:ModuleRoot "Invoke-SampleDataIngestion.ps1"
    $args = @{
        TableName = $tableName
        Schema = $schemaPath
        RowCount = $rowCount
        WorkspaceConfig = $WorkspaceConfig
        EntitiesFile = $EntitiesFile
        Deploy = $deploy
        Ingest = $ingest
        TimeWindowMinutes = 30
    }
    Invoke-LogSeederScript -ScriptPath $scriptPath -Arguments $args -PreviewOnly:$runPreview
}

function Test-OpenAIConfigured {
    if (-not [string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY)) { return $true }
    if (-not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_ENDPOINT) -and
        -not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_DEPLOYMENT) -and
        (-not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_API_KEY) -or -not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_AUTH_TOKEN))) {
        return $true
    }
    return $false
}

function Test-AzureOpenAIConfigured {
    return (-not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_ENDPOINT) -and
        -not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_DEPLOYMENT) -and
        (-not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_API_KEY) -or -not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_AUTH_TOKEN)))
}

function Get-OpenAIEndpoint {
    if (Test-AzureOpenAIConfigured) {
        $base = $env:AZURE_OPENAI_ENDPOINT.TrimEnd("/")
        if ($base -notmatch '/openai/v1$') {
            $base = "$base/openai/v1"
        }
        return "$base/responses"
    }

    if (-not [string]::IsNullOrWhiteSpace($env:OPENAI_BASE_URL)) {
        return ($env:OPENAI_BASE_URL.TrimEnd("/") + "/responses")
    }
    return "https://api.openai.com/v1/responses"
}

function Get-OpenAIModel {
    if (Test-AzureOpenAIConfigured) {
        return $env:AZURE_OPENAI_DEPLOYMENT
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOGSEEDER_OPENAI_MODEL)) {
        return $env:LOGSEEDER_OPENAI_MODEL
    }
    return "gpt-4.1-mini"
}

function Get-OpenAIProviderName {
    if (Test-AzureOpenAIConfigured) { return "Azure OpenAI" }
    return "OpenAI"
}

function Get-OpenAIHeaders {
    $headers = @{
        "Content-Type" = "application/json"
    }

    if (Test-AzureOpenAIConfigured) {
        if (-not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_API_KEY)) {
            $headers["api-key"] = $env:AZURE_OPENAI_API_KEY
        } else {
            $headers["Authorization"] = "Bearer $env:AZURE_OPENAI_AUTH_TOKEN"
        }
        return $headers
    }

    $headers["Authorization"] = "Bearer $env:OPENAI_API_KEY"
    return $headers
}

function Get-ResponseOutputText {
    param([Parameter(Mandatory = $true)]$Response)

    if ($Response.PSObject.Properties['output_text'] -and -not [string]::IsNullOrWhiteSpace($Response.output_text)) {
        return $Response.output_text
    }

    $parts = @()
    foreach ($item in @($Response.output)) {
        if ($item.PSObject.Properties['content']) {
            foreach ($content in @($item.content)) {
                if ($content.PSObject.Properties['text']) {
                    $parts += $content.text
                }
            }
        }
    }

    return ($parts -join "`n")
}

function Invoke-OpenAIJson {
    param(
        [Parameter(Mandatory = $true)][string]$Instructions,
        [Parameter(Mandatory = $true)][string]$InputText,
        [Parameter(Mandatory = $true)][string]$SchemaName,
        [Parameter(Mandatory = $true)][hashtable]$JsonSchema
    )

    if (-not (Test-OpenAIConfigured)) {
        throw "OPENAI_API_KEY is not set. Set it before using AI generation."
    }

    $endpoint = Get-OpenAIEndpoint
    $body = @{
        model = Get-OpenAIModel
        instructions = $Instructions
        input = @(
            @{
                role = "user"
                content = @(
                    @{
                        type = "input_text"
                        text = $InputText
                    }
                )
            }
        )
        text = @{
            format = @{
                type = "json_schema"
                name = $SchemaName
                schema = $JsonSchema
                strict = $true
            }
        }
    } | ConvertTo-Json -Depth 100

    $headers = Get-OpenAIHeaders

    $response = Invoke-RestMethod -Method Post -Uri $endpoint -Headers $headers -Body $body
    $text = Get-ResponseOutputText -Response $response
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "OpenAI returned no output text."
    }
    return ($text | ConvertFrom-Json)
}

function Get-SchemaGenerationContract {
    return @{
        type = "object"
        additionalProperties = $false
        required = @("tableName", "description", "columns")
        properties = @{
            tableName = @{ type = "string" }
            description = @{ type = "string" }
            columns = @{
                type = "array"
                minItems = 2
                items = @{
                    type = "object"
                    additionalProperties = $false
                    required = @("name", "type", "valuesJson", "notes")
                    properties = @{
                        name = @{ type = "string" }
                        type = @{
                            type = "string"
                            enum = @("string", "int", "long", "real", "boolean", "datetime", "dynamic")
                        }
                        valuesJson = @{ type = "string" }
                        notes = @{ type = "string" }
                    }
                }
            }
        }
    }
}

function Get-LogSeederInstructions {
    $promptPath = Join-Path (Join-Path $script:ProjectRoot "prompts") "logseeder-system.md"
    if (Test-Path $promptPath) {
        return Get-Content -Path $promptPath -Raw
    }

    return @"
You generate Microsoft Sentinel LogSeeder schema JSON. Use only DCR-supported types:
string, int, long, real, boolean, datetime, dynamic. Use TimeGenerated as a datetime
column. For dynamic values, put a JSON array string in valuesJson. Keep rows realistic
and safe for synthetic security training.
"@
}

function Convert-GeneratedSchema {
    param([Parameter(Mandatory = $true)]$Generated)

    $columns = @()
    $hasTimeGenerated = $false

    foreach ($col in @($Generated.columns)) {
        $entry = [ordered]@{
            name = $col.name
            type = $col.type
        }
        if ($col.name -eq "TimeGenerated") {
            $hasTimeGenerated = $true
        }
        if ($col.PSObject.Properties['valuesJson'] -and -not [string]::IsNullOrWhiteSpace($col.valuesJson)) {
            try {
                $values = $col.valuesJson | ConvertFrom-Json
                $entry.values = @($values)
            } catch {
                Write-Host "Could not parse valuesJson for column '$($col.name)'; values were omitted." -ForegroundColor Yellow
            }
        }
        $columns += ,$entry
    }

    if (-not $hasTimeGenerated) {
        $columns = @([ordered]@{ name = "TimeGenerated"; type = "datetime" }) + $columns
    }

    return [ordered]@{
        columns = $columns
    }
}

function Invoke-CustomGenerationWorkflow {
    param(
        [string]$WorkspaceConfig,
        [string]$EntitiesFile,
        [switch]$PreviewOnly
    )

    if (-not (Test-OpenAIConfigured)) {
        Write-Host ""
        Write-Host "AI generation is not configured." -ForegroundColor Yellow
        Write-Host "Set OPENAI_API_KEY before using custom AI generation:" -ForegroundColor Gray
        Write-Host '  $env:OPENAI_API_KEY = "sk-..."' -ForegroundColor DarkCyan
        Write-Host "Or for Azure OpenAI / Foundry:" -ForegroundColor Gray
        Write-Host '  $env:AZURE_OPENAI_ENDPOINT = "https://<resource>.openai.azure.com/"' -ForegroundColor DarkCyan
        Write-Host '  $env:AZURE_OPENAI_API_KEY = "<key>"' -ForegroundColor DarkCyan
        Write-Host '  $env:AZURE_OPENAI_DEPLOYMENT = "<deployment-name>"' -ForegroundColor DarkCyan
        return
    }

    $product = Read-Text -Prompt "Product/vendor or log source"
    $tableDefault = (($product -replace '[^A-Za-z0-9]', '') + "_CL")
    $tableName = Read-Text -Prompt "Target custom table name" -Default $tableDefault
    if ($tableName -notlike "*_CL") {
        Write-Host "Custom tables should end in _CL. I will use ${tableName}_CL." -ForegroundColor Yellow
        $tableName = "${tableName}_CL"
    }
    $description = Read-Text -Prompt "What should the synthetic logs represent?"

    $input = @"
Create a Sentinel LogSeeder schema for this synthetic log source.

Product/source: $product
Target table: $tableName
Use case: $description

Return realistic columns and values for security training. Include TimeGenerated.
Prefer 12 to 35 useful columns. Use valuesJson as a JSON array string when a column
has useful sample values. For dynamic columns, valuesJson must be a JSON array of
objects or arrays represented as a string.
"@

    Write-Host ""
    Write-Host "Calling $(Get-OpenAIProviderName) model/deployment $(Get-OpenAIModel)..." -ForegroundColor Cyan
    $generated = Invoke-OpenAIJson -Instructions (Get-LogSeederInstructions) -InputText $input -SchemaName "logseeder_schema" -JsonSchema (Get-SchemaGenerationContract)

    $schema = Convert-GeneratedSchema -Generated $generated
    $schemaPath = Join-Path (Join-Path $script:ProjectRoot "schemas") "$tableName.json"

    Write-Host ""
    Write-Host "Generated schema for $tableName" -ForegroundColor Green
    Write-Host $generated.description -ForegroundColor Gray
    Write-Host ("Columns: " + @($schema.columns).Count)
    Write-Host "Output: $schemaPath"

    if (-not (Read-YesNo -Prompt "Save this schema?" -DefaultYes $true)) {
        return
    }

    Write-JsonFile -InputObject $schema -Path $schemaPath -Depth 100
    Write-Host "Schema saved." -ForegroundColor Green

    if (Read-YesNo -Prompt "Run this table through LogSeeder now?" -DefaultYes $false) {
        $rowCount = Read-Number -Prompt "Rows to generate" -Default 25 -Minimum 1 -Maximum 100000
        $mode = Get-RunMode
        if ($null -eq $mode) { return }

        $previewChoice = ($mode.Value -eq "preview")
        $runPreview = $PreviewOnly -or $previewChoice
        $deploy = $previewChoice -or ($mode.Value -eq "deploy" -or $mode.Value -eq "deployIngest")
        $ingest = $previewChoice -or ($mode.Value -eq "ingest" -or $mode.Value -eq "deployIngest")

        if ($ingest -and -not $runPreview) {
            Write-Host ""
            Write-Host "Cost guard: this will ingest $rowCount billable rows into $tableName." -ForegroundColor Yellow
            if (-not (Read-YesNo -Prompt "Continue?" -DefaultYes $false)) { return }
        }

        $scriptPath = Join-Path $script:ModuleRoot "Invoke-SampleDataIngestion.ps1"
        $args = @{
            TableName = $tableName
            Schema = $schemaPath
            RowCount = $rowCount
            WorkspaceConfig = $WorkspaceConfig
            EntitiesFile = $EntitiesFile
            Deploy = $deploy
            Ingest = $ingest
            TimeWindowMinutes = 30
        }
        Invoke-LogSeederScript -ScriptPath $scriptPath -Arguments $args -PreviewOnly:$runPreview
    }
}

function Invoke-SampleFileWorkflow {
    param(
        [string]$WorkspaceConfig,
        [string]$EntitiesFile,
        [switch]$PreviewOnly
    )

    $samplePath = Read-Text -Prompt "JSON or CSV sample file path"
    $samplePath = Resolve-RepoPath -Path $samplePath
    if (-not (Test-Path $samplePath)) {
        Write-Host "Sample file not found: $samplePath" -ForegroundColor Red
        return
    }

    $tableName = Read-Text -Prompt "Target table name"
    $rowCount = Read-Number -Prompt "Rows to generate" -Default 25 -Minimum 1 -Maximum 100000
    $mode = Get-RunMode
    if ($null -eq $mode) { return }

    $previewChoice = ($mode.Value -eq "preview")
    $runPreview = $PreviewOnly -or $previewChoice
    $deploy = $previewChoice -or ($mode.Value -eq "deploy" -or $mode.Value -eq "deployIngest")
    $ingest = $previewChoice -or ($mode.Value -eq "ingest" -or $mode.Value -eq "deployIngest")

    if ($ingest -and -not $runPreview) {
        Write-Host ""
        Write-Host "Cost guard: this will ingest $rowCount billable rows into $tableName." -ForegroundColor Yellow
        if (-not (Read-YesNo -Prompt "Continue?" -DefaultYes $false)) { return }
    }

    $scriptPath = Join-Path $script:ModuleRoot "Invoke-SampleDataIngestion.ps1"
    $args = @{
        TableName = $tableName
        SampleDataFile = $samplePath
        RowCount = $rowCount
        WorkspaceConfig = $WorkspaceConfig
        EntitiesFile = $EntitiesFile
        Deploy = $deploy
        Ingest = $ingest
        TimeWindowMinutes = 30
    }
    Invoke-LogSeederScript -ScriptPath $scriptPath -Arguments $args -PreviewOnly:$runPreview
}

function Invoke-WorkspaceSetupWorkflow {
    param([string]$WorkspaceConfig)

    Write-Host ""
    Write-Host "Workspace setup" -ForegroundColor Cyan
    Write-Host "Config file: $WorkspaceConfig"

    if (Test-Path $WorkspaceConfig) {
        Write-Host "Current config:" -ForegroundColor Gray
        Get-Content -Path $WorkspaceConfig | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
        if (-not (Read-YesNo -Prompt "Recreate workspace config?" -DefaultYes $false)) {
            return
        }
        Remove-Item -Path $WorkspaceConfig -Force
    }

    Ensure-WorkspaceConfig -WorkspaceConfig $WorkspaceConfig | Out-Null
}

function Invoke-OtherRequestWorkflow {
    if (-not (Test-OpenAIConfigured)) {
        Write-Host ""
        Write-Host "The 'other' path uses OpenAI to interpret your request." -ForegroundColor Yellow
        Write-Host 'Set $env:OPENAI_API_KEY first, or use one of the menu options above.' -ForegroundColor Gray
        return
    }

    $request = Read-Text -Prompt "Describe what you want LogSeeder to do"
    $schema = @{
        type = "object"
        additionalProperties = $false
        required = @("recommendedAction", "summary", "details", "nextMenu")
        properties = @{
            recommendedAction = @{
                type = "string"
                enum = @("run_prebuilt_scenario", "ingest_single_table", "generate_custom_schema", "ask_clarifying_question")
            }
            summary = @{ type = "string" }
            details = @{ type = "string" }
            nextMenu = @{ type = "string" }
        }
    }

    $input = @"
The user wants to use Sentinel LogSeeder. Recommend the safest next menu path.
Do not claim you executed anything.

User request:
$request

Menu paths:
- run_prebuilt_scenario
- ingest_single_table
- generate_custom_schema
- ask_clarifying_question
"@

    $result = Invoke-OpenAIJson -Instructions (Get-LogSeederInstructions) -InputText $input -SchemaName "logseeder_next_step" -JsonSchema $schema

    Write-Host ""
    Write-Host "Recommendation" -ForegroundColor Cyan
    Write-Host $result.summary -ForegroundColor White
    Write-Host $result.details -ForegroundColor Gray
    Write-Host ("Next menu: " + $result.nextMenu) -ForegroundColor DarkCyan
}

function Start-LogSeederMenu {
    [CmdletBinding()]
    param(
        [string]$WorkspaceConfig,
        [string]$EntitiesFile,
        [switch]$PreviewOnly
    )

    if ([string]::IsNullOrWhiteSpace($WorkspaceConfig)) {
        $WorkspaceConfig = Get-DefaultWorkspaceConfigPath
    } else {
        $WorkspaceConfig = Resolve-RepoPath -Path $WorkspaceConfig
    }
    if ([string]::IsNullOrWhiteSpace($EntitiesFile)) {
        $EntitiesFile = Get-DefaultEntitiesPath
    } else {
        $EntitiesFile = Resolve-RepoPath -Path $EntitiesFile
    }

    if (-not (Test-Path $EntitiesFile)) {
        throw "Entities file not found: $EntitiesFile"
    }

    $WorkspaceConfig = Ensure-WorkspaceConfig -WorkspaceConfig $WorkspaceConfig

    while ($true) {
        Write-Host ""
        Write-Host "Sentinel LogSeeder OpenAI Mode" -ForegroundColor Cyan
        Write-Host "Workspace config: $WorkspaceConfig" -ForegroundColor DarkGray
        if (Test-OpenAIConfigured) {
        Write-Host ("AI: configured via {0}, model/deployment {1}" -f (Get-OpenAIProviderName), (Get-OpenAIModel)) -ForegroundColor DarkGray
    } else {
        Write-Host "AI: not configured. Prebuilt and known-table modes still work." -ForegroundColor DarkGray
        }
        if ($PreviewOnly) {
            Write-Host "Preview mode is ON." -ForegroundColor Yellow
        }

        $items = @(
            [pscustomobject]@{ Label = "Run prebuilt attack scenario"; Description = "Pick scenario 1, 2, 3, etc. Uses ASIM defaults or manual mapping."; Value = "scenario" },
            [pscustomobject]@{ Label = "Ingest sample data into a table"; Description = "Use an existing schema from schemas/ with a low row count."; Value = "single" },
            [pscustomobject]@{ Label = "Generate product/vendor logs with AI"; Description = "Uses OpenAI or Azure OpenAI to create a schema, then optionally ingests."; Value = "custom" },
            [pscustomobject]@{ Label = "Ingest JSON/CSV sample file"; Description = "Infer schema from a file and reuse the upstream ingestion engine."; Value = "file" },
            [pscustomobject]@{ Label = "Configure/test workspace"; Description = "Create or inspect config/workspace.json."; Value = "setup" },
            [pscustomobject]@{ Label = "Other / describe what you want"; Description = "Uses AI to recommend the next safe menu path."; Value = "other" }
        )

        $choice = Read-MenuChoice -Title "Main Menu" -Items $items
        if ($null -eq $choice) { break }

        switch ($choice.Value) {
            "scenario" { Invoke-PrebuiltScenarioWorkflow -WorkspaceConfig $WorkspaceConfig -EntitiesFile $EntitiesFile -PreviewOnly:$PreviewOnly }
            "single" { Invoke-SingleTableWorkflow -WorkspaceConfig $WorkspaceConfig -EntitiesFile $EntitiesFile -PreviewOnly:$PreviewOnly }
            "custom" { Invoke-CustomGenerationWorkflow -WorkspaceConfig $WorkspaceConfig -EntitiesFile $EntitiesFile -PreviewOnly:$PreviewOnly }
            "file" { Invoke-SampleFileWorkflow -WorkspaceConfig $WorkspaceConfig -EntitiesFile $EntitiesFile -PreviewOnly:$PreviewOnly }
            "setup" { Invoke-WorkspaceSetupWorkflow -WorkspaceConfig $WorkspaceConfig }
            "other" { Invoke-OtherRequestWorkflow }
        }
    }
}

Export-ModuleMember -Function Start-LogSeederMenu
