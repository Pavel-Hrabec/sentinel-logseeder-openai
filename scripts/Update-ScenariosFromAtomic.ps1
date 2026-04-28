# Update-ScenariosFromAtomic.ps1
# Fetch Atomic Red Team technique YAMLs over HTTPS (in-memory only) and (re)generate
# scenario JSON files in scenarios/generated/. The repo is NEVER cloned and red-team
# payloads are never written to disk.
#
# Usage:
#   .\scripts\Update-ScenariosFromAtomic.ps1
#   .\scripts\Update-ScenariosFromAtomic.ps1 -TechniqueId T1110,T1486 -Force
#   .\scripts\Update-ScenariosFromAtomic.ps1 -MaxNew 3

[CmdletBinding()]
param(
    [string[]]$TechniqueId,
    [string[]]$Platform = @('windows'),
    [int]$MaxNew = 25,
    [switch]$Force,
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$ErrorActionPreference = 'Stop'

$intelDir   = Join-Path $PSScriptRoot 'intel'
$mapPath    = Join-Path $intelDir 'technique-table-map.json'
$statePath  = Join-Path $RepoRoot '.state\atomic-seen.json'
$outDir     = Join-Path $RepoRoot 'scenarios\generated'
$invalidDir = Join-Path $outDir   '.invalid'

. (Join-Path $intelDir 'Get-AtomicRedTeamItems.ps1')
. (Join-Path $intelDir 'ConvertTo-Scenario.ps1')

if (-not (Test-Path $outDir))     { New-Item -ItemType Directory -Path $outDir     -Force | Out-Null }
if (-not (Test-Path $invalidDir)) { New-Item -ItemType Directory -Path $invalidDir -Force | Out-Null }
$stateDir = Split-Path -Parent $statePath
if (-not (Test-Path $stateDir))   { New-Item -ItemType Directory -Path $stateDir   -Force | Out-Null }

Write-Host "[update] Loading technique map: $mapPath" -ForegroundColor Cyan
$map = Get-Content -Raw -LiteralPath $mapPath | ConvertFrom-Json

$mappedIds = @($map.techniques.PSObject.Properties.Name)
Write-Host "[update] Mapped techniques: $($mappedIds -join ', ')" -ForegroundColor Cyan

# If no explicit -TechniqueId, restrict to mapped ones (don't fetch the world)
$filterIds = if ($TechniqueId) { $TechniqueId } else { $mappedIds }

# Load state
$state = if (Test-Path $statePath) { Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json -AsHashtable } else { @{} }

# Fetch (in-memory) and parse
$items = Get-AtomicRedTeamItems -TechniqueId $filterIds -Platform $Platform

Write-Host "[update] Discovered $($items.Count) parent technique(s) after filtering" -ForegroundColor Cyan

$created = 0; $updated = 0; $skipped = 0; $unmapped = 0; $invalid = 0
$summary = @()

foreach ($item in $items) {
    $tid = $item.TechniqueId

    if (-not $map.techniques.PSObject.Properties.Name.Contains($tid)) {
        Write-Verbose "[update] $tid - unmapped, skipping"
        $unmapped++
        continue
    }

    $prevHash = $state[$tid]
    if (-not $Force -and $prevHash -eq $item.CombinedHash) {
        Write-Host "[update] $tid - unchanged (hash match), skipping" -ForegroundColor DarkGray
        $skipped++
        continue
    }

    $scenario = ConvertTo-Scenario -Item $item -TechniqueMap $map
    if (-not $scenario) { $unmapped++; continue }

    # Validate referenced schemas exist
    $missingSchemas = @()
    foreach ($tbl in $scenario.tables.GetEnumerator()) {
        $schemaPath = Join-Path $RepoRoot $tbl.Value.schema
        if (-not (Test-Path $schemaPath)) { $missingSchemas += $tbl.Value.schema }
    }

    $fileName = "$($scenario.name).json"
    $json     = $scenario | ConvertTo-Json -Depth 12

    if ($missingSchemas.Count -gt 0) {
        $dest = Join-Path $invalidDir $fileName
        $json | Set-Content -LiteralPath $dest -Encoding UTF8
        Write-Warning "[update] $tid - missing schemas: $($missingSchemas -join ', ') -> wrote to .invalid\$fileName"
        $invalid++
        $summary += "INVALID  $tid -> $fileName (missing: $($missingSchemas -join ', '))"
        continue
    }

    $dest = Join-Path $outDir $fileName
    $isNew = -not (Test-Path $dest)
    $json | Set-Content -LiteralPath $dest -Encoding UTF8

    if ($isNew) { $created++; $tag = 'CREATED' } else { $updated++; $tag = 'UPDATED' }
    $state[$tid] = $item.CombinedHash
    Write-Host "[update] $tag  $tid -> scenarios/generated/$fileName" -ForegroundColor Green
    $summary += "$tag  $tid -> $fileName"

    if (($created + $updated) -ge $MaxNew) {
        Write-Host "[update] Reached MaxNew=$MaxNew, stopping" -ForegroundColor Yellow
        break
    }
}

# Persist state
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8

Write-Host ''
Write-Host '=== Summary ===' -ForegroundColor Cyan
Write-Host "Created : $created"
Write-Host "Updated : $updated"
Write-Host "Skipped : $skipped (unchanged)"
Write-Host "Unmapped: $unmapped"
Write-Host "Invalid : $invalid"
if ($summary) {
    Write-Host ''
    $summary | ForEach-Object { Write-Host "  $_" }
}
