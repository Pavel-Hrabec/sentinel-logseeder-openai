# Get-AtomicRedTeamItems.ps1
# Fetch Atomic Red Team technique YAMLs OVER HTTPS (no clone, no disk writes).
# Designed to avoid landing red-team payloads/commands on the filesystem,
# which would otherwise trip endpoint protection.
#
# This file is meant to be dot-sourced; it exposes Get-AtomicRedTeamItems.

$ErrorActionPreference = 'Stop'

# Endpoints
$script:AtomicOwner   = 'redcanaryco'
$script:AtomicRepo    = 'atomic-red-team'
$script:AtomicBranch  = 'master'
$script:GitHubApi     = "https://api.github.com/repos/$script:AtomicOwner/$script:AtomicRepo/contents/atomics"
$script:RawBase       = "https://raw.githubusercontent.com/$script:AtomicOwner/$script:AtomicRepo/$script:AtomicBranch/atomics"

function Ensure-PowerShellYamlModule {
    if (-not (Get-Module -ListAvailable -Name 'powershell-yaml')) {
        Write-Host '[atomic] Installing powershell-yaml module (CurrentUser)...' -ForegroundColor Yellow
        Install-Module -Name 'powershell-yaml' -Scope CurrentUser -Force -AllowClobber | Out-Null
    }
    Import-Module 'powershell-yaml' -ErrorAction Stop
}

function Get-AtomicGitHubHeaders {
    $h = @{
        'User-Agent' = 'Sentinel-LogSeeder'
        'Accept'     = 'application/vnd.github+json'
    }
    if ($env:GITHUB_TOKEN) { $h['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
    return $h
}

function Get-AtomicAtomicsListing {
    # One-shot listing of every directory under /atomics. Cached per process.
    if ($script:AtomicAtomicsCache) { return $script:AtomicAtomicsCache }

    $url = $script:GitHubApi
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers (Get-AtomicGitHubHeaders) -Method Get -ErrorAction Stop
    } catch {
        throw "[atomic] GitHub API list failed for /atomics : $($_.Exception.Message)"
    }

    $names = @()
    foreach ($entry in $resp) {
        if ($entry.type -eq 'dir' -and $entry.name -match '^T\d+(\.\d+)?$') {
            $names += $entry.name
        }
    }
    $script:AtomicAtomicsCache = $names
    return $names
}

function Get-AtomicSubTechniqueIds {
    # Returns parent + sub-technique IDs that have a matching directory in the repo.
    param([string]$ParentId)

    $all = Get-AtomicAtomicsListing
    $matches = @($all | Where-Object {
        $_ -eq $ParentId -or $_ -like "$ParentId.*"
    })
    # Sort: parent first, then subs in order
    return $matches | Sort-Object @{ Expression = { if ($_ -eq $ParentId) { '' } else { $_ } } }
}

function Get-AtomicYamlInMemory {
    # Fetch a single YAML file as a string, never written to disk.
    param([string]$TechniqueId)

    $url = "$script:RawBase/$TechniqueId/$TechniqueId.yaml"
    try {
        $resp = Invoke-WebRequest -Uri $url -Headers (Get-AtomicGitHubHeaders) -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Warning "[atomic] Could not fetch $url : $($_.Exception.Message)"
        return $null
    }

    if ($resp.StatusCode -ne 200) {
        Write-Warning "[atomic] HTTP $($resp.StatusCode) fetching $url"
        return $null
    }

    # Invoke-WebRequest returns Content as string for text bodies on PS7.
    if ($resp.Content -is [byte[]]) {
        return [System.Text.Encoding]::UTF8.GetString($resp.Content)
    }
    return [string]$resp.Content
}

function ConvertFrom-AtomicYamlString {
    param([string]$Yaml, [string]$TechniqueId)

    if ([string]::IsNullOrWhiteSpace($Yaml)) { return $null }
    try {
        $doc = ConvertFrom-Yaml -Yaml $Yaml
    } catch {
        Write-Warning "[atomic] Failed to parse YAML for $TechniqueId : $_"
        return $null
    }
    if (-not $doc -or -not $doc['attack_technique']) { return $null }

    $tests = @()
    if ($doc['atomic_tests']) {
        foreach ($t in $doc['atomic_tests']) {
            $exec = $t['executor']
            $tests += [pscustomobject]@{
                Name               = [string]$t['name']
                Description        = [string]$t['description']
                SupportedPlatforms = @($t['supported_platforms'])
                ExecutorName       = if ($exec) { [string]$exec['name'] } else { '' }
                Command            = if ($exec) { [string]$exec['command'] } else { '' }
                ElevationRequired  = if ($exec -and $exec.ContainsKey('elevation_required')) { [bool]$exec['elevation_required'] } else { $false }
            }
        }
    }

    # Hash the YAML *string* in memory — never persist the file.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Yaml)
    $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '')

    [pscustomobject]@{
        TechniqueId        = [string]$doc['attack_technique']
        TechniqueName      = [string]$doc['display_name']
        Platforms          = @($tests.SupportedPlatforms | Select-Object -Unique)
        Tests              = $tests
        ContentHash        = $hash
    }
}

function Get-AtomicRedTeamItems {
    [CmdletBinding()]
    param(
        [string[]]$TechniqueId,
        [string[]]$Platform
    )

    Ensure-PowerShellYamlModule

    if (-not $TechniqueId) {
        throw "Get-AtomicRedTeamItems requires -TechniqueId. Pass the parent T-IDs you want (e.g. from technique-table-map.json) so we don't download the entire repo."
    }

    # Normalize to top-level parent IDs only (e.g. 'T1110.001' -> 'T1110')
    $parents = @($TechniqueId | ForEach-Object { ($_ -split '\.')[0] } | Select-Object -Unique)

    $byParent = @{}

    foreach ($parent in $parents) {
        Write-Host "[atomic] Listing $parent via GitHub API..." -ForegroundColor DarkCyan
        $ids = Get-AtomicSubTechniqueIds -ParentId $parent
        if (-not $ids) {
            Write-Warning "[atomic] No technique YAMLs found for $parent"
            continue
        }

        $bucket = [pscustomobject]@{
            TechniqueId    = $parent
            TechniqueName  = ''
            SubTechniques  = @()
            AllTests       = @()
            Platforms      = @()
            ContentHashes  = @()
        }

        foreach ($id in $ids) {
            $yaml = Get-AtomicYamlInMemory -TechniqueId $id
            if (-not $yaml) { continue }

            $item = ConvertFrom-AtomicYamlString -Yaml $yaml -TechniqueId $id
            # Discard YAML string ASAP (defense in depth — no payload retained)
            $yaml = $null
            if (-not $item) { continue }

            if ($Platform) {
                $platMatch = $false
                foreach ($p in $Platform) { if ($item.Platforms -contains $p) { $platMatch = $true; break } }
                if (-not $platMatch) { continue }
            }

            if ($item.TechniqueId -eq $parent) { $bucket.TechniqueName = $item.TechniqueName }

            $bucket.SubTechniques  += [pscustomobject]@{
                Id    = $item.TechniqueId
                Name  = $item.TechniqueName
                Tests = $item.Tests
            }
            $bucket.AllTests       += $item.Tests
            $bucket.Platforms       = @($bucket.Platforms + $item.Platforms | Select-Object -Unique)
            $bucket.ContentHashes  += $item.ContentHash
        }

        if ($bucket.SubTechniques.Count -eq 0) { continue }

        if (-not $bucket.TechniqueName -and $bucket.SubTechniques.Count -gt 0) {
            $bucket.TechniqueName = ($bucket.SubTechniques[0].Name -replace ':\s.*$', '')
        }

        $combined = ($bucket.ContentHashes | Sort-Object) -join ''
        $sha   = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($combined)
        $combinedHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '')
        Add-Member -InputObject $bucket -NotePropertyName 'CombinedHash' -NotePropertyValue $combinedHash -Force

        $byParent[$parent] = $bucket
    }

    return $byParent.Values | Sort-Object TechniqueId
}
