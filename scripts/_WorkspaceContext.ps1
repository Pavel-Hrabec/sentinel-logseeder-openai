<#
.SYNOPSIS
Shared workspace-context resolver for the LogSeeder scripts.

.DESCRIPTION
Reads config/workspace.json and fills in any missing fields from the current Azure CLI
context. The minimum required content of workspace.json is either 'workspaceName' or
'workspaceId' (the customerId GUID). Everything else (tenantId, subscriptionId,
resourceGroup, the other identifier, dceName) is auto-resolved.

This file is intended to be dot-sourced; it defines functions only.
#>

function Get-OptionalProperty {
    param(
        [Parameter(Mandatory)] $Object,
        [Parameter(Mandatory)] [string] $Name
    )
    if ($null -eq $Object) { return $null }
    if ($Object.PSObject.Properties[$Name]) {
        $val = $Object.$Name
        if ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) { return $null }
        return $val
    }
    return $null
}

function Invoke-AzCommandJson {
    param(
        [Parameter(Mandatory)] [string[]] $Arguments
    )
    $prevEA = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = & az @Arguments -o json 2>&1
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $prevEA
    if ($exitCode -ne 0) {
        $errText = ($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"
        return @{ Success = $false; Error = $errText; Data = $null }
    }
    $jsonText = ($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
    if (-not $jsonText) { return @{ Success = $true; Error = $null; Data = $null } }
    try {
        return @{ Success = $true; Error = $null; Data = ($jsonText | ConvertFrom-Json) }
    } catch {
        return @{ Success = $false; Error = "JSON parse error: $_"; Data = $null }
    }
}

function Test-AzExtensionInstalled {
    param([Parameter(Mandatory)] [string] $Name)
    $r = Invoke-AzCommandJson -Arguments @('extension', 'list', '--query', "[?name=='$Name'].name")
    if (-not $r.Success) { return $false }
    return ($r.Data -and @($r.Data).Count -gt 0)
}

function Find-WorkspaceViaResourceGraph {
    param(
        [string] $WorkspaceName,
        [string] $WorkspaceCustomerId,
        [string] $SubscriptionId,
        [string] $ResourceGroup
    )

    if (-not (Test-AzExtensionInstalled -Name 'resource-graph')) {
        throw "EXT_NOT_INSTALLED"
    }

    $filters = @("type =~ 'microsoft.operationalinsights/workspaces'")
    if ($WorkspaceCustomerId)  { $filters += "tolower(tostring(properties.customerId)) == tolower('$WorkspaceCustomerId')" }
    if ($WorkspaceName)        { $filters += "name =~ '$WorkspaceName'" }
    if ($SubscriptionId)       { $filters += "subscriptionId =~ '$SubscriptionId'" }
    if ($ResourceGroup)        { $filters += "resourceGroup =~ '$ResourceGroup'" }

    $kql = "Resources | where " + ($filters -join ' and ') +
        " | project id, name, resourceGroup, subscriptionId, tenantId, customerId=tostring(properties.customerId), location | take 25"

    $result = Invoke-AzCommandJson -Arguments @('graph', 'query', '-q', $kql, '--query', 'data')
    if (-not $result.Success) {
        throw "Azure Resource Graph query failed: $($result.Error)"
    }
    if (-not $result.Data) { return @() }
    return @($result.Data)
}

function Find-WorkspaceViaListFallback {
    param(
        [string] $WorkspaceName,
        [string] $WorkspaceCustomerId,
        [string] $SubscriptionId,
        [string] $ResourceGroup
    )

    # Determine which subscriptions to search.
    $subIds = @()
    if ($SubscriptionId) {
        $subIds = @($SubscriptionId)
    } else {
        $subResult = Invoke-AzCommandJson -Arguments @('account', 'list', '--query', '[?state==`Enabled`].id')
        if ($subResult.Success -and $subResult.Data) {
            $subIds = @($subResult.Data)
        }
        if (-not $subIds -or $subIds.Count -eq 0) {
            $current = Invoke-AzCommandJson -Arguments @('account', 'show', '--query', 'id')
            if ($current.Success -and $current.Data) { $subIds = @($current.Data) }
        }
    }

    $found = @()
    foreach ($sid in $subIds) {
        $listResult = Invoke-AzCommandJson -Arguments @('monitor', 'log-analytics', 'workspace', 'list', '--subscription', $sid)
        if (-not $listResult.Success -or -not $listResult.Data) { continue }
        foreach ($w in @($listResult.Data)) {
            # Prefer workspaceId (globally unique) when present; otherwise match on name.
            $isMatch = if ($WorkspaceCustomerId) {
                $w.customerId -eq $WorkspaceCustomerId
            } elseif ($WorkspaceName) {
                $w.name -eq $WorkspaceName
            } else {
                $false
            }
            if (-not $isMatch) { continue }

            $segments = $w.id -split '/'
            if ($ResourceGroup -and $segments[4] -ne $ResourceGroup) { continue }

            $found += [pscustomobject]@{
                id             = $w.id
                name           = $w.name
                resourceGroup  = $segments[4]
                subscriptionId = $segments[2]
                tenantId       = $null
                customerId     = $w.customerId
                location       = $w.location
            }
        }
    }
    return @($found)
}

function Find-WorkspaceViaDirectLookup {
    param(
        [string] $WorkspaceName,
        [string] $SubscriptionId,
        [string] $ResourceGroup
    )

    if (-not $WorkspaceName -or -not $SubscriptionId -or -not $ResourceGroup) {
        return @()
    }

    $result = Invoke-AzCommandJson -Arguments @(
        'monitor', 'log-analytics', 'workspace', 'show',
        '--workspace-name', $WorkspaceName,
        '--resource-group', $ResourceGroup,
        '--subscription', $SubscriptionId
    )
    if (-not $result.Success -or -not $result.Data) { return @() }

    $w = $result.Data
    return @([pscustomobject]@{
        id             = $w.id
        name           = $w.name
        resourceGroup  = $ResourceGroup
        subscriptionId = $SubscriptionId
        tenantId       = $null
        customerId     = $w.customerId
        location       = $w.location
    })
}

function Resolve-WorkspaceContext {
    <#
    .SYNOPSIS
    Returns a hashtable with all workspace coordinates, filling gaps from az CLI context.
    #>
    param(
        [Parameter(Mandatory)] [string] $ConfigPath
    )

    if (-not (Test-Path $ConfigPath)) {
        throw "Workspace config not found: $ConfigPath. Create it with at least { `"workspaceName`": `"<name>`" }."
    }

    $cfg = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

    $tenantId       = Get-OptionalProperty $cfg 'tenantId'
    $subscriptionId = Get-OptionalProperty $cfg 'subscriptionId'
    $resourceGroup  = Get-OptionalProperty $cfg 'resourceGroup'
    $workspaceName  = Get-OptionalProperty $cfg 'workspaceName'
    $workspaceId    = Get-OptionalProperty $cfg 'workspaceId'   # customerId GUID
    $dceName        = Get-OptionalProperty $cfg 'dceName'

    $needsResolve = (-not $tenantId) -or (-not $subscriptionId) -or (-not $resourceGroup) -or (-not $workspaceName) -or (-not $workspaceId)

    if ($needsResolve) {
        if (-not $workspaceName -and -not $workspaceId) {
            throw "workspace.json must contain at least 'workspaceName' or 'workspaceId'."
        }
        try { $null = Get-Command az -ErrorAction Stop } catch {
            throw "Azure CLI (az) is required to auto-resolve workspace details. Install from https://aka.ms/installazurecli or fully populate workspace.json."
        }

        Write-Host "Resolving workspace coordinates from Azure CLI context..." -ForegroundColor DarkGray

        $matched = @()
        $matched = Find-WorkspaceViaDirectLookup -WorkspaceName $workspaceName -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup
        if (-not $matched -or $matched.Count -eq 0) {
            try {
                $matched = Find-WorkspaceViaResourceGraph -WorkspaceName $workspaceName -WorkspaceCustomerId $workspaceId -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup
            } catch {
                if ($_.Exception.Message -ne 'EXT_NOT_INSTALLED') {
                    Write-Host "  Resource Graph lookup failed: $($_.Exception.Message)" -ForegroundColor Yellow
                } else {
                    Write-Host "  (Tip: install 'az extension add --name resource-graph' for faster lookups.)" -ForegroundColor DarkGray
                }
                $matched = Find-WorkspaceViaListFallback -WorkspaceName $workspaceName -WorkspaceCustomerId $workspaceId -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup
            }
        }

        if (-not $matched -or $matched.Count -eq 0) {
            $hint = if ($workspaceName) { "name '$workspaceName'" } else { "workspaceId '$workspaceId'" }
            throw "Could not find a Log Analytics workspace matching $hint. Run 'az login' against the right tenant, or set 'subscriptionId' in workspace.json."
        }
        if ($matched.Count -gt 1) {
            $details = ($matched | ForEach-Object { "  - $($_.name)  (sub=$($_.subscriptionId), rg=$($_.resourceGroup))" }) -join "`n"
            throw "Multiple workspaces matched. Disambiguate by adding 'subscriptionId' (and/or 'resourceGroup') to workspace.json:`n$details"
        }

        $m = $matched[0]
        if (-not $subscriptionId) { $subscriptionId = $m.subscriptionId }
        if (-not $resourceGroup)  { $resourceGroup  = $m.resourceGroup }
        if (-not $workspaceName)  { $workspaceName  = $m.name }
        if (-not $workspaceId)    { $workspaceId    = $m.customerId }
        if (-not $tenantId) {
            $tenantId = $m.tenantId
            if (-not $tenantId) {
                $acct = Invoke-AzCommandJson -Arguments @('account', 'show')
                if ($acct.Success -and $acct.Data) { $tenantId = $acct.Data.tenantId }
            }
        }
    }

    if (-not $dceName) { $dceName = 'sample-data-dce' }

    $resourceId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.OperationalInsights/workspaces/$workspaceName"
    return @{
        TenantId            = $tenantId
        SubscriptionId      = $subscriptionId
        ResourceGroup       = $resourceGroup
        WorkspaceName       = $workspaceName
        WorkspaceId         = $workspaceId
        WorkspaceResourceId = $resourceId
        DceName             = $dceName
    }
}
