<#
.SYNOPSIS
Beginner setup for Sentinel LogSeeder OpenAI mode.

.DESCRIPTION
Creates config/workspace.json if needed, checks common prerequisites, and then
starts the interactive launcher. This script does not install software or write
secrets. Set OPENAI_API_KEY or AZURE_OPENAI_* variables in your shell if you
want custom AI generation.
#>
[CmdletBinding()]
param(
    [string]$WorkspaceName,
    [string]$WorkspaceId,
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$DceName = "sample-data-dce",
    [switch]$StartMenu,
    [switch]$PreviewOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$configDir = Join-Path $root "config"
$workspaceConfig = Join-Path $configDir "workspace.json"

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host ""
Write-Host "Sentinel LogSeeder OpenAI setup" -ForegroundColor Cyan
Write-Host "Project: $root" -ForegroundColor DarkGray

if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

if (-not (Test-Command "az")) {
    Write-Host "Azure CLI was not found on PATH. Install it and run az login before ingestion." -ForegroundColor Yellow
} else {
    Write-Host "Azure CLI found." -ForegroundColor Green
    try {
        $account = az account show -o json 2>$null | ConvertFrom-Json
        if ($account) {
            Write-Host ("Azure account: {0} / subscription {1}" -f $account.user.name, $account.name) -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "Azure CLI is installed, but no active login was detected. Run az login." -ForegroundColor Yellow
    }
}

if (-not (Test-Command "pwsh")) {
    Write-Host "PowerShell 7 (pwsh) was not found. It is recommended for the upstream ingestion scripts." -ForegroundColor Yellow
    Write-Host "The menu can start in Windows PowerShell, but ingestion is best run with PowerShell 7." -ForegroundColor Yellow
} else {
    Write-Host "PowerShell 7 found." -ForegroundColor Green
}

if (-not (Test-Path $workspaceConfig)) {
    if ([string]::IsNullOrWhiteSpace($WorkspaceName) -and [string]::IsNullOrWhiteSpace($WorkspaceId)) {
        Write-Host ""
        Write-Host "Workspace config was not found." -ForegroundColor Yellow
        $WorkspaceName = Read-Host "Log Analytics workspace name"
        $WorkspaceId = Read-Host "Workspace customer ID (optional)"
        $SubscriptionId = Read-Host "Subscription ID (optional)"
        $ResourceGroup = Read-Host "Resource group (optional)"
        $dceInput = Read-Host "DCE name [$DceName]"
        if (-not [string]::IsNullOrWhiteSpace($dceInput)) {
            $DceName = $dceInput
        }
    }

    $cfg = [ordered]@{}
    if (-not [string]::IsNullOrWhiteSpace($WorkspaceName)) { $cfg.workspaceName = $WorkspaceName }
    if (-not [string]::IsNullOrWhiteSpace($WorkspaceId)) { $cfg.workspaceId = $WorkspaceId }
    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) { $cfg.subscriptionId = $SubscriptionId }
    if (-not [string]::IsNullOrWhiteSpace($ResourceGroup)) { $cfg.resourceGroup = $ResourceGroup }
    if (-not [string]::IsNullOrWhiteSpace($DceName)) { $cfg.dceName = $DceName }

    if (-not $cfg.Contains("workspaceName") -and -not $cfg.Contains("workspaceId")) {
        throw "Provide WorkspaceName or WorkspaceId."
    }

    $cfg | ConvertTo-Json -Depth 10 | Out-File -FilePath $workspaceConfig -Encoding utf8
    Write-Host "Created $workspaceConfig" -ForegroundColor Green
} else {
    Write-Host "Workspace config exists: $workspaceConfig" -ForegroundColor Green
}

if (-not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_ENDPOINT) -and
    -not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_DEPLOYMENT) -and
    (-not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_API_KEY) -or -not [string]::IsNullOrWhiteSpace($env:AZURE_OPENAI_AUTH_TOKEN))) {
    Write-Host "Azure OpenAI configuration detected. Deployment: $env:AZURE_OPENAI_DEPLOYMENT" -ForegroundColor Green
} elseif (-not [string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY)) {
    $model = if ([string]::IsNullOrWhiteSpace($env:LOGSEEDER_OPENAI_MODEL)) { "gpt-4.1-mini" } else { $env:LOGSEEDER_OPENAI_MODEL }
    Write-Host "OpenAI key detected. Model: $model" -ForegroundColor Green
} else {
    Write-Host "No OpenAI/Azure OpenAI key is set. Prebuilt scenarios still work; custom AI generation will be disabled." -ForegroundColor Yellow
    Write-Host "For OpenAI, set OPENAI_API_KEY. For Azure OpenAI, set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT, and AZURE_OPENAI_API_KEY or AZURE_OPENAI_AUTH_TOKEN." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Next command:" -ForegroundColor Cyan
Write-Host "  .\scripts\Start-LogSeederOpenAI.ps1" -ForegroundColor DarkCyan

if ($StartMenu) {
    & (Join-Path (Join-Path $root "scripts") "Start-LogSeederOpenAI.ps1") -WorkspaceConfig $workspaceConfig -PreviewOnly:$PreviewOnly
}
