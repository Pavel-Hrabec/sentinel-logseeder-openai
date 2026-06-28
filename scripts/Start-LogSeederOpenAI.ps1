<#
.SYNOPSIS
Interactive OpenAI-powered launcher for Sentinel LogSeeder.

.DESCRIPTION
Provides a beginner-friendly menu over the existing LogSeeder PowerShell
ingestion scripts. Prebuilt scenarios and known-table ingestion do not require
OpenAI. OpenAI is used only for custom/product-specific generation and "other"
requests when OPENAI_API_KEY is configured.
#>
[CmdletBinding()]
param(
    [string]$WorkspaceConfig,
    [string]$EntitiesFile,
    [switch]$PreviewOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$modulePath = Join-Path $scriptDir "LogSeeder.OpenAI.psm1"

if (-not (Test-Path $modulePath)) {
    throw "Required module not found: $modulePath"
}

Import-Module $modulePath -Force

Start-LogSeederMenu -WorkspaceConfig $WorkspaceConfig -EntitiesFile $EntitiesFile -PreviewOnly:$PreviewOnly
