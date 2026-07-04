# OpenAI PowerShell Mode

This fork keeps the original Sentinel LogSeeder ingestion engine and adds an
interactive PowerShell launcher that can use the OpenAI API instead of GitHub
Copilot.

OpenAI is optional:

- Prebuilt attack scenarios can run without OpenAI.
- Known table ingestion can run without OpenAI.
- JSON/CSV sample-file ingestion can run without OpenAI.
- Custom product/vendor schema generation uses `OPENAI_API_KEY`.

## Quick Start

```powershell
git clone <your-repo-url>
cd sentinel-logseeder-openai

az login
.\setup.ps1 -StartMenu
```

For custom AI generation with OpenAI:

```powershell
$env:OPENAI_API_KEY = "sk-..."
$env:LOGSEEDER_OPENAI_MODEL = "gpt-4.1-mini"
.\scripts\Start-LogSeederOpenAI.ps1
```

For custom AI generation with Azure OpenAI / Foundry:

```powershell
$env:AZURE_OPENAI_ENDPOINT = "https://<resource-name>.openai.azure.com/"
$env:AZURE_OPENAI_API_KEY = "<key>"
$env:AZURE_OPENAI_DEPLOYMENT = "<deployment-name>"
.\scripts\Start-LogSeederOpenAI.ps1
```

Microsoft Entra ID tokens are also supported:

```powershell
$env:AZURE_OPENAI_ENDPOINT = "https://<resource-name>.openai.azure.com/"
$env:AZURE_OPENAI_AUTH_TOKEN = az account get-access-token --resource "https://ai.azure.com/" --query accessToken -o tsv
$env:AZURE_OPENAI_DEPLOYMENT = "<deployment-name>"
.\scripts\Start-LogSeederOpenAI.ps1
```

The OpenAI model can be changed with `LOGSEEDER_OPENAI_MODEL`. The public
OpenAI base URL defaults to `https://api.openai.com/v1` and can be changed with
`OPENAI_BASE_URL`.

## Menu Paths

### 1. Run Prebuilt Attack Scenario

Lists the JSON files in `scenarios/` and lets the user select one by number.
The launcher converts the scenario's abstract categories, such as
`Authentication` and `ProcessEvent`, into ingestible ASIM tables by default.

Default mapping:

| Scenario Category | Destination Table |
|---|---|
| Authentication | `ASimAuthenticationEventLogs` |
| ProcessEvent | `ASimProcessEventLogs` |
| FileEvent | `ASimFileEventLogs` |
| RegistryEvent | `ASimRegistryEventLogs` |
| NetworkSession | `ASimNetworkSessionLogs` |
| Dns | `ASimDnsActivityLogs` |
| AuditEvent | `ASimAuditEventLogs` |
| UserManagement | `ASimUserManagementActivityLogs` |

The launcher writes a generated runtime scenario to `scenarios/*-openai-runtime.json`.
Those files are ignored by git. Prebuilt scenarios always use the original
upstream row and event counts.

### 2. Ingest Sample Data Into A Table

Uses an existing schema from `schemas/` and calls:

```powershell
.\scripts\Invoke-SampleDataIngestion.ps1 -Deploy -Ingest
```

The default row count is intentionally small.

### 3. Generate Product/Vendor Logs With AI

Calls the OpenAI or Azure OpenAI Responses API and asks for a LogSeeder schema.
The schema is saved into `schemas/<table>.json` only after confirmation.

The AI does not run Azure commands. It only creates structured JSON for the
PowerShell launcher to review and save.

### 4. Ingest JSON/CSV Sample File

Uses the upstream sample-file path. The existing engine infers column types
from the first sample row and uses the file values as sample pools.

### 5. Configure/Test Workspace

Creates or reviews `config/workspace.json`. This file is ignored by git.

### 6. Other

Uses OpenAI to recommend the safest next menu path. It does not execute Azure
commands.

## Cost Controls

- Prebuilt scenarios use the original upstream scenario size.
- Default table generation is 25 rows.
- The launcher asks for confirmation before billable ingestion.
- Each destination table gets its own DCR because this is the most reliable
  pattern for custom Logs Ingestion API streams.
- OpenAI is only called for custom generation and "other" requests.
- Generated schemas are cached as files, so they can be reused without more
  OpenAI calls.

Azure cost still depends on Log Analytics and Sentinel ingestion, retention,
and queries. Use preview mode first, keep single-table/custom row counts low for
demos, and set workspace daily caps where appropriate.

## Verify Logs

After ingestion, the scripts print a KQL query that can be pasted directly into
Microsoft Sentinel > Logs. For prebuilt scenarios that use the default ASIM
mapping, this query shows recent seeded rows across the supported tables:

```kql
union isfuzzy=true withsource=LogTable
    ASimAuthenticationEventLogs,
    ASimProcessEventLogs,
    ASimFileEventLogs,
    ASimRegistryEventLogs,
    ASimNetworkSessionLogs,
    ASimDnsActivityLogs,
    ASimAuditEventLogs,
    ASimUserManagementActivityLogs
| where TimeGenerated > ago(24h)
| order by TimeGenerated desc
```

## Upstream Compatibility

The original scripts remain the ingestion engine:

- `scripts/Invoke-SampleDataIngestion.ps1`
- `scripts/Invoke-AttackScenarioIngestion.ps1`

The OpenAI mode adds a launcher around them rather than replacing them.
