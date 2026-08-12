# Sentinel LogSeeder OpenAI

Beginner-friendly PowerShell launcher for generating and ingesting synthetic
security logs into Microsoft Sentinel / Log Analytics.

This fork keeps the useful ingestion engine from the original
[sentinel-logseeder](https://github.com/javiersoriano/sentinel-logseeder)
project, but removes the need for GitHub Copilot. You can run prebuilt
scenarios without any AI key. OpenAI or Azure OpenAI is only needed when you ask
the tool to generate a new custom product/vendor schema or interpret a free-form
request.

## What This Does

- Runs prebuilt attack scenarios into Microsoft Sentinel.
- Creates Sentinel scheduled analytics rules for prebuilt scenarios.
- Generates sample rows for existing supported tables.
- Ingests JSON or CSV sample files.
- Optionally uses OpenAI or Azure OpenAI to create reusable custom schemas.
- Prints KQL you can paste directly into Microsoft Sentinel > Logs.
- Uses the original Azure Monitor Logs Ingestion API based scripts underneath.

## What This Does Not Require

- GitHub Copilot is not required.
- OpenAI is not required for prebuilt scenarios.
- OpenAI is not required for known-table sample ingestion.
- OpenAI is not required for JSON/CSV file ingestion.

## Prerequisites

- Azure CLI installed and signed in with `az login`.
- PowerShell 7 recommended. Windows PowerShell can start the menu, but
  PowerShell 7 is the safer default for sharing and repeatable demos.
- A Log Analytics workspace with Microsoft Sentinel enabled.
- Permissions to create or reuse ingestion resources:
  - Log Analytics Contributor, or equivalent permissions for workspace/table/DCR work.
  - Permission to assign `Monitoring Metrics Publisher` on the DCR, or someone
    with that permission can run the printed role assignment command.

The scripts create or reuse:

- Data Collection Endpoint (DCE)
- Data Collection Rule (DCR) per destination table
- Supported Log Analytics tables
- DCR deployment metadata in ignored `schemas/*.deploy.json` files

## Quick Start

```powershell
git clone https://github.com/Pavel-Hrabec/sentinel-logseeder-openai.git
cd sentinel-logseeder-openai

az login
pwsh -ExecutionPolicy Bypass -File .\setup.ps1 -StartMenu
```

If `pwsh` is not available, Windows PowerShell can also start the setup:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1 -StartMenu
```

The setup script checks for common prerequisites, creates
`config/workspace.json` if needed, and opens the interactive menu.

## Workspace Configuration

The setup wizard can create `config/workspace.json` interactively. You can also
create it manually:

```json
{
  "workspaceName": "<your-log-analytics-workspace-name>",
  "subscriptionId": "<your-subscription-id>",
  "resourceGroup": "<your-resource-group>",
  "dceName": "sample-data-dce"
}
```

You can use `workspaceId` instead of `workspaceName` if you prefer the workspace
customer ID:

```json
{
  "workspaceId": "<workspace-customer-id-guid>",
  "subscriptionId": "<your-subscription-id>",
  "resourceGroup": "<your-resource-group>",
  "dceName": "sample-data-dce"
}
```

`config/workspace.json` is ignored by git and should not be committed.

## Optional AI Configuration

AI is optional. Configure it only if you want to use:

- Generate product/vendor logs with AI
- Other / describe what you want
- Custom schema generation

### OpenAI

```powershell
$env:OPENAI_API_KEY = "<your-openai-api-key>"
$env:LOGSEEDER_OPENAI_MODEL = "gpt-4.1-mini"
pwsh -ExecutionPolicy Bypass -File .\scripts\Start-LogSeederOpenAI.ps1
```

### Azure OpenAI / Azure AI Foundry

```powershell
$env:AZURE_OPENAI_ENDPOINT = "https://<resource-name>.openai.azure.com/"
$env:AZURE_OPENAI_API_KEY = "<your-azure-openai-key>"
$env:AZURE_OPENAI_DEPLOYMENT = "<deployment-name>"
pwsh -ExecutionPolicy Bypass -File .\scripts\Start-LogSeederOpenAI.ps1
```

Microsoft Entra token auth is also supported:

```powershell
$env:AZURE_OPENAI_ENDPOINT = "https://<resource-name>.openai.azure.com/"
$env:AZURE_OPENAI_DEPLOYMENT = "<deployment-name>"
$env:AZURE_OPENAI_AUTH_TOKEN = az account get-access-token --resource "https://ai.azure.com/" --query accessToken -o tsv
pwsh -ExecutionPolicy Bypass -File .\scripts\Start-LogSeederOpenAI.ps1
```

Depending on your Azure AI resource, the endpoint may also look like
`https://<resource-name>.cognitiveservices.azure.com/`.

Do not commit API keys, tokens, or local workspace config files.

## Menu Options

When you run `setup.ps1 -StartMenu` or `scripts/Start-LogSeederOpenAI.ps1`, you
get a numbered menu.

| Option | What it does | Needs AI? | Good for |
|---|---|---:|---|
| Run prebuilt attack scenario | Lets you choose a scenario from `scenarios/`, maps it to supported ASIM tables, deploys resources, optionally ingests correlated attack data, and can create a Sentinel analytics rule for the scenario. | No | First demo, Sentinel detections, training data |
| Ingest sample data into a table | Uses an existing schema from `schemas/` and generates rows for one table. | No | Quick table validation |
| Generate product/vendor logs with AI | Uses OpenAI or Azure OpenAI to create a reusable schema, then optionally deploys and ingests sample rows. | Yes | New custom log source demos |
| Ingest JSON/CSV sample file | Infers a schema from a local sample file and ingests generated rows using values from that file. | No | Turning real-looking samples into Sentinel test data |
| Configure/test workspace | Creates or reviews `config/workspace.json`. | No | Setup and troubleshooting |
| Other / describe what you want | Uses AI to recommend the safest next menu path. | Yes | Guidance when you are unsure |

Most ingestion paths then ask for an action:

| Action | What happens |
|---|---|
| Deploy and ingest | Creates/reuses Azure ingestion resources and sends synthetic log rows. This can create Azure/Sentinel ingestion cost. |
| Deploy, ingest, and create detection rule | Runs the full demo path, then creates or updates a Sentinel scheduled analytics rule that creates incidents for matching scenario logs. |
| Create detection rule | Creates or updates the Sentinel analytics rule only. It does not deploy ingestion resources or send logs. |
| Deploy only | Creates/reuses DCE, DCR, table resources, and deployment metadata, but sends no log data. |
| Ingest only | Uses existing `schemas/*.deploy.json` metadata to send log data without redeploying. |
| Preview command only | Prints the underlying command and makes no Azure changes. Recommended before a first run. |

## Recommended First Run

Use a prebuilt scenario first because it does not require any AI key.

```powershell
pwsh -ExecutionPolicy Bypass -File .\setup.ps1 -StartMenu
```

Then choose:

1. `Run prebuilt attack scenario`
2. A scenario such as `brute-force-lateral-movement`
3. `Use ASIM defaults`
4. `Preview command only`

Review the command. If it looks correct, run the same path again and choose
`Deploy, ingest, and create detection rule`.

Prebuilt scenarios use the original upstream scenario size. The script shows a
cost guard before any billable ingestion.

## How The Current Version Works

The main tested path is the prebuilt scenario workflow. It is designed so a
beginner can choose numbered options and still get a complete Sentinel demo:
synthetic logs, an analytics rule, and a Sentinel incident.

Run:

```powershell
pwsh -ExecutionPolicy Bypass -File .\scripts\Start-LogSeederOpenAI.ps1
```

Then choose:

1. `Run prebuilt attack scenario`
2. Pick a built-in scenario, for example `brute-force-lateral-movement`
3. `Use ASIM defaults`
4. `Deploy, ingest, and create detection rule`
5. Confirm the billable ingestion guard
6. Confirm the detection rule guard

The launcher then performs these steps in order:

1. Reads the selected scenario from `scenarios/*.json`.
2. Maps scenario categories to supported ASIM tables.
3. Writes a local runtime file in `scenarios/*-openai-runtime.json`.
4. Creates or reuses the DCE, DCRs, and destination tables.
5. Ingests the scenario rows into Log Analytics / Sentinel.
6. Creates or updates a Microsoft Sentinel scheduled analytics rule.
7. The analytics rule creates an incident when the generated KQL matches the
   ingested scenario logs.

The menu waits for the ingestion script to finish before creating the detection
rule. If deployment or ingestion fails, the menu stops instead of continuing
with a partial run.

The workspace resolver first uses direct lookup when `workspaceName`,
`subscriptionId`, and `resourceGroup` are present in `config/workspace.json`.
This avoids broad subscription discovery problems in beginner environments.

The full path has been tested with these built-in scenarios:

| Scenario | Rule / incident name | Default tables |
|---|---|---|
| `brute-force-lateral-movement` | `Brute Force Lateral Movement` | `ASimAuthenticationEventLogs`, `ASimNetworkSessionLogs`, `ASimProcessEventLogs` |
| `credential-theft-privesc` | `Credential Theft Privesc` | `ASimAuthenticationEventLogs`, `ASimProcessEventLogs`, `ASimUserManagementActivityLogs` |
| `data-exfiltration` | `Data Exfiltration` | `ASimAuditEventLogs`, `ASimFileEventLogs`, `ASimNetworkSessionLogs`, `ASimDnsActivityLogs` |
| `ransomware-deployment` | `Ransomware Deployment` | `ASimAuthenticationEventLogs`, `ASimProcessEventLogs`, `ASimFileEventLogs`, `ASimRegistryEventLogs` |

Generated analytics rule and incident names use the scenario name directly.
They do not add `LogSeeder` as a prefix.

## Example: Run A Prebuilt Scenario

What it does:

- Reads a scenario JSON file from `scenarios/`.
- Converts abstract categories such as `Authentication`, `ProcessEvent`, and
  `NetworkSession` into supported ASIM destination tables.
- Creates a runtime scenario file in `scenarios/*-openai-runtime.json`.
- Deploys or reuses DCE/DCR/table resources.
- Ingests correlated synthetic events.
- Optionally creates a Sentinel scheduled analytics rule with incident creation enabled.
- Prints KQL for Sentinel Logs.

Example destination tables:

- `ASimAuthenticationEventLogs`
- `ASimNetworkSessionLogs`
- `ASimProcessEventLogs`

The detection rule is generated from the selected scenario's phase templates.
For example, a brute-force scenario rule looks for the authentication,
network-session, and process-event patterns described in that scenario rather
than simply alerting on every row in those tables.

Scenario detection rules run every 5 minutes, look back 6 hours by default, and
create Microsoft Sentinel incidents when matching logs are found. Suppression is
enabled for the lookback window to avoid repeated alert noise from the same demo
data. Generated analytics rule and incident names use the scenario name directly,
without adding the repository/tool name as a prefix.

## Example: Ingest Sample Data Into A Table

What it does:

- Lets you choose an existing schema from `schemas/`.
- Asks how many rows to generate. The default is intentionally low.
- Deploys or reuses ingestion resources.
- Sends generated rows to the selected table.
- Prints KQL for that table.

Example use cases:

- Generate 25 rows for `ASimAuthenticationEventLogs`.
- Generate test rows for a custom `_CL` table.
- Validate that a DCR and DCE are working.

## Example: Generate Product/Vendor Logs With AI

What it does:

- Asks for a product/vendor or log source name.
- Calls OpenAI or Azure OpenAI to draft a LogSeeder schema.
- Saves the schema into `schemas/<table>.json` after confirmation.
- Optionally runs deployment and ingestion for that generated table.

Example ideas:

- `Okta authentication events`
- `Contoso VPN login logs`
- `Custom firewall deny events`
- `Demo EDR process telemetry`

The generated schema is just a local JSON file. You can review and edit it
before ingesting anything.

## Example: Ingest A JSON Or CSV Sample File

What it does:

- Reads a local `.json` or `.csv` file.
- Infers columns and sample values.
- Creates/reuses ingestion resources.
- Generates rows using values from the file.
- Sends them to the destination table.

This is useful when you have sample logs but do not want to write the schema by
hand.

## Verify Logs In Sentinel

After ingestion, the scripts print KQL that can be pasted directly into
Microsoft Sentinel > Logs.

For default ASIM scenario tables, this query shows recent seeded rows across the
common prebuilt destinations:

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

For a single table, use:

```kql
<TableName>
| where TimeGenerated > ago(24h)
| order by TimeGenerated desc
```

Logs can take 5-10 minutes to appear after ingestion.

## Verify Analytics Rules And Incidents

To verify the built-in scenario analytics rules, use Azure CLI:

```powershell
az rest --method get `
  --uri "https://management.azure.com/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>/providers/Microsoft.SecurityInsights/alertRules?api-version=2025-09-01" `
  --query "value[?properties.displayName=='Brute Force Lateral Movement' || properties.displayName=='Credential Theft Privesc' || properties.displayName=='Data Exfiltration' || properties.displayName=='Ransomware Deployment'].properties.{displayName:displayName,enabled:enabled,queryFrequency:queryFrequency,queryPeriod:queryPeriod,suppressionEnabled:suppressionEnabled,createIncident:incidentConfiguration.createIncident,severity:severity}" `
  -o table
```

Expected rule settings:

```text
Enabled=True
QueryFrequency=PT5M
QueryPeriod=PT6H
SuppressionEnabled=True
CreateIncident=True
Severity=Medium
```

To verify incidents in Sentinel Logs:

```kql
SecurityIncident
| where TimeGenerated > ago(24h)
| where Title in~ (
    "Brute Force Lateral Movement",
    "Credential Theft Privesc",
    "Data Exfiltration",
    "Ransomware Deployment"
)
| project TimeGenerated, IncidentNumber, Title, Severity, Status
| order by TimeGenerated desc
```

To verify alerts:

```kql
SecurityAlert
| where TimeGenerated > ago(24h)
| where AlertName in~ (
    "Brute Force Lateral Movement",
    "Credential Theft Privesc",
    "Data Exfiltration",
    "Ransomware Deployment"
)
| project TimeGenerated, AlertName, AlertSeverity, ProviderName, SystemAlertId
| order by TimeGenerated desc
```

## Supported Destinations

The Azure Monitor Logs Ingestion API supports custom `_CL` tables and a limited
set of built-in tables. This project is designed around those supported
destinations.

Good default choices for scenarios are the ASIM normalized tables included in
the repo:

- `ASimAuthenticationEventLogs`
- `ASimProcessEventLogs`
- `ASimFileEventLogs`
- `ASimRegistryEventLogs`
- `ASimNetworkSessionLogs`
- `ASimDnsActivityLogs`
- `ASimAuditEventLogs`
- `ASimUserManagementActivityLogs`
- `ASimWebSessionLogs`
- `ASimDhcpEventLogs`

You cannot ingest into vendor-managed tables such as `SigninLogs`, `AuditLogs`,
or `DeviceProcessEvents`. Those tables are populated by their source products.
Use supported ASIM tables or custom `_CL` tables for synthetic training data.

## Project Structure

| Path | Purpose |
|---|---|
| `setup.ps1` | Beginner setup and optional menu launcher |
| `scripts/Start-LogSeederOpenAI.ps1` | Interactive menu entrypoint |
| `scripts/LogSeeder.OpenAI.psm1` | Menu logic and OpenAI/Azure OpenAI integration |
| `scripts/Invoke-ScenarioDetectionRule.ps1` | Creates or previews Sentinel scheduled analytics rules for generated runtime scenarios |
| `scripts/Invoke-SampleDataIngestion.ps1` | Original single-table ingestion engine, with KQL verification output |
| `scripts/Invoke-AttackScenarioIngestion.ps1` | Original multi-table scenario ingestion engine, with KQL verification output |
| `schemas/` | Reusable table schema JSON files |
| `scenarios/` | Prebuilt attack scenario JSON files |
| `samples/` | Example JSON/CSV data files |
| `config/entities.json` | Shared entity pools for users, IPs, devices, domains, and URLs |
| `config/workspace.json.template` | Example workspace configuration |
| `docs/openai-mode.md` | More detail on the OpenAI/Azure OpenAI mode |
| `NOTICE.md` | Notes about the upstream project and fork changes |

Generated local files are ignored by git:

- `config/workspace.json`
- `schemas/*.deploy.json`
- `scenarios/*-openai-runtime.json`

## Cost Notes

- Preview mode does not make Azure changes.
- Deploy only creates/reuses Azure resources but does not ingest rows.
- Create detection rule creates or updates a Sentinel analytics rule but does not ingest rows.
- Deploy and ingest sends billable Log Analytics/Sentinel data.
- Each table uses a dedicated DCR. This is more reliable for Logs Ingestion API
  propagation than updating one shared DCR with new custom streams.
- Prebuilt scenarios use the original scenario row/event counts.
- Single-table and custom AI paths default to low row counts.
- Set workspace daily caps and retention appropriately for demos.

## Troubleshooting

If Azure CLI is not signed in:

```powershell
az login
az account show
```

Make sure Azure CLI is using the tenant and subscription that contain the target
workspace:

```powershell
az account list -o table
az account set --subscription "<subscription-name-or-id>"
az account show
```

This matters because Logs Ingestion API uses the current Azure CLI token. The
signed-in principal must have `Monitoring Metrics Publisher` on each DCR used by
the scenario.

If role assignment fails during deployment, ask someone with Owner or User
Access Administrator permissions to assign `Monitoring Metrics Publisher` on the
DCR. The script prints a command you can use.

If ingestion fails with `authentication token provided does not have access to
ingest data`, the `Monitoring Metrics Publisher` role assignment may still be
propagating. The ingestion step retries this specific 403, but if Azure still
blocks it, wait a few minutes and use `Ingest only` for the same table/scenario.

If ingestion fails with a message like `data collection endpoint FQDN is not
associated with the data collection rule`, rerun the same path with `Deploy and
ingest` or `Deploy only`. The deployment step checks existing DCRs and updates
them when they point to an old or different DCE. Azure can take a few minutes
to propagate that association, so ingestion retries this specific 403 before
failing.

If logs do not appear immediately, wait 5-10 minutes and rerun the KQL with a
larger time window:

```kql
<TableName>
| where TimeGenerated > ago(48h)
| order by TimeGenerated desc
```

If custom AI generation says AI is not configured, set either the OpenAI
environment variables or the Azure OpenAI environment variables shown above.

If custom table deployment says a table already exists with different casing,
for example `fortinet_CL` exists as `Fortinet_CL`, rerun with the latest code.
The deploy step reuses the Azure table casing for the DCR and ingestion stream.

## Upstream Credit

This repository is based on the original Sentinel LogSeeder project by Javier
Soriano:

https://github.com/javiersoriano/sentinel-logseeder

This fork keeps the original ingestion approach and reusable scenario/schema
assets, then adds a PowerShell menu and OpenAI/Azure OpenAI option so beginners
can run it without GitHub Copilot.
