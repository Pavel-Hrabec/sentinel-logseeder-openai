# ConvertTo-Scenario.ps1
# Convert a normalized Atomic Red Team item into a product-agnostic scenario JSON object
# matching scenarios/_template.json shape.

$ErrorActionPreference = 'Stop'

# --- Phase builders -----------------------------------------------------------
# Each builder returns one or more timeline phase objects given:
#   $Item   : merged atomic technique bucket (TechniqueId, TechniqueName, SubTechniques, AllTests)
#   $Tables : list of mapped table entries from technique-table-map.json

function _Sanitize-CommandLine {
    param([string]$Cmd)
    if (-not $Cmd) { return '' }
    # Truncate to keep templates compact and strip Atomic input-arg placeholders
    $t = $Cmd -replace '\r?\n', ' ' -replace '\s+', ' '
    if ($t.Length -gt 400) { $t = $t.Substring(0, 400) + '...' }
    return $t.Trim()
}

function _CommandSamples {
    param($Item, [int]$Max = 6)
    $out = @()
    foreach ($sub in $Item.SubTechniques) {
        foreach ($t in $sub.Tests) {
            $c = _Sanitize-CommandLine $t.Command
            if ($c) { $out += $c }
            if ($out.Count -ge $Max) { break }
        }
        if ($out.Count -ge $Max) { break }
    }
    if (-not $out) { $out = @('') }
    return $out
}

function Build-CredentialBruteforcePhases {
    param($Item, $Tables)
    @(
        [ordered]@{
            phase           = "Brute Force - Failed Logons ($($Item.TechniqueId))"
            description     = "Repeated failed authentication attempts characteristic of $($Item.TechniqueName)."
            offsetMinutes   = 0
            durationMinutes = 20
            table           = 'Authentication'
            count           = 60
            eventTemplate   = [ordered]@{
                EventType          = 'Logon'
                EventResult        = 'Failure'
                EventResultDetails = @('InvalidPassword', 'NoSuchUser', 'AccountLocked')
                EventSeverity      = 'Low'
                SrcIpAddr          = '{{attacker.ip}}'
                TargetUsername     = '{{victim.username}}'
                TargetUsernameType = 'Simple'
                LogonMethod        = @('Remote', 'Interactive')
                LogonProtocol      = @('RDP', 'SSH', 'Kerberos', 'NTLM')
                EventCount         = 1
            }
        },
        [ordered]@{
            phase           = "Brute Force - Successful Logon ($($Item.TechniqueId))"
            description     = 'Attacker eventually authenticates successfully.'
            offsetMinutes   = 22
            durationMinutes = 1
            table           = 'Authentication'
            count           = 1
            eventTemplate   = [ordered]@{
                EventType          = 'Logon'
                EventResult        = 'Success'
                EventSeverity      = 'Informational'
                SrcIpAddr          = '{{attacker.ip}}'
                TargetUsername     = '{{victim.username}}'
                TargetUsernameType = 'Simple'
                LogonMethod        = 'Remote'
                LogonProtocol      = 'RDP'
                EventCount         = 1
            }
        }
    )
}

function Build-ValidAccountsPhases {
    param($Item, $Tables)
    @(
        [ordered]@{
            phase           = "Valid Accounts - Anomalous Sign-in ($($Item.TechniqueId))"
            description     = "Successful authentication using stolen or default credentials."
            offsetMinutes   = 0
            durationMinutes = 10
            table           = 'Authentication'
            count           = 5
            eventTemplate   = [ordered]@{
                EventType          = 'Logon'
                EventResult        = 'Success'
                EventSeverity      = 'Informational'
                SrcIpAddr          = '{{attacker.ip}}'
                TargetUsername     = '{{victim.username}}'
                TargetUsernameType = 'Simple'
                LogonMethod        = @('Remote', 'Interactive', 'Network')
                LogonProtocol      = @('Kerberos', 'NTLM', 'RDP')
                EventCount         = 1
            }
        }
    )
}

function Build-LateralAuthPhases {
    param($Item, $Tables)
    @(
        [ordered]@{
            phase           = "Lateral Movement - Auth on Remote Host ($($Item.TechniqueId))"
            description     = "Authentication to a remote system over a remote service ($($Item.TechniqueName))."
            offsetMinutes   = 0
            durationMinutes = 5
            table           = 'Authentication'
            count           = 4
            eventTemplate   = [ordered]@{
                EventType          = 'Logon'
                EventResult        = 'Success'
                EventSeverity      = 'Informational'
                SrcIpAddr          = '{{victim.ip}}'
                TargetUsername     = '{{victim.username}}'
                TargetUsernameType = 'Simple'
                LogonMethod        = 'Remote'
                LogonProtocol      = @('RDP', 'SMB', 'WinRM', 'SSH')
                DvcHostname        = '{{targetServer.device}}'
                EventCount         = 1
            }
        }
    )
}

function Build-CommandExecutionPhases {
    param($Item, $Tables)
    $cmds = _CommandSamples -Item $Item -Max 8
    @(
        [ordered]@{
            phase           = "Execution - Interpreter Commands ($($Item.TechniqueId))"
            description     = "Suspicious commands executed via $($Item.TechniqueName)."
            offsetMinutes   = 0
            durationMinutes = 5
            table           = 'ProcessEvent'
            count           = [Math]::Max($cmds.Count, 6)
            eventTemplate   = [ordered]@{
                EventType            = 'ProcessCreated'
                EventResult          = 'Success'
                EventSeverity        = 'Medium'
                ActingProcessName    = @('explorer.exe', 'cmd.exe', 'services.exe')
                TargetProcessName    = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'bash', 'sh')
                TargetProcessCommandLine = $cmds
                ActorUsername        = '{{victim.username}}'
                DvcHostname          = '{{victim.device}}'
                EventCount           = 1
            }
        }
    )
}

function Build-CredentialDumpPhases {
    param($Item, $Tables)
    $cmds = _CommandSamples -Item $Item -Max 6
    @(
        [ordered]@{
            phase           = "Credential Dumping - Process ($($Item.TechniqueId))"
            description     = "Tools/commands associated with credential dumping ($($Item.TechniqueName))."
            offsetMinutes   = 0
            durationMinutes = 3
            table           = 'ProcessEvent'
            count           = 8
            eventTemplate   = [ordered]@{
                EventType                = 'ProcessCreated'
                EventResult              = 'Success'
                EventSeverity            = 'High'
                ActingProcessName        = @('powershell.exe', 'cmd.exe')
                TargetProcessName        = @('mimikatz.exe', 'procdump.exe', 'rundll32.exe', 'lsass.exe', 'reg.exe', 'ntdsutil.exe')
                TargetProcessCommandLine = $cmds
                ActorUsername            = '{{victim.username}}'
                DvcHostname              = '{{victim.device}}'
                EventCount               = 1
            }
        },
        [ordered]@{
            phase           = "Credential Dumping - Sensitive File Access ($($Item.TechniqueId))"
            description     = 'Access to credential stores on disk.'
            offsetMinutes   = 1
            durationMinutes = 2
            table           = 'FileEvent'
            count           = 5
            eventTemplate   = [ordered]@{
                EventType        = @('FileAccessed', 'FileRead')
                EventResult      = 'Success'
                EventSeverity    = 'High'
                TargetFilePath   = @('C:\Windows\System32\config\SAM', 'C:\Windows\System32\config\SYSTEM', 'C:\Windows\NTDS\ntds.dit', 'C:\Windows\System32\lsass.dmp', '/etc/shadow')
                ActingProcessName = @('powershell.exe', 'cmd.exe', 'reg.exe')
                ActorUsername    = '{{victim.username}}'
                DvcHostname      = '{{victim.device}}'
                EventCount       = 1
            }
        }
    )
}

function Build-PersistenceAutostartPhases {
    param($Item, $Tables)
    @(
        [ordered]@{
            phase           = "Persistence - Autostart Registry Modification ($($Item.TechniqueId))"
            description     = "Registry changes establishing autostart persistence ($($Item.TechniqueName))."
            offsetMinutes   = 0
            durationMinutes = 2
            table           = 'RegistryEvent'
            count           = 4
            eventTemplate   = [ordered]@{
                EventType            = @('RegistryValueSet', 'RegistryKeyCreated')
                EventResult          = 'Success'
                EventSeverity        = 'Medium'
                RegistryKey          = @(
                    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
                    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services'
                )
                RegistryValueName    = @('Updater', 'OneDriveSync', 'SecurityHealth', 'Shell')
                RegistryValueType    = @('Reg_Sz', 'Reg_ExpandSz')
                ActorUsername        = '{{victim.username}}'
                DvcHostname          = '{{victim.device}}'
                EventCount           = 1
            }
        },
        [ordered]@{
            phase           = "Persistence - Process Spawned at Logon ($($Item.TechniqueId))"
            description     = 'Persisted binary executes on next logon.'
            offsetMinutes   = 5
            durationMinutes = 1
            table           = 'ProcessEvent'
            count           = 2
            eventTemplate   = [ordered]@{
                EventType                = 'ProcessCreated'
                EventResult              = 'Success'
                ActingProcessName        = 'explorer.exe'
                TargetProcessName        = @('updater.exe', 'svchost.exe', 'wscript.exe')
                TargetProcessCommandLine = @('C:\\Users\\Public\\updater.exe', 'wscript.exe C:\\Users\\Public\\run.vbs')
                ActorUsername            = '{{victim.username}}'
                DvcHostname              = '{{victim.device}}'
                EventCount               = 1
            }
        }
    )
}

function Build-ScheduledTaskPhases {
    param($Item, $Tables)
    $cmds = _CommandSamples -Item $Item -Max 4
    @(
        [ordered]@{
            phase           = "Scheduled Task - Creation ($($Item.TechniqueId))"
            description     = "schtasks.exe / at.exe used to register a scheduled task ($($Item.TechniqueName))."
            offsetMinutes   = 0
            durationMinutes = 2
            table           = 'ProcessEvent'
            count           = 4
            eventTemplate   = [ordered]@{
                EventType                = 'ProcessCreated'
                EventResult              = 'Success'
                EventSeverity            = 'Medium'
                ActingProcessName        = @('cmd.exe', 'powershell.exe')
                TargetProcessName        = @('schtasks.exe', 'at.exe')
                TargetProcessCommandLine = $cmds
                ActorUsername            = '{{victim.username}}'
                DvcHostname              = '{{victim.device}}'
                EventCount               = 1
            }
        },
        [ordered]@{
            phase           = "Scheduled Task - Registry/Tree Update ($($Item.TechniqueId))"
            description     = 'TaskCache registry tree updated for new task.'
            offsetMinutes   = 1
            durationMinutes = 1
            table           = 'RegistryEvent'
            count           = 2
            eventTemplate   = [ordered]@{
                EventType         = 'RegistryKeyCreated'
                EventResult       = 'Success'
                RegistryKey       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
                RegistryValueName = @('Id', 'Path', 'Hash')
                RegistryValueType = 'Reg_Sz'
                ActorUsername     = '{{victim.username}}'
                DvcHostname       = '{{victim.device}}'
                EventCount        = 1
            }
        }
    )
}

function Build-CreateAccountPhases {
    param($Item, $Tables)
    @(
        [ordered]@{
            phase           = "Persistence - Account Created ($($Item.TechniqueId))"
            description     = "New local or domain account created ($($Item.TechniqueName))."
            offsetMinutes   = 0
            durationMinutes = 2
            table           = 'AuditEvent'
            count           = 3
            eventTemplate   = [ordered]@{
                EventType        = 'Create'
                EventResult      = 'Success'
                EventSeverity    = 'Medium'
                Operation        = @('UserCreated', 'AccountCreated', 'AddMemberToGroup')
                Object           = @('svc_backup', 'admin2', 'helpdesk_t1', 'support_local')
                ObjectType       = 'User'
                ActorUsername    = '{{victim.username}}'
                DvcHostname      = '{{victim.device}}'
                EventCount       = 1
            }
        }
    )
}

function Build-RansomwareEncryptPhases {
    param($Item, $Tables)
    @(
        [ordered]@{
            phase           = "Impact - Mass File Encryption ($($Item.TechniqueId))"
            description     = "High-volume file modifications consistent with ransomware encryption ($($Item.TechniqueName))."
            offsetMinutes   = 0
            durationMinutes = 15
            table           = 'FileEvent'
            count           = 250
            eventTemplate   = [ordered]@{
                EventType            = @('FileModified', 'FileRenamed', 'FileCreated')
                EventResult          = 'Success'
                EventSeverity        = 'High'
                TargetFilePath       = @(
                    'C:\\Users\\{{victim.username}}\\Documents\\report.docx.locked',
                    'C:\\Users\\{{victim.username}}\\Pictures\\photo.jpg.crypt',
                    'C:\\Users\\{{victim.username}}\\Desktop\\budget.xlsx.enc',
                    'D:\\Shares\\Finance\\ledger.xlsx.locked',
                    'D:\\Shares\\HR\\contract.pdf.crypt'
                )
                ActingProcessName    = @('rundll32.exe', 'svchost.exe', 'wmiprvse.exe', 'powershell.exe')
                ActorUsername        = '{{victim.username}}'
                DvcHostname          = '{{victim.device}}'
                EventCount           = 1
            }
        },
        [ordered]@{
            phase           = "Impact - Shadow Copy Deletion ($($Item.TechniqueId))"
            description     = 'vssadmin / wmic used to delete shadow copies before encryption.'
            offsetMinutes   = 0
            durationMinutes = 1
            table           = 'ProcessEvent'
            count           = 3
            eventTemplate   = [ordered]@{
                EventType                = 'ProcessCreated'
                EventResult              = 'Success'
                EventSeverity            = 'High'
                TargetProcessName        = @('vssadmin.exe', 'wmic.exe', 'wbadmin.exe')
                TargetProcessCommandLine = @('vssadmin.exe delete shadows /all /quiet', 'wmic.exe shadowcopy delete', 'wbadmin.exe delete catalog -quiet')
                ActorUsername            = '{{victim.username}}'
                DvcHostname              = '{{victim.device}}'
                EventCount               = 1
            }
        }
    )
}

function Build-DataCollectPhases {
    param($Item, $Tables)
    @(
        [ordered]@{
            phase           = "Collection - Sensitive File Access ($($Item.TechniqueId))"
            description     = "Sequential access to sensitive files for collection ($($Item.TechniqueName))."
            offsetMinutes   = 0
            durationMinutes = 10
            table           = 'FileEvent'
            count           = 35
            eventTemplate   = [ordered]@{
                EventType        = @('FileAccessed', 'FileRead', 'FileCopied')
                EventResult      = 'Success'
                TargetFilePath   = @(
                    'C:\\Users\\{{victim.username}}\\Documents\\passwords.xlsx',
                    'C:\\Users\\{{victim.username}}\\Documents\\customers.csv',
                    'D:\\Shares\\Finance\\Q4-2025.xlsx',
                    'D:\\Shares\\HR\\employees.csv',
                    'C:\\Users\\{{victim.username}}\\Desktop\\source.zip'
                )
                ActingProcessName = @('powershell.exe', 'explorer.exe', '7z.exe', 'rar.exe')
                ActorUsername    = '{{victim.username}}'
                DvcHostname      = '{{victim.device}}'
                EventCount       = 1
            }
        }
    )
}

# Hint -> builder dispatch
$script:PhaseBuilders = @{
    'credential-bruteforce' = 'Build-CredentialBruteforcePhases'
    'valid-accounts'        = 'Build-ValidAccountsPhases'
    'lateral-auth'          = 'Build-LateralAuthPhases'
    'command-execution'     = 'Build-CommandExecutionPhases'
    'credential-dump'       = 'Build-CredentialDumpPhases'
    'persistence-autostart' = 'Build-PersistenceAutostartPhases'
    'scheduled-task'        = 'Build-ScheduledTaskPhases'
    'create-account'        = 'Build-CreateAccountPhases'
    'ransomware-encrypt'    = 'Build-RansomwareEncryptPhases'
    'data-collect'          = 'Build-DataCollectPhases'
}

function ConvertTo-Scenario {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Item,
        [Parameter(Mandatory)] $TechniqueMap
    )

    $tid = $Item.TechniqueId
    $entry = $TechniqueMap.techniques.$tid
    if (-not $entry) {
        Write-Verbose "[scenario] Skipping $tid - no mapping"
        return $null
    }

    $hint = [string]$entry.phaseHint
    if (-not $script:PhaseBuilders.ContainsKey($hint)) {
        Write-Warning "[scenario] No phase builder for hint '$hint' (technique $tid)"
        return $null
    }
    $builderName = $script:PhaseBuilders[$hint]
    $tables = @($entry.tables)
    $phases = & $builderName -Item $Item -Tables $tables

    # Build tables block keyed by category
    $tablesBlock = [ordered]@{}
    foreach ($t in $tables) {
        $tablesBlock[$t.category] = [ordered]@{
            schema   = $t.schema
            rowCount = [int]$t.rowCount
        }
    }

    # mitreIds: parent + each sub-technique that has tests
    $mitreIds = @($tid)
    foreach ($sub in $Item.SubTechniques) {
        if ($sub.Id -ne $tid -and $sub.Tests.Count -gt 0) { $mitreIds += $sub.Id }
    }
    $mitreIds = $mitreIds | Select-Object -Unique

    $slug = ($Item.TechniqueName -replace '[^\w\s-]', '' -replace '\s+', '-').ToLower()
    if (-not $slug) { $slug = $tid.ToLower() }
    $name = "atomic-$($tid.ToLower())-$slug"

    $subSummary = ($Item.SubTechniques | Where-Object { $_.Tests.Count -gt 0 } | ForEach-Object { $_.Id }) -join ', '
    $description = "Auto-generated from Atomic Red Team. Technique $tid - $($Item.TechniqueName). " +
                   "Includes sub-techniques: $subSummary. Total atomic tests merged: $($Item.AllTests.Count)."

    [ordered]@{
        '_generated' = [ordered]@{
            source        = 'atomic-red-team'
            techniqueId   = $tid
            generatedAt   = (Get-Date).ToUniversalTime().ToString('o')
            contentHash   = $Item.CombinedHash
            subTechniques = @($Item.SubTechniques | ForEach-Object { $_.Id })
            testCount     = $Item.AllTests.Count
        }
        name          = $name
        description   = $description
        mitreTactics  = @($entry.tactics)
        mitreIds      = @($mitreIds)
        tables        = $tablesBlock
        actors        = [ordered]@{
            attacker     = [ordered]@{ ip = 'external'; username = $null }
            victim       = [ordered]@{ ip = 'internal'; username = 'random'; upn = 'random'; device = 'random' }
            targetServer = [ordered]@{ ip = 'internal'; device = 'random'; deviceFqdn = 'random' }
        }
        timeline      = @($phases)
    }
}
