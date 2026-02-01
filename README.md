# Unauthorized AI Agent Detection & Response

Detection and automated remediation framework for unauthorized AI coding agents (Clawdbot, Moltbot, OpenClaw) using Microsoft Defender for Endpoint, Microsoft Sentinel, and Intune.

## Overview

AI coding agents are powerful tools that can execute arbitrary commands, access files, and communicate with external APIs. When installed without IT approval, they create significant security blind spots. This framework provides:

- **Proactive Detection** - Identify unauthorized installations before they cause harm
- **Automated Remediation** - Remove threats automatically via Intune
- **Centralized Visibility** - Monitor activity across your environment with Sentinel

## Components

```
├── intune/
│   ├── Detect-UnauthorizedAIAgents.ps1    # Detection script
│   └── Remediate-UnauthorizedAIAgents.ps1 # Remediation script
├── sentinel/
│   ├── SentinelRules-UnauthorizedAIAgents.json    # Analytics rules (ARM template)
│   └── SentinelWorkbook-UnauthorizedAIAgents.json # Investigation workbook
└── docs/
    └── DNSFilter-Blocklist.md             # DNS filtering domains
```

## Detection Coverage

| Category | Indicators |
|----------|-----------|
| **File Artifacts** | `~/.clawdbot`, `~/.moltbot`, `~/.openclaw`, config files, credentials |
| **Processes** | clawdbot, moltbot, openclaw, gateway, agent processes |
| **Network** | Port 18789 (gateway), Port 5353 (mDNS discovery) |
| **Persistence** | Registry Run keys, Scheduled Tasks, Windows Services |
| **API Traffic** | Non-browser connections to api.anthropic.com, api.openai.com, etc. |
| **Package Managers** | npm/pnpm/yarn/bun installations of agent packages |

## Quick Start

### 1. Deploy Intune Proactive Remediation

1. Navigate to **Intune > Devices > Remediations**
2. Create a new script package
3. Upload `Detect-UnauthorizedAIAgents.ps1` as Detection script
4. Upload `Remediate-UnauthorizedAIAgents.ps1` as Remediation script
5. Configure:
   - Run script in 64-bit PowerShell: **Yes**
   - Run as logged-on user: **No** (run as SYSTEM)
   - Schedule: **Daily**
6. Assign to device groups

### 2. Import Sentinel Analytics Rules

1. Navigate to **Microsoft Sentinel > Analytics**
2. Click **Import** 
3. Select `SentinelRules-UnauthorizedAIAgents.json`
4. Choose your workspace
5. Review and enable rules

### 3. Import Sentinel Workbook

1. Navigate to **Microsoft Sentinel > Workbooks**
2. Click **Add workbook**
3. Click **Edit** then **Advanced Editor** (`</>`)
4. Replace content with `SentinelWorkbook-UnauthorizedAIAgents.json`
5. Click **Apply** then **Save**

### 4. Configure DNS Filtering (Optional)

Add the domains from `docs/DNSFilter-Blocklist.md` to your DNS filtering solution.

## Sentinel Rules

| Rule | Severity | MITRE ATT&CK |
|------|----------|--------------|
| File Artifact Detection | Medium | T1074, T1547 |
| Process Execution Detection | High | T1059 |
| Gateway Network Activity (Port 18789) | High | T1571 |
| mDNS Discovery Activity (Port 5353) | Medium | T1046 |
| npm Package Installation | High | T1059.007 |
| Suspicious API Traffic to AI Providers | Medium | T1041, T1071 |
| Registry Persistence | High | T1547.001 |
| Scheduled Task Creation | High | T1053.005 |
| Service Installation | High | T1543.003 |
| Node.js Spawning Shell Processes | Medium | T1059 |
| WebSocket Gateway Connection | High | T1071.001 |

## Customization

### Exclude Authorized Users (Entra ID)

To exclude authorized users from the API Traffic rule, add this to the query:

```kusto
// Get authorized users from Entra group
let AuthorizedUsers = IdentityInfo
| where TimeGenerated > ago(14d)
| where GroupMembership has "YourAuthorizedGroupName"
| summarize by AccountUPN, AccountName = tolower(AccountName);

// Then add before | project:
| extend AccountNameLower = tolower(InitiatingProcessAccountName)
| join kind=leftanti AuthorizedUsers on $left.AccountNameLower == $right.AccountName
```

**Note**: Requires UEBA enabled in Sentinel (Settings > UEBA).

### Add Browser Exclusions

The Process Execution rule excludes common browsers to prevent false positives when users read articles about these tools. Add additional browsers as needed:

```kusto
| where FileName !in~ (
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    // Add more browsers here
)
```

## Prerequisites

- Microsoft Defender for Endpoint P2
- Microsoft Sentinel
- Microsoft Intune
- (Optional) DNS filtering solution (DNSFilter, Umbrella, etc.)
- (Optional) UEBA enabled for Entra group exclusions

## Technical Details

### Artifact Locations

```
~/.openclaw/
├── openclaw.json          # Main configuration
├── workspace/             # Agent workspace
├── credentials/
│   └── oauth.json         # OAuth tokens
├── agents/<agentId>/      # Multi-agent configurations
├── sandboxes/             # Docker sandbox workspaces
└── settings/
    └── tts.json           # Text-to-speech preferences
```

### Network Indicators

| Port | Protocol | Purpose |
|------|----------|---------|
| 18789 | TCP/WebSocket | Default gateway server |
| 5353 | UDP | mDNS/Bonjour service discovery |

### Process Patterns

```
openclaw onboard --install-daemon    # Initial setup
openclaw gateway --port 18789        # Gateway server
openclaw agent --message "..."       # Agent execution
```

## Contributing

Contributions welcome! Please submit issues and pull requests.

## License

MIT License - See LICENSE file for details.

## Disclaimer

This framework is provided as-is for security monitoring purposes. Test thoroughly in a non-production environment before deployment. The remediation script will forcibly terminate processes and delete files.

## References

- [Token Security - The Clawdbot Enterprise AI Risk](https://www.token.security/blog/the-clawdbot-enterprise-ai-risk-one-in-five-have-it-installed)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Sentinel Documentation](https://docs.microsoft.com/azure/sentinel/)
