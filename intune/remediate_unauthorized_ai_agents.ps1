# remediate_unauthorized_ai_agents.ps1
# Remediation script for unauthorized AI agent tools (Clawdbot, Moltbot, OpenClaw)
# Deploy via Intune Proactive Remediation - Remediation Script
# Author: IR Pros IT Security
# Version: 1.0
# Last Updated: 2026-01-31
#
# DISCLAIMER: This script is provided "AS IS" without warranty of any kind,
# express or implied. The author(s) assume no liability for any damages,
# data loss, or other issues arising from the use of this script. Use at
# your own risk. Always test in a non-production environment before deployment.
#
# WARNING: This script will forcibly terminate processes and delete files.
# Test thoroughly in a non-production environment before deployment.

$ErrorActionPreference = "SilentlyContinue"
$RemediationLog = @()
$RemediationSuccess = $true

# ============================================================================
# ARTIFACT PATHS TO REMOVE
# ============================================================================

$FileArtifacts = @(
    # Clawdbot artifacts
    "$env:USERPROFILE\.clawdbot",
    
    # Moltbot artifacts
    "$env:USERPROFILE\.moltbot",
    
    # OpenClaw artifacts
    "$env:USERPROFILE\.openclaw",
    
    # AppData locations
    "$env:APPDATA\clawdbot",
    "$env:APPDATA\moltbot",
    "$env:APPDATA\openclaw",
    "$env:LOCALAPPDATA\clawdbot",
    "$env:LOCALAPPDATA\moltbot",
    "$env:LOCALAPPDATA\openclaw",
    
    # npm global install locations
    "$env:APPDATA\npm\node_modules\clawdbot",
    "$env:APPDATA\npm\node_modules\moltbot",
    "$env:APPDATA\npm\node_modules\openclaw",
    "$env:APPDATA\npm\node_modules\@openclaw"
)

# ============================================================================
# PROCESS PATTERNS TO TERMINATE
# ============================================================================

$ProcessPatterns = @(
    "clawdbot*",
    "moltbot*",
    "openclaw*",
    "openclaw-gateway*",
    "openclaw-agent*"
)

# ============================================================================
# REGISTRY PATTERNS TO CLEAN
# ============================================================================

$RegistryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$RegistryPatterns = @("*clawdbot*", "*moltbot*", "*openclaw*")

# ============================================================================
# SCHEDULED TASK PATTERNS TO REMOVE
# ============================================================================

$TaskPatterns = @("*clawdbot*", "*moltbot*", "*openclaw*")

# ============================================================================
# REMEDIATION FUNCTIONS
# ============================================================================

function Stop-MaliciousProcesses {
    Write-Output "Terminating unauthorized processes..."
    
    foreach ($pattern in $ProcessPatterns) {
        $procs = Get-Process -Name $pattern -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($proc in $procs) {
                try {
                    $proc | Stop-Process -Force -ErrorAction Stop
                    $script:RemediationLog += "TERMINATED [PROCESS]: $($proc.Name) (PID: $($proc.Id))"
                }
                catch {
                    $script:RemediationLog += "FAILED [PROCESS]: Could not terminate $($proc.Name) (PID: $($proc.Id)) - $($_.Exception.Message)"
                    $script:RemediationSuccess = $false
                }
            }
        }
    }
}

function Remove-FileArtifacts {
    Write-Output "Removing file artifacts..."
    
    foreach ($path in $FileArtifacts) {
        if (Test-Path $path) {
            try {
                # Handle both files and directories
                if ((Get-Item $path).PSIsContainer) {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                }
                else {
                    Remove-Item -Path $path -Force -ErrorAction Stop
                }
                $script:RemediationLog += "REMOVED [FILE]: $path"
            }
            catch {
                $script:RemediationLog += "FAILED [FILE]: Could not remove $path - $($_.Exception.Message)"
                $script:RemediationSuccess = $false
            }
        }
    }
}

function Remove-RegistryPersistence {
    Write-Output "Cleaning registry persistence..."
    
    foreach ($regPath in $RegistryPaths) {
        if (Test-Path $regPath) {
            $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($items) {
                $props = $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
                foreach ($prop in $props) {
                    foreach ($pattern in $RegistryPatterns) {
                        if ($prop.Name -like $pattern -or $prop.Value -like $pattern) {
                            try {
                                Remove-ItemProperty -Path $regPath -Name $prop.Name -Force -ErrorAction Stop
                                $script:RemediationLog += "REMOVED [REGISTRY]: $regPath\$($prop.Name)"
                            }
                            catch {
                                $script:RemediationLog += "FAILED [REGISTRY]: Could not remove $regPath\$($prop.Name) - $($_.Exception.Message)"
                                $script:RemediationSuccess = $false
                            }
                        }
                    }
                }
            }
        }
    }
}

function Remove-ScheduledTasks {
    Write-Output "Removing scheduled tasks..."
    
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {
        foreach ($pattern in $TaskPatterns) {
            if ($task.TaskName -like $pattern -or $task.TaskPath -like $pattern) {
                try {
                    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
                    $script:RemediationLog += "REMOVED [SCHEDULED_TASK]: $($task.TaskPath)$($task.TaskName)"
                }
                catch {
                    $script:RemediationLog += "FAILED [SCHEDULED_TASK]: Could not remove $($task.TaskName) - $($_.Exception.Message)"
                    $script:RemediationSuccess = $false
                }
            }
        }
    }
}

function Remove-Services {
    Write-Output "Removing unauthorized services..."
    
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "*clawdbot*" -or 
        $_.Name -like "*moltbot*" -or 
        $_.Name -like "*openclaw*" -or
        $_.DisplayName -like "*clawdbot*" -or
        $_.DisplayName -like "*moltbot*" -or
        $_.DisplayName -like "*openclaw*"
    }
    
    foreach ($svc in $services) {
        try {
            # Stop the service first
            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
            }
            # Remove the service
            sc.exe delete $svc.Name | Out-Null
            $script:RemediationLog += "REMOVED [SERVICE]: $($svc.Name)"
        }
        catch {
            $script:RemediationLog += "FAILED [SERVICE]: Could not remove $($svc.Name) - $($_.Exception.Message)"
            $script:RemediationSuccess = $false
        }
    }
}

function Remove-NpmGlobalPackages {
    Write-Output "Removing global npm packages..."
    
    $packages = @("clawdbot", "moltbot", "openclaw", "@openclaw/openclaw")
    
    foreach ($pkg in $packages) {
        # Check if package exists
        $installed = npm list -g $pkg --depth=0 2>$null
        if ($installed -and $installed -notmatch "empty") {
            try {
                npm uninstall -g $pkg 2>$null
                $script:RemediationLog += "REMOVED [NPM_GLOBAL]: $pkg"
            }
            catch {
                $script:RemediationLog += "FAILED [NPM_GLOBAL]: Could not remove $pkg - $($_.Exception.Message)"
                $script:RemediationSuccess = $false
            }
        }
    }
}

function Block-NetworkPorts {
    Write-Output "Creating firewall rules to block suspicious ports..."
    
    # Block inbound on port 18789 (OpenClaw gateway default)
    $ruleName = "Block_OpenClaw_Gateway_Inbound"
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        try {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound `
                -LocalPort 18789 `
                -Protocol TCP `
                -Action Block `
                -Profile Any `
                -Description "Blocks inbound traffic on OpenClaw default gateway port" `
                -ErrorAction Stop | Out-Null
            $script:RemediationLog += "CREATED [FIREWALL]: $ruleName (Inbound TCP 18789)"
        }
        catch {
            $script:RemediationLog += "FAILED [FIREWALL]: Could not create $ruleName - $($_.Exception.Message)"
        }
    }
    
    # Block outbound on port 18789
    $ruleName = "Block_OpenClaw_Gateway_Outbound"
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        try {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Outbound `
                -RemotePort 18789 `
                -Protocol TCP `
                -Action Block `
                -Profile Any `
                -Description "Blocks outbound traffic on OpenClaw default gateway port" `
                -ErrorAction Stop | Out-Null
            $script:RemediationLog += "CREATED [FIREWALL]: $ruleName (Outbound TCP 18789)"
        }
        catch {
            $script:RemediationLog += "FAILED [FIREWALL]: Could not create $ruleName - $($_.Exception.Message)"
        }
    }
}

# ============================================================================
# MAIN REMEDIATION ROUTINE
# ============================================================================

Write-Output "========================================"
Write-Output "UNAUTHORIZED AI AGENT REMEDIATION"
Write-Output "========================================"
Write-Output "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Computer: $env:COMPUTERNAME"
Write-Output "User: $env:USERNAME"
Write-Output "----------------------------------------"

# Execute remediation steps in order
Stop-MaliciousProcesses
Start-Sleep -Seconds 2  # Allow processes to fully terminate

Remove-FileArtifacts
Remove-RegistryPersistence
Remove-ScheduledTasks
Remove-Services
Remove-NpmGlobalPackages
Block-NetworkPorts

# ============================================================================
# OUTPUT RESULTS
# ============================================================================

Write-Output ""
Write-Output "========================================"
Write-Output "REMEDIATION SUMMARY"
Write-Output "========================================"

foreach ($entry in $RemediationLog) {
    Write-Output $entry
}

Write-Output "----------------------------------------"
Write-Output "Total actions: $($RemediationLog.Count)"
Write-Output "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

if ($RemediationSuccess) {
    Write-Output "STATUS: Remediation completed successfully"
    Write-Output "========================================"
    exit 0
}
else {
    Write-Output "STATUS: Remediation completed with errors - review log"
    Write-Output "========================================"
    exit 1
}
