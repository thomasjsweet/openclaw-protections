# detect_unauthorized_ai_agents.ps1
# Detection script for unauthorized AI agent tools (Clawdbot, Moltbot, OpenClaw)
# Deploy via Intune Proactive Remediation - Detection Script
# Author: IR Pros IT Security
# Version: 1.0
# Last Updated: 2026-01-31
#
# DISCLAIMER: This script is provided "AS IS" without warranty of any kind,
# express or implied. The author(s) assume no liability for any damages,
# data loss, or other issues arising from the use of this script. Use at
# your own risk. Always test in a non-production environment before deployment.

$ErrorActionPreference = "SilentlyContinue"
$DetectionLog = @()
$Detected = $false

# ============================================================================
# ARTIFACT PATHS TO CHECK
# ============================================================================

$FileArtifacts = @(
    # Clawdbot artifacts
    "$env:USERPROFILE\.clawdbot",
    "$env:USERPROFILE\.clawdbot\moltbot.json",
    "$env:USERPROFILE\.clawdbot\config.json",
    "$env:USERPROFILE\.clawdbot\credentials",
    
    # Moltbot artifacts
    "$env:USERPROFILE\.moltbot",
    "$env:USERPROFILE\.moltbot\config.json",
    "$env:USERPROFILE\.moltbot\moltbot.json",
    
    # OpenClaw artifacts (from GitHub repo analysis)
    "$env:USERPROFILE\.openclaw",
    "$env:USERPROFILE\.openclaw\openclaw.json",
    "$env:USERPROFILE\.openclaw\workspace",
    "$env:USERPROFILE\.openclaw\credentials",
    "$env:USERPROFILE\.openclaw\credentials\oauth.json",
    "$env:USERPROFILE\.openclaw\agents",
    "$env:USERPROFILE\.openclaw\sandboxes",
    "$env:USERPROFILE\.openclaw\settings",
    "$env:USERPROFILE\.openclaw\.env",
    
    # AppData locations (common for Node.js apps)
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
# PROCESS NAMES TO CHECK
# ============================================================================

$ProcessPatterns = @(
    "clawdbot*",
    "moltbot*",
    "openclaw*",
    "openclaw-gateway*",
    "openclaw-agent*"
)

# ============================================================================
# REGISTRY KEYS TO CHECK (startup persistence)
# ============================================================================

$RegistryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$RegistryPatterns = @("*clawdbot*", "*moltbot*", "*openclaw*")

# ============================================================================
# SCHEDULED TASKS TO CHECK
# ============================================================================

$TaskPatterns = @("*clawdbot*", "*moltbot*", "*openclaw*")

# ============================================================================
# NETWORK INDICATORS
# ============================================================================

$SuspiciousPorts = @(18789, 5353)  # Default gateway port and mDNS

# ============================================================================
# DETECTION FUNCTIONS
# ============================================================================

function Test-FileArtifacts {
    foreach ($path in $FileArtifacts) {
        if (Test-Path $path) {
            $script:DetectionLog += "DETECTED [FILE]: $path"
            $script:Detected = $true
        }
    }
}

function Test-RunningProcesses {
    foreach ($pattern in $ProcessPatterns) {
        $procs = Get-Process -Name $pattern -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($proc in $procs) {
                $script:DetectionLog += "DETECTED [PROCESS]: $($proc.Name) (PID: $($proc.Id), Path: $($proc.Path))"
                $script:Detected = $true
            }
        }
    }
}

function Test-RegistryPersistence {
    foreach ($regPath in $RegistryPaths) {
        if (Test-Path $regPath) {
            $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($items) {
                $props = $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
                foreach ($prop in $props) {
                    foreach ($pattern in $RegistryPatterns) {
                        if ($prop.Name -like $pattern -or $prop.Value -like $pattern) {
                            $script:DetectionLog += "DETECTED [REGISTRY]: $regPath\$($prop.Name) = $($prop.Value)"
                            $script:Detected = $true
                        }
                    }
                }
            }
        }
    }
}

function Test-ScheduledTasks {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {
        foreach ($pattern in $TaskPatterns) {
            if ($task.TaskName -like $pattern -or $task.TaskPath -like $pattern) {
                $script:DetectionLog += "DETECTED [SCHEDULED_TASK]: $($task.TaskPath)$($task.TaskName)"
                $script:Detected = $true
            }
        }
    }
}

function Test-NetworkListeners {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($port in $SuspiciousPorts) {
        $match = $listeners | Where-Object { $_.LocalPort -eq $port }
        if ($match) {
            foreach ($conn in $match) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $script:DetectionLog += "DETECTED [NETWORK]: Port $port listening (PID: $($conn.OwningProcess), Process: $($proc.Name))"
                $script:Detected = $true
            }
        }
    }
}

function Test-ServiceInstallation {
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "*clawdbot*" -or 
        $_.Name -like "*moltbot*" -or 
        $_.Name -like "*openclaw*" -or
        $_.DisplayName -like "*clawdbot*" -or
        $_.DisplayName -like "*moltbot*" -or
        $_.DisplayName -like "*openclaw*"
    }
    
    foreach ($svc in $services) {
        $script:DetectionLog += "DETECTED [SERVICE]: $($svc.Name) ($($svc.DisplayName)) - Status: $($svc.Status)"
        $script:Detected = $true
    }
}

function Test-NodeModulesGlobal {
    # Check for global npm packages
    $npmList = npm list -g --depth=0 2>$null
    if ($npmList) {
        $patterns = @("clawdbot", "moltbot", "openclaw", "@openclaw")
        foreach ($pattern in $patterns) {
            if ($npmList -match $pattern) {
                $script:DetectionLog += "DETECTED [NPM_GLOBAL]: Package '$pattern' installed globally"
                $script:Detected = $true
            }
        }
    }
}

# ============================================================================
# MAIN DETECTION ROUTINE
# ============================================================================

Write-Output "Starting unauthorized AI agent detection scan..."
Write-Output "Scan Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Computer: $env:COMPUTERNAME"
Write-Output "User: $env:USERNAME"
Write-Output "----------------------------------------"

Test-FileArtifacts
Test-RunningProcesses
Test-RegistryPersistence
Test-ScheduledTasks
Test-NetworkListeners
Test-ServiceInstallation
Test-NodeModulesGlobal

# ============================================================================
# OUTPUT RESULTS
# ============================================================================

if ($Detected) {
    Write-Output ""
    Write-Output "========================================"
    Write-Output "DETECTION SUMMARY - THREATS FOUND"
    Write-Output "========================================"
    foreach ($entry in $DetectionLog) {
        Write-Output $entry
    }
    Write-Output "========================================"
    Write-Output "Total detections: $($DetectionLog.Count)"
    Write-Output "========================================"
    
    # Exit with code 1 to trigger remediation
    exit 1
}
else {
    Write-Output "No unauthorized AI agent artifacts detected."
    exit 0
}
