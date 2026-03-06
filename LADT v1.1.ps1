<#
    LADT v3.1
    A Lightweight Auto-Discovery Tool for domain-wide computer/servers while running parallel audits.
    This script also scans for potential risks such as open ports and unknown processes.
    
    by Murat Berber
    

    Change Log:
    v1.1 - 2024-03-15
        - Added self-elevation block for PS5 compatibility
        - Improved error handling in audit function
        - Added test mode for quick audits on TEST* machines
        - Added risk flagging logic for security and management purposes
#>

param(
    [string]$Domain = $env:USERDNSDOMAIN,
    [string]$OutputPath = ".\DomainWideAudit_$(Get-Date -f 'yyyyMMdd_HHmm')",
    [int]$ThrottleLimit = 16,
    [switch]$ServersOnly,
    [switch]$TestRun
)

# Self-Elevation Block (for PS5 Compatibility)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Elevation required. Restarting with admin privileges..." -ForegroundColor Yellow
    
    $scriptPath = $MyInvocation.MyCommand.Path
    $exe = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
    
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Domain $Domain -OutputPath `"$OutputPath`" -ThrottleLimit $ThrottleLimit"
    if ($ServersOnly) { $arguments += " -ServersOnly" }
    if ($TestRun) { $arguments += " -TestRun" }
    
    Start-Process -FilePath $exe -Verb RunAs -ArgumentList $arguments
    exit
}

# Pre-reqs Check

if (-not (Get-Module ActiveDirectory -ListAvailable)) {
    Write-Error "ActiveDirectory module required. Install RSAT-AD-PowerShell feature."
    exit 1
}

Import-Module ActiveDirectory

if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }
$rptDate = Get-Date -Format "yyyy-MM-dd"

# Autodiscover Domain Computers

Write-Host "`nDiscovering ALL computers in domain: $Domain" -ForegroundColor Cyan

$filter = if ($ServersOnly) { 
    "(OperatingSystem -like '*Server*') -and (Name -notlike 'DC*')" 
} else { 
    "*" 
}

if ($TestRun) { 
    $filter = "Name -like 'TEST*'"
    Write-Host "TEST MODE: Only TEST* computers" -ForegroundColor Yellow
}

$allComputers = Get-ADComputer -Filter $filter -Properties Name,OperatingSystem,LastLogonDate |
    Where-Object { $_.Name -ne $null } |
    Select-Object Name, OperatingSystem, @{N='DaysSinceLogon';E={
        if($_.LastLogonDate){ 
            [math]::Round((New-TimeSpan $_.LastLogonDate $(Get-Date)).TotalDays,0) 
        } else { 999 }
    }} |
    Sort-Object Name

Write-Host "Found $($allComputers.Count) targets:" -ForegroundColor Green
Write-Host "   Servers: $(($allComputers | Where-Object { $_.OperatingSystem -like '*Server*' }).Count)"
Write-Host "   Workstations: $(($allComputers | Where-Object { $_.OperatingSystem -notlike '*Server*' }).Count)"
Write-Host "   Stale (>90 days): $(($allComputers | Where-Object { $_.DaysSinceLogon -gt 90 }).Count)"

if ($TestRun -and $allComputers.Count -eq 0) {
    Write-Host "No test machines found. Run without -TestRun for full audit." -ForegroundColor Yellow -BackgroundColor Black
    exit 0
}

$targetList = $allComputers.Name

# Audit Function Block (Runs on each server in parallel)

function Invoke-ServerAudit {
    param([string]$Computer)

    $srvName = if ($Computer -eq "localhost") { (hostname).ToUpper() } else { $Computer.ToUpper() }
    
    try {
        # TCP Mapping (Pre-filtered for common ports)
        $tcpMap = @{}
        $standardPorts = @(80,443,3389,22,23,25,53,110,123,143)
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -notin $standardPorts } |
            Group-Object OwningProcess |
            ForEach-Object { $tcpMap[$_.Name] = ($_.Group.LocalPort -join ';') }

        # Processes (Batch Get-Process)
        $processList = Get-Process -ErrorAction SilentlyContinue |
            Select-Object Id, ProcessName, 
                @{N='UserName';E={if($_.PSObject.Properties['UserName']){$_.UserName}else{$null}}},
                @{N='FileName';E={try{$_.MainModule.FileName}catch{$null}}}
        
        $processes = foreach ($proc in $processList) {
            $ports = $tcpMap[$proc.Id]
            $risk = if ($ports) { "Review Port" } else { "" }
            [PSCustomObject]@{ Server=$srvName; ProcessName=$proc.ProcessName; Id=$proc.Id; UserName=$proc.UserName; Ports=$ports; RiskFlag=$risk; FileName=$proc.FileName }
        }

        # Services (Batch CIM-Discovery)
        $sessionParams = if ($Computer -eq "localhost") { @{} } else { @{ComputerName = $Computer} }
        $serviceList = Get-CimInstance Win32_Service @sessionParams -ErrorAction SilentlyContinue
        
        $services = foreach ($svc in $serviceList) {
            $risk = if ($svc.StartName -eq "LocalSystem") { "Runs as LocalSystem" } else { "" }
            [PSCustomObject]@{ Server=$srvName; Name=$svc.Name; State=$svc.State; StartMode=$svc.StartMode; StartName=$svc.StartName; RiskFlag=$risk }
        }

        # Fetch Scheduled Tasks
        $tasks = foreach ($task in Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $execs = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
            $risk = if ($task.Principal.RunLevel -eq "Highest") { "Highest Privilege" } else { "" }
            [PSCustomObject]@{ Server=$srvName; TaskName=$task.TaskName; State=$task.State; User=$task.Principal.UserID; RunLevel=$task.Principal.RunLevel; Executable=$execs; RiskFlag=$risk }
        }

        return @{ Processes = $processes; Services = $services; Tasks = $tasks }
    }
    catch {
        return @{ Processes = @(); Services = @(); Tasks = @() }
    }
}

# Domain-wide Parallel Audit

Write-Host "`nStarting PARALLEL audit ($ThrottleLimit concurrent)..." -ForegroundColor Cyan -BackgroundColor Black

$allResults = $targetList | ForEach-Object -Parallel {
    Invoke-ServerAudit -Computer $_
} -ThrottleLimit $ThrottleLimit

# Aggregate
$allProcesses = $allResults.Processes
$allServices  = $allResults.Services
$allTasks     = $allResults.Tasks

# Export Master Reports

$allProcesses | Export-Csv "$OutputPath\Processes_$rptDate.csv" -NoTypeInformation
$allServices  | Export-Csv "$OutputPath\Services_$rptDate.csv" -NoTypeInformation
$allTasks     | Export-Csv "$OutputPath\Tasks_$rptDate.csv" -NoTypeInformation

# AD Inventory
$allComputers | Export-Csv "$OutputPath\DomainInventory_$rptDate.csv" -NoTypeInformation

# Risk Flagging Logic Summary & Dashboard Printing

$riskProcesses = ($allProcesses | Where-Object { $_.RiskFlag }).Count
$riskServices  = ($allServices | Where-Object { $_.RiskFlag }).Count
$riskTasks     = ($allTasks | Where-Object { $_.RiskFlag }).Count
$totalRisks    = $riskProcesses + $riskServices + $riskTasks

$htmlHeader = @"
<h1>DOMAIN-WIDE AUDIT - $Domain ($($allComputers.Count) systems) - $rptDate</h1>
<h3>Total Risks: <span style='color:red'>$totalRisks</span></h3>
"@

$htmlRiskProcesses = if ($riskProcesses -gt 0) {
    "<h2>Risky Processes ($riskProcesses)</h2>" + 
    ($allProcesses | Where-Object { $_.RiskFlag } | ConvertTo-Html -Fragment)
} else {
    "<h2>Risky Processes ($riskProcesses)</h2><p>None</p>"
}

$htmlRiskServices = if ($riskServices -gt 0) {
    "<h2>Risky Services ($riskServices)</h2>" + 
    ($allServices | Where-Object { $_.RiskFlag } | ConvertTo-Html -Fragment)
} else {
    "<h2>Risky Services ($riskServices)</h2><p>None</p>"
}

$htmlRiskTasks = if ($riskTasks -gt 0) {
    "<h2>High-Priv Tasks ($riskTasks)</h2>" + 
    ($allTasks | Where-Object { $_.RiskFlag } | ConvertTo-Html -Fragment)
} else {
    "<h2>High-Priv Tasks ($riskTasks)</h2><p>None</p>"
}

$html = $htmlHeader + $htmlRiskProcesses + $htmlRiskServices + $htmlRiskTasks
$html | Out-File "$OutputPath\DomainAuditDashboard_$rptDate.html" -Encoding UTF8

# EXECUTIVE SUMMARY

Write-Host "`n" + "="*60 -ForegroundColor Green  -BackgroundColor Black
Write-Host "DOMAIN-WIDE AUDIT COMPLETE!" -ForegroundColor Green -BackgroundColor Black
Write-Host "="*60
Write-Host "Systems Audited: $($allComputers.Count)"
Write-Host "Total Risks Found: $totalRisks"
Write-Host "   Processes: $riskProcesses"
Write-Host "   Services:  $riskServices"  
Write-Host "   Tasks:     $riskTasks"
Write-Host "Output Folder: $OutputPath"
Write-Host "Dashboard: DomainAuditDashboard_$rptDate.html"
Write-Host "="*60

# Stale systems warning
$staleCount = ($allComputers | Where-Object { $_.DaysSinceLogon -gt 90 }).Count
if ($staleCount -gt 0) {
    Write-Host "Stale systems (>90 days): $staleCount" -ForegroundColor Yellow
}