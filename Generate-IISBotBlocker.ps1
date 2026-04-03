<#
.SYNOPSIS
    Generates IIS URL Rewrite bot-blocking rules and writes them directly
    into applicationHost.config via XML manipulation with automatic backup.

.DESCRIPTION
    Pulls lists from one of two sources (controlled by -WhichLists):
      Mode  : https://github.com/kpirnie-me/bots-for-scanner
      Nginx : https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker

    Lists pulled:
      - bad-user-agents.list
      - bad-referrers.list
      - fake-googlebots.list

    Whitelists (always pulled from kpirnie-me/bots-for-scanner, same for both modes):
      - whitelist-ip.list
      - whitelist-ua.list

    Also writes static security rules on every run:
      - Common hack pattern blocks
      - SQL injection guards (URL path + query string)

    Writes the rules directly into the global <system.webServer><rewrite><rules>
    section of applicationHost.config. A timestamped backup is created before
    every write. No per-site web.config files are touched.

    On the very first run the original applicationHost.config is preserved as
    applicationHost.config.original in $BackupDir and is never overwritten again.
    Use -RestoreOriginal to revert to that snapshot.

    REQUIREMENTS:
      - IIS URL Rewrite Module 2.x  (https://www.iis.net/downloads/microsoft/url-rewrite)
      - Windows Server 2012 / 2016 / 2019
      - PowerShell 4+
      - Must be run as Administrator

    SCHEDULING:
      schtasks /create /tn "IIS Bot Blocker Update" /tr "powershell -ExecutionPolicy Bypass -NonInteractive -File C:\Scripts\Generate-IISBotBlocker.v3.ps1 -RestartIIS" /sc daily /st 02:00 /ru SYSTEM /f

.PARAMETER ChunkSize
    Number of entries per regex alternation rule. Default: 200.

.PARAMETER RestartIIS
    If set, runs iisreset /noforce after writing the config.

.PARAMETER RestoreOriginal
    Restores applicationHost.config from the .original snapshot and exits.
    Does not generate or write any rules.

.PARAMETER WhichLists
    Which upstream list source to pull from.
    Valid values: Mode, Nginx
    Default: Nginx

.PARAMETER BackupDir
    Directory to store applicationHost.config backups.
    Default: C:\iis-config\backups

.EXAMPLE
    .\Generate-IISBotBlocker.v3.ps1 -ChunkSize 200 -RestartIIS -WhichLists Nginx

.EXAMPLE
    .\Generate-IISBotBlocker.v3.ps1 -WhichLists Mode -RestartIIS

.EXAMPLE
    .\Generate-IISBotBlocker.v3.ps1 -RestoreOriginal

.NOTES
    - Rules are written globally and apply to ALL sites on this IIS instance.
    - Whitelist rules are always written first.
    - A backup of applicationHost.config is created before every write.
    - The .original snapshot is created once and never overwritten.
    - For IP-based blocking use Windows Firewall or IIS Dynamic IP Restrictions.
#>

[CmdletBinding()]
param(
    [int]$ChunkSize = 200,
    [switch]$RestartIIS,
    [switch]$RestoreOriginal,
    [string]$BackupDir = "C:\iis-config\backups",
    [ValidateSet("Mode", "Nginx")]
    [string]$WhichLists = "Nginx"
)

$ErrorActionPreference = "Stop"

$AppHostPath = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"

# ---------------------------------------------------------------------------
# Fetch a URL and return a typed string array, always.
# ---------------------------------------------------------------------------
function Get-BlockList {
    param([string]$Url, [string]$Name)
    Write-Host "  Fetching $Name..." -ForegroundColor Cyan
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30
        [string[]]$lines = @(
            ($response.Content -split "`n") |
            ForEach-Object { $_.Trim() } |
            Where-Object { ($_ -ne "") -and (-not $_.StartsWith("#")) }
        )
        return $lines
    }
    catch {
        Write-Warning "Failed to fetch ${Name}: $_"
        return [string[]]@()
    }
}

# ---------------------------------------------------------------------------
# Split a string array into a list of fixed-size string array chunks.
# ---------------------------------------------------------------------------
function Get-Chunks {
    param([string[]]$Items, [int]$Size)
    $result = New-Object System.Collections.Generic.List[object]
    $i = 0
    while ($i -lt $Items.Length) {
        $end = [Math]::Min($i + $Size, $Items.Length)
        [string[]]$chunk = $Items[$i..($end - 1)]
        $result.Add($chunk)
        $i += $Size
    }
    return $result
}

# ---------------------------------------------------------------------------
# Build an alternation regex from a string array.
# Case-insensitivity is handled via ignoreCase="true" in the XML attribute,
# NOT via (?i) inline flag which IIS URL Rewrite does not support.
# ---------------------------------------------------------------------------
function New-AlternationPattern {
    param([string[]]$Entries)
    [string[]]$escaped = $Entries | ForEach-Object { [regex]::Escape($_) }
    return "(" + ($escaped -join "|") + ")"
}

# ---------------------------------------------------------------------------
# Append a block rule to a StringBuilder.
# Matches on a server variable with ignoreCase="true".
# ---------------------------------------------------------------------------
function Add-BlockRule {
    param(
        [System.Text.StringBuilder]$Builder,
        [string]$Name,
        [string]$ServerVar,
        [string]$Pattern
    )
    $Builder.AppendLine("        <rule name=""$Name"" stopProcessing=""true"">") | Out-Null
    $Builder.AppendLine("          <match url="".*"" />") | Out-Null
    $Builder.AppendLine("          <conditions logicalGrouping=""MatchAll"" trackAllCaptures=""false"">") | Out-Null
    $Builder.AppendLine("            <add input=""{$ServerVar}"" pattern=""$Pattern"" ignoreCase=""true"" />") | Out-Null
    $Builder.AppendLine("          </conditions>") | Out-Null
    $Builder.AppendLine("          <action type=""AbortRequest"" />") | Out-Null
    $Builder.AppendLine("        </rule>") | Out-Null
}

# ---------------------------------------------------------------------------
# Append an allow (whitelist) rule to a StringBuilder.
# ---------------------------------------------------------------------------
function Add-AllowRule {
    param(
        [System.Text.StringBuilder]$Builder,
        [string]$Name,
        [string]$ServerVar,
        [string]$Pattern
    )
    $Builder.AppendLine("        <rule name=""$Name"" stopProcessing=""true"">") | Out-Null
    $Builder.AppendLine("          <match url="".*"" />") | Out-Null
    $Builder.AppendLine("          <conditions logicalGrouping=""MatchAll"" trackAllCaptures=""false"">") | Out-Null
    $Builder.AppendLine("            <add input=""{$ServerVar}"" pattern=""$Pattern"" ignoreCase=""true"" />") | Out-Null
    $Builder.AppendLine("          </conditions>") | Out-Null
    $Builder.AppendLine("          <action type=""None"" />") | Out-Null
    $Builder.AppendLine("        </rule>") | Out-Null
}

# ---------------------------------------------------------------------------
# Append a URL match block rule (ignoreCase on <match> not <add>).
# ---------------------------------------------------------------------------
function Add-UrlBlockRule {
    param(
        [System.Text.StringBuilder]$Builder,
        [string]$Name,
        [string]$Pattern
    )
    $Builder.AppendLine("        <rule name=""$Name"" stopProcessing=""true"">") | Out-Null
    $Builder.AppendLine("          <match url=""$Pattern"" ignoreCase=""true"" />") | Out-Null
    $Builder.AppendLine("          <action type=""AbortRequest"" />") | Out-Null
    $Builder.AppendLine("        </rule>") | Out-Null
}

# ===========================================================================
# Main
# ===========================================================================

# Must be admin
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

if (-not (Test-Path $AppHostPath)) {
    Write-Error "applicationHost.config not found at: $AppHostPath"
    exit 1
}

# ---------------------------------------------------------------------------
# Ensure backup dir exists and establish the .original snapshot path
# ---------------------------------------------------------------------------
if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

$originalBackupPath = Join-Path $BackupDir "applicationHost.config.original"

# ---------------------------------------------------------------------------
# -RestoreOriginal: revert to the .original snapshot and exit
# ---------------------------------------------------------------------------
if ($RestoreOriginal) {
    if (-not (Test-Path $originalBackupPath)) {
        Write-Error "Original backup not found at: $originalBackupPath"
        exit 1
    }
    Copy-Item -Path $originalBackupPath -Destination $AppHostPath -Force
    Write-Host "Restored original : $AppHostPath" -ForegroundColor Green
    Write-Host "Tip: run iisreset /noforce to apply the restored config." -ForegroundColor DarkGray
    exit 0
}

# ---------------------------------------------------------------------------
# Create the .original snapshot once — never overwrite it
# ---------------------------------------------------------------------------
if (-not (Test-Path $originalBackupPath)) {
    Copy-Item -Path $AppHostPath -Destination $originalBackupPath -Force
    Write-Host "Original snapshot : $originalBackupPath" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Resolve list URLs based on -WhichLists
# ---------------------------------------------------------------------------
$wlIpUrl = "https://raw.githubusercontent.com/kpirnie-me/bots-for-scanner/refs/heads/main/whitelist-ip.list"
$wlUaUrl = "https://raw.githubusercontent.com/kpirnie-me/bots-for-scanner/refs/heads/main/whitelist-ua.list"

if ($WhichLists -eq "Mode") {
    $uaUrl = "https://raw.githubusercontent.com/kpirnie-me/bots-for-scanner/refs/heads/main/bad-user-agents.list"
    $refUrl = "https://raw.githubusercontent.com/kpirnie-me/bots-for-scanner/refs/heads/main/bad-referrers.list"
    $fgUrl = "https://raw.githubusercontent.com/kpirnie-me/bots-for-scanner/refs/heads/main/fake-googlebots.list"
}
else {
    $uaUrl = "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list"
    $refUrl = "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-referrers.list"
    $fgUrl = "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/fake-googlebots.list"
}

Write-Host ""
Write-Host "IIS Bad Bot Blocker Generator" -ForegroundColor Yellow
Write-Host "List source: $WhichLists" -ForegroundColor Yellow
Write-Host ""

# ---------------------------------------------------------------------------
# Fetch all lists
# ---------------------------------------------------------------------------
[string[]]$userAgents = Get-BlockList -Url $uaUrl  -Name "bad-user-agents"
[string[]]$referrers = Get-BlockList -Url $refUrl -Name "bad-referrers"
[string[]]$fakeBots = Get-BlockList -Url $fgUrl  -Name "fake-googlebots"
[string[]]$whitelistIPs = Get-BlockList -Url $wlIpUrl -Name "whitelist-ip"
[string[]]$whitelistUAs = Get-BlockList -Url $wlUaUrl -Name "whitelist-ua"

[string[]]$allUserAgents = @(($userAgents + $fakeBots) | Sort-Object -Unique)

Write-Host ""
Write-Host "  User-Agents to block : $($allUserAgents.Length)" -ForegroundColor Green
Write-Host "  Referrers to block   : $($referrers.Length)"     -ForegroundColor Green
Write-Host "  Whitelisted UAs      : $($whitelistUAs.Length)"  -ForegroundColor Green
Write-Host "  Whitelisted IPs      : $($whitelistIPs.Length)"  -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# Build the <rules> XML fragment
# ---------------------------------------------------------------------------
$sb = New-Object System.Text.StringBuilder
[int]$ruleCount = 0

# -- Whitelists (must be first — take precedence over all block rules) -------
$sb.AppendLine("        <!-- WHITELIST: evaluated first - always takes precedence -->") | Out-Null

if ($whitelistUAs.Length -gt 0) {
    $wlUaPattern = New-AlternationPattern -Entries $whitelistUAs
    Add-AllowRule -Builder $sb -Name "Whitelist Good Bots" -ServerVar "HTTP_USER_AGENT" -Pattern $wlUaPattern
    $ruleCount++
}

if ($whitelistIPs.Length -gt 0) {
    $wlIpPattern = New-AlternationPattern -Entries $whitelistIPs
    Add-AllowRule -Builder $sb -Name "Whitelist IPs" -ServerVar "REMOTE_ADDR" -Pattern $wlIpPattern
    $ruleCount++
}

$sb.AppendLine("") | Out-Null

# -- Static security rules ---------------------------------------------------
$sb.AppendLine("        <!-- Static security rules -->") | Out-Null

Add-UrlBlockRule -Builder $sb -Name "Block Common Hacks 1" -Pattern "(display_errors|set_time_limit|allow_url_include.*disable_functions.*open_basedir|set_magic_quotes_runtime|webconfig\.txt\.php|file_put_contentssever_root|wlwmanifest)"
$ruleCount++

Add-UrlBlockRule -Builder $sb -Name "Block Common Hacks 2" -Pattern "(globals|encode|localhost|loopback|xmlrpc|revslider|roundcube|webdav|smtp|http:|soap|w00tw00t)"
$ruleCount++

Add-UrlBlockRule -Builder $sb -Name "Block SQL Injection - URL Path" -Pattern "(;|%27|%22).*(request|insert|union|declare|drop)$"
$ruleCount++

# SQL injection - query string requires a condition on QUERY_STRING
$sb.AppendLine("        <rule name=""Block SQL Injection - Query String"" stopProcessing=""true"">") | Out-Null
$sb.AppendLine("          <match url="".*"" />") | Out-Null
$sb.AppendLine("          <conditions>") | Out-Null
$sb.AppendLine("            <add input=""{QUERY_STRING}"" pattern=""(;|%27|%22).*(request|insert|union|declare|drop)"" ignoreCase=""true"" />") | Out-Null
$sb.AppendLine("          </conditions>") | Out-Null
$sb.AppendLine("          <action type=""AbortRequest"" />") | Out-Null
$sb.AppendLine("        </rule>") | Out-Null
$ruleCount++

$sb.AppendLine("") | Out-Null

# -- Bad User-Agents ---------------------------------------------------------
$uaChunks = Get-Chunks -Items $allUserAgents -Size $ChunkSize
[int]$uaTotal = $uaChunks.Count
$sb.AppendLine("        <!-- BAD USER-AGENTS: $($allUserAgents.Length) entries in $uaTotal rules -->") | Out-Null

for ($i = 0; $i -lt $uaTotal; $i++) {
    [string[]]$chunk = $uaChunks[$i]
    $pattern = New-AlternationPattern -Entries $chunk
    $ruleName = "Block Bad Bots $($i + 1) of $uaTotal"
    Add-BlockRule -Builder $sb -Name $ruleName -ServerVar "HTTP_USER_AGENT" -Pattern $pattern
    $ruleCount++
}

$sb.AppendLine("") | Out-Null

# -- Bad Referrers -----------------------------------------------------------
$refChunks = Get-Chunks -Items $referrers -Size $ChunkSize
[int]$refTotal = $refChunks.Count
$sb.AppendLine("        <!-- BAD REFERRERS: $($referrers.Length) entries in $refTotal rules -->") | Out-Null

for ($i = 0; $i -lt $refTotal; $i++) {
    [string[]]$chunk = $refChunks[$i]
    $pattern = New-AlternationPattern -Entries $chunk
    $ruleName = "Block Bad Referrers $($i + 1) of $refTotal"
    Add-BlockRule -Builder $sb -Name $ruleName -ServerVar "HTTP_REFERER" -Pattern $pattern
    $ruleCount++
}

# ---------------------------------------------------------------------------
# Timestamped backup of the current applicationHost.config
# ---------------------------------------------------------------------------
$backupPath = Join-Path $BackupDir ("applicationHost.config." + (Get-Date -Format "yyyyMMdd-HHmmss") + ".bak")
Copy-Item -Path $AppHostPath -Destination $backupPath -Force
Write-Host "Backup created    : $backupPath" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Load applicationHost.config as XML and inject rules
# ---------------------------------------------------------------------------
[xml]$appHost = [System.IO.File]::ReadAllText($AppHostPath)

$swsNode = $appHost.configuration.'system.webServer'
if ($null -eq $swsNode) {
    Write-Error "Could not find <system.webServer> in applicationHost.config"
    exit 1
}

# Remove existing <rewrite> node if present
$existingRewrite = $swsNode.rewrite
if ($null -ne $existingRewrite) {
    $swsNode.RemoveChild($existingRewrite) | Out-Null
    Write-Host "Removed existing  : <rewrite> block" -ForegroundColor DarkGray
}

# Build the new <rewrite> node from our generated rules string
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$rewriteXml = "<rewrite><rules><!-- IIS Bad Bot Blocker | Generated: $timestamp | Source: $WhichLists | github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker | Written By: Kevin Pirnie -->" + $sb.ToString() + "</rules></rewrite>"

$tempDoc = New-Object System.Xml.XmlDocument
$tempDoc.LoadXml($rewriteXml)
$importedNode = $appHost.ImportNode($tempDoc.DocumentElement, $true)
$swsNode.AppendChild($importedNode) | Out-Null

# Save
$writerSettings = New-Object System.Xml.XmlWriterSettings
$writerSettings.Indent = $true
$writerSettings.IndentChars = "    "
$writerSettings.Encoding = [System.Text.Encoding]::UTF8
$writerSettings.OmitXmlDeclaration = $false

$writer = [System.Xml.XmlWriter]::Create($AppHostPath, $writerSettings)
$appHost.Save($writer)
$writer.Close()

Write-Host "Rules written to  : $AppHostPath" -ForegroundColor Green
Write-Host "Total rules       : $ruleCount" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# Optionally restart IIS
# ---------------------------------------------------------------------------
if ($RestartIIS) {
    Write-Host "Restarting IIS..." -ForegroundColor Yellow
    & "$env:SystemRoot\System32\iisreset.exe" /noforce
    if ($LASTEXITCODE -eq 0) {
        Write-Host "IIS restarted successfully." -ForegroundColor Green
    }
    else {
        Write-Warning "iisreset exited with code $LASTEXITCODE"
    }
}
else {
    Write-Host "Tip: use -RestartIIS to reload IIS after update." -ForegroundColor DarkGray
}

Write-Host ""