param(
    [switch]$Child,
    [string]$TenantId,
    [string]$Organization,
    [string]$UserId,
    [string]$Operation,
    [string]$Hidden,
    [string]$OutputFile
)

$ErrorActionPreference = 'Stop'

if ($Child) {
    try {
        Connect-ExchangeOnline -Device -Organization $Organization -ShowBanner:$false -ShowProgress:$false
        switch ($Operation) {
            'global-address-list' {
                Set-Mailbox -Identity $UserId -HiddenFromAddressListsEnabled ([System.Convert]::ToBoolean($Hidden)) -Confirm:$false
            }
            default { throw "Unsupported Exchange operation: $Operation" }
        }
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        exit 0
    } catch {
        Write-Error $_.Exception.Message
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        exit 1
    }
}

Add-Type -AssemblyName System.Net
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add('http://+:8080/')
$listener.Start()
$workerToken = $env:EXCHANGE_AUTOMATION_TOKEN
$authMode = if ($env:EXCHANGE_AUTH_MODE) { $env:EXCHANGE_AUTH_MODE.ToLowerInvariant() } else { 'interactive' }
$allowedTenants = @($env:EXCHANGE_ALLOWED_TENANT_IDS -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$jobs = @{}
$jobRoot = '/tmp/tenanttoolbox-exchange-jobs'
New-Item -ItemType Directory -Path $jobRoot -Force | Out-Null

function Send-Json($context, [int]$status, $payload) {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 8 -Compress))
    $context.Response.StatusCode = $status
    $context.Response.ContentType = 'application/json'
    $context.Response.ContentEncoding = [Text.Encoding]::UTF8
    $context.Response.ContentLength64 = $bytes.Length
    $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $context.Response.Close()
}

function Assert-Request($body) {
    if (-not $body.tenant_id -or -not $body.user_id -or -not $body.organization) { throw 'tenant_id, user_id, and organization are required' }
    if ($authMode -ne 'interactive' -and ($allowedTenants.Count -eq 0 -or $allowedTenants -notcontains $body.tenant_id)) { throw 'tenant_id is not allowlisted for this worker' }
    if ($body.organization -notmatch '\.onmicrosoft\.com$') { throw 'A verified customer .onmicrosoft.com organization domain is required' }
}

function New-ExchangeJob($body) {
    Assert-Request $body
    $jobId = [guid]::NewGuid().ToString()
    $stdout = Join-Path $jobRoot "$jobId.out"
    $stderr = Join-Path $jobRoot "$jobId.err"
    $args = @('-NoLogo', '-File', $PSCommandPath, '-Child', '-TenantId', [string]$body.tenant_id, '-Organization', [string]$body.organization, '-UserId', [string]$body.user_id, '-Operation', 'global-address-list', '-Hidden', ([string][bool]$body.hidden), '-OutputFile', $stdout)
    $process = Start-Process -FilePath 'pwsh' -ArgumentList $args -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    $jobs[$jobId] = @{ Process = $process; Stdout = $stdout; Stderr = $stderr; Created = [datetime]::UtcNow }
    return @{ status = 'awaiting_sign_in'; job_id = $jobId }
}

function Get-ExchangeJob($jobId) {
    if (-not $jobs.ContainsKey($jobId)) { return $null }
    $job = $jobs[$jobId]
    $stdout = if (Test-Path $job.Stdout) { Get-Content -Raw $job.Stdout } else { '' }
    $stderr = if (Test-Path $job.Stderr) { Get-Content -Raw $job.Stderr } else { '' }
    $verificationUri = if ($stdout -match '(https://microsoft\.com/devicelogin|https://login\.microsoftonline\.com/device)') { $Matches[1] } else { 'https://microsoft.com/devicelogin' }
    $code = if ($stdout -match '(?im)(?:code|enter the code)\s*[: ]*([A-Z0-9-]{6,})') { $Matches[1] } else { '' }
    $status = 'awaiting_sign_in'
    $result = @{ status = $status; job_id = $jobId; verification_uri = $verificationUri; user_code = $code }
    if ($job.Process.HasExited) {
        $status = if ($job.Process.ExitCode -eq 0) { 'completed' } else { 'failed' }
        $result.status = $status
        if ($status -eq 'failed') { $result.error = ($stderr.Trim() -replace '\s+', ' ') }
        Remove-Item $job.Stdout, $job.Stderr -Force -ErrorAction SilentlyContinue
        $jobs.Remove($jobId)
    }
    return $result
}

while ($listener.IsListening) {
    $context = $null
    try {
        $context = $listener.GetContext()
        if ($context.Request.Headers['Authorization'] -ne "Bearer $workerToken") {
            Send-Json $context 401 @{ detail = 'Unauthorized' }
            continue
        }
        $path = $context.Request.Url.AbsolutePath
        if ($context.Request.HttpMethod -eq 'GET' -and $path -match '^/v1/user-actions/jobs/([^/]+)$') {
            $result = Get-ExchangeJob $Matches[1]
            if ($null -eq $result) { Send-Json $context 404 @{ detail = 'Exchange job not found' } } else { Send-Json $context 200 $result }
            continue
        }
        if ($context.Request.HttpMethod -ne 'POST') { Send-Json $context 405 @{ detail = 'Method not allowed' }; continue }
        $reader = [IO.StreamReader]::new($context.Request.InputStream)
        $body = $reader.ReadToEnd() | ConvertFrom-Json
        if ($path -eq '/v1/user-actions/global-address-list') {
            Send-Json $context 202 (New-ExchangeJob $body)
        } else {
            Send-Json $context 501 @{ detail = 'This asynchronous worker currently implements only global-address-list' }
        }
    } catch {
        if ($context) { Send-Json $context 500 @{ detail = $_.Exception.Message } }
    }
}
