$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add('http://+:8080/')
$listener.Start()
$workerToken = $env:EXCHANGE_AUTOMATION_TOKEN
$appId = $env:EXCHANGE_APP_ID
$certificatePath = $env:EXCHANGE_CERTIFICATE_PATH
$certificatePassword = $env:EXCHANGE_CERTIFICATE_PASSWORD
$authMode = if ($env:EXCHANGE_AUTH_MODE) { $env:EXCHANGE_AUTH_MODE.ToLowerInvariant() } else { 'certificate' }
$allowedTenants = @($env:EXCHANGE_ALLOWED_TENANT_IDS -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Send-Json($context, [int]$status, $payload) {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 8 -Compress))
    $context.Response.StatusCode = $status
    $context.Response.ContentType = 'application/json'
    $context.Response.ContentEncoding = [Text.Encoding]::UTF8
    $context.Response.ContentLength64 = $bytes.Length
    $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $context.Response.Close()
}

function Connect-Exchange($tenantId, $organization, $adminUpn) {
    if ($authMode -eq 'interactive') {
        if (-not $adminUpn) { throw 'exchange_admin_upn is required for interactive Exchange sign-in' }
        if (-not $organization -or $organization -notmatch '\.onmicrosoft\.com$') { throw 'A verified customer .onmicrosoft.com organization domain is required' }
        # Device authentication is required because this worker runs in a
        # headless container without a browser. The URL and one-time code are
        # written to the worker log for the operator to open in a browser.
        Write-Output "Exchange administrator sign-in required for $organization using account $adminUpn. Open https://microsoft.com/devicelogin and enter the code shown below."
        Connect-ExchangeOnline -UserPrincipalName $adminUpn -Device -Organization $organization -ShowBanner:$false
        return
    }
    if (-not $appId -or -not $certificatePath -or -not $certificatePassword) { throw 'Exchange certificate worker credentials are not configured' }
    if (-not (Test-Path $certificatePath)) { throw 'Exchange certificate file was not found' }
    $securePassword = ConvertTo-SecureString $certificatePassword -AsPlainText -Force
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath, $securePassword)
    Connect-ExchangeOnline -AppId $appId -Certificate $certificate -Organization ($organization ?? $tenantId) -ShowBanner:$false
}

function Assert-Request($body) {
    if (-not $body.tenant_id -or -not $body.user_id) { throw 'tenant_id and user_id are required' }
    if ($authMode -eq 'interactive') {
        # The API is authoritative in interactive mode: it validates the
        # tenant against the authenticated MSP user's organization and mapped
        # ClientTenant row before calling this private worker. The bearer token
        # prevents callers outside the API network from submitting requests.
        return
    }
    if ($allowedTenants.Count -eq 0 -or $allowedTenants -notcontains $body.tenant_id) { throw 'tenant_id is not allowlisted for this worker' }
}

while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
        if ($context.Request.HttpMethod -ne 'POST' -or $context.Request.Headers['Authorization'] -ne "Bearer $workerToken") {
            Send-Json $context 401 @{ detail = 'Unauthorized' }
            continue
        }
        $reader = [IO.StreamReader]::new($context.Request.InputStream)
        $body = $reader.ReadToEnd() | ConvertFrom-Json
        Assert-Request $body
        Connect-Exchange $body.tenant_id $body.organization $body.exchange_admin_upn
        try {
            switch ($context.Request.Url.AbsolutePath) {
                '/v1/user-actions/global-address-list' {
                    $hidden = [bool]$body.hidden
                    Set-Mailbox -Identity $body.user_id -HiddenFromAddressListsEnabled $hidden -Confirm:$false
                    Send-Json $context 200 @{ status = 'completed'; operation = 'global-address-list'; hidden = $hidden }
                    continue
                }
                '/v1/user-actions/mail-forwarding' {
                    $forwardTo = if ($body.recipient) { $body.recipient } else { $null }
                    Set-Mailbox -Identity $body.user_id -ForwardingSmtpAddress $forwardTo -DeliverToMailboxAndForward ([bool]$body.keep_copy)
                }
                '/v1/user-actions/shared-mailbox-permissions' {
                    foreach ($permission in @($body.permissions)) {
                        if (-not $permission.mailbox -or $permission.mailbox -eq 'selected') { throw 'A real shared mailbox identity is required' }
                        if ($permission.full_access) { Add-MailboxPermission -Identity $permission.mailbox -User $body.user_id -AccessRights FullAccess -AutoMapping ([bool]$permission.auto_mapping) -Confirm:$false }
                        if ($permission.send_as) { Add-RecipientPermission -Identity $permission.mailbox -Trustee $body.user_id -AccessRights SendAs -Confirm:$false }
                        if ($permission.send_on_behalf) { Set-Mailbox -Identity $permission.mailbox -GrantSendOnBehalfTo @{Add=$body.user_id} }
                    }
                }
                default { throw 'Unknown Exchange automation operation' }
            }
            Send-Json $context 200 @{ status = 'completed' }
        } finally {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
    } catch {
        if ($context) { Send-Json $context 500 @{ detail = $_.Exception.Message } }
    }
}
