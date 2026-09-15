$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add('http://+:8080/')
$listener.Start()
$workerToken = $env:EXCHANGE_AUTOMATION_TOKEN
$appId = $env:EXCHANGE_APP_ID
$certificatePath = $env:EXCHANGE_CERTIFICATE_PATH
$certificatePassword = $env:EXCHANGE_CERTIFICATE_PASSWORD


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
    # The backend is authoritative for tenant authorization. It validates the
    # authenticated staff user, organization, and mapped ClientTenant before
    # calling this private worker with the shared bearer token.
    if ($body.organization -notmatch '\.onmicrosoft\.com$') { throw 'A verified customer .onmicrosoft.com organization domain is required' }
}

function Connect-Exchange($organization) {
    if (-not $appId -or -not $certificatePath -or -not $certificatePassword) { throw 'Exchange certificate worker credentials are not configured' }
    if (-not (Test-Path $certificatePath)) { throw 'Exchange certificate file was not found' }
    $securePassword = ConvertTo-SecureString $certificatePassword -AsPlainText -Force
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath, $securePassword)
    Connect-ExchangeOnline -AppId $appId -Certificate $certificate -Organization $organization -ShowBanner:$false
}

while ($listener.IsListening) {
    $context = $null
    try {
        $context = $listener.GetContext()
        if ($context.Request.HttpMethod -ne 'POST' -or $context.Request.Headers['Authorization'] -ne "Bearer $workerToken") {
            Send-Json $context 401 @{ detail = 'Unauthorized' }
            continue
        }
        $reader = [IO.StreamReader]::new($context.Request.InputStream)
        $body = $reader.ReadToEnd() | ConvertFrom-Json
        Assert-Request $body
        Connect-Exchange $body.organization
        try {
            switch ($context.Request.Url.AbsolutePath) {
                '/v1/user-actions/global-address-list-status' {
                    $mailbox = Get-Mailbox -Identity $body.user_id -ErrorAction Stop
                    Send-Json $context 200 @{ status = 'completed'; operation = 'global-address-list-status'; hidden = [bool]$mailbox.HiddenFromAddressListsEnabled; execution = 'powershell' }
                }
                '/v1/user-actions/global-address-list' {
                    $hidden = [bool]$body.hidden
                    Set-Mailbox -Identity $body.user_id -HiddenFromAddressListsEnabled $hidden -Confirm:$false
                    Send-Json $context 200 @{ status = 'completed'; operation = 'global-address-list'; hidden = $hidden; execution = 'powershell' }
                }
                '/v1/user-actions/mail-forwarding' {
                    $forwardTo = if ($body.recipient) { $body.recipient } else { $null }
                    Set-Mailbox -Identity $body.user_id -ForwardingSmtpAddress $forwardTo -DeliverToMailboxAndForward ([bool]$body.keep_copy) -Confirm:$false
                    Send-Json $context 200 @{ status = 'completed'; operation = 'mail-forwarding'; execution = 'powershell' }
                }
                '/v1/user-actions/shared-mailboxes' {
                    $mailboxes = @(Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | Select-Object @{Name='id';Expression={$_.Guid.ToString()}}, @{Name='display_name';Expression={$_.DisplayName}}, @{Name='primary_smtp_address';Expression={$_.PrimarySmtpAddress.ToString()}}, Alias, RecipientTypeDetails)
                    Send-Json $context 200 @{ status = 'completed'; operation = 'shared-mailboxes'; mailboxes = $mailboxes; execution = 'powershell' }
                }
                '/v1/user-actions/convert-mailbox' {
                    $mailbox = Get-Mailbox -Identity $body.user_id -ErrorAction Stop
                    if ($mailbox.RecipientTypeDetails -eq 'SharedMailbox') {
                        Send-Json $context 200 @{ status = 'completed'; operation = 'convert-mailbox'; mailbox = $body.user_id; already_shared = $true; execution = 'powershell' }
                    } else {
                        Set-Mailbox -Identity $body.user_id -Type Shared -Confirm:$false
                        Send-Json $context 200 @{ status = 'completed'; operation = 'convert-mailbox'; mailbox = $body.user_id; already_shared = $false; execution = 'powershell' }
                    }
                }
                '/v1/user-actions/shared-mailbox-permissions' {
                    foreach ($permission in @($body.permissions)) {
                        if (-not $permission.mailbox -or $permission.mailbox -eq 'selected') { throw 'A real shared mailbox identity is required' }
                        if ($permission.full_access) { Add-MailboxPermission -Identity $permission.mailbox -User $body.user_id -AccessRights FullAccess -AutoMapping ([bool]$permission.auto_mapping) -Confirm:$false }
                        if ($permission.send_as) { Add-RecipientPermission -Identity $permission.mailbox -Trustee $body.user_id -AccessRights SendAs -Confirm:$false }
                        if ($permission.send_on_behalf) { Set-Mailbox -Identity $permission.mailbox -GrantSendOnBehalfTo @{Add=$body.user_id} }
                    }
                    Send-Json $context 200 @{ status = 'completed'; operation = 'shared-mailbox-permissions'; execution = 'powershell' }
                }
                default { throw 'Unknown Exchange automation operation' }
            }
        } finally {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
    } catch {
        if ($context) { Send-Json $context 500 @{ detail = $_.Exception.Message } }
    }
}
