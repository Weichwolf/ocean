param([string]$ConfigPath = (Join-Path $PSScriptRoot 'browser.json'))

$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

function Write-Record($Record) {
    $Record.run = $config.run
    $port = [IO.Ports.SerialPort]::new('COM1', 115200)
    try {
        $port.Open()
        $port.WriteLine('OCEAN-WEB-EDGE ' + ($Record | ConvertTo-Json -Compress))
    } finally {
        $port.Dispose()
    }
}

function Read-Tickets {
    $result = & klist.exe
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the Windows logon ticket cache' }
    $result -join "`n"
}

$profile = $null
$process = $null
$stage = 'domain-session'
try {
    $computer = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
    $user = (& whoami.exe /upn).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $user -ne $config.user -or -not $computer.PartOfDomain -or $computer.Domain -ne $config.domain -or
        $os.ProductType -ne 1 -or $os.Caption -notmatch 'Windows 11' -or $edition -notin @('Professional', 'EnterpriseEval')) {
        throw 'Use the disposable domain employee desktop session'
    }
    $server = [regex]::Escape($config.serviceHost)
    $realm = [regex]::Escape($config.realm)
    $account = [regex]::Escape($config.account)
    $service = "(?im)^\s*Server:\s+HTTP/$server\s+@\s+$realm\s*$"
    $client = "(?im)^\s*(?:#\d+>\s*)?Client:\s+$account\s+@\s+$realm\s*$"
    $tgt = "(?im)^\s*Server:\s+krbtgt/$realm\s+@\s+$realm\s*$"
    $before = Read-Tickets
    if ($before -match $service) {
        & klist.exe purge | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not clear the disposable employee ticket cache' }
        $before = Read-Tickets
    }
    if ($before -notmatch $tgt) {
        $refresh = & klist.exe get "krbtgt/$($config.realm)"
        if ($LASTEXITCODE -ne 0) { throw ('Windows could not obtain a domain TGT from the current logon: ' + ($refresh -join ' ')) }
        $before = Read-Tickets
    }
    if ($before -notmatch $tgt -or $before -notmatch $client -or $before -match $service) {
        throw 'Expected a Windows domain TGT and no HTTP service ticket'
    }

    $stage = 'edge-policy'
    $policy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    if ($policy.AuthServerAllowlist -ne $config.serviceHost -or $policy.EnableAuthNegotiatePort -ne 0) {
        throw 'The managed Edge integrated authentication policy does not match the issuer'
    }
    $edge = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'
    $version = (Get-Item -LiteralPath $edge).VersionInfo.ProductVersion
    $profile = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('ocean-edge-' + [guid]::NewGuid().ToString('N')))

    $stage = 'https-callback'
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $browserArgs = @('--headless=new', '--no-first-run', '--no-default-browser-check', '--no-proxy-server',
                     '--disable-background-networking', '--disable-sync', "--user-data-dir=`"$($profile.FullName)`"", "`"$($config.authorize)`"")
    $process = Start-Process -FilePath $edge -ArgumentList $browserArgs -PassThru
    do {
        try {
            $reply = Invoke-WebRequest -Uri $config.completed -UseBasicParsing -TimeoutSec 3
            if ($reply.StatusCode -eq 204) { break }
        } catch {
            if ($null -eq $_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 404) { throw }
        }
        if ($process.HasExited) { throw 'Edge exited before the OIDC callback' }
        Start-Sleep -Milliseconds 200
    } while ($watch.Elapsed.TotalSeconds -lt 45)
    if ($null -eq $reply -or $reply.StatusCode -ne 204) { throw 'Edge did not reach the OIDC callback' }
    $duration = $watch.ElapsedMilliseconds

    $stage = 'service-ticket'
    $matching = @((Read-Tickets) -split '(?m)^#\d+>' | Where-Object { $_ -match $service -and $_ -match $client })
    if ($matching.Count -ne 1) { throw 'The Windows logon cache did not contain exactly one matching HTTP service ticket' }
    $cipher = [regex]::Match($matching[0], '(?im)^\s*KerbTicket Encryption Type:\s+(AES-(128|256)-CTS-HMAC-SHA1-96)\s*$')
    if (-not $cipher.Success) {
        throw 'Edge did not acquire the expected AES HTTP service ticket in the Windows logon cache'
    }
    $encryption = $cipher.Groups[1].Value.ToLowerInvariant().Replace('aes-', 'aes')
    Write-Record @{ user=$user; principal=$config.principal; servicePrincipal=$config.servicePrincipal;
                    encryption=$encryption; durationMs=$duration; edgeVersion=$version; windowsEdition=$edition }
} catch {
    Write-Record @{ errorStage=$stage; message=$_.Exception.Message }
    throw
} finally {
    if ($null -ne $process) {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            [void]$process.WaitForExit(5000)
        }
        $process.Dispose()
    }
    if ($null -ne $profile) { Remove-Item -LiteralPath $profile.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}
