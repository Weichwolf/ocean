param(
    [Parameter(Mandatory)][guid]$RunId,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')][string]$Share,
    [Parameter(Mandatory)][ipaddress]$FixtureServerIP
)

$ErrorActionPreference = 'Stop'
if ($FixtureServerIP.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'The private SMB fixture requires an IPv4 address'
}

$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$original = [IO.File]::ReadAllBytes($hostsPath)
try {
    [IO.File]::AppendAllText($hostsPath, "`r`n$FixtureServerIP files04.ad.ocean.test`r`n", [Text.Encoding]::ASCII)
    Clear-DnsClientCache
    $probe = Join-Path $PSScriptRoot 'verify_windows_smb_member.ps1'
    & $probe -RunId $RunId -Share $Share -Action Restore -Account smbwriter -AsFixtureUser
    & $probe -RunId $RunId -Share $Share -Action ReadOnly -Account smbreader -AsFixtureUser
    & $probe -RunId $RunId -Share $Share -Action Denied -Account smbdenied -AsFixtureUser
} finally {
    [IO.File]::WriteAllBytes($hostsPath, $original)
    Clear-DnsClientCache
}
