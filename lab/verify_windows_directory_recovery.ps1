param(
    [Parameter(Mandatory)][guid]$RecoveryId,
    [Parameter(Mandatory)][ValidateSet('pair','survivor')][string]$Stage,
    [Parameter(Mandatory)][ValidateSet('Machine','Employee')][string]$Action,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]+\.ad\.ocean\.test$')][string]$Controller,
    [Parameter(Mandatory)][ValidateSet('10.232.1.11','10.232.1.12')][string]$Address
)

$ErrorActionPreference = 'Stop'
$domain = 'ad.ocean.test'
$system = Get-CimInstance Win32_ComputerSystem
$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
$domainSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid.Value
if (!$system.PartOfDomain -or $system.Domain -ine $domain -or !$domainSid) {
    throw 'The Windows member or interactive account is outside the restored domain'
}
$answer = Resolve-DnsName -Server $Address -DnsOnly -Name "_ldap._tcp.dc._msdcs.$domain" -Type SRV
if (!($answer | Where-Object { ([string]$_.NameTarget).TrimEnd('.') -ieq $Controller -and $_.Port -eq 389 })) {
    throw 'The expected restored controller was missing from directory DNS'
}
$policy = "\\$Controller\SYSVOL\$domain\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI"
$result = [ordered]@{
    recoveryId = $RecoveryId.ToString()
    stage = $Stage
    check = $Action
    machine = $env:COMPUTERNAME
    edition = $edition
    controller = $Controller
    domainSid = $domainSid
    timestamp = [DateTime]::UtcNow.ToString('o')
}
if ($Action -eq 'Machine') {
    $nic = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -in @('10.232.1.20','10.232.1.21') }
    if (@($nic).Count -ne 1) {
        throw 'The Windows recovery network identity changed'
    }
    Set-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses @($Address)
    Clear-DnsClientCache
    if (!(Test-ComputerSecureChannel -Server $Controller -ErrorAction Stop)) {
        throw 'The original Netlogon secure channel is unhealthy'
    }
    $result.secureChannel = $true
    $result.policyAcl = (Get-Acl $policy).Sddl
} else {
    $principal = whoami.exe /upn
    if ($LASTEXITCODE -ne 0 -or $principal -ine 'employee@ad.ocean.test') {
        throw 'Sign in interactively as the original fixture employee'
    }
    $groups = whoami.exe /groups /fo csv
    if ($LASTEXITCODE -ne 0 -or !($groups -match '(?i)^"OCEANLAB\\FileUsers",')) {
        throw 'The original employee group is missing'
    }
    klist.exe purge | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to clear cached Kerberos tickets'
    }
    klist.exe get "cifs/$Controller" | Out-Null
    if ($LASTEXITCODE -ne 0 -or !((klist.exe) -match '(?i)krbtgt/AD\.OCEAN\.TEST')) {
        throw 'The employee did not establish a fresh Kerberos ticket'
    }
    $result.principal = $principal
    $result.group = 'OCEANLAB\FileUsers'
    $result.kerberos = $true
}
$result.policySha256 = (Get-FileHash -Algorithm SHA256 -Path $policy).Hash.ToLowerInvariant()
$json = $result | ConvertTo-Json -Compress
$port = [IO.Ports.SerialPort]::new('COM1',115200)
try {
    $port.Open()
    $port.WriteLine("OCEAN-REGIONAL-RECOVERY $json")
} finally {
    $port.Dispose()
}
Write-Output $json
