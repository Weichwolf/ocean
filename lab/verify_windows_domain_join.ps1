param(
    [Parameter(Mandatory)]
    [ValidateSet('Join', 'VerifyMachine', 'VerifyIdentity')]
    [string]$Action,

    [Parameter(Mandatory)]
    [ValidateSet('ServerCore', 'Windows11')]
    [string]$Profile,

    [System.Management.Automation.PSCredential]$JoinCredential,
    [switch]$SendToLab
)

$ErrorActionPreference = 'Stop'
$domain = 'ad.ocean.test'
$controller = "dc01.$domain"
$os = Get-CimInstance Win32_OperatingSystem
$edition = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$computer = Get-CimInstance Win32_ComputerSystem

function Write-ProbeRecord($Record) {
    $json = $Record | ConvertTo-Json -Compress
    if ($SendToLab) {
        $port = [IO.Ports.SerialPort]::new('COM1', 115200)
        try {
            $port.Open()
            $port.WriteLine("OCEAN-DOMAIN $json")
        } finally {
            $port.Dispose()
        }
    }
    $json
}

switch ($Profile) {
    'ServerCore' {
        if ($os.ProductType -ne 3 -or $edition.InstallationType -ne 'Server Core' -or
            $os.Caption -notmatch 'Windows Server 2025') {
            throw 'Expected a Windows Server 2025 Core member server'
        }
    }
    'Windows11' {
        if ($os.ProductType -ne 1 -or $edition.EditionID -notin @('Professional', 'EnterpriseEval') -or
            $os.Caption -notmatch 'Windows 11') {
            throw 'Expected a Windows 11 Pro or Enterprise Evaluation workstation'
        }
    }
}

$records = Resolve-DnsName "_ldap._tcp.dc._msdcs.$domain" -Type SRV -DnsOnly
if (-not ($records | Where-Object { ([string]$_.NameTarget).TrimEnd('.') -ieq $controller -and $_.Port -eq 389 })) {
    throw 'The domain DNS service record did not identify the test controller'
}

switch ($Action) {
    'Join' {
        if ($computer.PartOfDomain) {
            throw 'The join probe requires a disposable workgroup guest'
        }
        $timeSample = w32tm.exe /stripchart /computer:10.232.1.11 /samples:3 /dataonly
        if ($LASTEXITCODE -ne 0 -or $timeSample -match 'error') {
            throw 'Unable to query the disposable domain time source'
        }
        $offsets = foreach ($line in $timeSample) {
            if ($line -match '([+-][0-9]+[.,][0-9]+)s\s*$') {
                [double]::Parse($Matches[1].Replace(',', '.'), [Globalization.CultureInfo]::InvariantCulture)
            }
        }
        if (@($offsets).Count -ne 3 -or ($offsets | Where-Object { [Math]::Abs($_) -gt 5 })) {
            throw 'The guest clock is not within five seconds of the fixture controller'
        }
        if (-not $JoinCredential) {
            $JoinCredential = Get-Credential -UserName 'OCEANLAB\Administrator' -Message 'Disposable Ocean lab credentials'
        }
        try {
            Add-Computer -DomainName "missing.$domain" -Credential $JoinCredential -ErrorAction Stop
        } catch {
            $wrongDomainRejected = $true
        }
        if (-not $wrongDomainRejected) {
            throw 'The wrong-domain join unexpectedly succeeded'
        }
        Add-Computer -DomainName $domain -Credential $JoinCredential -ErrorAction Stop -WarningAction SilentlyContinue
        Write-ProbeRecord ([pscustomobject]@{
            check = 'join'
            wrongDomainRejected = $true
            requestedDomain = $domain
            guest = $env:COMPUTERNAME
            joinedAt = [DateTime]::UtcNow.ToString('o')
            clockOffsetsSeconds = @($offsets)
            edition = $edition.EditionID
            build = $os.BuildNumber
        })
    }
    'VerifyMachine' {
        if (-not $computer.PartOfDomain -or $computer.Domain -ine $domain -or
            -not (Test-ComputerSecureChannel -Server $controller -ErrorAction Stop)) {
            throw 'The domain machine secure channel is not healthy'
        }
        Write-ProbeRecord ([pscustomobject]@{
            check = 'machine'
            domain = $computer.Domain
            secureChannel = $true
            guest = $env:COMPUTERNAME
            profile = $Profile
            edition = $edition.EditionID
            build = $os.BuildNumber
            lastBoot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
        })
    }
    'VerifyIdentity' {
        $principal = whoami.exe /upn
        if ($LASTEXITCODE -ne 0 -or $principal -ine "employee@$domain") {
            throw 'Sign in interactively as the disposable domain employee before running this probe'
        }
        $groups = whoami.exe /groups /fo csv
        if ($LASTEXITCODE -ne 0 -or -not ($groups -match '(?i)^"OCEANLAB\\FileUsers",')) {
            throw 'The employee token does not have the expected domain group'
        }
        $tickets = klist.exe
        if ($LASTEXITCODE -ne 0 -or -not ($tickets -match '(?i)krbtgt/AD\.OCEAN\.TEST')) {
            throw 'The employee sign-in did not establish a Kerberos ticket'
        }
        Write-ProbeRecord ([pscustomobject]@{
            check = 'identity'
            guest = $env:COMPUTERNAME
            principal = $principal
            group = 'OCEANLAB\FileUsers'
            kerberosTicketGranted = $true
            profile = $Profile
        })
    }
}
