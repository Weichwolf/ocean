param(
    [Parameter(Mandatory)][guid]$RunId,
    [Parameter(Mandatory)][ValidateSet('Write', 'Read', 'ReadOnly', 'Denied')][string]$Action,
    [Parameter(Mandatory)][ValidateSet('smbwriter', 'smbreader', 'smbdenied')][string]$Account,
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')][string]$Share = 'company-files',
    [switch]$AsFixtureUser
)

$ErrorActionPreference = 'Stop'
$server = 'files04.ad.ocean.test'
$system = Get-CimInstance Win32_ComputerSystem
if (!$system.PartOfDomain -or $system.Domain -ine 'ad.ocean.test') {
    throw 'The SMB probe requires a Windows member of the lab domain'
}

if ($AsFixtureUser) {
    $password = Read-Host -Prompt 'Enter the private SMB fixture password' -AsSecureString
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -RunId {1} -Action {2} -Account {3} -Share {4}' -f $PSCommandPath, $RunId, $Action, $Account, $Share
    $start = [Diagnostics.ProcessStartInfo]::new("$PSHOME\powershell.exe", $arguments)
    $start.UseShellExecute = $false
    $start.WorkingDirectory = $env:SystemRoot
    $start.UserName = $Account
    $start.Domain = 'OCEANLAB'
    $start.Password = $password
    try {
        $process = [Diagnostics.Process]::Start($start)
        try {
            if (!$process.WaitForExit(45000) -or $process.ExitCode -ne 0) {
                throw 'The Windows domain-user SMB probe failed'
            }
        } finally {
            $process.Dispose()
        }
    } finally {
        $password.Dispose()
    }
    return
}

$principal = (whoami.exe /upn).Trim()
if ($LASTEXITCODE -ne 0 -or $principal -ine "$Account@ad.ocean.test") {
    throw 'The SMB probe token has the wrong domain user'
}
klist.exe get "cifs/$server" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'The user did not obtain a CIFS service ticket for the Samba member'
}
$result = [ordered]@{
    runId = $RunId.ToString()
    timestamp = [DateTime]::UtcNow.ToString('o')
    machine = $env:COMPUTERNAME
    edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
    user = $principal
    userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    server = $server
    share = $Share
    kerberos = $true
    action = $Action
}
$checkpoint = "\\$server\$Share\ocean-windows-$RunId.txt"

function Require-AccessDenied([scriptblock]$Attempt) {
    try {
        & $Attempt
    } catch {
        $native = $_.Exception.GetBaseException()
        if ($native -is [UnauthorizedAccessException] -or ($native.HResult -band 0xffff) -eq 5) {
            return
        }
        throw
    }
    throw 'The SMB operation unexpectedly had permission'
}

if ($Action -eq 'Denied') {
    Require-AccessDenied { [void][IO.File]::ReadAllText($checkpoint) }
    $result.readDenied = $true
} else {
    if ($Action -eq 'Write') {
        $data = [Text.Encoding]::UTF8.GetBytes($RunId.ToString())
        $file = [IO.File]::Open($checkpoint, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        try {
            $file.Write($data, 0, $data.Length)
            $file.Flush($true)
        } finally {
            $file.Dispose()
        }
        $result.writeAcknowledged = $true
    }
    if ([IO.File]::ReadAllText($checkpoint) -cne $RunId.ToString()) {
        throw 'The SMB checkpoint contains the wrong nonce'
    }
    $result.readVerified = $true
    if ($Action -eq 'ReadOnly') {
        Require-AccessDenied { [IO.File]::WriteAllText("$checkpoint.denied", 'must be rejected') }
        $result.writeDenied = $true
    }
}

$record = $result | ConvertTo-Json -Compress
$port = [IO.Ports.SerialPort]::new('COM1', 115200)
try {
    $port.Open()
    $port.WriteLine("OCEAN-KERBEROS-SMB $record")
} finally {
    $port.Dispose()
}
Write-Output $record
