param(
    [Parameter(Mandatory)][guid]$RunId,
    [Parameter(Mandatory)][ValidateSet('before-membership','with-membership','after-removal','old-password','rotated-password','disabled')][string]$Stage,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]+\.ad\.ocean\.test$')][string]$Controller,
    [Parameter(Mandatory)][ValidateSet('10.232.1.11','10.232.1.12')][string]$Address,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21(-[0-9]{1,10}){4}$')][string]$GroupSid,
    [switch]$Worker
)

$ErrorActionPreference = 'Stop'
$upn = 'graphprobe@ad.ocean.test'
$result = [ordered]@{
    runId = $RunId.ToString()
    stage = $Stage
    timestamp = [DateTime]::UtcNow.ToString('o')
    machine = $env:COMPUTERNAME
    edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
    controller = $Controller
    groupPresent = $false
    kerberos = $false
    shareRead = $false
}

function Publish-Result {
    $record = $result | ConvertTo-Json -Compress
    $port = [IO.Ports.SerialPort]::new('COM1',115200)
    try {
        $port.Open()
        $port.WriteLine("OCEAN-REGIONAL-GRAPH $record")
    } finally {
        $port.Dispose()
    }
    Write-Output $record
}

if ($Worker) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = whoami.exe /upn
    if ($LASTEXITCODE -ne 0 -or $principal -ine $upn) {
        throw 'The Windows logon token has the wrong UPN'
    }
    $result.principal = $principal
    $result.accountSid = $identity.User.Value
    $result.groupPresent = $GroupSid -in $identity.Groups.Value
    klist.exe purge | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to clear Windows Kerberos tickets'
    }
    klist.exe get "cifs/$Controller" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'The Windows logon session could not acquire a fresh CIFS ticket'
    }
    $result.kerberos = $true
    try {
        $data = [IO.File]::ReadAllText("\\$Controller\ocean-graph-probe\probe.txt")
        if ($data.Trim() -cne $RunId.ToString()) {
            throw 'The protected test share contains a different nonce'
        }
        $result.shareRead = $true
    } catch [UnauthorizedAccessException] {
        $result.shareError = $_.Exception.GetBaseException().HResult -band 0xffff
    }
    Publish-Result
    return
}

$nic = Get-NetIPAddress -IPAddress '10.232.1.20' -AddressFamily IPv4
Set-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses @($Address)
Clear-DnsClientCache
$system = Get-CimInstance Win32_ComputerSystem
if (!$system.PartOfDomain -or $system.Domain -ine 'ad.ocean.test' -or
    !(Test-ComputerSecureChannel -Server $Controller -ErrorAction Stop)) {
    throw 'The Windows Graph probe requires a live member of the directory'
}

$password = Read-Host -Prompt 'Enter the private Graph fixture password' -AsSecureString
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -RunId {1} -Stage {2} -Controller {3} -Address {4} -GroupSid {5} -Worker' -f $PSCommandPath, $RunId, $Stage, $Controller, $Address, $GroupSid
$start = [Diagnostics.ProcessStartInfo]::new("$PSHOME\powershell.exe", $arguments)
$start.UseShellExecute = $false
$start.WorkingDirectory = $env:SystemRoot
$start.UserName = 'graphprobe'
$start.Domain = 'OCEANLAB'
$start.Password = $password
try {
    $process = [Diagnostics.Process]::Start($start)
} catch {
    $native = $_.Exception
    while ($native -and $native -isnot [ComponentModel.Win32Exception]) {
        $native = $native.InnerException
    }
    if (!$native -or $native.NativeErrorCode -notin @(1326,1327,1331)) {
        throw
    }
    $result.signInError = $native.NativeErrorCode
    Publish-Result
    return
} finally {
    $password.Dispose()
}
try {
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "The Windows Kerberos and SMB probe returned $($process.ExitCode)"
    }
} finally {
    $process.Dispose()
}
