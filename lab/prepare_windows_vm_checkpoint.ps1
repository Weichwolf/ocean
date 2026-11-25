# Prepare a disposable Server Core image for the fenced VM storage probe.
[CmdletBinding()]
param([Security.SecureString]$Password)

$ErrorActionPreference = 'Stop'
$guestAddress = '10.232.1.20'
$clientAddress = '10.232.1.21'
$username = 'OceanVmProbe'
$base = Join-Path $env:SystemDrive 'OceanVmProbe'
$share = Join-Path $base 'share'
$writable = Join-Path $share 'data'
$account = "$env:COMPUTERNAME\$username"

$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if ($os.InstallationType -ne 'Server Core' -or $os.CurrentBuildNumber -ne '26100' -or
    -not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $guestAddress -ErrorAction SilentlyContinue)) {
    throw 'Use a disposable Windows Server 2025 Core probe guest at 10.232.1.20.'
}
if ((Test-Path $base) -or (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) -or
    (Get-SmbShare -Name 'OceanVmProbe' -ErrorAction SilentlyContinue)) {
    throw 'Use a fresh checkpoint fixture before configuring the share.'
}
if (!$Password) {
    $Password = Read-Host 'Disposable SMB probe password' -AsSecureString
}
New-LocalUser -Name $username -Password $Password -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
New-Item -ItemType Directory -Path $writable -Force | Out-Null
& icacls.exe $base /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the checkpoint fixture directory.' }
& icacls.exe $share /grant:r "${account}:(OI)(CI)RX"
if ($LASTEXITCODE -ne 0) { throw 'Could not grant checkpoint read access.' }
& icacls.exe $writable /grant:r "${account}:(OI)(CI)M"
if ($LASTEXITCODE -ne 0) { throw 'Could not grant write access to the checkpoint data directory.' }

$identityScript = Join-Path $base 'identity.ps1'
@'
$ErrorActionPreference = 'Stop'
$identity = [ordered]@{
    machineUUID = (Get-CimInstance Win32_ComputerSystemProduct).UUID
    machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
    computerName = $env:COMPUTERNAME
    build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    bootedAt = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
}
$path = Join-Path $PSScriptRoot 'share\identity.json'
$identity | ConvertTo-Json -Compress | Set-Content -Encoding ASCII -Path "$path.tmp"
Move-Item -Path "$path.tmp" -Destination $path -Force
'@ | Set-Content -Path $identityScript -Encoding ASCII
$powershell = Join-Path $PSHOME 'powershell.exe'
$action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$identityScript`""
Register-ScheduledTask -TaskName 'OceanVmProbeIdentity' -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -User 'SYSTEM' -RunLevel Highest | Out-Null
& $powershell -NoProfile -ExecutionPolicy Bypass -File $identityScript
if ($LASTEXITCODE -ne 0) { throw 'Could not capture the checkpoint fixture identity.' }

New-SmbShare -Name 'OceanVmProbe' -Path $share -ChangeAccess $account -EncryptData $true -CachingMode None | Out-Null
New-NetFirewallRule -Name 'OceanVmProbeSMB' -DisplayName 'Ocean VM checkpoint probe' -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 445 -LocalAddress $guestAddress -RemoteAddress $clientAddress -Profile Any | Out-Null
