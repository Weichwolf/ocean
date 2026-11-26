param([string]$ConfigPath = (Join-Path $PSScriptRoot 'rdp.json'))

$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

function Write-Record($Record) {
    $Record.run = $config.run
    $port = [IO.Ports.SerialPort]::new('COM1', 115200)
    try {
        $port.Open()
        $port.WriteLine('OCEAN-DESKTOP-RDP ' + ($Record | ConvertTo-Json -Compress))
    } finally {
        $port.Dispose()
    }
}

$stage = 'windows-client'
$root = $null
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
    $source = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $config.source
    $component = (Get-Item (Join-Path $env:SystemRoot 'System32\mstscax.dll')).VersionInfo.FileVersion
    if ($os.ProductType -ne 1 -or $os.Caption -notmatch 'Windows 11' -or $edition -notin @('Professional', 'EnterpriseEval') -or
        $source.PrefixLength -ne 28) {
        throw 'Use an unlocked disposable Windows 11 workstation on the private desktop subnet'
    }
    if ($config.check) {
        Write-Record @{ event='ready'; source=$source.IPAddress; clientVersion=$component; windowsEdition=$edition; build=$os.BuildNumber }
        return
    }

    $stage = 'tls-trust'
    $root = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $PSScriptRoot 'root.cer'))
    if (-not (Test-Path -LiteralPath ('Cert:\LocalMachine\Root\' + $root.Thumbprint))) {
        throw 'The disposable Windows client must trust the provisioned RDP test root'
    }
    $leaf = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $PSScriptRoot 'leaf.cer'))
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1')) | Out-Null
        $chain.ChainPolicy.RevocationMode = 'Online'
        $chain.ChainPolicy.RevocationFlag = 'ExcludeRoot'
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(4)
        if (-not $chain.Build($leaf)) {
            $codes = $chain.ChainStatus.Status -join ', '
            throw "The XRDP certificate failed Windows chain or revocation checks: $codes"
        }
        if ($chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint -ne $root.Thumbprint) {
            throw 'The XRDP certificate chains to an unexpected root'
        }
    } finally {
        $chain.Dispose()
        $leaf.Dispose()
    }

    $stage = 'private-network'
    $resolved = @([Net.Dns]::GetHostAddresses($config.target) | ForEach-Object IPAddressToString)
    if ($resolved.Count -ne 1 -or $resolved[0] -ne $config.address) {
        throw 'The private DNS name does not resolve to this ARM-provisioned VM'
    }
    $endpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Parse($source.IPAddress), 0)
    $tcp = [Net.Sockets.TcpClient]::new($endpoint)
    try {
        if (-not $tcp.ConnectAsync($config.target, 3389).Wait(4000) -or -not $tcp.Connected) {
            throw 'The configured private interface cannot reach the assigned RDP address'
        }
    } finally { $tcp.Dispose() }

    $stage = 'client-control'
    Add-Type -ReferencedAssemblies 'System.Windows.Forms', 'System.Drawing', 'Microsoft.CSharp' -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public sealed class OceanRdpControl : AxHost
{
    public OceanRdpControl() : base("8B918B82-7985-4C24-89DF-C33AD2BBFBCD") { }

    public static int[] ConnectFor(string server, string user, string password, Action ready)
    {
        using (var window = new Form { Width = 840, Height = 660, Text = "Ocean private desktop acceptance" })
        using (var rdp = new OceanRdpControl { Dock = DockStyle.Fill })
        using (var timer = new Timer { Interval = 16000 })
        {
            ((System.ComponentModel.ISupportInitialize)rdp).BeginInit();
            window.Controls.Add(rdp);
            ((System.ComponentModel.ISupportInitialize)rdp).EndInit();
            window.Show();
            rdp.CreateControl();
            dynamic client = rdp.GetOcx();
            client.Server = server;
            client.UserName = user;
            client.DesktopWidth = 800;
            client.DesktopHeight = 600;
            dynamic settings = client.AdvancedSettings8;
            settings.EnableCredSspSupport = false;
            settings.AuthenticationLevel = 1U;
            settings.ClearTextPassword = password;
            settings.ConnectToAdministerServer = false;
            int connected = 0;
            int disconnected = 0;
            var events = new Guid("336D5562-EFA8-482E-8CB3-C5C0FC7A7DB6");
            Action<int> onDisconnect = reason => { disconnected = reason; };
            ComEventsHelper.Combine((object)client, events, 4, onDisconnect);
            timer.Tick += (sender, args) => {
                timer.Stop();
                connected = (int)client.Connected;
                window.Close();
            };
            try {
                ready();
                client.Connect();
                timer.Start();
                Application.Run(window);
                return new[] { connected, disconnected };
            } finally {
                ComEventsHelper.Remove((object)client, events, 4, onDisconnect);
            }
        }
    }
}
'@

    $stage = 'rdp-connection'
    $connected = [OceanRdpControl]::ConnectFor($config.target, $config.user, $config.password, [Action]{
        Write-Record @{ event='starting'; source=$source.IPAddress; clientVersion=$component; windowsEdition=$edition; build=$os.BuildNumber }
    })
    Write-Record @{ event='finished'; connected=$connected[0]; disconnectReason=$connected[1] }
} catch {
    Write-Record @{ event='error'; stage=$stage; message=$_.Exception.Message }
    throw
} finally {
    if ($null -ne $root) { $root.Dispose() }
}
