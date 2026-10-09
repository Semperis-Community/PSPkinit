<#
.SYNOPSIS
Installs the actionlint CLI into a local tools directory.

.DESCRIPTION
Downloads a specific actionlint release for the current platform/architecture
and places the binary under a local tools path (default: .tools/bin).

.PARAMETER Version
actionlint release version to install (without the leading v).

.PARAMETER InstallDir
Repository-relative installation directory for the extracted binary.

.PARAMETER Force
Forces a re-download and overwrite even when the binary already exists.

.PARAMETER PrintPath
Prints only the binary path (for script consumption) instead of verbose output.
#>

[CmdletBinding()]
param(
    [string]$Version = '1.7.12',
    [string]$InstallDir = '.tools/bin',
    [switch]$Force,
    [switch]$PrintPath
)

$ErrorActionPreference = 'Stop'

function Get-AssetInfo
{
    <#
    .SYNOPSIS
    Resolves platform-specific actionlint release asset metadata.
    #>

    $isWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
    $isLinuxPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)
    $isMacOSPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX)

    $platform = if ($isWindowsPlatform)
    {
        'windows'
    }
    elseif ($isLinuxPlatform)
    {
        'linux'
    }
    elseif ($isMacOSPlatform)
    {
        'darwin'
    }
    else
    {
        throw 'Unsupported OS for actionlint install.'
    }

    $architecture = [string]([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)
    if ([string]::IsNullOrWhiteSpace($architecture))
    {
        $architecture = [string]$env:PROCESSOR_ARCHITECTURE
    }

    $arch = switch ($architecture.ToUpperInvariant())
    {
        'X64'
        {
            'amd64'
        }
        'AMD64'
        {
            'amd64'
        }
        'ARM64'
        {
            'arm64'
        }
        default
        {
            throw "Unsupported architecture '$architecture' for actionlint install."
        }
    }

    if ($platform -eq 'windows')
    {
        return [pscustomobject]@{
            FileName = "actionlint_${Version}_${platform}_${arch}.zip"
            BinaryName = 'actionlint.exe'
            IsZip = $true
        }
    }

    return [pscustomobject]@{
        FileName = "actionlint_${Version}_${platform}_${arch}.tar.gz"
        BinaryName = 'actionlint'
        IsZip = $false
    }
}

function Test-ArchiveSignature
{
    <#
    .SYNOPSIS
    Validates archive header bytes for downloaded actionlint assets.

    .DESCRIPTION
    Verifies the downloaded file signature before extraction to avoid
    processing transient HTML/error responses as archives.

    .PARAMETER Path
    File path to inspect.

    .PARAMETER IsZip
    Indicates whether the expected archive type is ZIP (true) or GZip (false).

    .OUTPUTS
    System.Boolean
    #>
    param(
        [string]$Path,
        [bool]$IsZip
    )

    if (-not (Test-Path $Path))
    {
        return $false
    }

    $requiredBytes = if ($IsZip) { 4 } else { 2 }
    $headerBytes = New-Object byte[] $requiredBytes
    $bytesRead = 0

    try
    {
        $stream = [System.IO.File]::OpenRead($Path)
        try
        {
            $bytesRead = $stream.Read($headerBytes, 0, $requiredBytes)
        }
        finally
        {
            $stream.Dispose()
        }
    }
    catch
    {
        return $false
    }

    if ($bytesRead -lt $requiredBytes)
    {
        return $false
    }

    if ($IsZip)
    {
        # ZIP local file header starts with PK\x03\x04.
        return ($headerBytes[0] -eq 0x50 -and $headerBytes[1] -eq 0x4B -and $headerBytes[2] -eq 0x03 -and $headerBytes[3] -eq 0x04)
    }

    # GZip header starts with 0x1F 0x8B.
    return ($headerBytes[0] -eq 0x1F -and $headerBytes[1] -eq 0x8B)
}

$isWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
$asset = Get-AssetInfo
$resolvedInstallDir = Join-Path (Get-Location) $InstallDir
New-Item -ItemType Directory -Path $resolvedInstallDir -Force | Out-Null

$binaryPath = Join-Path $resolvedInstallDir $asset.BinaryName
if ((Test-Path $binaryPath) -and -not $Force)
{
    if ($PrintPath)
    {
        Write-Output $binaryPath
    }
    else
    {
        Write-Output "actionlint already present at $binaryPath"
        & $binaryPath -version
    }

    exit 0
}

$downloadUrl = "https://github.com/rhysd/actionlint/releases/download/v$Version/$($asset.FileName)"
$archivePath = Join-Path $resolvedInstallDir $asset.FileName

$maxDownloadAttempts = 4
$downloadSucceeded = $false

for ($attempt = 1; $attempt -le $maxDownloadAttempts; $attempt += 1)
{
    Remove-Item -Path $archivePath -Force -ErrorAction SilentlyContinue

    try
    {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -Headers @{ 'User-Agent' = 'pipeline-build-actionlint-installer' }

        if (-not (Test-ArchiveSignature -Path $archivePath -IsZip $asset.IsZip))
        {
            $preview = ''
            try
            {
                $preview = (Get-Content -Path $archivePath -TotalCount 1 -ErrorAction Stop)
            }
            catch
            {
                $preview = '<unable to read content preview>'
            }

            throw "Downloaded file was not a valid archive. First line preview: $preview"
        }

        $downloadSucceeded = $true
        break
    }
    catch
    {
        if ($attempt -eq $maxDownloadAttempts)
        {
            throw "Failed to download actionlint asset '$($asset.FileName)' from '$downloadUrl' after $maxDownloadAttempts attempts. Last error: $($_.Exception.Message)"
        }

        $delaySeconds = [int][math]::Pow(2, $attempt - 1)
        Write-Warning "actionlint download attempt $attempt/$maxDownloadAttempts failed: $($_.Exception.Message). Retrying in $delaySeconds second(s)."
        Start-Sleep -Seconds $delaySeconds
    }
}

if (-not $downloadSucceeded)
{
    throw "Failed to download actionlint asset '$($asset.FileName)' from '$downloadUrl'."
}

if ($asset.IsZip)
{
    Expand-Archive -Path $archivePath -DestinationPath $resolvedInstallDir -Force
}
else
{
    tar -xzf $archivePath -C $resolvedInstallDir
}

Remove-Item -Path $archivePath -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $binaryPath))
{
    $discovered = Get-ChildItem -Path $resolvedInstallDir -Recurse -File -Filter $asset.BinaryName | Select-Object -First 1
    if ($null -eq $discovered)
    {
        throw 'actionlint binary not found after extraction.'
    }

    Move-Item -Path $discovered.FullName -Destination $binaryPath -Force
}

if (-not $isWindowsPlatform)
{
    chmod +x $binaryPath
}

if ($PrintPath)
{
    Write-Output $binaryPath
}
else
{
    Write-Output "Installed actionlint at $binaryPath"
    & $binaryPath -version
}


