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



# SIG # Begin signature block
# MIIu4wYJKoZIhvcNAQcCoIIu1DCCLtACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCZxOEackPdLh8Q
# xKqwALoxFVTQTN40CCypawoHv++9kqCCE6MwggVyMIIDWqADAgECAhB2U/6sdUZI
# k/Xl10pIOk74MA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDAzMTgwMDAwMDBaFw00NTAzMTgwMDAwMDBaMFMx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQD
# EyBHbG9iYWxTaWduIENvZGUgU2lnbmluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALYtxTDdeuirkD0DcrA6S5kWYbLl/6VnHTcc5X7s
# k4OqhPWjQ5uYRYq4Y1ddmwCIBCXp+GiSS4LYS8lKA/Oof2qPimEnvaFE0P31PyLC
# o0+RjbMFsiiCkV37WYgFC5cGwpj4LKczJO5QOkHM8KCwex1N0qhYOJbp3/kbkbuL
# ECzSx0Mdogl0oYCve+YzCgxZa4689Ktal3t/rlX7hPCA/oRM1+K6vcR1oW+9YRB0
# RLKYB+J0q/9o3GwmPukf5eAEh60w0wyNA3xVuBZwXCR4ICXrZ2eIq7pONJhrcBHe
# OMrUvqHAnOHfHgIB2DvhZ0OEts/8dLcvhKO/ugk3PWdssUVcGWGrQYP1rB3rdw1G
# R3POv72Vle2dK4gQ/vpY6KdX4bPPqFrpByWbEsSegHI9k9yMlN87ROYmgPzSwwPw
# jAzSRdYu54+YnuYE7kJuZ35CFnFi5wT5YMZkobacgSFOK8ZtaJSGxpl0c2cxepHy
# 1Ix5bnymu35Gb03FhRIrz5oiRAiohTfOB2FXBhcSJMDEMXOhmDVXR34QOkXZLaRR
# kJipoAc3xGUaqhxrFnf3p5fsPxkwmW8x++pAsufSxPrJ0PBQdnRZ+o1tFzK++Ol+
# A/Tnh3Wa1EqRLIUDEwIrQoDyiWo2z8hMoM6e+MuNrRan097VmxinxpI68YJj8S4O
# JGTfAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzANBgkqhkiG9w0BAQwFAAOCAgEA
# Xiu6dJc0RF92SChAhJPuAW7pobPWgCXme+S8CZE9D/x2rdfUMCC7j2DQkdYc8pzv
# eBorlDICwSSWUlIC0PPR/PKbOW6Z4R+OQ0F9mh5byV2ahPwm5ofzdHImraQb2T07
# alKgPAkeLx57szO0Rcf3rLGvk2Ctdq64shV464Nq6//bRqsk5e4C+pAfWcAvXda3
# XaRcELdyU/hBTsz6eBolSsr+hWJDYcO0N6qB0vTWOg+9jVl+MEfeK2vnIVAzX9Rn
# m9S4Z588J5kD/4VDjnMSyiDN6GHVsWbcF9Y5bQ/bzyM3oYKJThxrP9agzaoHnT5C
# JqrXDO76R78aUn7RdYHTyYpiF21PiKAhoCY+r23ZYjAf6Zgorm6N1Y5McmaTgI0q
# 41XHYGeQQlZcIlEPs9xOOe5N3dkdeBBUO27Ql28DtR6yI3PGErKaZND8lYUkqP/f
# obDckUCu3wkzq7ndkrfxzJF0O2nrZ5cbkL/nx6BvcbtXv7ePWu16QGoWzYCELS/h
# AtQklEOzFfwMKxv9cW/8y7x1Fzpeg9LJsy8b1ZyNf1T+fn7kVqOHp53hWVKUQY9t
# W76GlZr/GnbdQNJRSnC0HzNjI3c/7CceWeQIh+00gkoPP/6gHcH1Z3NFhnj0qinp
# J4fGGdvGExTDOUmHTaCX4GUT9Z13Vunas1jHOvLAzYIwggbmMIIEzqADAgECAhB3
# vQ4DobcI+FSrBnIQ2QRHMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS8w
# LQYDVQQDEyZHbG9iYWxTaWduIEdDQyBSNDUgQ29kZVNpZ25pbmcgQ0EgMjAyMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANZCTfnjT8Yj9GwdgaYw90g9
# z9DljeUgIpYHRDVdBs8PHXBg5iZU+lMjYAKoXwIC947Jbj2peAW9jvVPGSSZfM8R
# Fpsfe2vSo3toZXer2LEsP9NyBjJcW6xQZywlTVYGNvzBYkx9fYYWlZpdVLpQ0LB/
# okQZ6dZubD4Twp8R1F80W1FoMWMK+FvQ3rpZXzGviWg4QD4I6FNnTmO2IY7v3Y2F
# QVWeHLw33JWgxHGnHxulSW4KIFl+iaNYFZcAJWnf3sJqUGVOU/troZ8YHooOX1Re
# veBbz/IMBNLeCKEQJvey83ouwo6WwT/Opdr0WSiMN2WhMZYLjqR2dxVJhGaCJedD
# CndSsZlRQv+hst2c0twY2cGGqUAdQZdihryo/6LHYxcG/WZ6NpQBIIl4H5D0e6lS
# TmpPVAYqgK+ex1BC+mUK4wH0sW6sDqjjgRmoOMieAyiGpHSnR5V+cloqexVqHMRp
# 5rC+QBmZy9J9VU4inBDgoVvDsy56i8Te8UsfjCh5MEV/bBO2PSz/LUqKKuwoDy3K
# 1JyYikptWjYsL9+6y+JBSgh3GIitNWGUEvOkcuvuNp6nUSeRPPeiGsz8h+WX4VGH
# aekizIPAtw9FbAfhQ0/UjErOz2OxtaQQevkNDCiwazT+IWgnb+z4+iaEW3VCzYkm
# eVmda6tjcWKQJQ0IIPH/AgMBAAGjggGuMIIBqjAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU
# 2rONwCSQo2t30wygWd0hZ2R2C3gwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lW
# ULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2Nz
# cC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKG
# Omh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5n
# cm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFYGA1UdIARPME0wQQYJKwYB
# BAGgMgEyMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29t
# L3JlcG9zaXRvcnkvMAgGBmeBDAEEATANBgkqhkiG9w0BAQsFAAOCAgEACIhyJsav
# +qxfBsCqjJDa0LLAopf/bhMyFlT9PvQwEZ+PmPmbUt3yohbu2XiVppp8YbgEtfjr
# y/RhETP2ZSW3EUKL2Glux/+VtIFDqX6uv4LWTcwRo4NxahBeGQWn52x/VvSoXMNO
# Ca1Za7j5fqUuuPzeDsKg+7AE1BMbxyepuaotMTvPRkyd60zsvC6c8YejfzhpX0FA
# Z/ZTfepB7449+6nUEThG3zzr9s0ivRPN8OHm5TOgvjzkeNUbzCDyMHOwIhz2hNab
# XAAC4ShSS/8SS0Dq7rAaBgaehObn8NuERvtz2StCtslXNMcWwKbrIbmqDvf+28rr
# vBfLuGfr4z5P26mUhmRVyQkKwNkEcUoRS1pkw7x4eK1MRyZlB5nVzTZgoTNTs/Z7
# KtWJQDxxpav4mVn945uSS90FvQsMeAYrz1PYvRKaWyeGhT+RvuB4gHNU36cdZytq
# tq5NiYAkCFJwUPMB/0SuL5rg4UkI4eFb1zjRngqKnZQnm8qjudviNmrjb7lYYuA2
# eDYB+sGniXomU6Ncu9Ky64rLYwgv/h7zViniNZvY/+mlvW1LWSyJLC9Su7UpkNpD
# R7xy3bzZv4DB3LCrtEsdWDY3ZOub4YUXmimi/eYI0pL/oPh84emn0TCOXyZQK8ei
# 4pd3iu/YTT4m65lAYPM8Zwy2CHIpNVOBNNwwggc/MIIFJ6ADAgECAgxhoXx4c1Yw
# e7yEvMYwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEds
# b2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNpZ24gR0NDIFI0NSBDb2Rl
# U2lnbmluZyBDQSAyMDIwMB4XDTI2MDUyNzEyMzgzM1oXDTI3MDUyODEyMzgzM1ow
# gYoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRAwDgYDVQQHEwdI
# b2Jva2VuMRYwFAYDVQQKEw1TRU1QRVJJUyBJTkMuMRYwFAYDVQQDEw1TRU1QRVJJ
# UyBJTkMuMSQwIgYJKoZIhvcNAQkBFhVjb2Rlc2lnbkBzZW1wZXJpcy5jb20wggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDZtWsX4m6YZ5rql9xk479DX06R
# Ql+Clbt80sHtBHk/AafFQaW+YOUMvQG/BmKuqiVP4R3GKQUDunAgFV6mTLQ+BGqU
# hYrNrMjb16KbxVGQljjaNp5r7qpUXFxKxtOEHH8iGfSnRGglCXKmswLp+fmcNCee
# SnGTUtBsYIxm6B5JdsNHn05dtwbjq17VKNJvIcr0CoRKkhDBzkJ0rZCtlUkVNNlx
# 4vRVENgrq7FTrx4JZNKjepe5y8fBGOjfL33RtLrRJ5MGSi0h5++M7PU7NIXHPPK+
# jZxQlq+J4vp3uT0VoJex0iSf9dwAt+dTcif0HhracsrLAW/JKfe9n7XDc7jJHHQG
# XLG8Wz6MGTMNWqVrOId2fp3YUfDt1pLmJ31JkmYPHf8lIL2eNvpH6GvfmmB/wBwV
# atwmsEOJcKvZZaZFOSmrBCi1H7nPtb1igQFw5S2/bDUg/GyHf02DNusvJe/zBO1l
# Vm0HiZEqRyhnDY1ZNZpp19x3yUguB88GztBGhstOTCbeo3SJAxYiFogtweIoZe9f
# EE0pPp2TGHyX1KEoWCjfY6ET2YvwRKmERASw8qe7krvQpNwYWwENFCA6enJTdBIw
# GEohQ4XrGsO7Jt/rra6Ow2vymYAQ5E7ZJNOVfTPx5fChl4fFvFQqkzafOD0uYtPe
# nt4kOTh8CD/8mke8vQIDAQABo4IB0zCCAc8wDgYDVR0PAQH/BAQDAgeAMIGbBggr
# BgEFBQcBAQSBjjCBizBKBggrBgEFBQcwAoY+aHR0cDovL3NlY3VyZS5nbG9iYWxz
# aWduLmNvbS9jYWNlcnQvZ3NnY2NyNDVjb2Rlc2lnbmNhMjAyMC5jcnQwPQYIKwYB
# BQUHMAGGMWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1Y29kZXNp
# Z25jYTIwMjAwVgYDVR0gBE8wTTBBBgkrBgEEAaAyATIwNDAyBggrBgEFBQcCARYm
# aHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQQB
# MAkGA1UdEwQCMAAwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9nc2djY3I0NWNvZGVzaWduY2EyMDIwLmNybDAgBgNVHREEGTAXgRVj
# b2Rlc2lnbkBzZW1wZXJpcy5jb20wEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0j
# BBgwFoAU2rONwCSQo2t30wygWd0hZ2R2C3gwHQYDVR0OBBYEFPw3810h27dEjr8e
# bjtae1SE+Wv9MA0GCSqGSIb3DQEBCwUAA4ICAQAtK6LHRL29SEqPUv+I1m6XoySg
# DagVvZNhRhQGYATVAlth/D+qKDkjmQXkiopqLm62nCghpfsXFMOGkt/6LQb17/En
# z2J5aJXCaH3HFSNviRgZQTdndQn0qxsozODvIB8ZS04/7Or+wEPKmdHbtc0+jRO7
# f7/q/4D2dEE5Zldllpeuf5Ngmsx4FORYFW4LUFcZTOVW/e7mLoHCciaWwyUUV16n
# XclHs53GEaWD+D3vpHpTWVQi5yQTHzFXCiliIJuH4ORsVqM66E/B0TQHPBdq6LZY
# Zg6njLcyz2scMAm5L5tcvkJEe5iKZJBf6ibvmgcuaJPA1dtpfrXjqiBq0Symq00C
# jkwKC9Tr3/hY1ql3NGs+I92EolRRZ6qapoIvwPgyi3JFyUMScCXYddHtKQolVUYS
# mG+FxjA6N05/bmaHY3okBN63+qyxaEcr7wNA+R3HYKnqo4lvdWCWz2Iulj9besZO
# 8NYx0Kl/QdYIxPAeZskYP3KC0bs9/mkNAB2S3XMt4+OpT7y0/davCIzl3riL9X2K
# r4Mckw5oFYBeCZo3ehHYQvZnpjnOzoc+GjuFB90ipzNQ4mwdvNETqTMq7FRPIPdM
# 4hJtwOIjdw9F41odZfZyKSiPBOWLFjY6K2X03m0/JAgxjRdruLimD/YPqEcbmkwB
# n1KtQm7lUWQsI+Cz5zGCGpYwghqSAgEBMGkwWTELMAkGA1UEBhMCQkUxGTAXBgNV
# BAoTEEdsb2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNpZ24gR0NDIFI0
# NSBDb2RlU2lnbmluZyBDQSAyMDIwAgxhoXx4c1Ywe7yEvMYwDQYJYIZIAWUDBAIB
# BQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG
# 9w0BCQQxIgQgBbMiRmwEQzKaYNDFPCIhuYyzy9Poy4KKnen5HF5wZlswDQYJKoZI
# hvcNAQEBBQAEggIAvwGEZ0uDrWDofq7tZsyD2KM3wPuUTcOvrJz7+BfpVFujcJRz
# BP3RZmLG7hm+jlSW7PtWZZ7vNMrv6iTBF6hkVjSTpoGJ6iVWabHV9SFaT3B8eBrp
# CsMKOzYpDkpfN1OqQ3dzStCez5BBufsyBN3wAg82wr9Zia9wvSOtNg0jGeLrWPJO
# BYJBHx3T8vLetkv6v9VemnqKSxQMOODAscWSiDqrBC7usqbk+RhoXPHM/qhP38d+
# m3/zZlh97r89Wtdlz8P0MMZw7KkGYoB8/IWeAnuRJAInniK2SyKRIIwBK2wXAPub
# +k6fVq1B8SxuN5uFk62B2L7UeEaAja3PmL4j11tMDlYtQT5kWbRKEsvLaXl4RbEI
# tvI9vC/PROwpFfp5z1hAeTSZ1KA3DR+sIcbrkn/chjRgtrdAaPg/pYuOQ21P+hR2
# BX1dG9Fu23kTlBfvrQhd2/UqBVYLdvs/zmaizTNE0wIOxdsGsVhC7raZyDOdE5DG
# iln6yaqGQgRBqJmUvFW4AWZhswohVQi3zKAUlXDUoes2+hs89Xf4oxYcwWEvxPKr
# PXMNzl12/cFXUXkObA/UWAEv0UCZzohheDa9idhR94wf6RTgjixozFvSx5MOAJrL
# iWxbCLs3jnPhNlpniYjmeMvVShHW1XDFSkJrLWVo5tjbULfUAPQw2Ojcc8Ghghd3
# MIIXcwYKKwYBBAGCNwMDATGCF2MwghdfBgkqhkiG9w0BBwKgghdQMIIXTAIBAzEP
# MA0GCWCGSAFlAwQCAQUAMHgGCyqGSIb3DQEJEAEEoGkEZzBlAgEBBglghkgBhv1s
# BwEwMTANBglghkgBZQMEAgEFAAQgbbEr8QdHOiyDaGXb4L8v/Ypp6+YLRP3zS2Am
# ztG855wCEQDTSbwlzE7OSXEDYtIAXv3MGA8yMDI2MTAwNjIxMzg1MVqgghM6MIIG
# 7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsFADBpMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERp
# Z2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIw
# MjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYgMTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz/TjGMPh8
# CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMxt9l3Dm5o
# CG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkUxDjLJhBI
# +qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZEeoy/0B8Z
# m+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEOvZ3fP2Vx
# IgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn/FnbuTeg
# coRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolvykE1jive
# 4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZCZVl6pNU
# OCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW83vV8d67W
# owuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjdzi0xlp70
# W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9icflf55W1z
# OEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
# BBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW
# 9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgw
# gZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1
# Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAy
# NUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqG
# SIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQIENoyKqxr
# FbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGhz45F4Wt4
# WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfHhHv1mx9E
# Vh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA02nXD1nY
# LI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7KVyF5aQyW
# P4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jhtKVnd3D0r
# bHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvKqzpAec9e
# tE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs0NzU/+xX
# 7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGRsMNbXmMR
# EUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJNt68Yfim
# 6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yWQPT9gzCC
# BrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjEL
# MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
# LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0
# MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0
# tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLr
# C6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DF
# UF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVw
# xKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb
# +zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9Ia
# aGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVm
# UB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30y
# Z46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqzti
# T96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZG
# Kdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpf
# m4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
# A1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFd
# ZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUH
# AwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3Js
# MCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsF
# AAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNp
# oV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG
# +tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQX
# wcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOa
# l95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9n
# EC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTC
# W/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6
# FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eC
# khSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4s
# sd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZa
# psiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggWNMIIEdaAD
# AgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0y
# MjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAf
# BgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4Smn
# PVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6f
# qVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O
# 7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZ
# Vu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4F
# fYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLm
# qaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMre
# Sx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/ch
# srIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+U
# DCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xM
# dT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUb
# AgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFd
# ZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAO
# BgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0f
# BD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNz
# dXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEM
# BQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLt
# pIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouy
# XtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jS
# TEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAc
# AgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2
# h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN8MIIDeAIBATB9MGkxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQg
# VHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEC
# EAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkD
# MQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjEwMDYyMTM4NTFaMCsG
# CyqGSIb3DQEJEAIMMRwwGjAYMBYEFFHZq9oDSXPYT0JmrKSCSOazacQ5MC8GCSqG
# SIb3DQEJBDEiBCAPKrt6tgq9vf2USAMi/iuCeH8GSBPYu0mHjDYQsg7CfTA3Bgsq
# hkiG9w0BCRACLzEoMCYwJDAiBCAtoJ2n9BMfn+cttsXm6cllZ1WvBD8ep0LMDSEg
# 4UHr/DANBgkqhkiG9w0BAQEFAASCAgCPkXikCStiyVumzg2bNZ6gGjlDX6SVBVra
# 6CRVHAWW0lJaic7wZYYVdyPC8yCQJWVtNp7e4S3THglPAVBRpyaVWnTNhewixn/C
# OlhP501CIZeDc+czUYLUNas3UMLlfd/5h88fLqBRYVTkBl203rzsqEGreKLg0ddK
# WzfiuxmKnLN9XhaU90TABYL3yl/EIdbMWkTRE/73Dn296kMQQc/DnOjrf3Od75yo
# VvzeKXwU+unR/oaTiW9a8X/WHSmSxWVZCxUSXJUAd+QWPHmTAxbOwXZHVlZ/NFsD
# oRUT6lifjBaRdkV4/rbvGowq3hSBcKetBnxpoDEYQ7qmxFFl13O1iUfA8vQaX0ja
# voTFQDtkXIkeElUW87mOu84VKQj1Uey6jLEs6uGzCEAuY1ZqOfi//+lJcmJsn+31
# pmxUqqfqAtAW1Uv+E1EwkYM0GemhI33V5msSp54k96zidooKzuv79Rjy95n1C04j
# zKmpJpXkUoO+KqYWZfgV8PHO+EaMRT/5roib13ms3sg90Mbzq//1S7jchPJNCBW2
# QfrGtPzsMAslbVlPxJbLMkk8DRlBky+bkCo4rylgQqubUaF+IdRKNqtV5HPNCBZz
# lgTs+R02Ub4zR7e6RAmkjJvJ7FGNrGDKGFw49uwIAGRkn9T3Pooo6rE3hoxorqS3
# 3jq24Vzzfw==
# SIG # End signature block
