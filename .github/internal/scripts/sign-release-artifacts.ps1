<#
.SYNOPSIS
Signs and verifies release artifacts for the pipeline-build release workflow using Azure Key Vault.

.DESCRIPTION
Uses azureSignTool to apply Authenticode signatures to PowerShell scripts and module files
and creates detached signatures and plain-text checksum files for archive, NuGet, and Python artifacts.
The private key remains in Azure Key Vault and never leaves the vault.

The behavior is driven by pipeline-config/ref/signing.yaml and can be stage-gated.

.PARAMETER SigningConfigFile
Path to the signing configuration YAML file.
Defaults to pipeline-config/ref/signing.yaml.

.PARAMETER Stage
Release stage key used to evaluate stagePolicy in the signing configuration.
Defaults to production.

.PARAMETER WorkspaceRoot
Repository root path used as the search base for repository and artifact files.
Defaults to the current working directory.

.PARAMETER RepositorySignGlobs
File glob patterns used to find signable repository files.
Defaults to PowerShell script/module patterns (*.ps1, *.psm1, *.psd1).

.PARAMETER ArtifactRoots
Repository-relative directories scanned for release artifacts.
Defaults to release-content and out.

.PARAMETER AzureSignToolVersion
Version of azureSignTool to download and install.
Defaults to v7.0.1.

.EXAMPLE
./.github/internal/scripts/sign-release-artifacts.ps1

Runs signing with default settings using pipeline-config/ref/signing.yaml and the production stage.

.EXAMPLE
./.github/internal/scripts/sign-release-artifacts.ps1 -Stage beta

Runs signing for the beta stage and applies the configured stagePolicy for beta.

.EXAMPLE
./.github/internal/scripts/sign-release-artifacts.ps1 -SigningConfigFile pipeline-config/sample/signing.yaml -WorkspaceRoot .

Runs signing using an alternate signing config and an explicit workspace root.

.NOTES
- Signing must be enabled in the configuration file (enabled: true).
- Requires the following environment variables (from GitHub Actions secrets):
    - CODESIGN_AZURE_KEYVAULT_NAME: Azure Key Vault name
    - CODESIGN_AZURE_KEYVAULT_CERT_NAME: Certificate name in Key Vault
- Requires OIDC authentication to be configured for the GitHub runner.
- Non-PowerShell artifacts are signed with detached .sig files and plain-text checksum
    sidecars (.sha256 or .sha512).
#>

[CmdletBinding()]
param(
    [string]$SigningConfigFile = "pipeline-config/ref/signing.yaml",
    [string]$Stage = "production",
    [string]$WorkspaceRoot = (Get-Location).Path,
    [string[]]$RepositorySignGlobs = @('*.ps1', '*.psm1', '*.psd1'),
    [string[]]$ArtifactRoots = @('release-content', 'out'),
    [string]$AzureSignToolVersion = "v7.0.1"
)

$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Initializes YAML parsing support for signing config processing.
#>
function Initialize-YamlSupport
{
    if (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue)
    {
        return
    }

    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue))
    {
        Register-PSRepository -Default -ErrorAction Stop
    }

    Install-Module -Name powershell-yaml -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    Import-Module powershell-yaml -ErrorAction Stop
}

<#
.SYNOPSIS
Converts a value to boolean, handling string representations.
#>
function ConvertTo-Bool
{
    param([object]$Value)

    if ($null -eq $Value)
    {
        return $false
    }

    if ($Value -is [bool])
    {
        return [bool]$Value
    }

    return [string]$Value.Trim().ToLowerInvariant() -eq 'true'
}

<#
.SYNOPSIS
Resolves and validates the configured hash algorithm.
#>
function Resolve-HashAlgorithm
{
    param([string]$AlgorithmName)

    $resolved = [string]$AlgorithmName
    if ([string]::IsNullOrWhiteSpace($resolved))
    {
        $resolved = 'SHA256'
    }

    $resolved = $resolved.Trim().ToUpperInvariant()
    if ($resolved -notin @('SHA256', 'SHA512'))
    {
        throw "Unsupported hash algorithm '$resolved'. Use SHA256 or SHA512."
    }

    return $resolved
}

<#
.SYNOPSIS
Downloads and installs azureSignTool if not already present.
#>
function Install-AzureSignTool
{
    param([string]$Version)

    # Check if azureSignTool is in PATH
    $azureSignToolCmd = Get-Command azureSignTool -ErrorAction SilentlyContinue
    if ($null -ne $azureSignToolCmd)
    {
        #Write-Output "azureSignTool is already available at: $($azureSignToolCmd.Source)"
        Write-Information "azureSignTool is already available at: $($azureSignToolCmd.Source)" -InformationAction Continue
        return $azureSignToolCmd.Source
    }

    # Download from official GitHub releases
    $normalizedVersion = if ($Version -match '^v') { $Version } else { "v$Version" }
    $architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()
    $assetName = if ($architecture -eq 'arm64') { 'AzureSignTool-arm64.exe' } else { 'AzureSignTool-x64.exe' }
    $downloadUrl = "https://github.com/vcsjones/AzureSignTool/releases/download/$normalizedVersion/$assetName"
    $installPath = Join-Path -Path $env:TEMP -ChildPath "azureSignTool.exe"
    $maxAttempts = 4
    $baseDelaySeconds = 2

    Write-Information "Downloading azureSignTool $normalizedVersion ($assetName) from: $downloadUrl" -InformationAction Continue
    $downloadSucceeded = $false
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++)
    {
        try
        {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $installPath -ErrorAction Stop
            $downloadSucceeded = $true
            break
        }
        catch
        {
            if ($attempt -eq $maxAttempts)
            {
                throw "Failed to download azureSignTool after $maxAttempts attempts from '$downloadUrl': $($_.Exception.Message)"
            }

            $delaySeconds = $baseDelaySeconds * $attempt
            Write-Warning "Download attempt $attempt of $maxAttempts failed: $($_.Exception.Message). Retrying in $delaySeconds second(s)..."
            Start-Sleep -Seconds $delaySeconds
        }
    }

    if (-not $downloadSucceeded)
    {
        throw "Failed to download azureSignTool after $maxAttempts attempts from '$downloadUrl'."
    }

    # Guard against HTML/error responses being saved as .exe
    if (-not (Test-Path -Path $installPath))
    {
        throw "azureSignTool download did not produce an output file: $installPath"
    }

    $fileLength = (Get-Item -Path $installPath -ErrorAction Stop).Length
    if ($fileLength -lt 4096)
    {
        throw "Downloaded azureSignTool file is unexpectedly small ($fileLength bytes): $downloadUrl"
    }

    $probeLength = [Math]::Min(4096, $fileLength)
    $stream = [System.IO.File]::OpenRead($installPath)
    try
    {
        $probeBytes = New-Object byte[] $probeLength
        [void]$stream.Read($probeBytes, 0, $probeLength)
    }
    finally
    {
        $stream.Dispose()
    }

    $probeText = [System.Text.Encoding]::UTF8.GetString($probeBytes)
    if ($probeText -match '<!DOCTYPE html|<html|:root\s*\{|"featureFlags"')
    {
        throw "Downloaded content is not an executable (received HTML/error payload) from: $downloadUrl"
    }

    #Write-Output "azureSignTool installed at: $installPath"
    Write-Information "azureSignTool installed at: $installPath" -InformationAction Continue
    return $installPath
}

<#
.SYNOPSIS
Obtains an Azure Key Vault access token from the authenticated Azure CLI context.
#>
function Get-AzureKeyVaultAccessToken
{
    if (-not [string]::IsNullOrWhiteSpace($script:AzureKeyVaultAccessToken))
    {
        return $script:AzureKeyVaultAccessToken
    }

    $azCommand = Get-Command az -ErrorAction SilentlyContinue
    if ($null -eq $azCommand)
    {
        throw "Azure CLI (az) is required to obtain an access token for azureSignTool authentication."
    }

    $token = (& $azCommand.Source account get-access-token --resource https://vault.azure.net --query accessToken --output tsv).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token))
    {
        throw "Failed to acquire Azure Key Vault access token from Azure CLI for azureSignTool authentication."
    }

    $script:AzureKeyVaultAccessToken = $token
    return $script:AzureKeyVaultAccessToken
}

<#
.SYNOPSIS
Invokes azureSignTool to sign a file against an Azure Key Vault certificate.
#>
function Invoke-AzureSignTool
{
    param(
        [string]$FilePath,
        [string]$VaultUrl,
        [string]$CertificateName,
        [string]$TimestampServer,
        [string]$AzureSignToolPath
    )

    if (-not (Test-Path -Path $FilePath))
    {
        throw "File to sign not found: $FilePath"
    }

    $accessToken = Get-AzureKeyVaultAccessToken

    Write-Output "Signing '$([System.IO.Path]::GetFileName($FilePath))' with azureSignTool..."

    # Build azureSignTool arguments
    $arguments = @(
        "sign",
        "-kvu", $VaultUrl,
        "-kvc", $CertificateName,
        "--azure-key-vault-accesstoken", $accessToken,
        "-tr", $TimestampServer,
        "-td", "sha256",
        $FilePath
    )

    & $AzureSignToolPath @arguments
    if ($LASTEXITCODE -ne 0)
    {
        throw "azureSignTool signing failed for '$FilePath' with exit code $LASTEXITCODE"
    }

    Write-Output "[+] Signed '$([System.IO.Path]::GetFileName($FilePath))'"
}

<#
.SYNOPSIS
Resolves Azure Key Vault configuration from signing config and environment variables.
#>
function Get-AzureKeyVaultConfig
{
    param([object]$SigningConfig)

    $vaultName = [System.Environment]::GetEnvironmentVariable('CODESIGN_AZURE_KEYVAULT_NAME')
    $certName = [System.Environment]::GetEnvironmentVariable('CODESIGN_AZURE_KEYVAULT_CERT_NAME')

    if ([string]::IsNullOrWhiteSpace($vaultName))
    {
        throw "CODESIGN_AZURE_KEYVAULT_NAME environment variable is not configured."
    }
    if ([string]::IsNullOrWhiteSpace($certName))
    {
        throw "CODESIGN_AZURE_KEYVAULT_CERT_NAME environment variable is not configured."
    }

    $vaultUrl = "https://{0}.vault.azure.net/" -f $vaultName
    $timestampServer = [string]$SigningConfig.timestampServer

    if ([string]::IsNullOrWhiteSpace($timestampServer))
    {
        $timestampServer = "https://timestamp.digicert.com"
    }

    Write-Information "Azure Key Vault Configuration:" -InformationAction Continue
    Write-Information "  Vault URL: $vaultUrl" -InformationAction Continue
    Write-Information "  Certificate: $certName" -InformationAction Continue
    Write-Information "  Timestamp Server: $timestampServer" -InformationAction Continue

    return [pscustomobject]@{
        VaultUrl = $vaultUrl
        CertificateName = $certName
        TimestampServer = $timestampServer
    }
}

<#
.SYNOPSIS
Checks if a file is already signed.
#>
function Test-IsAlreadySigned
{
    param([string]$FilePath)

    $extension = [System.IO.Path]::GetExtension($FilePath).ToLowerInvariant()

    if ($extension -in @('.ps1', '.psm1', '.psd1'))
    {
        # Check PowerShell Authenticode signature
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        return $sig.Status -eq 'Valid'
    }
    else
    {
        # Check for detached .sig file
        return Test-Path -Path "$FilePath.sig"
    }
}

<#
.SYNOPSIS
Builds a plain-text checksum line for a file.
#>
function Get-ChecksumLine
{
    param(
        [string]$FilePath,
        [string]$HashAlgorithm
    )

    $resolvedAlgorithm = Resolve-HashAlgorithm -AlgorithmName $HashAlgorithm
    $fileHash = Get-FileHash -Path $FilePath -Algorithm $resolvedAlgorithm -ErrorAction Stop

    return "{0} *{1}" -f $fileHash.Hash.ToUpperInvariant(), [System.IO.Path]::GetFileName($FilePath)
}

<#
.SYNOPSIS
Validates a checksum sidecar file against a target artifact.
#>
function Test-ChecksumFile
{
    param(
        [string]$FilePath,
        [string]$ChecksumPath,
        [string]$ExpectedAlgorithm
    )

    if (-not (Test-Path -Path $ChecksumPath))
    {
        throw "Missing checksum file '$ChecksumPath' for '$FilePath'."
    }

    $expectedResolvedAlgorithm = Resolve-HashAlgorithm -AlgorithmName $ExpectedAlgorithm
    $line = ((Get-Content -Path $ChecksumPath -ErrorAction Stop) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace([string]$line))
    {
        throw "Checksum file '$ChecksumPath' is empty."
    }

    if ([string]$line -notmatch '^(?<hash>[A-Fa-f0-9]+)\s+\*(?<file>.+)$')
    {
        throw "Checksum file '$ChecksumPath' is not in expected plain-text checksum format '<HASH> *<FILE>'."
    }

    $expectedFileName = [System.IO.Path]::GetFileName($FilePath)
    if ([string]$Matches.file -ne $expectedFileName)
    {
        throw "Checksum file '$ChecksumPath' does not reference expected file '$expectedFileName'."
    }

    $actualHash = (Get-FileHash -Path $FilePath -Algorithm $expectedResolvedAlgorithm -ErrorAction Stop).Hash.ToUpperInvariant()
    if ($actualHash -ne ([string]$Matches.hash).ToUpperInvariant())
    {
        throw "Checksum verification failed for '$FilePath'."
    }
}

# Initialize and load config
Initialize-YamlSupport

if (-not (Test-Path -Path $SigningConfigFile))
{
    Write-Output "Signing config '$SigningConfigFile' not found. Skipping artifact signing."
    return
}

$signingConfig = Get-Content -Path $SigningConfigFile -Raw | ConvertFrom-Yaml -ErrorAction Stop
if (-not (ConvertTo-Bool $signingConfig.enabled))
{
    Write-Output "Signing is disabled in '$SigningConfigFile'."
    return
}

$stagePolicy = $signingConfig.stagePolicy.$Stage
if ($null -eq $stagePolicy)
{
    throw "Signing config does not define a stagePolicy entry for '$Stage'."
}

if (-not (ConvertTo-Bool $stagePolicy.sign))
{
    Write-Output "Signing is disabled for stage '$Stage'."
    return
}

if ($null -eq $signingConfig.azureKeyVault)
{
    throw "Signing config '$SigningConfigFile' must define an azureKeyVault section when signing is enabled."
}

# Get Key Vault configuration
$kvConfig = Get-AzureKeyVaultConfig -SigningConfig $signingConfig
$hashAlgorithm = Resolve-HashAlgorithm -AlgorithmName ([string]$signingConfig.hashAlgorithm)

# Install azureSignTool
$azureSignToolPath = Install-AzureSignTool -Version $AzureSignToolVersion

# Collect files for signing and checksums
$repoRoot = (Resolve-Path -Path $WorkspaceRoot).Path
$filesToSign = New-Object System.Collections.Generic.List[string]
$filesToChecksum = New-Object System.Collections.Generic.List[string]

foreach ($glob in $RepositorySignGlobs)
{
    $files = Get-ChildItem -Path $repoRoot -Recurse -File -Include $glob -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '[\\/](out|\.git)[\\/]' }
    foreach ($file in $files)
    {
        [void]$filesToSign.Add($file.FullName)
        [void]$filesToChecksum.Add($file.FullName)
    }
}

foreach ($artifactRoot in $ArtifactRoots)
{
    $artifactRootPath = Join-Path -Path $repoRoot -ChildPath $artifactRoot
    if (-not (Test-Path -Path $artifactRootPath))
    {
        continue
    }

    $artifacts = Get-ChildItem -Path $artifactRootPath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -notin @('.sig', '.sha256', '.sha512') }
    foreach ($artifact in $artifacts)
    {
        [void]$filesToChecksum.Add($artifact.FullName)

        # zip archives are checksum-only artifacts and should not be Authenticode-signed
        if ($artifact.Extension.ToLowerInvariant() -eq '.zip')
        {
            continue
        }

        [void]$filesToSign.Add($artifact.FullName)
    }
}

$filesToSign = @($filesToSign | Sort-Object -Unique)
$filesToChecksum = @($filesToChecksum | Sort-Object -Unique)

if ($filesToChecksum.Count -eq 0)
{
    Write-Output 'No artifacts matched the signing/checksum scope.'
    return
}

Write-Output "Signing $($filesToSign.Count) file(s) and generating checksums for $($filesToChecksum.Count) file(s) for stage '$Stage'..."
# Sign supported files
foreach ($filePath in $filesToSign)
{
    # Skip files that are already signed
    if (Test-IsAlreadySigned -FilePath $filePath)
    {
        Write-Output "Skipping already-signed: '$([System.IO.Path]::GetFileName($filePath))'"
        continue
    }

    Invoke-AzureSignTool -FilePath $filePath `
        -VaultUrl $kvConfig.VaultUrl `
        -CertificateName $kvConfig.CertificateName `
        -TimestampServer $kvConfig.TimestampServer `
        -AzureSignToolPath $azureSignToolPath
}

# Create checksum files for all included artifacts (including checksum-only archives)
foreach ($filePath in $filesToChecksum)
{
    $checksumExtension = $hashAlgorithm.ToLowerInvariant()
    $checksumPath = "$filePath.$($checksumExtension)"
    $checksumLine = Get-ChecksumLine -FilePath $filePath -HashAlgorithm $hashAlgorithm
    $checksumLine | Out-File -FilePath $checksumPath -Encoding ascii -Force
    Write-Output "  [+] Checksum: $([System.IO.Path]::GetFileName($checksumPath))"
}

# Verify signatures
Write-Output "`nVerifying signatures for stage '$Stage'..."
foreach ($filePath in $filesToSign)
{
    $extension = [System.IO.Path]::GetExtension($filePath).ToLowerInvariant()

    if ($extension -in @('.ps1', '.psm1', '.psd1'))
    {
        # Verify Authenticode signature for PowerShell files
        $signature = Get-AuthenticodeSignature -FilePath $filePath
        if ($signature.Status -ne 'Valid')
        {
            throw "Authenticode verification failed for '$filePath' with status '$($signature.Status)'."
        }
        Write-Output "  [+] $([System.IO.Path]::GetFileName($filePath)) (Authenticode)"
    }
    else
    {
        # Verify file exists (azureSignTool creates .sig file)
        $sigPath = "$filePath.sig"
        if (-not (Test-Path -Path $sigPath))
        {
            throw "Missing detached signature file '$sigPath' for '$filePath'."
        }
        Write-Output "  [+] $([System.IO.Path]::GetFileName($filePath)) (Detached signature)"
    }
}

foreach ($filePath in $filesToChecksum)
{
    # Verify checksum file
    $checksumExtension = $hashAlgorithm.ToLowerInvariant()
    Test-ChecksumFile -FilePath $filePath -ChecksumPath "$filePath.$($checksumExtension)" -ExpectedAlgorithm $hashAlgorithm
    Write-Output "  [+] Checksum verified"
}

Write-Output "`n[OK] Signing and verification complete for stage '$Stage'."
# SIG # Begin signature block
# MIIu4gYJKoZIhvcNAQcCoIIu0zCCLs8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAxs5TBA3ej6F7v
# 7NuGWchUe8ZQf3xcv15PewAdRJZPS6CCE6MwggVyMIIDWqADAgECAhB2U/6sdUZI
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
# n1KtQm7lUWQsI+Cz5zGCGpUwghqRAgEBMGkwWTELMAkGA1UEBhMCQkUxGTAXBgNV
# BAoTEEdsb2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNpZ24gR0NDIFI0
# NSBDb2RlU2lnbmluZyBDQSAyMDIwAgxhoXx4c1Ywe7yEvMYwDQYJYIZIAWUDBAIB
# BQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG
# 9w0BCQQxIgQgAl1TNfDDv92Ac8yRDirHcA/YedWVClXrxFfj78e6s+cwDQYJKoZI
# hvcNAQEBBQAEggIAL13hFMDSCFWWaUES5ug7pGfogoN3f93WHr3nfEDeLZ4Vn9hr
# eBKkiSHBKZnspli7nccWJYF+tawXdfLjV5jQgd97C7Is+lU7rHjAaKOoSSyCLH6s
# fSiM0a3zSqAGJX6XednvStaH22l5HWUnNbOWUZBKIpBBfAz2ZRqgInajnKiblfG/
# Q/vGYl0NgNHdMsPvI9+MM8Wdaen9OOgCt45Q1+wR1sLMYMSctmUYrWa/Ym/id3ci
# QieXjHZBqC8cVoHfQ/PA7oh1fLVUM/tJXlSEKK/V15xAB56Ksm3he8UN1jDY7UHb
# FHhnscbuD3eZ1EOZZLH9q8qelxJQctyow3fyxhlIeR8AAO8By+UkGcWnSeJotwEA
# KxomK3ALz2I/zz2g4x+Rqo62iNVJLbH2SKmu5xL5PWxv9OLM+BHEXcfCL+uU2WJy
# LrJnfRLGp+iyPw1Wo+BB2AS/nEB9Oh5j9zFDO7Zjku+WdBgwWGoOmYo92f7GUPEM
# mI8dPyX9kBBcXahcvc7HZWnV8kMnibR6Od8kSftEUXH33+Tluh84fRXcClObmKyI
# NBjDNz53LwUYSc+FROs9zDVeS5wbJRclPGYKI+n8WEiODcoyTrdcRtNWlilmrfoc
# ZMfFwJLgeU+mj+/Y89TzlSPiWEJ9oyqZq1Wax7NDQLBGjkeM6Xt/0EI8k9yhghd2
# MIIXcgYKKwYBBAGCNwMDATGCF2IwghdeBgkqhkiG9w0BBwKgghdPMIIXSwIBAzEP
# MA0GCWCGSAFlAwQCAQUAMHcGCyqGSIb3DQEJEAEEoGgEZjBkAgEBBglghkgBhv1s
# BwEwMTANBglghkgBZQMEAgEFAAQgxSGYW/jJ1662LnRSXA7bP2mN5PMEpRyRFd4W
# +byfdUsCEBJtfPViAyP5sRK/8+rPWngYDzIwMjYxMDA2MjEzODQxWqCCEzowggbt
# MIIE1aADAgECAhAIT9wzT35FTtvDD4/5khg1MA0GCSqGSIb3DQEBCwUAMGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTEwHhcNMjYwODA1MDAwMDAwWhcNMzcxMTA0MjM1OTU5WjBjMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0
# IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNiAxMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtnum8sn+zUr41JtMZbP9OMYw+HwJ
# DpG5xkIu/lqcfNYmMX81YmsUiHLbh9ykpeWBGKTLhYBrAN9Tdg/QEzG32XcObmgI
# blnr0CoQ3WSAeDZ6nH6X6VkFyYkJw3QBJREwvm4UhLzSxmwPA7cFKRTEOMsmEEj6
# qJk/dqLEAL+oQYuOwE2UuiX1Vnul8YReIyWd4kgLn9gq6LNXM0UplkR6jL/QHxmb
# 6fMoGBJYbnaUI7XD6cKDpekK2SVMld4iDbzeHDtOaaxldH5IxuNusQ69nd8/ZXEi
# B5Hbxj3RlK13cX1W4DlFXKdv/CEhM8Cj1vvlmvhNroyPdRGbbpBlgyf8Wdu5N6By
# hFwURn0U6ozlPoxN22v+fviUhP+6DR547OZnpBMWDfei1f5sVGwiiW/KQTWOK97g
# +4RJpPzPNV4VYMAwO2jM2Aty2QYPVmOQTJm0msuXnJrSbl2gf9JylpkJlWXqk1Q4
# LJsxz+TELoQCZIljbgvTJgoPU2R12ydv8i1UqL/adelA0y7U9Pmmtbze9Xx3rtaj
# C5SzQd1jgfwAwsa90v9YcSPdmeoyoBBA/27cCL237l5DTYYPDLQ4ON3OLTGWnvRb
# 6jDrf/T75gMRfUzSLCBQfBusm9+mSWRlC/Df6S/e9Q8i13CuhzOT2Jx+V/nlbXM4
# QoBwlUAhelwwJT0CAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE
# FBTJY4owLtRK+26U8+bjQH717M3iMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2
# L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCB
# lQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVD
# QTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1
# Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAI3FOmEenVIK35msCYB+fShAsWvSYvLBItoNdAgQ2jIqrGsV
# sluXMJU/+mRebBc52s6lbKAvOVPXaizmKkMLLflEEKDZQx4CkS2t8aHPjkXha3hY
# Z010htFa3dhNgmalH5vuWvh3tTCf4frTS7gPtGc4Z/xaPhQ2AB1mR8eEe/WbH0RW
# HvVIl6VwQ3+g5FKNfN2N/DWJkf13w2H+2GfqEfbd35Ww8CvoYBjLNIDTadcPWdgs
# jsiOaK/7EsKJgLjUNIVgvcaFOLLQ/GlrA+0ZHJoFUbOr5SJN8zykPspXIXlpDJY/
# gqFUZRROeab9GVgmhbdOJcD/63RhxPahFUGbckRONqMe6DYAv6/mOG0pWd3cPSts
# dcS7buj5DyniwRY8yooMH6ptx5vpP/pZzBPBeZD2U4IsthyxB5Jaa8qrOkB5z160
# TXiM5ADMspZ0TfD9MJoq0tFpFPssKRFhWeEDYPvcUuN7U7lvcdHl4ezQ3NT/7Ffs
# 1sR1yh/LRbdZ3B3Vc6q2WmD8mDC0p9kzl2o73iVtS946IkEj7FkRsZGww1teYxER
# ROC745xrtjvcw9ZyyUjHZWGRIpJeMNsPquCDf0fkyHtB+J4AiNZqCQk23rxh+Kbp
# yMTNVKItJ5l92Svl20U9NbqMBOVYl1h54NEYLJq1/xHWFKPNK903zJZA9P2DMIIG
# tDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0
# URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusL
# opuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQ
# XSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDE
# pKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7
# PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpo
# YGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQ
# HkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJn
# jq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP
# 3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp
# 2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+b
# gIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# CDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# IAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUA
# A4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mh
# XZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib6
# 1eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfB
# wAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX
# 3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQ
# LwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb
# 82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToW
# d2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KS
# FLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx
# 3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8Blqm
# yIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBY0wggR1oAMC
# AQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIy
# MDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8G
# A1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9
# WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+p
# VxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7s
# Xk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW
# 7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9
# iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuap
# oGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5L
# HucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGy
# shG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QM
# IR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1
# P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsC
# AwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1k
# TN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4G
# A1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8E
# PjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
# cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwF
# AAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2k
# iHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je
# 1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJM
# QBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwC
# A8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaH
# lv1b0VysGMNNn3O3AamfV6peKOK5lDGCA3wwggN4AgEBMH0waTELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBU
# cnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQ
# CE/cM09+RU7bww+P+ZIYNTANBglghkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMx
# DQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTAwNjIxMzg0MVowKwYL
# KoZIhvcNAQkQAgwxHDAaMBgwFgQUUdmr2gNJc9hPQmaspIJI5rNpxDkwLwYJKoZI
# hvcNAQkEMSIEIA79cakyLpHCUloPYzot+BgOOvf27chJaXnbr/OdkzlqMDcGCyqG
# SIb3DQEJEAIvMSgwJjAkMCIEIC2gnaf0Ex+f5y22xebpyWVnVa8EPx6nQswNISDh
# Qev8MA0GCSqGSIb3DQEBAQUABIICAJxjpmA+Z2LUjpY4VwF5B99UId2Q7c2qh3T1
# gALeTuS7u+K2EccIMV5pw/17QQzrPknQbTta27XBpQXzOQfq3JVjMwJLd6s6gZNm
# dVIUZCotfa5GQPPKaHN8zyhJjsPRMOdUr55RPkcFdAAIuHLgddPhSVbDvcGWRglg
# l4fcon1B6Nkqzk1MaCOskRdBV0XB6UnGUSPjB0uDpoYByD9ukZBaorxMKFXyQRzF
# NuSH5LVSSKIfXom75CyW1u4sppGV3ZzzsRnvQvwubFiTd5puQVdQFcPEvSfbQGTW
# /5141G6MwHwB7PL9HxupFzNVoVKEzcn/5GH0rDLqes8rcwH5Y7Wa2Dy9v9bW5hVK
# 68lDS9LYvuBcMshN6vTNUKPphhWuMZVnNPHJT8qyZ+Rx/eJJycf8iduWyYJMxOQw
# 8ZaBlHk2W/RggrY5NQ2qL/YdXwDhtMZaOUPqTAAKdnsJqO8IKEfc/Evab/+GIMRo
# zyTcRROck/wHJYOOMxrV2+AV3T55TC240GYd1Ach2SDXVhYZoE/pOq5eGCLWBIs8
# BWo8SpNhDYPeTvUWJ6F4qdY3PU+cnBXsMh7mg+d+gU4ctuy5MJ/zTs+CzcjcQ99o
# /SMgoCmiu+02GsQp0ERlG22w/a+gWp515pOOHWKuwa/CsUJYTGORufJ/JpLF6RL3
# Zokx4W7G
# SIG # End signature block
