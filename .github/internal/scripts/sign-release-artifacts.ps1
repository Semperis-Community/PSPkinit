<#
.SYNOPSIS
Signs and verifies release artifacts for the pipeline-build release workflow using Azure Key Vault.

.DESCRIPTION
Uses azureSignTool to apply embedded Authenticode signatures to PowerShell files and
native binaries. Other resources are checksum-only artifacts.
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
- Included artifacts receive plain-text checksum sidecars (.sha256 or .sha512).
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

    if ($extension -in $authenticodeExtensions)
    {
        # Check PowerShell Authenticode signature
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        return $sig.Status -eq 'Valid'
    }
    else
    {
        return $false
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
$authenticodeExtensions = @('.ps1', '.psm1', '.psd1', '.exe', '.dll', '.pyd')

foreach ($glob in $RepositorySignGlobs)
{
    $files = Get-ChildItem -Path $repoRoot -Recurse -File -Include $glob -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '[\\/](out|\.git)[\\/]' }
    foreach ($file in $files)
    {
        if ($file.Extension.ToLowerInvariant() -in $authenticodeExtensions)
        {
            [void]$filesToSign.Add($file.FullName)
        }
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

        if ($artifact.Extension.ToLowerInvariant() -notin $authenticodeExtensions)
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

    if ($extension -in $authenticodeExtensions)
    {
        # Native binaries and PowerShell files both use embedded Authenticode signatures.
        $signature = Get-AuthenticodeSignature -FilePath $filePath
        if ($signature.Status -ne 'Valid')
        {
            throw "Authenticode verification failed for '$filePath' with status '$($signature.Status)'."
        }
        Write-Output "  [+] $([System.IO.Path]::GetFileName($filePath)) (Authenticode)"
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
# MIIu4wYJKoZIhvcNAQcCoIIu1DCCLtACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAIX6Dajla24Dnk
# 4LQScZ5PKK9WhQ8iPFtUDv2Fyheg76CCE6MwggVyMIIDWqADAgECAhB2U/6sdUZI
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
# 9w0BCQQxIgQgrS/BLyNIZeTDtun/oRlD25IDZf5wHBsgpSiiJFWThlAwDQYJKoZI
# hvcNAQEBBQAEggIABSF49MiJY+vbQNUxYaQlNnvjso8nmjue1700OmvLlGAvWZWo
# 7X/uOKz2qzHOWfQPxLDmGh9IIraDY9tABCXLodj5TUnSBA1dqRdvxKLvntb0NZ1M
# 0zjmnxWHHnT4fpewYu+Us4NukVrtzIwADYVNmx2emOrvEQVhj8L20Ck9F8/qYQFz
# DWnhznCeITg0IU+JX6+OylvUlEXg6HQIZ6yPXC/FmVmvD5/Fpo0SPzzRSBvg9nQ3
# DJg3B9kvjxQCQY9jaft57sf0/DxtwEHhFn4HCuKDvVK1/v7GiAQjDw+US29UU2I9
# EaZ/c5b5+GhHJ6BrY9VJe7X5Lj75MhiTGIJu9KfjnYrWr5/WSJ4uOwBe+iImyT5Q
# ogLgYW6m1JN/GPFB+QtXG7dSL2xub2DfO3sFtUSgGgbSfhlbql/pLQHoRz/IWlRl
# IFJnFDWwiWyR8PHQSz8ZqYu4EALBZs/CnJwbFj49UkFtlfXVuqW0YHRpvFQ7aEKl
# ruJUqG2RuMMWvx6NPIaQBNlm0ZQ2tCbJ0Yg5HCCEIaClWHQGfsv6j+FyqkODGM1a
# eGlx1yegPKfQrd4v94uCFU7QpbW2tyPNoEMlUB/bWq8oLPFS8N37+5vC6++HL03O
# oQHkkPkDfdVjFXhv6fx9kUEn0vHwSIY0ilQZb03ZotaGB5Z0ur+j0eUESpChghd3
# MIIXcwYKKwYBBAGCNwMDATGCF2MwghdfBgkqhkiG9w0BBwKgghdQMIIXTAIBAzEP
# MA0GCWCGSAFlAwQCAQUAMHgGCyqGSIb3DQEJEAEEoGkEZzBlAgEBBglghkgBhv1s
# BwEwMTANBglghkgBZQMEAgEFAAQgv4pJ2x/sWByXxi3xYAQD/ksDDJaqNPH6RiYQ
# 8OLHuAECEQDBmxig4/fhhfZSZTaOtLLtGA8yMDI2MTAxNjE4NDE0NFqgghM6MIIG
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
# MQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjEwMTYxODQxNDRaMCsG
# CyqGSIb3DQEJEAIMMRwwGjAYMBYEFFHZq9oDSXPYT0JmrKSCSOazacQ5MC8GCSqG
# SIb3DQEJBDEiBCDWY2V+PM4ig6F4hWVAmx0M38yaL+kbj6dkteSmKzU52DA3Bgsq
# hkiG9w0BCRACLzEoMCYwJDAiBCAtoJ2n9BMfn+cttsXm6cllZ1WvBD8ep0LMDSEg
# 4UHr/DANBgkqhkiG9w0BAQEFAASCAgAQi3e7sZoINalP/zn/vWaNlFpIfr/sQVBx
# UTy53w5h4Qfzc0EU9DFNd77McEJvgKIJuRoqbGi2J0DJDPl+yh8hIjawl9Uuk34J
# Pyi3hdQ2MPmaf9iDsUED9oQ4kdJyyO/nWu3zrkZXzs/+Bj8D5YZtOPzLZ2EvT6bM
# tFMri2bMeQJ0/9xi2NzbDDINqAAWRZG7FR25F1Fp3bUtqrvhQxwKiOuwr1At+7km
# l8Rdhhgc1E57RcoI+gWfwUOuM+BF7UxiRhUE6ih/Nw2BxgJWquSAUW2Ea/e9fSAF
# vhiSiaKo3e3uoEq1hVD9q/290ZpXCmUYyZVzRhiUDFeer2vPd/Jipdc6W7KkKDmc
# wAJ0kJAGgfBjWqGL7MY1jNYXM9KLdMMrsH3gy+01uEqeugEgufmQR/p843QQD9dv
# XCNhrwxpB/pK7PCxq5e2o7I9BC+OYlBID2f/0kCUMWzUmnvNLDyjgo1+tr0xUcYK
# P8m+hLPdawBFEvQBwNNivM9HtAQAHfITg6q+UGg02e4u1xpJ9GKazkpmo8iI9sSE
# k2IPwgleMLYGp0DG8OJUUhmQfxcRWRdxtJdRyE/L1sKyP6KmrSvmkWX7bKZ04arL
# VjgcISJQ2FAJ7vASV860jdUgQsQI8GtQsIicIlVJP+3sAoJQ0sVwW6/aq659CzYw
# sFa4EJ2pBA==
# SIG # End signature block
