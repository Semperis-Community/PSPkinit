<#
.SYNOPSIS
Probes SharePoint authentication and destination folder resolution; optionally performs a single-file upload probe when -FilePath is provided.

.DESCRIPTION
Loads sharePointTargets from pipeline-config/ref/publish-targets.yaml, resolves enabled targets,
authenticates with Connect-PnPOnline using certificate-based credentials from secret payload JSON,
and then performs a Get-PnPWeb and Resolve-PnPFolder check for the computed destination folder.

This script is intended for local diagnosis when SharePoint publish attempts return Unauthorized.
It does not upload any files.

.PARAMETER RepoRoot
Repository root path.

.PARAMETER PublishTargetsFile
Path to publish-targets YAML file, relative to RepoRoot unless absolute.

.PARAMETER SharePointSecretsFile
Path to YAML file containing local secret payloads under a top-level `secrets` map.
Relative to RepoRoot unless absolute.

.PARAMETER ReleaseStage
Release stage used in destination path construction.

.PARAMETER RepositoryName
Repository name segment appended to SharePoint destination path.

.PARAMETER TargetName
Optional list of SharePoint target names to include.

.PARAMETER FilePath
Optional local file path to upload after successful auth and folder resolution.
Relative to RepoRoot unless absolute.

.EXAMPLE
./scripts/probe-sharepoint-auth.ps1 -ReleaseStage production -TargetName SandboxRelease

Probes the SandboxRelease target using the same auth method and folder path as the publish workflow.

.EXAMPLE
./scripts/probe-sharepoint-auth.ps1 -ReleaseStage production -TargetName SandboxRelease -FilePath .\out\pipeline-build-v1.5.36.zip

Probes auth, folder resolution, and a single file upload attempt without processing all files.

.EXAMPLE
$env:SHAREPOINT_RELEASE_CREDENTIALS_SAND = '{"authType":"certificate","tenantId":"00000000-0000-0000-0000-000000000000","clientId":"11111111-1111-1111-1111-111111111111","certificatePath":"C:\\certs\\sp-app.pfx","certificatePassword":"replace-with-password"}'
./scripts/probe-sharepoint-auth.ps1 -ReleaseStage production -TargetName SandboxRelease

Probes SharePoint auth using an app registration certificate.
#>

[CmdletBinding()]
param(
    [string]$RepoRoot = (Get-Location).Path,
    [string]$PublishTargetsFile = 'pipeline-config/ref/publish-targets.yaml',
    [string]$SharePointSecretsFile = 'pipeline-config/ref/sharepoint-secrets.yaml',
    [ValidateSet('alpha', 'beta', 'rc', 'production')]
    [Parameter(Mandatory = $false)]
    [string]$ReleaseStage = 'production',
    [string]$RepositoryName = 'pipeline-build',
    [string[]]$TargetName,
    [string]$FilePath
)

$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Resolves a path that may be absolute or relative to a provided base path.
#>
function Resolve-LocalPath
{
    param(
        [string]$BasePath,
        [string]$PathValue
    )

    if ([System.IO.Path]::IsPathRooted($PathValue))
    {
        return (Resolve-Path -Path $PathValue -ErrorAction Stop).Path
    }

    return (Resolve-Path -Path (Join-Path -Path $BasePath -ChildPath $PathValue) -ErrorAction Stop).Path
}

<#
.SYNOPSIS
Converts common boolean-like values to a boolean with a fallback default.
#>
function Convert-ToBoolOrDefault
{
    param(
        [AllowNull()]$Value,
        [bool]$DefaultValue = $true,
        [string]$FieldName = 'value'
    )

    if ($null -eq $Value)
    {
        return $DefaultValue
    }

    if ($Value -is [bool])
    {
        return [bool]$Value
    }

    $normalized = ([string]$Value).Trim().ToLowerInvariant()
    if ($normalized -in @('true', '1', 'yes', 'on'))
    {
        return $true
    }

    if ($normalized -in @('false', '0', 'no', 'off'))
    {
        return $false
    }

    throw "Invalid boolean value '$Value' for $FieldName. Use true or false."
}

<#
.SYNOPSIS
Ensures ConvertFrom-Yaml support is available in the current session.
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
Ensures PnP.PowerShell is installed and imported.
#>
function Initialize-PnPPowerShell
{
    if (-not (Get-Module -ListAvailable -Name PnP.PowerShell))
    {
        if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue))
        {
            Register-PSRepository -Default -ErrorAction Stop
        }

        Install-Module -Name PnP.PowerShell -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }

    Import-Module PnP.PowerShell -ErrorAction Stop
}

<#
.SYNOPSIS
Parses a SharePoint credential payload from JSON into an object.
#>
function Get-SharePointCredential
{
    param([string]$SecretValue)

    if ([string]::IsNullOrWhiteSpace($SecretValue))
    {
        return $null
    }

    try
    {
        return ($SecretValue | ConvertFrom-Json -ErrorAction Stop)
    }
    catch
    {
        throw 'SharePoint credential secret must be JSON. Expected fields: authType (optional), and either certificate fields (clientId, tenantId plus certificatePath/certificatePassword or certificateBase64/certificatePassword) or accessToken.'
    }
}

<#
.SYNOPSIS
Builds a secure string from in-memory plaintext without using ConvertTo-SecureString -AsPlainText.
#>
function Convert-PlainTextToSecureString
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlainText
    )

    $secureString = [System.Security.SecureString]::new()
    foreach ($character in $PlainText.ToCharArray())
    {
        $secureString.AppendChar($character)
    }

    $secureString.MakeReadOnly()
    return $secureString
}

<#
.SYNOPSIS
Initializes a secret lookup map from a local YAML file when available.
#>
function Initialize-SecretLookup
{
    param(
        [string]$BasePath,
        [string]$SecretsFilePath
    )

    $lookup = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if ([string]::IsNullOrWhiteSpace($SecretsFilePath))
    {
        return $lookup
    }

    $candidatePath = $SecretsFilePath
    if (-not [System.IO.Path]::IsPathRooted($candidatePath))
    {
        $candidatePath = Join-Path -Path $BasePath -ChildPath $candidatePath
    }

    if (-not (Test-Path -Path $candidatePath))
    {
        Write-Information "Secrets file not found at '$candidatePath'. Falling back to environment variables." -InformationAction Continue
        return $lookup
    }

    $resolvedSecretsPath = (Resolve-Path -Path $candidatePath -ErrorAction Stop).Path
    $secretsConfig = Get-Content -Path $resolvedSecretsPath -Raw | ConvertFrom-Yaml -ErrorAction Stop
    if ($null -eq $secretsConfig -or $null -eq $secretsConfig.secrets)
    {
        Write-Output "Secrets file '$resolvedSecretsPath' has no top-level 'secrets' map. Falling back to environment variables."
        return $lookup
    }

    $secretsNode = $secretsConfig.secrets
    if ($secretsNode -is [System.Collections.IDictionary])
    {
        foreach ($key in $secretsNode.Keys)
        {
            $value = [string]$secretsNode[$key]
            if (-not [string]::IsNullOrWhiteSpace($value))
            {
                $lookup[[string]$key] = $value.Trim()
            }
        }
    }
    else
    {
        foreach ($property in $secretsNode.PSObject.Properties)
        {
            $value = [string]$property.Value
            if (-not [string]::IsNullOrWhiteSpace($value))
            {
                $lookup[[string]$property.Name] = $value.Trim()
            }
        }
    }

    Write-Output "Loaded $($lookup.Count) secret value(s) from '$resolvedSecretsPath'."
    return $lookup
}

<#
.SYNOPSIS
Connects to a SharePoint site using supported credential payload types.
#>
function Connect-SharePointTarget
{
    param(
        [string]$SiteUrl,
        [psobject]$CredentialObject
    )

    if ($null -eq $CredentialObject)
    {
        throw 'Missing SharePoint credential payload.'
    }

    $authType = [string]$CredentialObject.authType
    if ([string]::IsNullOrWhiteSpace($authType))
    {
        $authType = 'certificate'
    }

    switch ($authType.Trim().ToLowerInvariant())
    {
        'accesstoken'
        {
            $accessToken = [string]$CredentialObject.accessToken
            if ([string]::IsNullOrWhiteSpace($accessToken))
            {
                throw "SharePoint credentials authType 'accessToken' requires 'accessToken'."
            }

            Connect-PnPOnline -Url $SiteUrl -AccessToken $accessToken -ErrorAction Stop
            break
        }
        'graphaccesstoken'
        {
            $accessToken = [string]$CredentialObject.accessToken
            if ([string]::IsNullOrWhiteSpace($accessToken))
            {
                throw "SharePoint credentials authType 'graphAccessToken' requires 'accessToken'."
            }

            Connect-PnPOnline -Url $SiteUrl -AccessToken $accessToken -ErrorAction Stop
            break
        }
        'certificate'
        {
            $clientId = [string]$CredentialObject.clientId
            $tenantId = [string]$CredentialObject.tenantId
            $certificatePath = [string]$CredentialObject.certificatePath
            $certificatePassword = [string]$CredentialObject.certificatePassword
            $certificateBase64 = [string]$CredentialObject.certificateBase64

            if ([string]::IsNullOrWhiteSpace($clientId) -or [string]::IsNullOrWhiteSpace($tenantId))
            {
                throw "SharePoint credentials authType 'certificate' requires clientId and tenantId."
            }

            if (-not [string]::IsNullOrWhiteSpace($certificatePath))
            {
                if ([string]::IsNullOrWhiteSpace($certificatePassword))
                {
                    throw "SharePoint credentials authType 'certificate' using certificatePath requires certificatePassword."
                }

                $securePassword = Convert-PlainTextToSecureString -PlainText $certificatePassword
                Connect-PnPOnline -Url $SiteUrl -ClientId $clientId -Tenant $tenantId -CertificatePath $certificatePath -CertificatePassword $securePassword -ErrorAction Stop
                break
            }

            if (-not [string]::IsNullOrWhiteSpace($certificateBase64))
            {
                if ([string]::IsNullOrWhiteSpace($certificatePassword))
                {
                    throw "SharePoint credentials authType 'certificate' using certificateBase64 requires certificatePassword."
                }

                $securePassword = Convert-PlainTextToSecureString -PlainText $certificatePassword
                Connect-PnPOnline -Url $SiteUrl -ClientId $clientId -Tenant $tenantId -CertificateBase64Encoded $certificateBase64 -CertificatePassword $securePassword -ErrorAction Stop
                break
            }

            throw "SharePoint credentials authType 'certificate' requires either certificatePath or certificateBase64."
            break
        }
        default
        {
            throw "Unsupported SharePoint authType '$authType'. Supported values: certificate, accessToken, graphAccessToken."
        }
    }
}

Initialize-YamlSupport
Initialize-PnPPowerShell

$resolvedRepoRoot = Resolve-Path -Path $RepoRoot -ErrorAction Stop
$repoRootPath = $resolvedRepoRoot.Path

if ([string]::IsNullOrWhiteSpace($RepositoryName))
{
    $RepositoryName = Split-Path -Path $repoRootPath -Leaf
}

$RepositoryName = ($RepositoryName -replace '[^A-Za-z0-9._-]', '-').Trim('-')
if ([string]::IsNullOrWhiteSpace($RepositoryName))
{
    $RepositoryName = 'repository'
}

$targetsPath = Resolve-LocalPath -BasePath $repoRootPath -PathValue $PublishTargetsFile
$secretLookup = Initialize-SecretLookup -BasePath $repoRootPath -SecretsFilePath $SharePointSecretsFile

$dependencyConfig = Get-Content -Path $targetsPath -Raw | ConvertFrom-Yaml -ErrorAction Stop
$sharePointEnabled = Convert-ToBoolOrDefault -Value $dependencyConfig.sharePointPublishing.enabled -DefaultValue $true -FieldName 'sharePointPublishing.enabled'
if (-not $sharePointEnabled)
{
    Write-Output 'sharePointPublishing.enabled is false. Nothing to probe.'
    exit 0
}

$publishTargets = @()
if ($null -ne $dependencyConfig.sharePointTargets)
{
    $publishTargets = @($dependencyConfig.sharePointTargets)
}

if ($TargetName -and $TargetName.Count -gt 0)
{
    $nameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $TargetName)
    {
        [void]$nameSet.Add([string]$n)
    }

    $publishTargets = @($publishTargets | Where-Object { $nameSet.Contains([string]$_.name) })
}

if ($publishTargets.Count -eq 0)
{
    Write-Output 'No matching sharePointTargets configured. Nothing to probe.'
    exit 0
}

$targetResults = New-Object System.Collections.Generic.List[string]
$failedTargets = New-Object System.Collections.Generic.List[string]

$resolvedFilePath = $null
if (-not [string]::IsNullOrWhiteSpace($FilePath))
{
    $resolvedFilePath = Resolve-LocalPath -BasePath $repoRootPath -PathValue $FilePath
    Write-Output "Optional file probe path: $resolvedFilePath"
}

<#
.SYNOPSIS
Writes a preflight-style summary for SharePoint probe details.
#>
function Write-ProbeSummary
{
    param(
        [string]$TargetName,
        [string]$AuthType,
        [string]$SiteUrl,
        [string]$SiteRelativeFolder,
        [string]$FilePath
    )

    Write-Output ''
    Write-Output 'Probe summary:'
    Write-Output "- Target: $TargetName"
    Write-Output "- AuthType: $AuthType"
    Write-Output "- SiteUrl: $SiteUrl"
    Write-Output "- SiteRelativeFolder: $SiteRelativeFolder"
    if ([string]::IsNullOrWhiteSpace($FilePath))
    {
        Write-Output '- File: (none)'
    }
    else
    {
        Write-Output "- File: $FilePath"
    }
}

foreach ($target in $publishTargets)
{
    $targetName = [string]$target.name
    $isTargetEnabled = Convert-ToBoolOrDefault -Value $target.enabled -DefaultValue $true -FieldName "sharePointTargets[$targetName].enabled"
    if (-not $isTargetEnabled)
    {
        $targetResults.Add("- SharePoint target '$targetName': skipped (disabled).") | Out-Null
        continue
    }

    $siteUrl = [string]$target.siteUrl
    $documentLibrary = [string]$target.documentLibrary
    $folderPath = [string]$target.folderPath
    $secretName = [string]$target.secretEnvVar

    if ([string]::IsNullOrWhiteSpace($siteUrl) -or [string]::IsNullOrWhiteSpace($documentLibrary) -or [string]::IsNullOrWhiteSpace($secretName))
    {
        Write-Warning "SharePoint target '$targetName' missing required fields (siteUrl, documentLibrary, secretEnvVar). Skipping."
        $targetResults.Add("- SharePoint target '$targetName': skipped (missing required target configuration).") | Out-Null
        continue
    }

    $secretValue = $null
    if ($secretLookup.ContainsKey($secretName))
    {
        $secretValue = $secretLookup[$secretName]
    }

    if ([string]::IsNullOrWhiteSpace($secretValue))
    {
        $secretValue = [System.Environment]::GetEnvironmentVariable($secretName)
    }

    if ([string]::IsNullOrWhiteSpace($secretValue))
    {
        Write-Warning "No secret value found for '$secretName' in '$SharePointSecretsFile' or environment variables. Skipping target '$targetName'."
        $targetResults.Add("- SharePoint target '$targetName': skipped (missing secret '$secretName' in local YAML and environment variables).") | Out-Null
        continue
    }

    $siteRelativeBase = $documentLibrary.Trim('/')
    if (-not [string]::IsNullOrWhiteSpace($folderPath))
    {
        $trimmedFolderPath = $folderPath.Trim('/')
        if (-not [string]::IsNullOrWhiteSpace($trimmedFolderPath))
        {
            $siteRelativeBase = "$siteRelativeBase/$trimmedFolderPath"
        }
    }
    $siteRelativeBase = "$siteRelativeBase/$RepositoryName/$ReleaseStage"

    Write-Output "Probing SharePoint target '$targetName'..."
    Write-Output "-> SiteUrl: $siteUrl"
    Write-Output "-> SiteRelativeFolder: $siteRelativeBase"

    try
    {
        $credentials = Get-SharePointCredential -SecretValue $secretValue
        $authTypeUsed = 'certificate'
        if (-not [string]::IsNullOrWhiteSpace([string]$credentials.authType))
        {
            $authTypeUsed = [string]$credentials.authType
        }

        Write-ProbeSummary -TargetName $targetName -AuthType $authTypeUsed -SiteUrl $siteUrl -SiteRelativeFolder $siteRelativeBase -FilePath $resolvedFilePath
        Write-Output "-> AuthType: $authTypeUsed"
        Connect-SharePointTarget -SiteUrl $siteUrl -CredentialObject $credentials

        $web = Get-PnPWeb -ErrorAction Stop
        Write-Output "-> Connected web title: $($web.Title)"
        Write-Output "-> Connected web url:   $($web.Url)"

        Resolve-PnPFolder -SiteRelativePath $siteRelativeBase -ErrorAction Stop | Out-Null
        Write-Output "-> Folder resolution succeeded."

        if (-not [string]::IsNullOrWhiteSpace($resolvedFilePath))
        {
            $uploadFolder = $siteRelativeBase
            Write-Output "-> Attempting single-file upload probe..."
            Write-Output "-> Upload file: $resolvedFilePath"
            Add-PnPFile -Path $resolvedFilePath -Folder $uploadFolder -Overwrite -ErrorAction Stop | Out-Null
            Write-Output "-> Single-file upload probe succeeded."
        }

        $targetResults.Add("- SharePoint target '$targetName': connection and folder resolution succeeded.") | Out-Null
    }
    catch
    {
        Write-Warning "SharePoint probe failed for '$targetName'. $($_.Exception.Message)"
        Write-Error $_
        $targetResults.Add("- SharePoint target '$targetName': failed. See error output above.") | Out-Null
        $failedTargets.Add($targetName) | Out-Null
    }
    finally
    {
        Disconnect-PnPOnline -ErrorAction SilentlyContinue
    }
}

Write-Output ''
Write-Output 'Probe results:'
foreach ($line in $targetResults)
{
    Write-Output $line
}

if ($failedTargets.Count -gt 0)
{
    throw ('SharePoint probe failed for target(s): ' + ($failedTargets -join ', '))
}