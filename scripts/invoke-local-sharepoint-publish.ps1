<#
.SYNOPSIS
Publishes release artifacts to SharePoint using the same auth and target logic as the workflow.

.DESCRIPTION
Reads sharePointTargets from pipeline-config/ref/publish-targets.yaml, resolves enabled targets,
authenticates with Connect-PnPOnline based on each target's secret payload, and uploads files from
an artifact folder into:

<documentLibrary>/<folderPath>/<repository>/<releaseStage>/<relativeArtifactDirectory>

Credential payloads are read from local environment variables whose names match each target's
secretEnvVar value (for example SHAREPOINT_RELEASE_CREDENTIALS_SAND).

When SharePointSecretsFile exists, secret payloads are loaded from that file first, then
environment variables are used as fallback.

GitHub secret values cannot be read back via API/CLI, so this script expects equivalent values to
already be present in local environment variables.

.PARAMETER RepoRoot
Repository root path.

.PARAMETER PublishTargetsFile
Path to publish-targets YAML file, relative to RepoRoot unless absolute.

.PARAMETER SharePointSecretsFile
Path to YAML file containing local secret payloads under a top-level `secrets` map.
Relative to RepoRoot unless absolute.

.PARAMETER ArtifactPath
Folder containing files to upload. Relative to RepoRoot unless absolute.

.PARAMETER ReleaseStage
Release stage used in destination path construction.

.PARAMETER RepositoryName
Repository name segment appended to SharePoint destination path.

.PARAMETER TargetName
Optional list of SharePoint target names to include.

.PARAMETER AllowMissingFolders
When set, treats Resolve-PnPFolder errors as warnings and continues upload attempts.

.EXAMPLE
./scripts/invoke-local-sharepoint-publish.ps1 -ReleaseStage production

Uploads files found in ./out to enabled SharePoint targets using locally available secret env vars.

.EXAMPLE
$env:SHAREPOINT_RELEASE_CREDENTIALS_SAND = '{"authType":"certificate","tenantId":"...","clientId":"...","certificatePath":"C:\\certs\\sp-app.pfx","certificatePassword":"..."}'
./scripts/invoke-local-sharepoint-publish.ps1 -ReleaseStage production -TargetName SandboxRelease

Publishes to only the SandboxRelease target.
#>

[CmdletBinding()]
param(
    [string]$RepoRoot = (Get-Location).Path,
    [string]$PublishTargetsFile = 'pipeline-config/ref/publish-targets.yaml',
    [string]$SharePointSecretsFile = 'pipeline-config/ref/sharepoint-secrets.yaml',
    [string]$ArtifactPath = 'out',
    [ValidateSet('alpha', 'beta', 'rc', 'production')]
    [Parameter(Mandatory = $false)]
    [string]$ReleaseStage = 'production',
    [string]$RepositoryName = 'pipeline-build',
    [string[]]$TargetName,
    [switch]$AllowMissingFolders
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
Builds a detailed, multiline summary from a PowerShell ErrorRecord.
#>
function Get-ErrorRecordSummary
{
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string[]]$Context = @()
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('--- SharePoint Publish Error Detail ---') | Out-Null

    foreach ($line in $Context)
    {
        if (-not [string]::IsNullOrWhiteSpace($line))
        {
            $lines.Add($line) | Out-Null
        }
    }

    $lines.Add("ErrorId: $($ErrorRecord.FullyQualifiedErrorId)") | Out-Null
    $lines.Add("Category: $($ErrorRecord.CategoryInfo)") | Out-Null
    if ($null -ne $ErrorRecord.Exception)
    {
        $lines.Add("ExceptionType: $($ErrorRecord.Exception.GetType().FullName)") | Out-Null
        $lines.Add("Message: $($ErrorRecord.Exception.Message)") | Out-Null

        $inner = $ErrorRecord.Exception.InnerException
        $depth = 0
        while ($null -ne $inner -and $depth -lt 5)
        {
            $lines.Add("InnerException[$depth]: $($inner.GetType().FullName): $($inner.Message)") | Out-Null
            $inner = $inner.InnerException
            $depth++
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ErrorRecord.ScriptStackTrace))
    {
        $lines.Add('ScriptStackTrace:') | Out-Null
        $lines.Add($ErrorRecord.ScriptStackTrace) | Out-Null
    }

    return ($lines -join [Environment]::NewLine)
}

<#
.SYNOPSIS
Writes a preflight summary for a SharePoint target publish operation.
#>
function Write-SharePointPreflightSummary
{
    param(
        [string]$TargetName,
        [string]$AuthType,
        [string]$SiteUrl,
        [string]$SiteRelativeFolder,
        [string]$ArtifactRoot,
        [int]$FileCount,
        [string]$SecretName
    )

    Write-Output ''
    Write-Output 'Preflight summary:'
    Write-Output "- Target: $TargetName"
    Write-Output "- AuthType: $AuthType"
    Write-Output "- SiteUrl: $SiteUrl"
    Write-Output "- SiteRelativeFolder: $SiteRelativeFolder"
    Write-Output "- ArtifactRoot: $ArtifactRoot"
    Write-Output "- FileCount: $FileCount"
    Write-Output "- SecretName: $SecretName"
}

<#
.SYNOPSIS
Writes a preflight summary for a single SharePoint file upload context.
#>
function Write-SharePointFilePreflightSummary
{
    param(
        [string]$TargetName,
        [string]$AuthType,
        [string]$SiteUrl,
        [string]$SiteRelativeFolder,
        [string]$FilePath
    )

    Write-Output ''
    Write-Output 'Preflight summary:'
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

Write-Output "Repo root: $RepoRoot"

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

Initialize-YamlSupport
Initialize-PnPPowerShell

$targetsPath = Resolve-LocalPath -BasePath $repoRootPath -PathValue $PublishTargetsFile
$artifactRoot = Resolve-LocalPath -BasePath $repoRootPath -PathValue $ArtifactPath
$secretLookup = Initialize-SecretLookup -BasePath $repoRootPath -SecretsFilePath $SharePointSecretsFile

$dependencyConfig = Get-Content -Path $targetsPath -Raw | ConvertFrom-Yaml -ErrorAction Stop
$sharePointEnabled = Convert-ToBoolOrDefault -Value $dependencyConfig.sharePointPublishing.enabled -DefaultValue $true -FieldName 'sharePointPublishing.enabled'
if (-not $sharePointEnabled)
{
    Write-Output 'sharePointPublishing.enabled is false. Nothing to publish.'
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
    Write-Output 'No matching sharePointTargets configured. Nothing to publish.'
    exit 0
}

$releaseFiles = @(Get-ChildItem -Path $artifactRoot -Recurse -File -ErrorAction SilentlyContinue)
if ($releaseFiles.Count -eq 0)
{
    Write-Output "No release assets found in '$artifactRoot'. Nothing to publish."
    exit 0
}

$targetResults = New-Object System.Collections.Generic.List[string]
$failedTargets = New-Object System.Collections.Generic.List[string]
$failedTargetDetails = New-Object System.Collections.Generic.List[string]

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

    Write-Output "Publishing $($releaseFiles.Count) file(s) to '$targetName' ($siteUrl/$siteRelativeBase)..."

    $currentDestinationFolder = $null
    $currentRelativePath = $null
    $authTypeUsed = 'certificate'

    try
    {
        $credentials = Get-SharePointCredential -SecretValue $secretValue
        if (-not [string]::IsNullOrWhiteSpace([string]$credentials.authType))
        {
            $authTypeUsed = [string]$credentials.authType

            Write-SharePointPreflightSummary -TargetName $targetName -AuthType $authTypeUsed -SiteUrl $siteUrl -SiteRelativeFolder $siteRelativeBase -ArtifactRoot $artifactRoot -FileCount $releaseFiles.Count -SecretName $secretName
        }

        Write-SharePointFilePreflightSummary -TargetName $targetName -AuthType $authTypeUsed -SiteUrl $siteUrl -SiteRelativeFolder $siteRelativeBase -FilePath $null

        Connect-SharePointTarget -SiteUrl $siteUrl -CredentialObject $credentials

        foreach ($file in $releaseFiles)
        {
            $relativePath = [System.IO.Path]::GetRelativePath($artifactRoot, $file.FullName) -replace '\\', '/'
            $relativeDirectory = [System.IO.Path]::GetDirectoryName($relativePath)
            $currentRelativePath = $relativePath

            $destinationFolder = $siteRelativeBase
            if (-not [string]::IsNullOrWhiteSpace($relativeDirectory))
            {
                $relativeDirectory = ($relativeDirectory -replace '\\', '/').Trim('/')
                $destinationFolder = "$destinationFolder/$relativeDirectory"
            }
            $currentDestinationFolder = $destinationFolder

            Write-Output "-> Folder: $destinationFolder"
            Write-Output "-> File:   $relativePath"

            try
            {
                Resolve-PnPFolder -SiteRelativePath $destinationFolder -ErrorAction Stop | Out-Null
            }
            catch
            {
                if ($AllowMissingFolders)
                {
                    Write-Warning "Resolve-PnPFolder issue for '$destinationFolder'. Continuing due to -AllowMissingFolders. $($_.Exception.Message)"
                }
                else
                {
                    throw "Resolve-PnPFolder failed for destination '$destinationFolder' and file '$relativePath'. $($_.Exception.Message)"
                }
            }

            Add-PnPFile -Path $file.FullName -Folder $destinationFolder -ErrorAction Stop | Out-Null
        }

        $targetResults.Add("- SharePoint target '$targetName': published ($($releaseFiles.Count) files).") | Out-Null
    }
    catch
    {
        $errorDetail = Get-ErrorRecordSummary -ErrorRecord $_ -Context @(
            "Target: $targetName",
            "ReleaseStage: $ReleaseStage",
            "SiteUrl: $siteUrl",
            "DocumentLibrary: $documentLibrary",
            "FolderPath: $folderPath",
            "SiteRelativeBase: $siteRelativeBase",
            "CurrentDestinationFolder: $currentDestinationFolder",
            "CurrentFile: $currentRelativePath",
            "ArtifactRoot: $artifactRoot",
            "SecretName: $secretName",
            "AuthTypeUsed: $authTypeUsed"
        )

        Write-Warning "SharePoint publish failed for '$targetName'. Detailed diagnostics follow."
        Write-Error $errorDetail
        $targetResults.Add("- SharePoint target '$targetName': failed. See detailed diagnostics in output.") | Out-Null
        $failedTargets.Add($targetName) | Out-Null
        $failedTargetDetails.Add($errorDetail) | Out-Null
    }
    finally
    {
        Disconnect-PnPOnline -ErrorAction SilentlyContinue
    }
}

Write-Output ''
Write-Output 'SharePoint publish results:'
foreach ($line in $targetResults)
{
    Write-Output $line
}

if ($failedTargets.Count -gt 0)
{
    Write-Output ''
    Write-Output 'Detailed failure report:'
    foreach ($detail in $failedTargetDetails)
    {
        Write-Output $detail
        Write-Output ''
    }

    throw ('SharePoint publish failed for target(s): ' + ($failedTargets -join ', '))
}
