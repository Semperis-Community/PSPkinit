<#PSScriptInfo
.VERSION 1.1.0
.GUID 4a7f2e1c-83b6-4d9a-bc45-e1f730a2d867
.AUTHOR Semperis-Community
.COMPANYNAME Semperis
.TAGS sharepoint catalog github pipeline
.PROJECTURI https://github.com/Semperis-Community/pipeline-build
.RELEASENOTES
  1.0.0 - Initial release. Local dry-run equivalent of the Update SharePoint Catalog workflow build-catalog job.
  1.1.0 - Added catalog-page-body.html generation. Replaced Write-Host with Write-Verbose/Write-Warning.
#>

<#
.SYNOPSIS
Locally builds SharePoint catalog artifacts from organization repositories.

.DESCRIPTION
Enumerates all repositories in the configured GitHub organization using the gh CLI,
applies the same exclusion and filtering logic as the Update SharePoint Catalog workflow,
and writes the same five output artifacts to a local directory along with per-repository
README and release-notes exports under subfolders:

  catalog.json             - Full catalog data (one entry per repository)
  catalog.md               - Markdown table version of the catalog
  catalog-warnings.md      - Repositories with shepherd policy warnings
  catalog-metadata.json    - Build metadata and summary statistics
  catalog-page-body.html   - SharePoint page body HTML (preview of the catalog.aspx page)

This script is a local dry-run equivalent of both the build-catalog and publish-catalog
jobs. It does not publish to SharePoint but generates all artifacts including the HTML
page body that would be written to catalog.aspx.

Requires: gh CLI authenticated to the target organization, powershell-yaml module.

.PARAMETER OrgName
GitHub organization name to enumerate. Defaults to 'Semperis-Community'.

.PARAMETER RepoRoot
Repository root path used to resolve relative config and output paths.
Defaults to the current working directory.

.PARAMETER CatalogConfigFile
Path to the catalog exclusion config YAML file, relative to RepoRoot unless absolute.
Defaults to pipeline-config/ref/catalog-config.yaml.

.PARAMETER OutDir
Directory to write output artifacts into, relative to RepoRoot unless absolute.
Defaults to out/catalog-dryrun.

.EXAMPLE
./scripts/invoke-sharepoint-catalog-build.ps1

Builds catalog artifacts using defaults: Semperis-Community org, output to out/catalog-dryrun/.

.EXAMPLE
./scripts/invoke-sharepoint-catalog-build.ps1 -OutDir out/catalog-test

Writes output to out/catalog-test/ instead of the default directory.

.PARAMETER CatalogBaseUrl
Base URL used in the Raw Artifacts section of the generated page body HTML.
Defaults to a placeholder; set this to your SharePoint document library URL for accurate links.

.NOTES
Output artifacts are compatible with the publish-catalog job in the Update SharePoint Catalog
workflow. The catalog-metadata.json workflowRunUrl field will be empty for local runs.
The catalog-page-body.html file is a standalone HTML preview of what catalog.aspx will contain.
#>

[CmdletBinding()]
param(
    [string]$OrgName = 'Semperis-Community',
    [string]$RepoRoot = (Get-Location).Path,
    [string]$CatalogConfigFile = 'pipeline-config/ref/catalog-config.yaml',
    [string]$OutDir = 'out/catalog-dryrun',
    [string]$CatalogBaseUrl = 'https://your-sharepoint-site/Shared%20Documents/Catalog'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [System.IO.Path]::IsPathRooted($CatalogConfigFile))
{
    $CatalogConfigFile = Join-Path $RepoRoot $CatalogConfigFile
}
if (-not [System.IO.Path]::IsPathRooted($OutDir))
{
    $OutDir = Join-Path $RepoRoot $OutDir
}

if (-not (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue))
{
    Import-Module powershell-yaml -ErrorAction Stop
}

$org = $OrgName
$configPath = $CatalogConfigFile
$outDir = $OutDir
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$excludedByName = @{}
$excludedConfigured = @()
$suppressInlineWarnings = $false
if (Test-Path $configPath)
{
    $cfg = Get-Content -Path $configPath -Raw | ConvertFrom-Yaml -ErrorAction Stop
    if ($null -ne $cfg -and $null -ne $cfg.pageOptions)
    {
        $suppressInlineWarnings = [bool]$cfg.pageOptions.suppressInlineWarnings
    }
    foreach ($entry in @($cfg.excludedRepositories))
    {
        $n = [string]$entry.name
        if ([string]::IsNullOrWhiteSpace($n)) { continue }
        $r = [string]$entry.reason
        if ([string]::IsNullOrWhiteSpace($r)) { $r = 'other' }
        $k = $n.Trim().ToLowerInvariant()
        if (-not $excludedByName.ContainsKey($k))
        {
            $excludedByName[$k] = $r
            $excludedConfigured += [pscustomobject]@{ name = $n.Trim(); reason = $r }
        }
    }
}

Write-Verbose 'Enumerating organization repositories...'
$rawRepos = gh api orgs/$org/repos --paginate | ConvertFrom-Json
$repos = @($rawRepos)
$templateRepos = @($repos | Where-Object { $_.is_template })
$nonTemplate = @($repos | Where-Object { -not $_.is_template })
$forkRepos = @($nonTemplate | Where-Object { $_.fork })
$filtered = @($nonTemplate | Where-Object { -not $_.fork })
Write-Verbose "Enumerated $($repos.Count) repositories: $($filtered.Count) to process, $($templateRepos.Count) templates excluded, $($forkRepos.Count) forks excluded"

$included = New-Object System.Collections.Generic.List[object]
$excludedApplied = New-Object System.Collections.Generic.List[object]
foreach ($repo in $filtered)
{
    $name = [string]$repo.name
    $key = $name.Trim().ToLowerInvariant()
    if ($excludedByName.ContainsKey($key))
    {
        $excludedApplied.Add([pscustomobject]@{ name = $name; reason = [string]$excludedByName[$key] })
        continue
    }
    $included.Add($repo)
}

function ConvertTo-HtmlEncoded
{
    <#
    .SYNOPSIS
    HTML-encodes a string for safe embedding in page body markup.
    .PARAMETER Value
    The string to encode. Returns an empty string when null.
    #>
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-UrlEncodedRelativePath
{
    param([string]$RelativePath)
    if ([string]::IsNullOrWhiteSpace($RelativePath)) { return '' }
    return (([string]$RelativePath -split '/') | ForEach-Object { [System.Uri]::EscapeDataString($_) }) -join '/'
}

function Get-Stage
{
    <#
    .SYNOPSIS
    Derives a release stage label from a release tag string.
    .PARAMETER Tag
    The release tag (e.g. v1.0.0-beta.1). Returns null when blank.
    #>
    param([string]$Tag)
    if ([string]::IsNullOrWhiteSpace($Tag)) { return $null }
    if ($Tag -match '-alpha(\.|$)') { return 'alpha' }
    if ($Tag -match '-beta(\.|$)') { return 'beta' }
    if ($Tag -match '-rc(\.|$)') { return 'rc' }
    return 'production'
}

function Get-RepositoryReadmeMarkdown
{
    param(
        [Parameter(Mandatory = $true)][string]$Owner,
        [Parameter(Mandatory = $true)][string]$RepositoryName
    )

    try
    {
        $readmeJson = gh api repos/$Owner/$RepositoryName/readme 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($readmeJson))
        {
            return $null
        }

        $readme = $readmeJson | ConvertFrom-Json
        if ($null -eq $readme -or [string]::IsNullOrWhiteSpace([string]$readme.name))
        {
            return $null
        }

        if ([string]$readme.name -notmatch '(?i)^readme\.md$')
        {
            return $null
        }

        if ([string]::IsNullOrWhiteSpace([string]$readme.content))
        {
            return $null
        }

        return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(([string]$readme.content).Replace("`n", '')))
    }
    catch
    {
        return $null
    }
}

$items = New-Object System.Collections.Generic.List[object]
$warnings = New-Object System.Collections.Generic.List[string]
$repoTotal = $included.Count
Write-Verbose "Building catalog entries for $repoTotal repositories..."
$repoIndex = 0
foreach ($repo in $included)
{
    $repoIndex++
    $name = [string]$repo.name
    Write-Verbose "  [$repoIndex/$repoTotal] $name"

    $latest = $null
    try
    {
        $latestJson = gh api repos/$org/$name/releases/latest 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($latestJson))
        {
            $latest = $latestJson | ConvertFrom-Json
        }
    }
    catch
    {
        $latest = $null
    }

    $hasPipeline = $false
    try
    {
        $null = gh api repos/$org/$name/contents/pipeline-config/ref/pipeline.yaml 2>$null
        if ($LASTEXITCODE -eq 0) { $hasPipeline = $true }
    }
    catch { $hasPipeline = $false }

    $shepherds = @()
    try
    {
        $cat = gh api repos/$org/$name/contents/.github/catalog.yaml 2>$null | ConvertFrom-Json
        if ($null -ne $cat -and -not [string]::IsNullOrWhiteSpace([string]$cat.content))
        {
            $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(([string]$cat.content).Replace("`n", '')))
            $parsed = $decoded | ConvertFrom-Yaml -ErrorAction Stop
            if ($null -ne $parsed -and $null -ne $parsed.shepherds)
            {
                $resolvedShepherds = New-Object System.Collections.Generic.List[string]
                foreach ($entry in @($parsed.shepherds))
                {
                    if ($entry -is [string])
                    {
                        $value = ([string]$entry).Trim()
                        if (-not [string]::IsNullOrWhiteSpace($value))
                        {
                            $resolvedShepherds.Add($value)
                        }
                        continue
                    }

                    $github = [string]$entry.github
                    if ([string]::IsNullOrWhiteSpace($github)) { $github = [string]$entry.username }
                    if ([string]::IsNullOrWhiteSpace($github)) { $github = [string]$entry.githubUsername }

                    $fullName = [string]$entry.name
                    if ([string]::IsNullOrWhiteSpace($fullName)) { $fullName = [string]$entry.fullName }

                    $github = $github.Trim()
                    $fullName = $fullName.Trim()

                    if (-not [string]::IsNullOrWhiteSpace($fullName) -and -not [string]::IsNullOrWhiteSpace($github))
                    {
                        $resolvedShepherds.Add("$fullName (@$github)")
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($fullName))
                    {
                        $resolvedShepherds.Add($fullName)
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($github))
                    {
                        $resolvedShepherds.Add("@$github")
                    }
                }

                $shepherds = @($resolvedShepherds)
            }
        }
    }
    catch
    {
        $shepherds = @()
    }

    $warn = $shepherds.Count -lt 2
    if ($warn)
    {
        $warningMessage = "Repository '$name' has fewer than two shepherds defined in .github/catalog.yaml."
        $warnings.Add($warningMessage)
        Write-Warning $warningMessage
    }

    $releaseNotesCatalogRelativePath = $null
    if ($null -ne $latest)
    {
        $repoArtifactDir = Join-Path $outDir $name
        New-Item -ItemType Directory -Force -Path $repoArtifactDir | Out-Null

        $releaseNotesPath = Join-Path $repoArtifactDir 'RELEASE-NOTES.md'
        $releaseBody = [string]$latest.body
        if ([string]::IsNullOrWhiteSpace($releaseBody))
        {
            $releaseBody = '_No release notes body provided in the latest GitHub release._'
        }

        $releaseLines = New-Object System.Collections.Generic.List[string]
        $releaseLines.Add('# Release Notes')
        $releaseLines.Add('')
        $releaseLines.Add("Repository: $name")
        $releaseLines.Add("Tag: $([string]$latest.tag_name)")
        $releaseLines.Add("Published: $([string]$latest.published_at)")
        $releaseLines.Add("Source: $([string]$latest.html_url)")
        $releaseLines.Add('')
        $releaseLines.Add($releaseBody)
        $releaseLines | Out-File -FilePath $releaseNotesPath -Encoding utf8
        $releaseNotesCatalogRelativePath = "$name/RELEASE-NOTES.md"
    }

    $readmeCatalogRelativePath = $null
    $readmeContent = Get-RepositoryReadmeMarkdown -Owner $org -RepositoryName $name
    if (-not [string]::IsNullOrWhiteSpace($readmeContent))
    {
        $repoArtifactDir = Join-Path $outDir $name
        New-Item -ItemType Directory -Force -Path $repoArtifactDir | Out-Null
        $readmePath = Join-Path $repoArtifactDir 'README.md'
        $readmeContent | Out-File -FilePath $readmePath -Encoding utf8
        $readmeCatalogRelativePath = "$name/README.md"
    }

    $items.Add([pscustomobject]@{
            repositoryName = $name
            description = [string]$repo.description
            url = [string]$repo.html_url
            visibility = [string]$repo.visibility
            isArchived = [bool]$repo.archived
            isFork = [bool]$repo.fork
            isTemplate = [bool]$repo.is_template
            primaryLanguage = [string]$repo.language
            topics = @($repo.topics)
            openIssuesCount = [int]$repo.open_issues_count
            defaultBranch = [string]$repo.default_branch
            latestReleaseTag = if ($null -ne $latest) { [string]$latest.tag_name } else { $null }
            latestReleaseDate = if ($null -ne $latest) { [string]$latest.published_at } else { $null }
            latestReleaseUrl = if ($null -ne $latest) { [string]$latest.html_url } else { $null }
            releaseNotesCatalogRelativePath = $releaseNotesCatalogRelativePath
            releaseStage = if ($null -ne $latest) { Get-Stage ([string]$latest.tag_name) } else { $null }
            hasPipelineConfig = [bool]$hasPipeline
            shepherds = $shepherds
            shepherdPolicyWarning = [bool]$warn
            readmeCatalogRelativePath = $readmeCatalogRelativePath
            lastPushedAt = [string]$repo.pushed_at
            lastUpdatedAt = [string]$repo.updated_at
        })
}

$items = @($items | Sort-Object repositoryName)
$generatedAt = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'", [System.Globalization.CultureInfo]::InvariantCulture)

Write-Verbose 'Writing output files...'
$items | ConvertTo-Json -Depth 12 | Out-File -FilePath (Join-Path $outDir 'catalog.json') -Encoding utf8

$md = New-Object System.Collections.Generic.List[string]
$activeItems = @($items | Where-Object { -not [bool]$_.isArchived })
$archivedItems = @($items | Where-Object { [bool]$_.isArchived })
$md.Add('# Community Solutions Catalog')
$md.Add('')
$md.Add("Generated (UTC): $generatedAt")
$md.Add('')
$md.Add('| Repository | Description | Latest Release | Release Notes | Language | Shepherds | README |')
$md.Add('|---|---|---|---|---|---|---|')
foreach ($it in $activeItems)
{
    $repoLink = "[$($it.repositoryName)]($($it.url))"
    $description = if ([string]::IsNullOrWhiteSpace([string]$it.description))
    {
        'n/a'
    }
    else
    {
        ([string]$it.description).Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ')
    }
    $tag = if ([string]::IsNullOrWhiteSpace([string]$it.latestReleaseTag)) { 'none' } else { [string]$it.latestReleaseTag }
    $releaseNotesLink = if ([string]::IsNullOrWhiteSpace([string]$it.releaseNotesCatalogRelativePath)) { 'n/a' } else { "[Notes](./$(Get-UrlEncodedRelativePath -RelativePath ([string]$it.releaseNotesCatalogRelativePath))?web=1)" }
    $lang = if ([string]::IsNullOrWhiteSpace([string]$it.primaryLanguage)) { 'n/a' } else { [string]$it.primaryLanguage }
    $shep = if ($it.shepherds.Count -gt 0) { ($it.shepherds -join ', ') } else { 'missing' }
    $readmeLink = if ([string]::IsNullOrWhiteSpace([string]$it.readmeCatalogRelativePath)) { 'n/a' } else { "[README](./$(Get-UrlEncodedRelativePath -RelativePath ([string]$it.readmeCatalogRelativePath))?web=1)" }
    $md.Add("| $repoLink | $description | $tag | $releaseNotesLink | $lang | $shep | $readmeLink |")
}

$md.Add('')
$md.Add('## Archived Repositories')
$md.Add('')
if ($archivedItems.Count -eq 0)
{
    $md.Add('_No archived repositories at time of generation._')
}
else
{
    $md.Add('| Repository | Description | Latest Release | Release Notes | Language | Shepherds | README |')
    $md.Add('|---|---|---|---|---|---|---|')
    foreach ($it in $archivedItems)
    {
        $repoLink = "[$($it.repositoryName)]($($it.url))"
        $description = if ([string]::IsNullOrWhiteSpace([string]$it.description))
        {
            'n/a'
        }
        else
        {
            ([string]$it.description).Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ')
        }
        $tag = if ([string]::IsNullOrWhiteSpace([string]$it.latestReleaseTag)) { 'none' } else { [string]$it.latestReleaseTag }
        $releaseNotesLink = if ([string]::IsNullOrWhiteSpace([string]$it.releaseNotesCatalogRelativePath)) { 'n/a' } else { "[Notes](./$(Get-UrlEncodedRelativePath -RelativePath ([string]$it.releaseNotesCatalogRelativePath))?web=1)" }
        $lang = if ([string]::IsNullOrWhiteSpace([string]$it.primaryLanguage)) { 'n/a' } else { [string]$it.primaryLanguage }
        $shep = if ($it.shepherds.Count -gt 0) { ($it.shepherds -join ', ') } else { 'missing' }
        $readmeLink = if ([string]::IsNullOrWhiteSpace([string]$it.readmeCatalogRelativePath)) { 'n/a' } else { "[README](./$(Get-UrlEncodedRelativePath -RelativePath ([string]$it.readmeCatalogRelativePath))?web=1)" }
        $md.Add("| $repoLink | $description | $tag | $releaseNotesLink | $lang | $shep | $readmeLink |")
    }
}
$md | Out-File -FilePath (Join-Path $outDir 'catalog.md') -Encoding utf8

$warningLines = New-Object System.Collections.Generic.List[string]
$warningLines.Add('# Catalog Warnings')
$warningLines.Add('')
$warningLines.Add("Generated (UTC): $generatedAt")
$warningLines.Add('')
if ($warnings.Count -gt 0)
{
    foreach ($w in $warnings) { $warningLines.Add("- $w") }
}
else
{
    $warningLines.Add('- No warnings.')
}
$warningLines | Out-File -FilePath (Join-Path $outDir 'catalog-warnings.md') -Encoding utf8

$totalRepositories = @($repos).Count
$filteredRepositories = @($filtered).Count
$publishedRepositories = @($items).Count
$templateExcluded = @($templateRepos).Count
$forkExcluded = @($forkRepos).Count

$configuredExclusionEntries = @($excludedConfigured | ForEach-Object {
        [pscustomobject]@{
            name = [string]$_.name
            reason = [string]$_.reason
        }
    })

$appliedExclusionEntries = @($excludedApplied | ForEach-Object {
        [pscustomobject]@{
            name = [string]$_.name
            reason = [string]$_.reason
        }
    })

$warningEntries = @($warnings | ForEach-Object { [string]$_ })

$catalogMetadata = [pscustomobject]@{
    generatedAtUtc = $generatedAt
    generatedByWorkflow = 'Local Dry Run'
    workflowRunId = 'local-dry-run'
    workflowRunNumber = 'local-dry-run'
    workflowRunAttempt = '1'
    workflowRunUrl = ''
    organization = $org
    totalRepositoriesEnumerated = $totalRepositories
    repositoriesAfterTemplateAndForkFilter = $filteredRepositories
    repositoriesPublished = $publishedRepositories
    templateRepositoriesExcluded = $templateExcluded
    forkRepositoriesExcluded = $forkExcluded
    exclusionsConfigured = $configuredExclusionEntries
    exclusionsApplied = $appliedExclusionEntries
    repoFilter = [pscustomobject]@{
        includeArchived = $true
        includeForks = $false
        includeTemplates = $false
    }
    shepherdPolicyWarnings = $warningEntries
    suppressInlineWarnings = [bool]$suppressInlineWarnings
}

$catalogMetadata | ConvertTo-Json -Depth 12 | Out-File -FilePath (Join-Path $outDir 'catalog-metadata.json') -Encoding utf8

Write-Verbose 'Building SharePoint page body...'
$activeTableRows = New-Object System.Text.StringBuilder
$archivedTableRows = New-Object System.Text.StringBuilder
foreach ($item in $items)
{
    $repoName = ConvertTo-HtmlEncoded -Value ([string]$item.repositoryName)
    $repoUrl = ConvertTo-HtmlEncoded -Value ([string]$item.url)
    $description = if ([string]::IsNullOrWhiteSpace([string]$item.description)) { 'n/a' } else { ConvertTo-HtmlEncoded -Value ([string]$item.description) }
    $latestTag = if ([string]::IsNullOrWhiteSpace([string]$item.latestReleaseTag)) { 'none' } else { ConvertTo-HtmlEncoded -Value ([string]$item.latestReleaseTag) }
    $releaseNotesCatalogRelativePath = [string]$item.releaseNotesCatalogRelativePath
    $language = if ([string]::IsNullOrWhiteSpace([string]$item.primaryLanguage)) { 'n/a' } else { ConvertTo-HtmlEncoded -Value ([string]$item.primaryLanguage) }
    $shepherdList = if ($null -ne $item.shepherds -and @($item.shepherds).Count -gt 0)
    {
        ConvertTo-HtmlEncoded -Value ((@($item.shepherds | ForEach-Object { [string]$_ }) -join ', '))
    }
    else
    {
        'missing'
    }

    $releaseNotesLink = if ([string]::IsNullOrWhiteSpace($releaseNotesCatalogRelativePath))
    {
        'n/a'
    }
    else
    {
        $releaseNotesRelativePath = Get-UrlEncodedRelativePath -RelativePath $releaseNotesCatalogRelativePath
        "<a href='$(ConvertTo-HtmlEncoded -Value $CatalogBaseUrl)/$($releaseNotesRelativePath)?web=1'>Notes</a>"
    }

    $readmeLink = if ([string]::IsNullOrWhiteSpace([string]$item.readmeCatalogRelativePath))
    {
        'n/a'
    }
    else
    {
        $readmeRelativePath = Get-UrlEncodedRelativePath -RelativePath ([string]$item.readmeCatalogRelativePath)
        "<a href='$(ConvertTo-HtmlEncoded -Value $CatalogBaseUrl)/$($readmeRelativePath)?web=1'>README</a>"
    }

    $rowHtml = "<tr><td><a href='$repoUrl'>$repoName</a></td><td>$description</td><td>$latestTag</td><td>$releaseNotesLink</td><td>$language</td><td>$shepherdList</td><td>$readmeLink</td></tr>"
    if ([bool]$item.isArchived)
    {
        $null = $archivedTableRows.AppendLine($rowHtml)
    }
    else
    {
        $null = $activeTableRows.AppendLine($rowHtml)
    }
}

$archivedCount = @($items | Where-Object { [bool]$_.isArchived }).Count
$archivedSection = if ($archivedCount -gt 0)
{
    @(
        '  <h2>Archived Repositories</h2>'
        "  <table style='border-collapse:collapse;width:100%;'>"
        '    <thead>'
        '      <tr>'
        "        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Repository</th>"
        "        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Description</th>"
        "        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Latest Release</th>"
        "        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Release Notes</th>"
        "        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Language</th>"
        "        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Shepherds</th>"
        "        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>README</th>"
        '      </tr>'
        '    </thead>'
        '    <tbody>'
        "      $($archivedTableRows.ToString())"
        '    </tbody>'
        '  </table>'
    ) -join "`n"
}
else
{
    "<h2>Archived Repositories</h2>`n  <p><em>No archived repositories at time of generation.</em></p>"
}

$warningsSection = ''
if (-not $suppressInlineWarnings -and $warnings.Count -gt 0)
{
    $warningItems = New-Object System.Text.StringBuilder
    foreach ($w in $warnings)
    {
        $null = $warningItems.AppendLine("<li>$(ConvertTo-HtmlEncoded -Value $w)</li>")
    }
    $warningsSection = "<h2>Warnings</h2>`n  <ul>`n    $($warningItems.ToString())`n  </ul>"
}

$pageBody = @"
<div>
    <h1>Community Solutions Catalog</h1>
  <p><strong>Generated (UTC):</strong> $generatedAt</p>
  <h2>Summary</h2>
  <ul>
    <li>Total repositories enumerated: $($catalogMetadata.totalRepositoriesEnumerated)</li>
    <li>After template/fork filter: $($catalogMetadata.repositoriesAfterTemplateAndForkFilter)</li>
    <li>Published repositories: $($catalogMetadata.repositoriesPublished)</li>
    <li>Template repositories excluded: $($catalogMetadata.templateRepositoriesExcluded)</li>
    <li>Fork repositories excluded: $($catalogMetadata.forkRepositoriesExcluded)</li>
    <li>Exclusions applied: $(@($catalogMetadata.exclusionsApplied).Count)</li>
    <li>Warning count: $($warnings.Count) (see catalog-warnings.md)</li>
  </ul>
  $warningsSection
    <div style='height:12px;'></div>
    <hr style='border:0;border-top:1px solid #d0d7de;margin:0 0 14px 0;' />
  <table style='border-collapse:collapse;width:100%;'>
    <thead>
      <tr>
        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Repository</th>
        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Description</th>
        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Latest Release</th>
        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Release Notes</th>
        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Language</th>
        <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>Shepherds</th>
                <th style='text-align:left;border:1px solid #d0d7de;padding:6px;'>README</th>
      </tr>
    </thead>
    <tbody>
            $($activeTableRows.ToString())
    </tbody>
  </table>
    $archivedSection
  <h2>Raw Artifacts</h2>
  <ul>
    <li><a href='$CatalogBaseUrl/catalog.json'>catalog.json</a></li>
    <li><a href='$CatalogBaseUrl/catalog.md'>catalog.md</a></li>
    <li><a href='$CatalogBaseUrl/catalog-warnings.md'>catalog-warnings.md</a></li>
    <li><a href='$CatalogBaseUrl/catalog-metadata.json'>catalog-metadata.json</a></li>
  </ul>
</div>
"@

$pageBody | Out-File -FilePath (Join-Path $outDir 'catalog-page-body.html') -Encoding utf8

Write-Verbose "Output written to: $outDir"
Write-Verbose "  Total repos: $($repos.Count)"
Write-Verbose "  After template+fork filter: $($filtered.Count)"
Write-Verbose "  Published repos: $($items.Count)"
Write-Verbose "  Template excluded: $($templateRepos.Count)"
Write-Verbose "  Fork excluded: $($forkRepos.Count)"
Write-Verbose "  Exclusions configured: $($excludedConfigured.Count)"
Write-Verbose "  Exclusions applied: $($excludedApplied.Count)"
Write-Verbose "  Shepherd warnings: $($warnings.Count)"
Write-Verbose "  README exports: $(@($items | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.readmeCatalogRelativePath) }).Count)"
Write-Verbose "  Files: catalog.json, catalog.md, catalog-warnings.md, catalog-metadata.json, catalog-page-body.html"