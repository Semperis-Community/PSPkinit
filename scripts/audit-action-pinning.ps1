<#
.SYNOPSIS
Validates GitHub Actions uses references against repository pinning policy.

.DESCRIPTION
Scans workflow files under .github/workflows and local action definition files under
.github/actions for uses references, then enforces policy rules from the policy YAML file.

The audit blocks floating refs, wildcard refs, and non-tag/non-SHA refs for external actions,
and enforces minimum major versions for configured actions.

.PARAMETER PolicyFile
Path to the action version policy YAML file. Defaults to pipeline-config/ref/action-version-policy.yaml.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\audit-action-pinning.ps1

Runs the audit using the default policy file.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\audit-action-pinning.ps1 -PolicyFile .\pipeline-config\ref\action-version-policy.yaml

Runs the audit using an explicit policy file path.

.NOTES
The script emits GitHub annotation errors for violations when run in GitHub Actions.
#>

[CmdletBinding()]
param(
    [string]$PolicyFile = "pipeline-config/ref/action-version-policy.yaml"
)

$ErrorActionPreference = "Stop"

function Test-MatchAny
{
    <#
    .SYNOPSIS
    Tests whether a string matches any pattern in a list.

    .DESCRIPTION
    Evaluates a string against a collection of wildcard patterns and returns $true when
    the value matches any non-empty pattern. Empty or whitespace-only patterns are ignored.

    .PARAMETER Value
    The string value to test.

    .PARAMETER Patterns
    One or more wildcard patterns to compare against the value.

    .OUTPUTS
    System.Boolean

    .EXAMPLE
    Test-MatchAny -Value 'docs/user-guide.md' -Patterns @('docs/*.md', 'README.md')

    Returns $true because the value matches one of the supplied patterns.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [string[]]$Patterns
    )

    foreach ($pattern in $Patterns)
    {
        if ([string]::IsNullOrWhiteSpace($pattern))
        {
            continue
        }

        if ($Value -like $pattern)
        {
            return $true
        }
    }

    return $false
}

function Write-Annotation
{
    <#
    .SYNOPSIS
    Writes a GitHub Actions error annotation.

    .DESCRIPTION
    Formats an error message for GitHub Actions annotation output and escapes reserved
    characters so the annotation renders correctly in workflow logs.

    .PARAMETER File
    The repository-relative file path associated with the annotation.

    .PARAMETER Line
    The 1-based line number associated with the annotation.

    .PARAMETER Message
    The error message to emit.

    .EXAMPLE
    Write-Annotation -File 'docs/user-guide.md' -Line 12 -Message 'Example validation failure.'

    Writes a GitHub Actions error annotation for the specified file and line.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$File,
        [Parameter(Mandatory = $true)]
        [int]$Line,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $safeMessage = $Message -replace '%', '%25' -replace "`r", '%0D' -replace "`n", '%0A'
    Write-Output "::error file=$File,line=$Line::[action-version-audit] $safeMessage"
}

$repoRootPath = (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath "..")).Path
Push-Location -Path $repoRootPath

try
{
    if (-not (Test-Path -Path $PolicyFile))
    {
        throw "Policy file '$PolicyFile' does not exist."
    }

    if (-not (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue))
    {
        if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue))
        {
            Register-PSRepository -Default -ErrorAction Stop
        }

        Install-Module -Name powershell-yaml -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module powershell-yaml -ErrorAction Stop
    }

    $policy = Get-Content -Path $PolicyFile -Raw | ConvertFrom-Yaml -ErrorAction Stop

    $blockedRefs = @($policy.blockedRefs)
    $allowlistPrefixes = @($policy.allowlistPrefixes)
    $ignorePathGlobs = @($policy.ignorePathGlobs)

    $minMajorVersions = @{}
    if ($null -ne $policy.minMajorVersions)
    {
        if ($policy.minMajorVersions -is [hashtable])
        {
            foreach ($key in $policy.minMajorVersions.Keys)
            {
                $minMajorVersions[[string]$key.ToLowerInvariant()] = [int]$policy.minMajorVersions[$key]
            }
        }
        else
        {
            foreach ($entry in $policy.minMajorVersions.PSObject.Properties)
            {
                $minMajorVersions[$entry.Name.ToLowerInvariant()] = [int]$entry.Value
            }
        }
    }

    $workflowFiles = @(Get-ChildItem -Path ".github/workflows" -File -Recurse -Include *.yml, *.yaml -ErrorAction SilentlyContinue)

    $actionDefinitionFiles = @()
    if (Test-Path -Path ".github/actions")
    {
        $actionDefinitionFiles = @(
            Get-ChildItem -Path ".github/actions" -File -Recurse -Include action.yml, action.yaml -ErrorAction SilentlyContinue
        )
    }

    $filesToScan = @($workflowFiles + $actionDefinitionFiles | Sort-Object -Property FullName -Unique)
    if ($filesToScan.Count -eq 0)
    {
        Write-Output "No workflow or local action definition files found to scan."
        exit 0
    }

    $violations = New-Object System.Collections.Generic.List[string]

    foreach ($file in $filesToScan)
    {
        $relativePath = $file.FullName.Substring($repoRootPath.Length).TrimStart('\', '/').Replace('\', '/')

        if ($ignorePathGlobs.Count -gt 0 -and (Test-MatchAny -Value $relativePath -Patterns $ignorePathGlobs))
        {
            continue
        }

        $lines = Get-Content -Path $file.FullName
        for ($lineIndex = 0; $lineIndex -lt $lines.Count; $lineIndex += 1)
        {
            $lineNumber = $lineIndex + 1
            $line = [string]$lines[$lineIndex]

            if ($line -notmatch '^\s*uses\s*:\s*(?<value>.+?)\s*(#.*)?$')
            {
                continue
            }

            $usesValue = $Matches.value.Trim()
            $doubleQuote = [string][char]34
            $singleQuote = [string][char]39
            if (
                ($usesValue.StartsWith($doubleQuote) -and $usesValue.EndsWith($doubleQuote)) -or
                ($usesValue.StartsWith($singleQuote) -and $usesValue.EndsWith($singleQuote))
            )
            {
                $usesValue = $usesValue.Substring(1, $usesValue.Length - 2)
            }

            if ($usesValue -like 'docker://*')
            {
                continue
            }

            $isLocalAction = $usesValue.StartsWith('./')
            if ($isLocalAction)
            {
                $isAllowlisted = $false
                foreach ($prefix in $allowlistPrefixes)
                {
                    if ($usesValue.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase))
                    {
                        $isAllowlisted = $true
                        break
                    }
                }

                if (-not $isAllowlisted)
                {
                    $message = "Local action '$usesValue' is not allowlisted."
                    Write-Annotation -File $relativePath -Line $lineNumber -Message $message
                    [void]$violations.Add(('{0}:{1} {2}' -f $relativePath, $lineNumber, $message))
                }

                continue
            }

            $lastAt = $usesValue.LastIndexOf('@')
            if ($lastAt -lt 1 -or $lastAt -ge ($usesValue.Length - 1))
            {
                $message = "External action '$usesValue' must include an explicit @ref pin."
                Write-Annotation -File $relativePath -Line $lineNumber -Message $message
                [void]$violations.Add(('{0}:{1} {2}' -f $relativePath, $lineNumber, $message))
                continue
            }

            $actionName = $usesValue.Substring(0, $lastAt)
            $refName = $usesValue.Substring($lastAt + 1)

            if ($refName.Contains('*'))
            {
                $message = "Action '$actionName' uses wildcard ref '$refName', which is not allowed."
                Write-Annotation -File $relativePath -Line $lineNumber -Message $message
                [void]$violations.Add(('{0}:{1} {2}' -f $relativePath, $lineNumber, $message))
                continue
            }

            if ($blockedRefs -contains $refName)
            {
                $message = "Action '$actionName' uses blocked ref '$refName'."
                Write-Annotation -File $relativePath -Line $lineNumber -Message $message
                [void]$violations.Add(('{0}:{1} {2}' -f $relativePath, $lineNumber, $message))
                continue
            }

            $isShaPin = $refName -match '^[0-9a-fA-F]{40}$'
            $isTagPin = $refName -match '^v?\d+(\.\d+){0,2}([-.][0-9A-Za-z.-]+)?$'

            if (-not $isShaPin -and -not $isTagPin)
            {
                $message = "Action '$actionName' uses non-tag/non-SHA ref '$refName'. Use a version tag or commit SHA."
                Write-Annotation -File $relativePath -Line $lineNumber -Message $message
                [void]$violations.Add(('{0}:{1} {2}' -f $relativePath, $lineNumber, $message))
                continue
            }

            $normalizedAction = $actionName.ToLowerInvariant()
            if ($minMajorVersions.ContainsKey($normalizedAction) -and -not $isShaPin)
            {
                $requiredMajor = [int]$minMajorVersions[$normalizedAction]

                if ($refName -match '^v?(?<major>\d+)')
                {
                    $actualMajor = [int]$Matches.major
                    if ($actualMajor -lt $requiredMajor)
                    {
                        $message = "Action '$actionName@$refName' is below required major v$requiredMajor."
                        Write-Annotation -File $relativePath -Line $lineNumber -Message $message
                        [void]$violations.Add(('{0}:{1} {2}' -f $relativePath, $lineNumber, $message))
                        continue
                    }
                }
            }
        }
    }

    if ($violations.Count -gt 0)
    {
        throw "Action version pinning audit found $($violations.Count) violation(s)."
    }

    Write-Output "Action version pinning audit passed for $($filesToScan.Count) file(s)."
    exit 0
}
finally
{
    Pop-Location
}


