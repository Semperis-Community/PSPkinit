<#
.SYNOPSIS
Validates that scaffold files (global/ and local/) follow path conventions.

.DESCRIPTION
Ensures that global/ and local/ scaffold workflow files use correct final-state paths:
- global/ files use ./.github/ paths (not ./global/.github/)
- local/ files reference Semperis-Community/.github external repo
- No references to ./global/ from top-level .github/workflows/
- local wrapper reusable call `with:` mappings do not use `${{ env.* }}` context

This script should be run before committing scaffold changes.

.PARAMETER Verbose
Display detailed validation output for each file.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate-scaffold-compliance.ps1

Runs validation and reports any violations.

.NOTES
The script exits with code 1 if violations are found, 0 if all pass.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
Determines whether a repository-relative path should be ignored.
#>
function Test-IsIgnoredPath
{
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path))
    {
        return $false
    }

    $normalizedPath = $Path.Replace('\\', '/')

    # Explicit safeguard for deprecated content regardless of git state.
    if ($normalizedPath -like 'depr/*')
    {
        return $true
    }

    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $gitCommand)
    {
        return $false
    }

    & git check-ignore --quiet -- "$normalizedPath"
    return ($LASTEXITCODE -eq 0)
}

<#
.SYNOPSIS
Filters a file list to tracked or unignored paths.
#>
function Get-TrackedOrUnignoredFile
{
    param([System.IO.FileInfo[]]$Files)

    $filtered = @()
    foreach ($file in $Files)
    {
        $relativePath = $file.FullName.Substring((Get-Location).Path.Length).TrimStart('\', '/').Replace('\\', '/')
        if (-not (Test-IsIgnoredPath -Path $relativePath))
        {
            $filtered += $file
        }
    }

    return $filtered
}

<#
.SYNOPSIS
Builds a structured validation error record.
#>
function Write-ValidationError
{
    param(
        [string]$File,
        [int]$LineNumber,
        [string]$Message
    )

    if ($VerbosePreference -eq 'Continue')
    {
        #Write-Output "ERROR $File`:$LineNumber - $Message"
        Write-Verbose "ERROR $File`:$LineNumber - $Message"
    }

    return [pscustomobject]@{
        File = $File
        LineNumber = $LineNumber
        Message = $Message
    }
}

<#
.SYNOPSIS
Writes a verbose pass message for a validation check.
#>
function Write-ValidationPass
{
    param([string]$Message)

    if ($VerbosePreference -eq 'Continue')
    {
        Write-Verbose "PASS $Message"
    }
}

<#
.SYNOPSIS
Validates path conventions for files in the global scaffold tier.
#>
function Test-GlobalScaffoldFile
{
    param([System.IO.FileInfo]$File)

    $violations = @()
    $lines = Get-Content -Path $File.FullName
    $relativePath = $File.FullName.Substring((Get-Location).Path.Length).TrimStart('\', '/').Replace('\', '/')

    for ($i = 0; $i -lt $lines.Count; $i += 1)
    {
        $lineNumber = $i + 1
        $line = [string]$lines[$i]

        # Check for ./global/ references (should use ./.github/ instead)
        if ($line -like '*./global/.github*')
        {
            $violations += Write-ValidationError -File $relativePath -LineNumber $lineNumber `
                -Message "References './global/.github/' - should use './.github/'"
        }

        # Check for any ./global/ reference in uses clause
        if ($line -like '*uses:*./global/*' -and $line -notmatch '#')
        {
            $violations += Write-ValidationError -File $relativePath -LineNumber $lineNumber `
                -Message "Uses clause references './global/' - should use './.github/' path"
        }

        # Check for ./local references
        if (($line -like '*uses:*./local/*' -or $line -like '*run:*./local/*') -and $line -notmatch '#')
        {
            $violations += Write-ValidationError -File $relativePath -LineNumber $lineNumber `
                -Message "Global scaffold references './local/' - should not reference local tier"
        }
    }

    return $violations
}

<#
.SYNOPSIS
Validates path conventions for files in the local scaffold tier.
#>
function Test-LocalScaffoldFile
{
    param([System.IO.FileInfo]$File)

    $violations = @()
    $lines = Get-Content -Path $File.FullName
    $relativePath = $File.FullName.Substring((Get-Location).Path.Length).TrimStart('\', '/').Replace('\', '/')

    for ($i = 0; $i -lt $lines.Count; $i += 1)
    {
        $lineNumber = $i + 1
        $line = [string]$lines[$i]

        # Check for ./global/ references (local should use external refs)
        if ($line -like '*uses:*./global/*' -and $line -notmatch '#')
        {
            $violations += Write-ValidationError -File $relativePath -LineNumber $lineNumber `
                -Message "Local wrapper uses './global/' - should reference Semperis-Community/.github"
        }

        # Check for ./local references
        if ($line -like '*uses:*./local/*' -and $line -notmatch '#')
        {
            $violations += Write-ValidationError -File $relativePath -LineNumber $lineNumber `
                -Message "Local wrapper references './local/' - invalid path"
        }
    }

    # Check for invalid env context usage in reusable workflow call with-mappings.
    # In jobs.<id>.uses workflow-call context, GitHub does not allow ${{ env.* }} in with: mappings.
    $insideReusableCall = $false
    $insideWithBlock = $false
    $reusableCallIndent = -1
    $withIndent = -1

    for ($i = 0; $i -lt $lines.Count; $i += 1)
    {
        $lineNumber = $i + 1
        $line = [string]$lines[$i]
        $trimmed = $line.Trim()

        if ([string]::IsNullOrWhiteSpace($trimmed))
        {
            continue
        }

        if ($trimmed.StartsWith('#'))
        {
            continue
        }

        $leadingWhitespaceCount = 0
        while ($leadingWhitespaceCount -lt $line.Length -and [char]::IsWhiteSpace($line[$leadingWhitespaceCount]))
        {
            $leadingWhitespaceCount += 1
        }

        if ($insideWithBlock)
        {
            if ($leadingWhitespaceCount -le $withIndent)
            {
                $insideWithBlock = $false
            }
            elseif ($line -match '\$\{\{\s*env\.')
            {
                $violations += Write-ValidationError -File $relativePath -LineNumber $lineNumber `
                    -Message "Local wrapper reusable workflow call maps with: from env context. Use literals or allowed contexts (github, inputs, vars, needs, strategy, matrix)."
            }
        }

        if ($insideReusableCall -and $leadingWhitespaceCount -lt $reusableCallIndent)
        {
            $insideReusableCall = $false
            $insideWithBlock = $false
            $reusableCallIndent = -1
            $withIndent = -1
        }

        if (-not $insideReusableCall)
        {
            if ($line -match '^\s*uses:\s*(?<target>.+)$')
            {
                $target = ([string]$matches['target']).Trim()
                if ($target -match 'Semperis-Community/\.github/\.github/workflows/.+@' -or $target -match '^\./\.github/workflows/.+')
                {
                    $insideReusableCall = $true
                    $reusableCallIndent = $leadingWhitespaceCount
                }
            }
            continue
        }

        if ($insideReusableCall -and -not $insideWithBlock -and $line -match '^\s*with:\s*$' -and $leadingWhitespaceCount -gt $reusableCallIndent)
        {
            $insideWithBlock = $true
            $withIndent = $leadingWhitespaceCount
        }
    }

    return $violations
}

<#
.SYNOPSIS
Validates that top-level workflows do not reference scaffold paths.
#>
function Test-TopLevelWorkflow
{
    param([System.IO.FileInfo]$File)

    $violations = @()
    $lines = Get-Content -Path $File.FullName
    $relativePath = $File.FullName.Substring((Get-Location).Path.Length).TrimStart('\', '/').Replace('\', '/')

    for ($i = 0; $i -lt $lines.Count; $i += 1)
    {
        $lineNumber = $i + 1
        $line = [string]$lines[$i]

        # Top-level workflows should never reference global/ or local/
        if ($line -like '*uses:*./global/*' -and $line -notmatch '#')
        {
            $violations += Write-ValidationError -File $relativePath -LineNumber $lineNumber `
                -Message "Top-level workflow references './global/' - use standalone implementations"
        }

        if ($line -like '*uses:*./local/*' -and $line -notmatch '#')
        {
            $violations += Write-ValidationError -File $relativePath -LineNumber $lineNumber `
                -Message "Top-level workflow references './local/' - invalid path"
        }
    }

    return $violations
}

# Main validation

Write-Output "Validating scaffold compliance..."
$allViolations = @()

# Check global/ scaffold files
$globalWorkflows = @(Get-ChildItem -Path "global/.github/workflows" -File -Include *.yaml, *.yml -ErrorAction SilentlyContinue)
$globalWorkflows = @(Get-TrackedOrUnignoredFile -Files $globalWorkflows)
if ($globalWorkflows.Count -gt 0)
{
    Write-ValidationPass "Found $($globalWorkflows.Count) global scaffold workflow(s)"

    foreach ($file in $globalWorkflows)
    {
        $violations = Test-GlobalScaffoldFile -File $file
        if ($violations.Count -gt 0)
        {
            $allViolations += $violations
        }
        else
        {
            Write-ValidationPass "  $($file.Name) - path compliance OK"
        }
    }
}

# Check global/ actions
$globalActions = @(Get-ChildItem -Path "global/.github/actions" -File -Include action.yaml, action.yml -Recurse -ErrorAction SilentlyContinue)
$globalActions = @(Get-TrackedOrUnignoredFile -Files $globalActions)
if ($globalActions.Count -gt 0)
{
    Write-ValidationPass "Found $($globalActions.Count) global scaffold action(s)"

    foreach ($file in $globalActions)
    {
        $violations = Test-GlobalScaffoldFile -File $file
        if ($violations.Count -gt 0)
        {
            $allViolations += $violations
        }
        else
        {
            Write-ValidationPass "  $($file.Name) - path compliance OK"
        }
    }
}

# Check local/ scaffold files
$localWorkflows = @(Get-ChildItem -Path "local/.github/workflows" -File -Include *.yaml, *.yml -ErrorAction SilentlyContinue)
$localWorkflows = @(Get-TrackedOrUnignoredFile -Files $localWorkflows)
if ($localWorkflows.Count -gt 0)
{
    Write-ValidationPass "Found $($localWorkflows.Count) local scaffold workflow(s)"

    foreach ($file in $localWorkflows)
    {
        $violations = Test-LocalScaffoldFile -File $file
        if ($violations.Count -gt 0)
        {
            $allViolations += $violations
        }
        else
        {
            Write-ValidationPass "  $($file.Name) - path compliance OK"
        }
    }
}

# Check top-level workflows
$topLevelWorkflows = @(Get-ChildItem -Path ".github/workflows" -File -Include *.yaml, *.yml -ErrorAction SilentlyContinue)
$topLevelWorkflows = @(Get-TrackedOrUnignoredFile -Files $topLevelWorkflows)
if ($topLevelWorkflows.Count -gt 0)
{
    Write-ValidationPass "Found $($topLevelWorkflows.Count) top-level workflow(s)"

    foreach ($file in $topLevelWorkflows)
    {
        $violations = Test-TopLevelWorkflow -File $file
        if ($violations.Count -gt 0)
        {
            $allViolations += $violations
        }
        else
        {
            Write-ValidationPass "  $($file.Name) - scaffold reference OK"
        }
    }
}

# Summary and exit

Write-Output ""

if ($allViolations.Count -eq 0)
{
    Write-Output "PASS All scaffold files passed compliance validation."
    exit 0
}
else
{
    Write-Output "ERROR Found $($allViolations.Count) scaffold compliance violation(s):"
    Write-Output ""

    foreach ($violation in $allViolations)
    {
        Write-Output "  $($violation.File):$($violation.LineNumber)"
        Write-Output "    $($violation.Message)"
    }

    Write-Output ""
    Write-Output "Fix the violations above and re-run this script."
    exit 1
}
