<#
.SYNOPSIS
Runs local preflight checks that mirror pipeline PowerShell lint and spell gates.

.DESCRIPTION
Validates the repository using the same core checks used by CI:
- PowerShell help validation
- PowerShell formatting rules (PSScriptAnalyzer)
- PowerShell error lint (PSScriptAnalyzer)
- cspell spell checking

Use this script locally before pushing changes to reduce CI failures.

.PARAMETER RepoRoot
Path to the repository root. Defaults to the current directory.

.PARAMETER SpellScope
Controls cspell input scope.
`pipeline` mirrors the workflow spell-check scope.
`powershell` limits spell-checking to PowerShell files only.

.PARAMETER InstallMissingPowerShellTools
Installs PSScriptAnalyzer from PSGallery when it is missing.

.PARAMETER InstallMissingNodeTools
Installs Node.js LTS when Node tooling required for cspell is missing.

.PARAMETER NodeInstallMethod
Preferred installation method when InstallMissingNodeTools is used.
Supported values: winget, choco.

.PARAMETER CspellPackageVersion
Version selector for cspell package execution. Defaults to latest.

.EXAMPLE
./scripts/validate-local-pipeline-checks.ps1

Runs all checks from the current directory using pipeline spell-check scope.

.EXAMPLE
./scripts/validate-local-pipeline-checks.ps1 -RepoRoot . -SpellScope powershell

Runs all checks with spell-check limited to PowerShell source files.

.EXAMPLE
./scripts/validate-local-pipeline-checks.ps1 -InstallMissingPowerShellTools

Installs PSScriptAnalyzer if needed, then runs all checks.

.EXAMPLE
./scripts/validate-local-pipeline-checks.ps1 -InstallMissingNodeTools -NodeInstallMethod winget

Installs Node.js LTS with winget if needed, then runs cspell checks.
#>

[CmdletBinding()]
param(
    [string]$RepoRoot = (Get-Location).Path,
    [ValidateSet('pipeline', 'powershell')]
    [string]$SpellScope = 'pipeline',
    [switch]$InstallMissingPowerShellTools,
    [switch]$InstallMissingNodeTools,
    [ValidateSet('winget', 'choco')]
    [string]$NodeInstallMethod = 'winget',
    [string]$CspellPackageVersion = 'latest'
)

$ErrorActionPreference = 'Stop'

# Explicit top-level references keep PSReviewUnusedParameter accurate for scriptblock-based usage later in the script.
$null = $InstallMissingNodeTools
$null = $NodeInstallMethod
$null = $CspellPackageVersion

$script:Warnings = New-Object System.Collections.Generic.List[string]
$script:ExcludedByDeprCount = 0

<#
.SYNOPSIS
Writes a standardized section header for local validation output.
#>
function Write-Section
{
    param([string]$Name)
    Write-Output ''
    Write-Output "==> $Name"
}

<#
.SYNOPSIS
Adds a warning message to output and the final summary.
#>
function Add-ValidationWarning
{
    param([string]$Message)

    Write-Warning $Message
    $script:Warnings.Add($Message) | Out-Null
}

<#
.SYNOPSIS
Provides remediation guidance for failed checks.
#>
function Get-RemediationHint
{
    param(
        [string]$CheckName,
        [string]$FailureMessage
    )

    $message = [string]$FailureMessage
    switch ($CheckName)
    {
        'PowerShell help validation'
        {
            return 'Add comment-based help with .SYNOPSIS to script and function scopes, then re-run the validator.'
        }
        'PowerShell formatting rules'
        {
            return 'Run Invoke-Formatter with ./.github/powershell-formatting.psd1 or fix reported rules manually.'
        }
        'PowerShell error lint rules'
        {
            return 'Resolve PSScriptAnalyzer error-severity findings shown above and re-run the validator.'
        }
        'cspell spell-check'
        {
            if ($message -match 'Node.js tooling is not available')
            {
                return "Run: ./scripts/validate-local-pipeline-checks.ps1 -InstallMissingNodeTools -NodeInstallMethod winget`nOr install Node.js LTS manually, open a new shell, and rerun this script."
            }

            if ($message -match 'Node.js installation completed but tooling is still unavailable')
            {
                return 'Open a new shell session so PATH refreshes, then rerun: ./scripts/validate-local-pipeline-checks.ps1'
            }

            return 'Fix reported spelling issues or add approved project-specific terms to .cspell.json, then rerun the validator.'
        }
        default
        {
            return 'Review the error details and rerun after applying the required fix.'
        }
    }
}

<#
.SYNOPSIS
Initializes Invoke-ScriptAnalyzer availability, optionally installing it.
#>
function Initialize-PSScriptAnalyzer
{
    param([switch]$InstallMissing)

    if (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)
    {
        return
    }

    if (-not $InstallMissing)
    {
        throw "Invoke-ScriptAnalyzer is not available. Install PSScriptAnalyzer or re-run with -InstallMissingPowerShellTools."
    }

    Write-Output 'PSScriptAnalyzer not found. Installing from PSGallery...'
    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue))
    {
        Register-PSRepository -Default -ErrorAction Stop
    }

    Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}

<#
.SYNOPSIS
Refreshes PATH for the current process from machine and user scopes.
#>
function Update-ProcessPathFromMachineAndUser
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $machinePath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')

    $combined = @($machinePath, $userPath) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if ($combined.Count -gt 0 -and $PSCmdlet.ShouldProcess('process PATH', 'Update from machine and user PATH values'))
    {
        $env:Path = ($combined -join ';')
    }
}

<#
.SYNOPSIS
Gets the first available command path from a candidate list.
#>
function Get-FirstAvailableCommandPath
{
    param([string[]]$Names)

    $command = Get-Command $Names -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Source

    if ([string]::IsNullOrWhiteSpace([string]$command))
    {
        return $null
    }

    return [string]$command
}

<#
.SYNOPSIS
Gets PowerShell source files that are tracked or not ignored by git.
#>
function Get-PowerShellSourceFile
{
    param([string]$RootPath)

    $script:ExcludedByDeprCount = 0

    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $gitCommand)
    {
        Write-Verbose 'git not found on PATH; falling back to filesystem enumeration for PowerShell files.'
        $fallbackFiles = New-Object System.Collections.Generic.List[string]
        $discoveredFiles = @(Get-ChildItem -Path $RootPath -Recurse -File -Include *.ps1, *.psm1, *.psd1 -ErrorAction SilentlyContinue)
        foreach ($discoveredFile in $discoveredFiles)
        {
            $relativePath = $discoveredFile.FullName.Substring($RootPath.Length).TrimStart('\\', '/').Replace('\\', '/')
            if ($relativePath -like 'depr/*')
            {
                $script:ExcludedByDeprCount += 1
                continue
            }

            $fallbackFiles.Add($discoveredFile.FullName) | Out-Null
        }

        return @($fallbackFiles | Sort-Object -Unique)
    }

    $patterns = @('*.ps1', '*.psm1', '*.psd1')
    $lsArgs = @('ls-files', '--cached', '--others', '--exclude-standard', '--') + $patterns
    $relativeFiles = @(& git @lsArgs)
    if ($LASTEXITCODE -ne 0)
    {
        throw 'Failed to enumerate tracked/unignored files via git ls-files.'
    }

    $resolvedFiles = @()
    foreach ($relativeFile in $relativeFiles)
    {
        if ([string]::IsNullOrWhiteSpace($relativeFile))
        {
            continue
        }

        if ($relativeFile.Replace('\\', '/') -like 'depr/*')
        {
            $script:ExcludedByDeprCount += 1
            continue
        }

        $fullPath = Join-Path -Path $RootPath -ChildPath $relativeFile
        if (Test-Path -Path $fullPath -PathType Leaf)
        {
            $resolvedFiles += (Resolve-Path -Path $fullPath).Path
        }
    }

    return @($resolvedFiles | Sort-Object -Unique)
}

<#
.SYNOPSIS
Ensures Node.js tooling is available, optionally installing Node.js LTS.
#>
function Initialize-NodeTooling
{
    param(
        [switch]$InstallMissing,
        [ValidateSet('winget', 'choco')]
        [string]$InstallMethod
    )

    $nodeCommand = Get-FirstAvailableCommandPath -Names @('node', 'node.exe')
    $npmCommand = Get-FirstAvailableCommandPath -Names @('npm', 'npm.cmd')
    $npxCommand = Get-FirstAvailableCommandPath -Names @('npx', 'npx.cmd')

    if ($null -ne $nodeCommand -and $null -ne $npmCommand -and $null -ne $npxCommand)
    {
        return [pscustomobject]@{
            NodeCommand = $nodeCommand
            NpmCommand = $npmCommand
            NpxCommand = $npxCommand
            InstalledNow = $false
        }
    }

    if (-not $InstallMissing)
    {
        throw 'Node.js tooling is not available (requires node, npm, and npx). Install Node.js LTS or rerun with -InstallMissingNodeTools.'
    }

    $selectedMethod = $InstallMethod
    if ($selectedMethod -eq 'winget' -and -not (Get-Command winget -ErrorAction SilentlyContinue))
    {
        if (Get-Command choco -ErrorAction SilentlyContinue)
        {
            Add-ValidationWarning -Message 'winget was requested but is unavailable; falling back to choco for Node.js installation.'
            $selectedMethod = 'choco'
        }
        else
        {
            throw "Node.js installation requested with -NodeInstallMethod winget, but winget is unavailable and no fallback installer is present."
        }
    }

    if ($selectedMethod -eq 'choco' -and -not (Get-Command choco -ErrorAction SilentlyContinue))
    {
        throw "Node.js installation requested with -NodeInstallMethod choco, but choco is unavailable."
    }

    #Write-Output "Node.js tooling not found. Installing Node.js LTS via $selectedMethod..."
    Write-Information "Node.js tooling not found. Installing Node.js LTS via $selectedMethod..." -InformationAction Continue
    if ($selectedMethod -eq 'winget')
    {
        & winget install --id OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -ne 0)
        {
            throw 'winget failed to install Node.js LTS.'
        }
    }
    else
    {
        & choco install nodejs-lts -y
        if ($LASTEXITCODE -ne 0)
        {
            throw 'choco failed to install nodejs-lts.'
        }
    }

    Update-ProcessPathFromMachineAndUser -Confirm:$false

    $nodeCommand = Get-FirstAvailableCommandPath -Names @('node', 'node.exe')
    $npmCommand = Get-FirstAvailableCommandPath -Names @('npm', 'npm.cmd')
    $npxCommand = Get-FirstAvailableCommandPath -Names @('npx', 'npx.cmd')

    if ($null -eq $nodeCommand -or $null -eq $npmCommand -or $null -eq $npxCommand)
    {
        throw 'Node.js installation completed but tooling is still unavailable in this session. Open a new shell and rerun the validator.'
    }

    #Write-Output 'Node.js LTS installation completed and tooling is available.'
    Write-Information 'Node.js LTS installation completed and tooling is available.' -InformationAction Continue
    return [pscustomobject]@{
        NodeCommand = $nodeCommand
        NpmCommand = $npmCommand
        NpxCommand = $npxCommand
        InstalledNow = $true
    }
}

<#
.SYNOPSIS
Runs cspell using npm exec or npx.
#>
function Invoke-CspellCommand
{
    param(
        [string]$NpmCommand,
        [string]$NpxCommand,
        [string[]]$CspellArgs,
        [string]$PackageVersion
    )

    $packageSpec = "cspell@$PackageVersion"

    if (-not [string]::IsNullOrWhiteSpace($NpmCommand))
    {
        & $NpmCommand exec --yes $packageSpec -- @CspellArgs
        return
    }

    & $NpxCommand --yes $packageSpec @CspellArgs
}

<#
.SYNOPSIS
Runs a single check and stores pass/fail status without stopping the full run.
#>
function Invoke-Check
{
    param(
        [string]$Name,
        [scriptblock]$Action,
        [ref]$Results
    )

    Write-Section -Name $Name
    try
    {
        & $Action
        Write-Output "PASS: $Name"
        $Results.Value.Add([pscustomobject]@{
                Name = $Name
                Passed = $true
                Message = 'OK'
                Hint = ''
            }) | Out-Null
    }
    catch
    {
        $failureMessage = $_.Exception.Message
        $hint = Get-RemediationHint -CheckName $Name -FailureMessage $failureMessage

        Write-Output "FAIL: $Name"
        Write-Output "Error: $failureMessage"
        Write-Output "Hint: $hint"

        $Results.Value.Add([pscustomobject]@{
                Name = $Name
                Passed = $false
                Message = $failureMessage
                Hint = $hint
            }) | Out-Null
    }
}

$resolvedRepoRoot = (Resolve-Path -Path $RepoRoot).Path
Set-Location -Path $resolvedRepoRoot

$helpValidator = Join-Path -Path $resolvedRepoRoot -ChildPath '.github/internal/scripts/Validate-PowerShellHelp.ps1'
$formatSettings = Join-Path -Path $resolvedRepoRoot -ChildPath '.github/powershell-formatting.psd1'
$cspellConfig = Join-Path -Path $resolvedRepoRoot -ChildPath '.cspell.json'

if (-not (Test-Path -Path $helpValidator))
{
    throw "Missing help validator script '$helpValidator'."
}

if (-not (Test-Path -Path $formatSettings))
{
    throw "Missing formatter settings file '$formatSettings'."
}

if (-not (Test-Path -Path $cspellConfig))
{
    throw "Missing cspell config file '$cspellConfig'."
}

if ($SpellScope -eq 'powershell')
{
    Add-ValidationWarning -Message "SpellScope is 'powershell'; CI default spelling scope is broader ('pipeline')."
}

Initialize-PSScriptAnalyzer -InstallMissing:$InstallMissingPowerShellTools

$powerShellSourceFiles = @(Get-PowerShellSourceFile -RootPath $resolvedRepoRoot)
if ($powerShellSourceFiles.Count -eq 0)
{
    throw 'No PowerShell source files found after applying git ignore rules.'
}

Write-Output "PowerShell source selection: $($powerShellSourceFiles.Count) file(s) analyzed; $($script:ExcludedByDeprCount) file(s) excluded by depr/ filter."

$results = New-Object System.Collections.Generic.List[object]

Invoke-Check -Name 'PowerShell help validation' -Results ([ref]$results) -Action {
    & $helpValidator -Root $resolvedRepoRoot
}

Invoke-Check -Name 'PowerShell formatting rules' -Results ([ref]$results) -Action {
    $formatRules = @(
        'PSUseConsistentIndentation'
        'PSPlaceOpenBrace'
        'PSPlaceCloseBrace'
        'PSUseConsistentWhitespace'
    )

    $formatFindings = @()
    foreach ($filePath in $powerShellSourceFiles)
    {
        $formatFindings += @(Invoke-ScriptAnalyzer -Path $filePath -Settings $formatSettings -IncludeRule $formatRules)
    }

    if ($formatFindings)
    {
        Write-Output "Formatting findings: $($formatFindings.Count)"
        $formatFindings | Select-Object RuleName, Severity, ScriptName, Line, Message | Format-Table -AutoSize
        throw 'PowerShell formatting violations detected.'
    }
}

Invoke-Check -Name 'PowerShell error lint rules' -Results ([ref]$results) -Action {
    $lintFindings = @()
    foreach ($filePath in $powerShellSourceFiles)
    {
        $lintFindings += @(Invoke-ScriptAnalyzer -Path $filePath -Severity Error)
    }

    if ($lintFindings)
    {
        Write-Output "Error-severity lint findings: $($lintFindings.Count)"
        $lintFindings | Select-Object RuleName, Severity, ScriptName, Line, Message | Format-Table -AutoSize
        throw 'PSScriptAnalyzer found error-severity findings.'
    }
}

Invoke-Check -Name 'cspell spell-check' -Results ([ref]$results) -Action {
    $nodeTools = Initialize-NodeTooling -InstallMissing:$InstallMissingNodeTools -InstallMethod $NodeInstallMethod

    $spellPaths = if ($SpellScope -eq 'powershell')
    {
        @('**/*.{ps1,psm1,psd1}')
    }
    else
    {
        @('**/*.{md,yaml,yml,ps1,psm1,psd1,py,cs,json}')
    }

    $cspellArgs = @(
        '--config'
        $cspellConfig
        '--gitignore'
        '--exclude'
        'depr/**'
    ) + $spellPaths

    Invoke-CspellCommand -NpmCommand $nodeTools.NpmCommand -NpxCommand $nodeTools.NpxCommand -CspellArgs $cspellArgs -PackageVersion $CspellPackageVersion
    if ($LASTEXITCODE -ne 0)
    {
        throw "cspell reported spelling issues for scope '$SpellScope' (cspell@$CspellPackageVersion)."
    }
}

Write-Section -Name 'Summary'
$results | Select-Object Name, Passed, Message | Format-Table -AutoSize

if ($script:Warnings.Count -gt 0)
{
    Write-Output ''
    Write-Output 'Warnings:'
    foreach ($warningMessage in $script:Warnings)
    {
        Write-Output " - $warningMessage"
    }
}

$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0)
{
    Write-Output ''
    Write-Output 'Failed checks and remediation:'
    foreach ($failure in $failed)
    {
        Write-Output " - $($failure.Name): $($failure.Message)"
        Write-Output "   Action: $($failure.Hint)"
    }

    Write-Output "ERROR: Validation failed ($($failed.Count) check(s) failed). Resolve the actions above and rerun."
    exit 1
}

Write-Output ''
Write-Output 'All local preflight checks passed.'