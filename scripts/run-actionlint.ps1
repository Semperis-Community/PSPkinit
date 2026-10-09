<#
.SYNOPSIS
Runs actionlint using a local bootstrap installer.

.DESCRIPTION
Ensures actionlint is installed in a local tools directory, then executes it
with optional additional arguments.

.PARAMETER Version
actionlint release version to install/use (without the leading v).

.PARAMETER InstallDir
Repository-relative directory where actionlint is installed.

.PARAMETER ActionlintArgs
Optional arguments passed directly to actionlint.
#>

[CmdletBinding()]
param(
    [string]$Version = '1.7.12',
    [string]$InstallDir = '.tools/bin',
    [string[]]$ActionlintArgs = @()
)

$ErrorActionPreference = 'Stop'

$installerPath = Join-Path $PSScriptRoot 'install-actionlint.ps1'
if (-not (Test-Path $installerPath))
{
    throw "Installer script not found at '$installerPath'."
}

$binaryPath = & $installerPath -Version $Version -InstallDir $InstallDir -PrintPath
if ([string]::IsNullOrWhiteSpace($binaryPath))
{
    throw 'Failed to resolve actionlint binary path.'
}

& $binaryPath @ActionlintArgs
exit $LASTEXITCODE

