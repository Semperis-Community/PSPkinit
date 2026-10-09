<#
    .SYNOPSIS
    Pure PowerShell/.NET PKINIT implementation for Kerberos certificate authentication.

    PSPkinit root module: dot-sources every Private (internal) implementation
    file and every Public (exported) function file, then exports only the
    Public surface area.
#>

$privatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Private'
$publicPath = Join-Path -Path $PSScriptRoot -ChildPath 'Public'

foreach ($folder in @($privatePath, $publicPath))
{
    if (-not (Test-Path -Path $folder))
    {
        continue
    }
    Get-ChildItem -Path $folder -Filter '*.ps1' -File | ForEach-Object {
        . $_.FullName
    }
}

$publicFunctionNames = if (Test-Path -Path $publicPath)
{
    @(Get-ChildItem -Path $publicPath -Filter '*.ps1' -File | ForEach-Object { $_.BaseName })
}
else
{
    @()
}

Export-ModuleMember -Function $publicFunctionNames

