<#
.SYNOPSIS
Runs cspell and writes annotations plus a markdown summary for workflow output.

.DESCRIPTION
Executes cspell for the provided paths, emits GitHub Actions annotations for
parseable findings, and appends a pass/fail summary to GITHUB_STEP_SUMMARY.
#>

param(
    [string]$ConfigPath = '.cspell.json',
    [string[]]$Paths = @('**/*.{md,yaml,yml,ps1,psm1,psd1,py,cs,json}'),
    [int]$MaxSummaryFindings = 25
)

$ErrorActionPreference = 'Stop'

$npxCommand = Get-Command npx, npx.cmd -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty Source

if ([string]::IsNullOrWhiteSpace($npxCommand))
{
    throw 'npx is not available on PATH. Install Node.js or run this script from a workflow/job that has executed actions/setup-node.'
}

$cspellArgs = @(
    '--yes'
    'cspell@latest'
    '--config'
    $ConfigPath
) + $Paths

$cspellOutput = & $npxCommand @cspellArgs 2>&1
$findings = New-Object System.Collections.Generic.List[object]

foreach ($line in $cspellOutput)
{
    $text = [string]$line
    Write-Output $text

    if ($text -match '^(?<file>.+?):(?<line>\d+):(?<column>\d+)\s+-\s+(?<message>.+)$')
    {
        $file = $Matches.file -replace '\\', '/'
        $lineNumber = [int]$Matches.line
        $columnNumber = [int]$Matches.column
        $message = [string]$Matches.message

        $findings.Add([pscustomobject]@{
                File = $file
                Line = $lineNumber
                Column = $columnNumber
                Message = $message
            })

        $annotationMessage = $message -replace '%', '%25' -replace "`r", '%0D' -replace "`n", '%0A'
        Write-Output "::error file=$file,line=$lineNumber,col=$columnNumber::$annotationMessage"
    }
}

if ($LASTEXITCODE -eq 0)
{
    @(
        '## CSpell Summary'
        '- Status: passed'
        "- Paths checked: $($Paths -join ', ')"
    ) | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append

    exit 0
}

if ($findings.Count -eq 0)
{
    Write-Output '::error::cspell failed but did not emit parseable file and line details. Review log output above.'
    @(
        '## CSpell Summary'
        '- Status: failed'
        '- Findings: output was not parseable; review the raw log output for details.'
    ) | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append

    throw 'cspell found spelling issues but the output could not be summarized.'
}

$uniqueFiles = @($findings | Select-Object -ExpandProperty File -Unique)
$findingsByFile = @(
    $findings |
        Group-Object File |
        Sort-Object -Property @(
            @{ Expression = 'Count'; Descending = $true },
            @{ Expression = 'Name'; Descending = $false }
        )
)
$summaryLines = @(
    '## CSpell Summary'
    '- Status: failed'
    "- Errors: $($findings.Count)"
    "- Files affected: $($uniqueFiles.Count)"
    ''
    '### Errors By File'
    '| File | Count |'
    '| --- | ---: |'
)

$summaryLines += $findingsByFile | ForEach-Object {
    "| $($_.Name) | $($_.Count) |"
}

$summaryLines += @(
    ''
    "### First $([Math]::Min($MaxSummaryFindings, $findings.Count)) Findings"
    '| File | Line | Column | Message |'
    '| --- | ---: | ---: | --- |'
)

$summaryLines += $findings |
    Select-Object -First $MaxSummaryFindings |
    ForEach-Object {
        $escapedMessage = $_.Message -replace '\|', '\|'
        "| $($_.File) | $($_.Line) | $($_.Column) | $escapedMessage |"
    }

$summaryLines | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append

throw 'cspell found spelling issues. See the annotations and step summary for details.'
