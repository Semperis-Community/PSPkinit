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
        . (Join-Path $PSScriptRoot 'Initialize-PowerShellYaml.ps1')
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



# SIG # Begin signature block
# MIIu4gYJKoZIhvcNAQcCoIIu0zCCLs8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCChQ0QJ2kwfZsIV
# sfbaXPD7EfbRnnnsC9zAUu6f7B/atKCCE6MwggVyMIIDWqADAgECAhB2U/6sdUZI
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
# n1KtQm7lUWQsI+Cz5zGCGpUwghqRAgEBMGkwWTELMAkGA1UEBhMCQkUxGTAXBgNV
# BAoTEEdsb2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNpZ24gR0NDIFI0
# NSBDb2RlU2lnbmluZyBDQSAyMDIwAgxhoXx4c1Ywe7yEvMYwDQYJYIZIAWUDBAIB
# BQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG
# 9w0BCQQxIgQgQ3AqVK+XNXHN3w3Vvu2i7AYRut6SE4U2jIisvi1xAJkwDQYJKoZI
# hvcNAQEBBQAEggIAJmxKy5f9c4oZYasJVFmzIxP0SlNTK5RSRueWyoOvQor2TDJD
# A4S7bbpsg8RhxQan9BTZ8wHnV/hErf+oCwt00MUwwex3l6O6PwMhkhXCMk1mvvqZ
# Pvf+0ZaHivclnEI05NruuS0NwTE97bKEyllfHGK8lT5j5ULHUUhNVHkp0gZjqQOK
# DUf4KBC/dmM6aVIc2ZIF1Un+A+97JZixl69Mnx68QVxOYmgMaXOuyBPBykV239ox
# qayLrF/AZAWQSI/tibiaboG+2q65jOIIh5gEehmHs0Yf+8F0nwg0oOTl4IJfX9H6
# OFXtUetGOCp5j7/+xA/Va9YMavAVu/hJZLZ0SVdQ5fnnqC7Wpy6FKZrhDw38TgoY
# piC+/Lmng7Po1bJrnTB7IjIa8w+fKRj3H2/g/ZYydT0cT/By4AoFKPmCUzob2qqg
# p0oQRqVVTvOwop8w8Ptxgg5u8wXXxapJeKJMH+X6D+EDi/qB6vTmUctf37EWfMJt
# 9b1SS7cip1wjslwpL840fEc7VolwydFkJvOaweP9gVYX8yoGHYQAbIUufpmf1T5b
# vP5Jky2Y8uCv6dZ1rrXwKi+3jJ2psy3dfuXt4AgV87f7UYgrX1VT2+ulQ5OPG4s4
# aRlfz8mQb1ZrE2DPEuIZpH9DQcHLCUqIbO7GU+iUOjxsk5LkFCeMm5jTCpGhghd2
# MIIXcgYKKwYBBAGCNwMDATGCF2IwghdeBgkqhkiG9w0BBwKgghdPMIIXSwIBAzEP
# MA0GCWCGSAFlAwQCAQUAMHcGCyqGSIb3DQEJEAEEoGgEZjBkAgEBBglghkgBhv1s
# BwEwMTANBglghkgBZQMEAgEFAAQgQfkO0SNATwv35sThX8brkSlLyITVnVE19mWk
# Xi3zllYCEDm4gFu9qZv7ZCpbIC+rzx0YDzIwMjYxMDA2MjEzODQ5WqCCEzowggbt
# MIIE1aADAgECAhAIT9wzT35FTtvDD4/5khg1MA0GCSqGSIb3DQEBCwUAMGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTEwHhcNMjYwODA1MDAwMDAwWhcNMzcxMTA0MjM1OTU5WjBjMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0
# IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNiAxMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtnum8sn+zUr41JtMZbP9OMYw+HwJ
# DpG5xkIu/lqcfNYmMX81YmsUiHLbh9ykpeWBGKTLhYBrAN9Tdg/QEzG32XcObmgI
# blnr0CoQ3WSAeDZ6nH6X6VkFyYkJw3QBJREwvm4UhLzSxmwPA7cFKRTEOMsmEEj6
# qJk/dqLEAL+oQYuOwE2UuiX1Vnul8YReIyWd4kgLn9gq6LNXM0UplkR6jL/QHxmb
# 6fMoGBJYbnaUI7XD6cKDpekK2SVMld4iDbzeHDtOaaxldH5IxuNusQ69nd8/ZXEi
# B5Hbxj3RlK13cX1W4DlFXKdv/CEhM8Cj1vvlmvhNroyPdRGbbpBlgyf8Wdu5N6By
# hFwURn0U6ozlPoxN22v+fviUhP+6DR547OZnpBMWDfei1f5sVGwiiW/KQTWOK97g
# +4RJpPzPNV4VYMAwO2jM2Aty2QYPVmOQTJm0msuXnJrSbl2gf9JylpkJlWXqk1Q4
# LJsxz+TELoQCZIljbgvTJgoPU2R12ydv8i1UqL/adelA0y7U9Pmmtbze9Xx3rtaj
# C5SzQd1jgfwAwsa90v9YcSPdmeoyoBBA/27cCL237l5DTYYPDLQ4ON3OLTGWnvRb
# 6jDrf/T75gMRfUzSLCBQfBusm9+mSWRlC/Df6S/e9Q8i13CuhzOT2Jx+V/nlbXM4
# QoBwlUAhelwwJT0CAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE
# FBTJY4owLtRK+26U8+bjQH717M3iMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2
# L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCB
# lQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVD
# QTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1
# Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAI3FOmEenVIK35msCYB+fShAsWvSYvLBItoNdAgQ2jIqrGsV
# sluXMJU/+mRebBc52s6lbKAvOVPXaizmKkMLLflEEKDZQx4CkS2t8aHPjkXha3hY
# Z010htFa3dhNgmalH5vuWvh3tTCf4frTS7gPtGc4Z/xaPhQ2AB1mR8eEe/WbH0RW
# HvVIl6VwQ3+g5FKNfN2N/DWJkf13w2H+2GfqEfbd35Ww8CvoYBjLNIDTadcPWdgs
# jsiOaK/7EsKJgLjUNIVgvcaFOLLQ/GlrA+0ZHJoFUbOr5SJN8zykPspXIXlpDJY/
# gqFUZRROeab9GVgmhbdOJcD/63RhxPahFUGbckRONqMe6DYAv6/mOG0pWd3cPSts
# dcS7buj5DyniwRY8yooMH6ptx5vpP/pZzBPBeZD2U4IsthyxB5Jaa8qrOkB5z160
# TXiM5ADMspZ0TfD9MJoq0tFpFPssKRFhWeEDYPvcUuN7U7lvcdHl4ezQ3NT/7Ffs
# 1sR1yh/LRbdZ3B3Vc6q2WmD8mDC0p9kzl2o73iVtS946IkEj7FkRsZGww1teYxER
# ROC745xrtjvcw9ZyyUjHZWGRIpJeMNsPquCDf0fkyHtB+J4AiNZqCQk23rxh+Kbp
# yMTNVKItJ5l92Svl20U9NbqMBOVYl1h54NEYLJq1/xHWFKPNK903zJZA9P2DMIIG
# tDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0
# URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusL
# opuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQ
# XSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDE
# pKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7
# PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpo
# YGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQ
# HkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJn
# jq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP
# 3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp
# 2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+b
# gIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# CDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# IAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUA
# A4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mh
# XZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib6
# 1eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfB
# wAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX
# 3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQ
# LwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb
# 82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToW
# d2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KS
# FLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx
# 3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8Blqm
# yIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBY0wggR1oAMC
# AQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIy
# MDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8G
# A1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9
# WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+p
# VxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7s
# Xk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW
# 7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9
# iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuap
# oGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5L
# HucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGy
# shG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QM
# IR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1
# P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsC
# AwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1k
# TN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4G
# A1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8E
# PjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
# cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwF
# AAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2k
# iHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je
# 1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJM
# QBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwC
# A8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaH
# lv1b0VysGMNNn3O3AamfV6peKOK5lDGCA3wwggN4AgEBMH0waTELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBU
# cnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQ
# CE/cM09+RU7bww+P+ZIYNTANBglghkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMx
# DQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTAwNjIxMzg0OVowKwYL
# KoZIhvcNAQkQAgwxHDAaMBgwFgQUUdmr2gNJc9hPQmaspIJI5rNpxDkwLwYJKoZI
# hvcNAQkEMSIEIBHQPoQcy+r+EOqHkKSSquq84bKkdCVXFmYwyy72qU0BMDcGCyqG
# SIb3DQEJEAIvMSgwJjAkMCIEIC2gnaf0Ex+f5y22xebpyWVnVa8EPx6nQswNISDh
# Qev8MA0GCSqGSIb3DQEBAQUABIICAIjCnCIAsm1KDtrvZ2P7FusAa1quSKPIfRze
# C87y+lXjsc6JKhwhhveMhmhyAiiBM0l+uyWzJmpARgrPu9xhV8BJUciVPHvuWtL8
# RBA1L7I3lUipRjgEOS2iggd8gGItta/Evm9djOq5+M0cs2ReKdMec+LfIhzU3yWp
# kRc49Ztfx81nbp6C5BRdicBrqABg+QVCYAFtb1Znh8O34hRih/GzTmWUujyB5QYS
# FlOwIn7NaoXVrKByQjIjCCKAyU3A4fqP7rdcG3hb4b8x50qtPVNfth+9ZlLDPP94
# qQLdEIvQ/qhesgSnzVs/43rCwHxbgohCwo9RO3TOau9qUUsQYghyfAVRNt6Um63+
# YeQ102IYRqqAeN1juj1u4MO2mwc1uDvGDTiarN8UcP4iNg9cRPRRvmTncvXLWnER
# QEaqsXkJRiTz0YVRx9mDi4oPiIG+Nx7Otir8rTwq383fEMa3RFrooNvqreWzdAfo
# oG6+Y0DmTH9OeWY5dBXVOZdiDFokgwh32p8FPGrTh3kkahgK7NUhyK8bRxhuTm+z
# 5WDXhQSGkrXF2TujTiAUA221E9mUgCo6a2gKVVTHkDteJeBskkeZk8ZD2RDD/Zak
# ImxpsYv11HQptOGsXu4HYBmYxswadlDRefdCxNVgZ8HEb0cv262MkAU+tjMBIXMv
# SNJjDnqW
# SIG # End signature block
