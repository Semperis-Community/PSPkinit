# Contributing

Thanks for helping improve PSPkinit. For substantial changes, open an issue first to discuss the proposed behavior and scope.

**Primary contact:** [Jake Hildreth](https://jakehildreth.com).

## Development Workflow

- Start feature and fix branches from the current `dev` branch.
- Open pull requests against `dev` unless a maintainer directs otherwise. Changes are promoted to `main` through the repository's release process.
- Keep each pull request focused and describe the user-visible behavior or rationale.
- Preserve the module's public command interfaces unless a change is intentional and discussed.

## Compatibility and Testing

PSPkinit supports Windows PowerShell 5.1 and PowerShell 7 or later on Windows. Keep changes compatible with both where practical, and avoid adding runtime dependencies without discussing them first.

Run the Pester tests before opening a pull request:

```powershell
Invoke-Pester -Path .\Tests
```

The CI workflows also run Pester 5, PSScriptAnalyzer, spelling and Markdown checks, and workflow checks when applicable. Include the checks you ran and any limitations in the pull request description.

## Sensitive Data

Use only certificates, identities, KDCs, and other systems you are authorized to test. Do not commit private keys, PFX files or passwords, Kerberos tickets, credentials, access tokens, or unredacted production data. See [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.
