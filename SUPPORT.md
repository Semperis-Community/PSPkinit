# Support

PSPkinit is a community project. Support is provided through the repository issue tracker; there is no separate discussion forum or guaranteed response time.

## Before Opening an Issue

- Check the [README](README.md), [Troubleshooting](docs/troubleshooting.md), and [Advanced Usage](docs/advanced-usage.md).
- Search [existing issues](https://github.com/Semperis-Community/PSPkinit/issues) for a similar question or problem.
- Confirm that you are using a supported environment: Windows with Windows PowerShell 5.1 or PowerShell 7 or later.

## Ask for Help or Report a Bug

Open an issue in the [PSPkinit issue tracker](https://github.com/Semperis-Community/PSPkinit/issues). Include:

- The PSPkinit version, PowerShell version, and Windows version.
- The command or a minimal sanitized reproduction, with the expected and actual behavior.
- The complete error text and relevant troubleshooting steps already tried.
- Relevant certificate or KDC configuration details, with personal and organizational identifiers redacted.

Do not attach private keys, PFX files or passwords, Kerberos tickets, credentials, access tokens, or unredacted production data. Use [SECURITY.md](SECURITY.md) to report suspected vulnerabilities privately.

## Project Scope

PSPkinit implements the client-side PKINIT AS exchange. It does not configure or administer Active Directory Certificate Services, domain controllers, KDCs, certificate templates, or trust stores. For issues in those systems, consult their administrator or vendor; include sanitized findings when they help explain a PSPkinit issue.
