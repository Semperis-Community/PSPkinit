@{
    RootModule = 'PSPkinit.psm1'
    ModuleVersion = '2026.7.101424'
    GUID = '767ad16c-1c30-4003-820d-e50fde18a712'
    Author = 'Jake Hildreth'
    CompanyName = 'Gilmour Technologies Ltd'
    Copyright = '(c) 2026 Jake Hildreth, Gilmour Technologies Ltd. Licensed under MIT with Commons Clause.'
    Description = 'Pure PowerShell/.NET implementation of RFC 4556 PKINIT (Diffie-Hellman key delivery method) for validating certificate/CA/KDC PKINIT configuration end-to-end.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @('Invoke-PkinitAuthentication', 'New-PkinitCertificateRequest')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags = @('Kerberos', 'PKINIT', 'ActiveDirectory', 'ADCS', 'Security')
        }
    }
}
