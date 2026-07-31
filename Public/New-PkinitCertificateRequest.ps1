function New-PkinitCertificateRequest {
    <#
        .SYNOPSIS
        Requests a certificate from an AD CS CA, with a caller-supplied Subject
        Alternative Name, using the native CertEnroll/CertificateAuthority COM
        object model (no certreq.exe, no INF files, no text-scraping - and no
        .NET-version gate, unlike the modern CertificateRequest/
        SubjectAlternativeNameBuilder classes, so this works on Windows
        PowerShell 5.1 as well as PowerShell 7+).

        .DESCRIPTION
        Generates a private key and PKCS#10 CSR, submits it to the specified CA
        with the given certificate template and SAN, and installs the resulting
        certificate against the same private key. The returned certificate can
        be passed straight to Invoke-PkinitAuthentication, and the SAN value
        returned alongside it is exactly what to pass as -ClientName so you
        authenticate as the identity that SAN represents.

        For the CA to actually honor the supplied SAN, the certificate template
        must allow the enrollee to supply it - the Subject Name tab set to
        "Supply in the request" rather than "Build from this Active Directory
        information" (msPKI-Certificate-Name-Flag bit
        CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, 0x00000001). This cmdlet embeds the
        SAN directly as an extension on the CSR, which is what that template
        setting honors - no CA-wide registry flag needed for it.

        As a fallback for templates that build the subject from AD instead,
        the SAN is also sent as a request attribute string (SAN:upn=...), but
        that mechanism additionally requires the CA to have the
        EDITF_ATTRIBUTESUBJECTALTNAME2 edit flag set:

            certutil -config <CAConfig> -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
            Restart-Service CertSvc

        .PARAMETER Subject
        The certificate's subject distinguished name, e.g. 'CN=Test User'.

        .PARAMETER San
        The Subject Alternative Name value to request, e.g. 'user@adcs.goat'.

        .PARAMETER SanType
        The SAN's type. Defaults to 'UserPrincipalName' (an otherName UPN SAN,
        OID 1.3.6.1.4.1.311.20.2.3 - what Windows/PKINIT strong certificate
        mapping actually looks at). 'Dns' and 'Email' are also supported.

        .PARAMETER Sid
        Optional. Embeds the SID security extension (OID 1.3.6.1.4.1.311.25.2 -
        the same extension a Windows CA normally adds automatically) directly
        on the CSR, set to this SID value. Useful when a template/CA has this
        extension disabled (msPKI-Enrollment-Flag NO_SECURITY_EXTENSION) and
        therefore won't add it itself - without it, a KDC in Full Enforcement
        mode will reject the resulting certificate for PKINIT.

        SECURITY: only ever supply the SID of an identity you are authorized
        to test as. A CA/template that honors an arbitrary client-supplied SID
        here - especially combined with an arbitrary client-supplied SAN - is
        the same primitive used by real certificate SID-spoofing/impersonation
        techniques (see e.g. GhostPack/Certify's --sid option, which is
        compiled out of release builds by default for this reason). This is
        NOT a way to authenticate as an identity you don't already control.

        .PARAMETER Template
        The certificate template name to request against (the CA-side
        template's common/short name, not its display name).

        .PARAMETER CertificateAuthority
        The target CA's config string, in "<CAHostname>\<CAName>" form (the
        same format certreq.exe's -config parameter uses).

        .PARAMETER KeyLength
        RSA key length in bits. Defaults to 2048.

        .PARAMETER ProviderName
        The CSP/KSP to generate the private key with. Defaults to 'Microsoft
        Software Key Storage Provider'.

        .PARAMETER MachineContext
        Requests/installs the certificate in the local machine context
        (Cert:\LocalMachine\My) instead of the current user's
        (Cert:\CurrentUser\My, the default).

        .OUTPUTS
        PSCustomObject with Certificate (X509Certificate2, with private key),
        Thumbprint, Subject, San, and SanType.

        .EXAMPLE
        $reqParams = @{
            Subject              = 'CN=Test User'
            San                  = 'user@adcs.goat'
            Template             = 'User'
            CertificateAuthority = 'ADCSGOAT-CA\LabRootCA1'
        }
        New-PkinitCertificateRequest @reqParams

        Requests and installs a certificate to Cert:\CurrentUser\My, returning
        the result without immediately authenticating.

        .EXAMPLE
        $reqParams = @{
            Subject              = 'CN=Test User'
            San                  = 'user@adcs.goat'
            Template             = 'UserWithSIDExtension'
            CertificateAuthority = 'ADCSGOAT-CA\LabRootCA1'
            Sid                  = 'S-1-5-21-1-2-3-1105'
            MachineContext       = $true
        }
        New-PkinitCertificateRequest @reqParams

        Embeds an explicit SID security extension on the CSR and installs the
        issued certificate to Cert:\LocalMachine\My instead of the current
        user's store.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Subject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $San,

        [Parameter()]
        [ValidateSet('UserPrincipalName', 'Dns', 'Email')]
        [string] $SanType = 'UserPrincipalName',

        [Parameter()]
        [string] $Sid,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Template,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CertificateAuthority,

        [Parameter()]
        [int] $KeyLength = 2048,

        [Parameter()]
        [string] $ProviderName = 'Microsoft Software Key Storage Provider',

        [Parameter()]
        [switch] $MachineContext
    )

    try {
        $csrResult = New-PkinitCertificateSigningRequest -Subject $Subject -San $San -SanType $SanType -Sid $Sid `
            -KeyLength $KeyLength -ProviderName $ProviderName -MachineContext:$MachineContext

        $issuedCertBase64 = Submit-PkinitCertificateSigningRequest -Base64Csr $csrResult.Base64Csr -Template $Template `
            -San $San -SanType $SanType -CertificateAuthorityConfig $CertificateAuthority

        Install-PkinitCertificateResponse -Enrollment $csrResult.Enrollment -Base64Certificate $issuedCertBase64

        $issuedCertBytes = [Convert]::FromBase64String($issuedCertBase64)
        $issuedCertPreview = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($issuedCertBytes)

        $installedCert = Get-PkinitCertificateFromStore -Thumbprint $issuedCertPreview.Thumbprint -MachineContext:$MachineContext
        if (-not $installedCert) {
            throw "Certificate was issued (thumbprint $($issuedCertPreview.Thumbprint)) but was not found in the certificate store after install."
        }

        return [PSCustomObject]@{
            PSTypeName  = 'PSPkinit.CertificateRequestResult'
            Certificate = $installedCert
            Thumbprint  = $installedCert.Thumbprint
            Subject     = $Subject
            San         = $San
            SanType     = $SanType
        }
    } catch {
        $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                $_.Exception, 'PkinitCertificateRequestFailed', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null))
    }
}
