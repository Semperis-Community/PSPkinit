<#
    CertEnroll.ps1: certificate request/enrollment support for PSPkinit, built on
    the native Windows CertEnroll (X509Enrollment.*) and CertificateAuthority.*
    COM object models - the same underlying API certreq.exe itself uses. Chosen
    over shelling out to certreq.exe so that request/submission results come back
    as structured data (disposition codes, exceptions) instead of scraped text,
    and so the whole module keeps working on Windows PowerShell 5.1 (the modern
    System.Security.Cryptography.X509Certificates.CertificateRequest/
    SubjectAlternativeNameBuilder .NET classes are .NET 5+ only and have no
    Framework equivalent - COM interop has no such version gate).

    Key enum values used below (from the CERTENROLLLib / CertCli type libraries):
      AlternativeNameType: RFC822_NAME=2, DNS_NAME=3, USER_PRINCIPAL_NAME=11
      X509CertificateEnrollmentContext: ContextUser=1, ContextMachine=2
      X509KeySpec: XCN_AT_KEYEXCHANGE=1
      X509PrivateKeyExportFlags: XCN_NCRYPT_ALLOW_EXPORT_FLAG=1
      EncodingType: XCN_CRYPT_STRING_BASE64HEADER=0, XCN_CRYPT_STRING_BASE64=1
      InstallResponseRestrictionFlags: AllowNone=0, AllowUntrustedCertificate=2
      ICertRequest2 disposition: CR_DISP_ISSUED=3 (others are treated as failure)

    Getting the CA to actually honor a client-supplied SAN has two independent
    paths:
      1. Embedded CSR extension (what New-PkinitCertificateSigningRequest
         builds via CX509ExtensionAlternativeNames) - honored automatically
         when the template allows enrollee-supplied subject/SAN
         (msPKI-Certificate-Name-Flag bit CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
         "Supply in the request" on the template's Subject Name tab). No
         CA-wide registry flag needed for this path.
      2. Request attribute string (SAN:upn=..., built by
         ConvertTo-PkinitSanAttributeString and sent as a fallback by
         Submit-PkinitCertificateSigningRequest) - only honored if the CA also
         has the EDITF_ATTRIBUTESUBJECTALTNAME2 edit flag set:
             certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
             Restart-Service CertSvc
         This path exists for templates that build the subject from AD and
         don't allow enrollee-supplied SANs.
#>

function New-PkinitComObject {
    <#
        .SYNOPSIS
        Thin seam around New-Object -ComObject, so every CertEnroll/CertificateAuthority
        COM object creation in this module can be intercepted by Pester mocks.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)] [string] $ProgId
    )

    return New-Object -ComObject $ProgId
}

function ConvertTo-PkinitAlternativeNameTypeCode {
    <#
        .SYNOPSIS
        Maps a friendly SAN type name to its CERTENROLLLib AlternativeNameType code.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [ValidateSet('UserPrincipalName', 'Dns', 'Email')] [string] $SanType
    )

    switch ($SanType) {
        'UserPrincipalName' { return 11 } # XCN_CERT_ALT_NAME_USER_PRINCIPAL_NAME (otherName, OID 1.3.6.1.4.1.311.20.2.3)
        'Dns' { return 3 }              # XCN_CERT_ALT_NAME_DNS_NAME
        'Email' { return 2 }            # XCN_CERT_ALT_NAME_RFC822_NAME
    }
}

function ConvertTo-PkinitSanAttributeString {
    <#
        .SYNOPSIS
        Builds the "SAN:keyword=value" ICertRequest2::Submit request-attribute
        string, sent as a fallback alongside the SAN already embedded in the
        CSR itself. This attribute-based path is only honored by CA policy
        modules that have EDITF_ATTRIBUTESUBJECTALTNAME2 set; templates that
        allow enrollee-supplied SANs pick up the embedded CSR extension
        directly and don't need this at all.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidateSet('UserPrincipalName', 'Dns', 'Email')] [string] $SanType,
        [Parameter(Mandatory)] [string] $San
    )

    $keyword = switch ($SanType) {
        'UserPrincipalName' { 'upn' }
        'Dns' { 'dns' }
        'Email' { 'email' }
    }

    return "SAN:$keyword=$San"
}

function ConvertTo-PkinitSidSecurityExtensionValue {
    <#
        .SYNOPSIS
        Builds the raw DER value of the SID security extension
        (szOID_NTDS_CA_SECURITY_EXT, OID 1.3.6.1.4.1.311.25.2) that Windows CAs
        normally add automatically, so it can be embedded directly on a CSR
        instead - useful when the CA/template has this extension disabled
        (msPKI-Enrollment-Flag NO_SECURITY_EXTENSION) and won't add it
        automatically, but doesn't strip a client-supplied one either.

        .DESCRIPTION
        Structurally this reuses the GeneralNames/otherName template from RFC
        5280 as a single-entry "SEQUENCE OF GeneralName", with the otherName's
        type-id set to 1.3.6.1.4.1.311.25.2.1 and its value an OCTET STRING
        containing the SID's string form (e.g. "S-1-5-21-...") - matching
        exactly what a real Windows CA embeds as this extension's value
        (verified byte-for-byte in tests against a captured CA-issued
        extension, and structurally confirmed against GhostPack/Certify's
        CertSidExtension.EncodeSidExtension implementation).

        This value is NOT itself the "2.5.29.17" Subject Alternative Name
        extension - it's the *value* of a separate, standalone extension
        identified by OID 1.3.6.1.4.1.311.25.2, which merely reuses the SAN
        ASN.1 template internally.

        .PARAMETER Sid
        The security identifier, in its string form (e.g. 'S-1-5-21-...-1105').

        .OUTPUTS
        System.Byte[] - the raw DER extension value. The caller is responsible
        for wrapping this in an actual X.509 Extension (OID
        1.3.6.1.4.1.311.25.2) - see New-PkinitSidSecurityExtension.

        .NOTES
        SECURITY: only ever supply the SID of an identity you are authorized
        to test as. Being able to freely set this value, if a CA/template
        also permits it, is the same primitive used in real-world certificate
        SID-spoofing techniques (see e.g. GhostPack/Certify's --sid option,
        which is compiled out by default via #if !DISARMED).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Sid
    )

    $typeIdOid = ConvertTo-Asn1Oid -Dotted '1.3.6.1.4.1.311.25.2.1'
    $sidOctetString = ConvertTo-Asn1OctetString -Bytes ([System.Text.Encoding]::ASCII.GetBytes($Sid))
    $valueWrapper = ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv $sidOctetString

    # otherName ::= [0] IMPLICIT SEQUENCE { type-id, value } as a GeneralName choice -
    # IMPLICIT means the context tag REPLACES the universal SEQUENCE tag entirely, so
    # the TLV is built directly here rather than wrapping an already-tagged SEQUENCE.
    $otherName = New-Asn1Tlv -Tag 0xA0 -Content ([byte[]]$typeIdOid + [byte[]]$valueWrapper)

    return ConvertTo-Asn1Sequence -Children @($otherName)
}

function New-PkinitSidSecurityExtension {
    <#
        .SYNOPSIS
        Builds a CX509Extension COM object for the SID security extension
        (1.3.6.1.4.1.311.25.2), ready to add to a
        CX509CertificateRequestPkcs10's X509Extensions collection.

        .PARAMETER Sid
        The security identifier, in its string form (e.g. 'S-1-5-21-...-1105').
        See the SECURITY note on ConvertTo-PkinitSidSecurityExtensionValue.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Sid
    )

    $extensionValueBase64 = [Convert]::ToBase64String((ConvertTo-PkinitSidSecurityExtensionValue -Sid $Sid))

    $oid = New-PkinitComObject -ProgId 'X509Enrollment.CObjectId'
    $oid.InitializeFromValue('1.3.6.1.4.1.311.25.2')

    $extension = New-PkinitComObject -ProgId 'X509Enrollment.CX509Extension'
    $extension.Initialize($oid, 1, $extensionValueBase64) # EncodingType XCN_CRYPT_STRING_BASE64

    return $extension
}

function New-PkinitCertificateSigningRequest {
    <#
        .SYNOPSIS
        Generates a private key and a PKCS#10 CSR (with a SAN extension embedded
        for good measure) via the CertEnroll COM object model.

        .PARAMETER Sid
        Optional. If supplied, embeds the SID security extension
        (1.3.6.1.4.1.311.25.2) directly on the CSR - see
        New-PkinitSidSecurityExtension for what this is for and its security
        implications. Only meaningful for CAs/templates that don't already add
        this extension automatically and don't strip a client-supplied one.

        .OUTPUTS
        PSCustomObject with Enrollment (the CX509Enrollment COM object - keep it
        around, it's needed later to install the CA's response against the same
        private key) and Base64Csr (string, ready to submit).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Subject,
        [Parameter(Mandatory)] [string] $San,
        [Parameter(Mandatory)] [ValidateSet('UserPrincipalName', 'Dns', 'Email')] [string] $SanType,
        [Parameter()] [string] $Sid,
        [Parameter()] [int] $KeyLength = 2048,
        [Parameter()] [string] $ProviderName = 'Microsoft Software Key Storage Provider',
        [Parameter()] [switch] $MachineContext
    )

    $enrollmentContext = if ($MachineContext) { 2 } else { 1 } # ContextMachine=2, ContextUser=1

    $privateKey = New-PkinitComObject -ProgId 'X509Enrollment.CX509PrivateKey'
    $privateKey.ProviderName = $ProviderName
    $privateKey.Length = $KeyLength
    $privateKey.KeySpec = 1 # XCN_AT_KEYEXCHANGE
    $privateKey.MachineContext = [bool]$MachineContext
    $privateKey.ExportPolicy = 1 # XCN_NCRYPT_ALLOW_EXPORT_FLAG
    $privateKey.Create()

    $distinguishedName = New-PkinitComObject -ProgId 'X509Enrollment.CX500DistinguishedName'
    $distinguishedName.Encode($Subject, 0) # X500NameFlags XCN_CERT_NAME_STR_NONE

    $alternativeName = New-PkinitComObject -ProgId 'X509Enrollment.CAlternativeName'
    $alternativeName.InitializeFromString((ConvertTo-PkinitAlternativeNameTypeCode -SanType $SanType), $San)

    $alternativeNames = New-PkinitComObject -ProgId 'X509Enrollment.CAlternativeNames'
    $alternativeNames.Add($alternativeName)

    $sanExtension = New-PkinitComObject -ProgId 'X509Enrollment.CX509ExtensionAlternativeNames'
    $sanExtension.InitializeEncode($alternativeNames)

    $pkcs10Request = New-PkinitComObject -ProgId 'X509Enrollment.CX509CertificateRequestPkcs10'
    $pkcs10Request.InitializeFromPrivateKey($enrollmentContext, $privateKey, '')
    $pkcs10Request.Subject = $distinguishedName
    $pkcs10Request.X509Extensions.Add($sanExtension)
    if ($Sid) {
        $pkcs10Request.X509Extensions.Add((New-PkinitSidSecurityExtension -Sid $Sid))
    }
    $pkcs10Request.Encode()

    $enrollment = New-PkinitComObject -ProgId 'X509Enrollment.CX509Enrollment'
    $enrollment.InitializeFromRequest($pkcs10Request)
    $base64Csr = $enrollment.CreateRequest(1) # EncodingType XCN_CRYPT_STRING_BASE64

    return [PSCustomObject]@{
        Enrollment = $enrollment
        Base64Csr  = $base64Csr
    }
}

function Submit-PkinitCertificateSigningRequest {
    <#
        .SYNOPSIS
        Submits a Base64 PKCS#10 CSR to a CA via the CertificateAuthority.Request
        (ICertRequest2) COM object, passing the certificate template and SAN as
        request attributes.

        .OUTPUTS
        System.String - the issued certificate, Base64-encoded (no PEM header).
        Throws if the CA does not issue the certificate.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Base64Csr,
        [Parameter(Mandatory)] [string] $Template,
        [Parameter(Mandatory)] [string] $San,
        [Parameter(Mandatory)] [ValidateSet('UserPrincipalName', 'Dns', 'Email')] [string] $SanType,
        [Parameter(Mandatory)] [string] $CertificateAuthorityConfig
    )

    $attributes = @(
        "CertificateTemplate:$Template"
        (ConvertTo-PkinitSanAttributeString -SanType $SanType -San $San)
    ) -join "`n"

    $certRequest = New-PkinitComObject -ProgId 'CertificateAuthority.Request'
    # 0xFF (CR_IN_ENCODEANY) lets the CA auto-detect the request encoding.
    $disposition = $certRequest.Submit(0xFF, $Base64Csr, $attributes, $CertificateAuthorityConfig)

    if ($disposition -ne 3) {
        # CR_DISP_ISSUED
        $message = $certRequest.GetDispositionMessage()
        throw "Certificate request was not issued (disposition $disposition): $message"
    }

    return $certRequest.GetCertificate(1) # CR_OUT_BASE64 (no header)
}

function Install-PkinitCertificateResponse {
    <#
        .SYNOPSIS
        Installs an issued certificate against the private key generated for it,
        via the same CX509Enrollment object used to create the request.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Enrollment,
        [Parameter(Mandatory)] [string] $Base64Certificate
    )

    # InstallResponseRestrictionFlags: AllowUntrustedCertificate (2) - this is a
    # test/lab-oriented tool, so don't require the CA's chain to already be
    # trusted by the local machine.
    $Enrollment.InstallResponse(2, $Base64Certificate, 1, '')
}

function Get-PkinitCertificateFromStore {
    <#
        .SYNOPSIS
        Finds a certificate (with its now-associated private key) in the
        certificate store by thumbprint, after Install-PkinitCertificateResponse.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Thumbprint,
        [Parameter()] [switch] $MachineContext
    )

    $storePath = if ($MachineContext) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }
    return Get-ChildItem -Path $storePath | Where-Object { $_.Thumbprint -eq $Thumbprint }
}
