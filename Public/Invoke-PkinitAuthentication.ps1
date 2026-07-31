<#
    Invoke-PkinitAuthentication: public entry point for PSPkinit.
#>

function Invoke-PkinitAuthentication {
    <#
        .SYNOPSIS
        Performs a full RFC 4556 PKINIT AS-REQ/AS-REP exchange against a KDC
        using the Diffie-Hellman key delivery method, and returns the
        decrypted identity/session information from a successful AS-REP.

        .DESCRIPTION
        Wraps the full PKINIT client flow - building a signed AuthPack,
        sending an AS-REQ, and parsing/decrypting the resulting AS-REP -
        behind a single cmdlet. Intended for validating that a certificate,
        CA, and KDC configuration actually support PKINIT end-to-end (cert
        chain, EKU, SID security extension, strong-mapping enforcement,
        etc.), not as a general-purpose Kerberos client.

        This only ever authenticates as the identity bound to the supplied
        certificate's own private key - it does not forge, inject, or reuse
        anyone else's tickets or credentials.

        .PARAMETER CertificateThumbprint
        Thumbprint of a certificate (with its private key) in
        Cert:\CurrentUser\My to authenticate with.

        .PARAMETER Certificate
        An already-loaded X509Certificate2 (with private key) to authenticate
        with, e.g. one you loaded yourself from a PFX or hardware token.

        .PARAMETER PfxPath
        Path to a .pfx/.p12 file containing the certificate and private key
        to authenticate with.

        .PARAMETER PfxPassword
        Password protecting the PFX file specified by -PfxPath.

        .PARAMETER ClientName
        The client principal name to authenticate as (RFC 4120 cname). For
        Active Directory, this is typically the user's UPN, e.g.
        'user@contoso.com'.

        .PARAMETER ClientNameType
        Kerberos name-type for -ClientName (RFC 4120 7.5.8). Defaults to
        NT-ENTERPRISE (10), which is the reliable choice for a UPN-style
        -ClientName against Active Directory. Use NT-PRINCIPAL (1) for a
        bare, single-component name.

        .PARAMETER Realm
        The Kerberos realm (typically the uppercase DNS domain name, e.g.
        'CONTOSO.COM').

        .PARAMETER KdcHostname
        Hostname or IP address of the KDC to send the AS-REQ to.

        .PARAMETER Port
        TCP port the KDC is listening on. Defaults to 88.

        .PARAMETER EncryptionTypes
        Encryption types to offer the KDC, in preference order. Defaults to
        @(18, 17) - aes256-cts-hmac-sha1-96, then aes128-cts-hmac-sha1-96.

        .PARAMETER Nonce
        The nonce to use in the KDC-REQ-BODY and PKAuthenticator. Defaults to
        a fresh cryptographically random value; override only for
        reproducible troubleshooting/testing.

        .PARAMETER TimeoutSeconds
        Timeout for the TCP connection and each read, in seconds. Defaults
        to 10.

        .PARAMETER SkipKdcSignatureVerification
        Skips cryptographic verification of the KDC's CMS signature on the
        DH reply (KDCDHKeyInfo). The KDC's certificate chain is never
        validated by this module regardless of this switch - only point it
        at a KDC you already trust.

        .OUTPUTS
        PSCustomObject describing the authenticated identity, ticket
        validity window, negotiated session key, and the KDC's PKINIT
        signing certificate.

        .EXAMPLE
        Invoke-PkinitAuthentication -CertificateThumbprint '1A49DADC...' -ClientName 'user@adcs.goat' -Realm 'ADCS.GOAT' -KdcHostname 'ADCSGoat-DC.adcs.goat'

        Authenticates using a certificate already in Cert:\CurrentUser\My.

        .EXAMPLE
        $securePassword = Read-Host -AsSecureString -Prompt 'PFX password'
        Invoke-PkinitAuthentication -PfxPath 'C:\certs\user.pfx' -PfxPassword $securePassword -ClientName 'user@adcs.goat' -Realm 'ADCS.GOAT' -KdcHostname 'ADCSGoat-DC.adcs.goat'

        Authenticates using a certificate loaded directly from a PFX file.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Thumbprint')]
        [ValidateNotNullOrEmpty()]
        [string] $CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [Parameter(Mandatory, ParameterSetName = 'PfxPath')]
        [ValidateNotNullOrEmpty()]
        [string] $PfxPath,

        [Parameter(Mandatory, ParameterSetName = 'PfxPath')]
        [ValidateNotNull()]
        [securestring] $PfxPassword,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ClientName,

        [Parameter()]
        [int] $ClientNameType = 10,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Realm,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $KdcHostname,

        [Parameter()]
        [int] $Port = 88,

        [Parameter()]
        [int[]] $EncryptionTypes = @(18, 17),

        [Parameter()]
        [uint32] $Nonce = [uint32](Get-Random -Minimum 1 -Maximum ([int]::MaxValue)),

        [Parameter()]
        [int] $TimeoutSeconds = 10,

        [Parameter()]
        [switch] $SkipKdcSignatureVerification
    )

    switch ($PSCmdlet.ParameterSetName) {
        'Thumbprint' {
            $resolvedCert = Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
            if (-not $resolvedCert) {
                $exception = [System.Security.Cryptography.CryptographicException]::new(
                    "No certificate with thumbprint '$CertificateThumbprint' was found in Cert:\CurrentUser\My.")
                $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                        $exception, 'PkinitCertificateNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $CertificateThumbprint))
            }
        }
        'Certificate' {
            $resolvedCert = $Certificate
        }
        'PfxPath' {
            if (-not (Test-Path -Path $PfxPath)) {
                $exception = [System.IO.FileNotFoundException]::new("PFX file not found: $PfxPath", $PfxPath)
                $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                        $exception, 'PkinitPfxNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $PfxPath))
            }
            $keyStorageFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            try {
                try {
                    # .NET 9+ prefers X509CertificateLoader over the (now-obsolete-marked) X509Certificate2 constructors.
                    $resolvedCert = [System.Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadPkcs12FromFile($PfxPath, $PfxPassword, $keyStorageFlags)
                } catch {
                    # X509CertificateLoader doesn't exist on this runtime (Windows PowerShell 5.1 / older .NET) - fall back.
                    $resolvedCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $PfxPassword, $keyStorageFlags)
                }
            } catch {
                $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                        $_.Exception, 'PkinitPfxLoadFailed', [System.Management.Automation.ErrorCategory]::InvalidData, $PfxPath))
            }
        }
    }

    if (-not $resolvedCert.HasPrivateKey) {
        $exception = [System.Security.Cryptography.CryptographicException]::new(
            "Certificate '$($resolvedCert.Thumbprint)' does not have a private key available.")
        $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                $exception, 'PkinitCertificateNoPrivateKey', [System.Management.Automation.ErrorCategory]::InvalidOperation, $resolvedCert))
    }

    try {
        $body = New-KdcReqBody -ClientName $ClientName -ClientNameType $ClientNameType -Realm $Realm -Nonce $Nonce -EncryptionTypes $EncryptionTypes
        $dh = New-PkinitDiffieHellmanKeyPair
        $authPack = New-PkinitAuthPack -KdcReqBody $body -Nonce $Nonce -DhKeyPair $dh
        $signed = New-PkinitSignedAuthPack -AuthPack $authPack -Certificate $resolvedCert
        $paData = New-PkinitPaData -SignedAuthPack $signed
        $asReq = New-AsReq -KdcReqBody $body -PaData @($paData)

        $response = Send-KerberosTcpMessage -KdcHostname $KdcHostname -Port $Port -Message $asReq -TimeoutSeconds $TimeoutSeconds

        if ($response[0] -eq 0x7e) {
            $krbError = ConvertFrom-KrbError -Message $response
            $kdcException = [System.Security.Authentication.AuthenticationException]::new(
                "KDC rejected the AS-REQ: KRB-ERROR $($krbError.ErrorCode) $($krbError.ErrorText)".Trim())
            $kdcException.Data['KrbError'] = $krbError
            throw $kdcException
        }

        $asRep = ConvertFrom-KdcRep -Message $response -ExpectedApplicationTag 11
        $pkAsRepPaData = $asRep.PaData | Where-Object { $_.Type -eq 17 }
        if (-not $pkAsRepPaData) {
            throw 'AS-REP did not include a PA-PK-AS-REP (type 17) padata element.'
        }

        $dhRepInfo = ConvertFrom-PkinitDhRepInfo -PaDataValue $pkAsRepPaData.Value
        $kdcDhKeyInfo = ConvertFrom-PkinitKdcDhKeyInfo -DhSignedData $dhRepInfo.DhSignedData -SkipSignatureVerification:$SkipKdcSignatureVerification

        if ($kdcDhKeyInfo.Nonce -ne $Nonce) {
            throw "Nonce mismatch: sent $Nonce, KDC returned $($kdcDhKeyInfo.Nonce) - possible replay or tampering."
        }

        $sharedSecret = Get-PkinitDiffieHellmanSharedSecret -TheirPublicValue $kdcDhKeyInfo.ServerPublicValue -OurPrivateExponent $dh.PrivateExponent -P $dh.P -ModulusByteLength $dh.ModulusByteLength

        $keyByteLength = switch ($asRep.EncPart.EType) {
            18 { 32 }
            17 { 16 }
            default { throw "Unsupported AS-REP enctype $($asRep.EncPart.EType)." }
        }
        $replyKey = ConvertTo-OctetString2Key -InputBytes $sharedSecret -KeyByteLength $keyByteLength
        $decrypted = Unprotect-KerberosData -BaseKey $replyKey -KeyUsage 3 -Ciphertext $asRep.EncPart.Cipher
        $encPart = ConvertFrom-EncKdcRepPart -Message $decrypted -ExpectedApplicationTag 25

        return [PSCustomObject]@{
            PSTypeName           = 'PSPkinit.AuthenticationResult'
            CName                = $asRep.CName.NameStrings -join '/'
            CRealm               = $asRep.CRealm
            SName                = $encPart.SName.NameStrings -join '/'
            SRealm               = $encPart.SRealm
            AuthTime             = $encPart.AuthTime
            StartTime            = $encPart.StartTime
            EndTime              = $encPart.EndTime
            RenewTill            = $encPart.RenewTill
            TicketFlags          = $encPart.Flags
            SessionKeyType       = $encPart.Key.KeyType
            SessionKey           = $encPart.Key.KeyValue
            Nonce                = $Nonce
            KdcSignerCertificate = $kdcDhKeyInfo.SignerCertificate
            Ticket               = $asRep.Ticket
        }
    } catch [System.Security.Authentication.AuthenticationException] {
        $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                $_.Exception, 'PkinitKdcError', [System.Management.Automation.ErrorCategory]::SecurityError, $_.Exception.Data['KrbError']))
    } catch {
        $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
                $_.Exception, 'PkinitAuthenticationFailed', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null))
    }
}
