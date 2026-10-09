<#
    PKINIT (RFC 4556) specific pieces: Diffie-Hellman key exchange (Diffie-Hellman
    key delivery method, section 3.2.3.1), AuthPack/PKAuthenticator construction, and
    CMS SignedData signing/parsing via the .NET System.Security.Cryptography.Pkcs
    APIs (so we don't have to hand-roll PKCS#7/CMS ASN.1 on top of everything else).
#>

# System.Security.Cryptography.Pkcs types (ContentInfo, SignedCms, CmsSigner) live in
# different assemblies depending on runtime: the "System.Security" assembly on .NET
# Framework / Windows PowerShell 5.1, versus "System.Security.Cryptography.Pkcs" on
# .NET (Core) - neither is guaranteed to be loaded automatically, so try both.
foreach ($assemblyName in 'System.Security', 'System.Security.Cryptography.Pkcs')
{
    try
    {
        Add-Type -AssemblyName $assemblyName -ErrorAction Stop
    }
    catch
    {
        # fall through - the other assembly name (or an already-loaded copy) may work
    }
}

# RFC 3526 section 3: 2048-bit MODP Group 14. Required support per RFC 4556 3.2.1.
$script:OakleyGroup14PrimeHex = (
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AACAA68FFFFFFFFFFFFFFFF'
) -replace '\s', ''

function ConvertFrom-HexString
{
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [string]$Hex
    )

    $clean = $Hex -replace '\s', ''
    $bytes = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++)
    {
        $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }
    return $bytes
}

function ConvertTo-UnsignedBigInteger
{
    <#
        .SYNOPSIS
        Builds a positive System.Numerics.BigInteger from big-endian bytes (which is
        how DH moduli/values and DER INTEGER content are naturally expressed).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$BigEndianBytes
    )

    $little = [byte[]]$BigEndianBytes.Clone()
    [Array]::Reverse($little)
    if ($little[$little.Length - 1] -ge 0x80)
    {
        $little += [byte]0
    }
    return [System.Numerics.BigInteger]::new($little)
}

function ConvertTo-BigEndianBytes
{
    <#
        .SYNOPSIS
        Converts a non-negative BigInteger to minimal big-endian bytes (no sign byte
        unless the value's own bits require it to stay non-negative under DER rules
        - callers needing a fixed-width field should pad separately).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [System.Numerics.BigInteger]$Value
    )

    $bytes = $Value.ToByteArray()
    [Array]::Reverse($bytes)
    while ($bytes.Length -gt 1 -and $bytes[0] -eq 0)
    {
        $bytes = $bytes[1..($bytes.Length - 1)]
    }
    return $bytes
}

function New-PkinitDiffieHellmanKeyPair
{
    <#
        .SYNOPSIS
        Generates a client Diffie-Hellman key pair using Oakley Group 14 (2048-bit
        MODP, RFC 3526), per RFC 4556 3.2.1 item 8.

        .OUTPUTS
        PSCustomObject with P, G, Q, PrivateExponent, PublicValue (all BigInteger),
        and ModulusByteLength (int).
    #>
    [CmdletBinding()]
    param()

    $p = ConvertTo-UnsignedBigInteger -BigEndianBytes (ConvertFrom-HexString -Hex $script:OakleyGroup14PrimeHex)
    $g = [System.Numerics.BigInteger]2
    $q = ($p - 1) / 2
    $modulusByteLength = (ConvertFrom-HexString -Hex $script:OakleyGroup14PrimeHex).Length

    # Per RFC 4556/RFC 3766: exponent should have at least twice the bit-length of the
    # symmetric key it will protect (256 bits for AES256) - use a full-width exponent
    # (same size as the modulus) for a comfortable margin, uniformly random in [2, p-2].
    $privateBytes = New-Object byte[] $modulusByteLength
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try
    {
        $rng.GetBytes($privateBytes)
    }
    finally
    {
        $rng.Dispose()
    }
    $privateBytes[0] = $privateBytes[0] -band 0x7f # keep positive / well below p
    $x = ConvertTo-UnsignedBigInteger -BigEndianBytes $privateBytes
    $x = ($x % ($p - 3)) + 2

    $y = [System.Numerics.BigInteger]::ModPow($g, $x, $p)

    return [PSCustomObject]@{
        P = $p
        G = $g
        Q = $q
        PrivateExponent = $x
        PublicValue = $y
        ModulusByteLength = $modulusByteLength
    }
}

function Get-PkinitDiffieHellmanSharedSecret
{
    <#
        .SYNOPSIS
        Computes DHSharedSecret = ZZ (RFC 2631 2.1.1: theirPublicValue^ourPrivateExponent
        mod p), padded with leading zeros to the modulus byte length (RFC 4556 3.2.3.1).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [System.Numerics.BigInteger]$TheirPublicValue,
        [Parameter(Mandatory)] [System.Numerics.BigInteger]$OurPrivateExponent,
        [Parameter(Mandatory)] [System.Numerics.BigInteger]$P,
        [Parameter(Mandatory)] [int]$ModulusByteLength
    )

    $zz = [System.Numerics.BigInteger]::ModPow($TheirPublicValue, $OurPrivateExponent, $P)
    $bytes = ConvertTo-BigEndianBytes -Value $zz
    if ($bytes.Length -lt $ModulusByteLength)
    {
        $padded = New-Object byte[] $ModulusByteLength
        [Array]::Copy($bytes, 0, $padded, $ModulusByteLength - $bytes.Length, $bytes.Length)
        $bytes = $padded
    }
    return $bytes
}

function ConvertTo-DhSubjectPublicKeyInfo
{
    <#
        .SYNOPSIS
        Builds the clientPublicValue [1] SubjectPublicKeyInfo field of AuthPack for
        the Diffie-Hellman case, per RFC 3279 section 2.3.3.

        SubjectPublicKeyInfo ::= SEQUENCE {
            algorithm AlgorithmIdentifier { id-dhpublicnumber, DomainParameters },
            subjectPublicKey BIT STRING -- DER INTEGER(y), wrapped
        }
        DomainParameters ::= SEQUENCE { p INTEGER, g INTEGER, q INTEGER }
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [PSObject]$DhKeyPair
    )

    $domainParams = ConvertTo-Asn1Sequence -Children @(
        (ConvertTo-Asn1Integer -Bytes (ConvertTo-BigEndianBytes -Value $DhKeyPair.P))
        (ConvertTo-Asn1Integer -Bytes (ConvertTo-BigEndianBytes -Value $DhKeyPair.G))
        (ConvertTo-Asn1Integer -Bytes (ConvertTo-BigEndianBytes -Value $DhKeyPair.Q))
    )

    $algorithmIdentifier = ConvertTo-Asn1Sequence -Children @(
        (ConvertTo-Asn1Oid -Dotted '1.2.840.10046.2.1')
        $domainParams
    )

    $publicValueInteger = ConvertTo-Asn1Integer -Bytes (ConvertTo-BigEndianBytes -Value $DhKeyPair.PublicValue)
    $subjectPublicKey = ConvertTo-Asn1BitString -Bytes $publicValueInteger

    return ConvertTo-Asn1Sequence -Children @($algorithmIdentifier, $subjectPublicKey)
}

function New-PkinitAuthPack
{
    <#
        .SYNOPSIS
        Builds the DER-encoded AuthPack (RFC 4556 3.2.1) for the Diffie-Hellman
        key delivery method: PKAuthenticator + clientPublicValue.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$KdcReqBody,
        [Parameter(Mandatory)] [uint32]$Nonce,
        [Parameter(Mandatory)] [PSObject]$DhKeyPair,
        [Parameter()] [datetime]$Time = (Get-Date).ToUniversalTime()
    )

    $paChecksum = [System.Security.Cryptography.SHA1]::Create().ComputeHash($KdcReqBody)
    $cusec = $Time.Millisecond * 1000

    $pkAuthenticator = ConvertTo-Asn1Sequence -Children @(
        (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-Asn1Integer -Value ([long]$cusec)))
        (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1GeneralizedTime -Value $Time))
        (ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1Integer -Value ([long]$Nonce)))
        (ConvertTo-Asn1ContextExplicit -TagNumber 3 -InnerTlv (ConvertTo-Asn1OctetString -Bytes $paChecksum))
    )

    $clientPublicValue = ConvertTo-DhSubjectPublicKeyInfo -DhKeyPair $DhKeyPair

    return ConvertTo-Asn1Sequence -Children @(
        (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv $pkAuthenticator)
        (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv $clientPublicValue)
    )
}

function New-PkinitSignedAuthPack
{
    <#
        .SYNOPSIS
        CMS SignedData-wraps an AuthPack using the client's certificate (RFC 4556
        3.2.1 items 1-7), via .NET's SignedCms so we don't have to hand-roll CMS.
        Returns the DER-encoded ContentInfo bytes to place in PA-PK-AS-REQ's
        signedAuthPack [0] IMPLICIT OCTET STRING field.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$AuthPack,
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter()] [System.Security.Cryptography.Oid]$DigestAlgorithm = [System.Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1') # SHA-256
    )

    $idPkinitAuthData = '1.3.6.1.5.2.3.1'
    $contentInfo = [System.Security.Cryptography.Pkcs.ContentInfo]::new(
        [System.Security.Cryptography.Oid]::new($idPkinitAuthData),
        $AuthPack
    )

    $signedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $false)
    $signer = [System.Security.Cryptography.Pkcs.CmsSigner]::new(
        [System.Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,
        $Certificate
    )
    $signer.DigestAlgorithm = $DigestAlgorithm
    $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly

    $signedCms.ComputeSignature($signer, $false)

    return $signedCms.Encode()
}

function New-PkinitPaData
{
    <#
        .SYNOPSIS
        Builds the PA_PK_AS_REQ (padata-type 16) PA-DATA element:
        PA-PK-AS-REQ ::= SEQUENCE { signedAuthPack [0] IMPLICIT OCTET STRING }
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$SignedAuthPack
    )

    $paPkAsReq = ConvertTo-Asn1Sequence -Children @(
        (ConvertTo-Asn1ContextImplicitPrimitive -TagNumber 0 -Content $SignedAuthPack)
    )

    return New-PaData -PaDataType 16 -PaDataValue $paPkAsReq
}

function ConvertFrom-PkinitDhRepInfo
{
    <#
        .SYNOPSIS
        Parses the PA-PK-AS-REP (padata-type 17) padata-value for the
        Diffie-Hellman case (RFC 4556 3.2.3):

        PA-PK-AS-REP ::= CHOICE {
            dhInfo      [0] DHRepInfo,
            encKeyPack  [1] IMPLICIT OCTET STRING
        }
        DHRepInfo ::= SEQUENCE {
            dhSignedData   [0] IMPLICIT OCTET STRING,
            serverDHNonce  [1] DHNonce OPTIONAL
        }

        Only the dhInfo choice (tag [0]) is supported, since this module only
        implements the Diffie-Hellman key delivery method - throws if the KDC
        instead chose encKeyPack (tag [1], the key-transport/reuse case).

        .OUTPUTS
        PSCustomObject with DhSignedData (byte[], the raw CMS ContentInfo DER
        to pass to ConvertFrom-PkinitKdcDhKeyInfo) and ServerDHNonce
        (byte[] or $null, only present when DH key reuse was negotiated).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$PaDataValue
    )

    $choice = Read-Asn1Tlv -Bytes $PaDataValue -Offset 0
    $choiceTagNumber = $choice.Tag -band 0x1f
    if ($choiceTagNumber -ne 0)
    {
        throw "ConvertFrom-PkinitDhRepInfo: expected the dhInfo choice (tag [0]), got tag number $choiceTagNumber (encKeyPack is not supported by this module)."
    }

    $dhRepInfoSeq = Read-Asn1Tlv -Bytes $choice.Content -Offset 0
    $fields = Read-Asn1Sequence -Content $dhRepInfoSeq.Content

    $result = [PSCustomObject]@{ DhSignedData = $null; ServerDHNonce = $null }
    foreach ($field in $fields)
    {
        $tagNumber = $field.Tag -band 0x1f
        switch ($tagNumber)
        {
            0 { $result.DhSignedData = $field.Content }
            1 { $result.ServerDHNonce = $field.Content }
            default { }
        }
    }

    return $result
}

function ConvertFrom-PkinitKdcDhKeyInfo
{
    <#
        .SYNOPSIS
        Decodes the CMS SignedData carried in DHRepInfo.dhSignedData (content
        type id-pkinit-DHKeyData, RFC 4556 3.2.3.1) via .NET's SignedCms, then
        parses its inner content:

        KDCDHKeyInfo ::= SEQUENCE {
            subjectPublicKey  [0] BIT STRING,       -- DER INTEGER(y), wrapped
            nonce             [1] INTEGER (0..4294967295),
            dhKeyExpiration   [2] KerberosTime OPTIONAL
        }

        .PARAMETER SkipSignatureVerification
        By default the CMS signature is cryptographically verified (but the
        signer certificate's chain/revocation status is NOT checked, since
        this module does not manage a trust store for the lab KDC's cert).
        Set this switch to skip signature verification entirely.

        .OUTPUTS
        PSCustomObject with ServerPublicValue (BigInteger), Nonce (uint32),
        and SignerCertificate (X509Certificate2, the KDC's PKINIT signing cert).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$DhSignedData,
        [Parameter()] [switch]$SkipSignatureVerification
    )

    $signedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
    $signedCms.Decode($DhSignedData)

    if (-not $SkipSignatureVerification)
    {
        # $true = verify the cryptographic signature only; skip cert chain/revocation checks.
        $signedCms.CheckSignature($true)
    }

    $kdcDhKeyInfo = $signedCms.ContentInfo.Content
    $seqTlv = Read-Asn1Tlv -Bytes $kdcDhKeyInfo -Offset 0
    $fields = Read-Asn1Sequence -Content $seqTlv.Content

    $result = [PSCustomObject]@{
        ServerPublicValue = $null
        Nonce = $null
        SignerCertificate = if ($signedCms.SignerInfos.Count -gt 0) { $signedCms.SignerInfos[0].Certificate } else { $null }
    }

    foreach ($field in $fields)
    {
        $tagNumber = $field.Tag -band 0x1f
        $inner = Read-Asn1Tlv -Bytes $field.Content -Offset 0
        switch ($tagNumber)
        {
            0
            {
                # subjectPublicKey BIT STRING wraps a DER INTEGER: [unused-bits octet][INTEGER TLV].
                $integerTlv = Read-Asn1Tlv -Bytes $inner.Content -Offset 1
                $result.ServerPublicValue = ConvertTo-UnsignedBigInteger -BigEndianBytes $integerTlv.Content
            }
            1 { $result.Nonce = [uint32](ConvertFrom-Asn1Integer -Content $inner.Content) }
            default { }
        }
    }

    return $result
}

