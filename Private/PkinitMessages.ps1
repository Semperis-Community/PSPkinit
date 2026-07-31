<#
    Kerberos (RFC 4120) and PKINIT (RFC 4556) message construction and parsing,
    built on the DER helpers in Asn1.ps1.
#>

function ConvertTo-KerberosPrincipalName {
    <#
        .SYNOPSIS
        PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [int]$NameType,
        [Parameter(Mandatory)] [string[]]$NameStrings
    )

    $nameStringChildren = $NameStrings | ForEach-Object { ConvertTo-Asn1GeneralString -Value $_ }
    $nameStringSeq = ConvertTo-Asn1Sequence -Children $nameStringChildren

    return ConvertTo-Asn1Sequence -Children @(
        (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-Asn1Integer -Value $NameType))
        (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv $nameStringSeq)
    )
}

function ConvertTo-KerberosFlags {
    <#
        .SYNOPSIS
        KerberosFlags ::= BIT STRING (SIZE(32..MAX)) - always sent as exactly 4 octets
        (32 bits) by this module since no options beyond the low 32 bits are used.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter()] [uint32]$Value = 0
    )

    $bytes = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return ConvertTo-Asn1BitString -Bytes $bytes
}

function New-KdcReqBody {
    <#
        .SYNOPSIS
        Builds a KDC-REQ-BODY (RFC 4120 section 5.4.1) for an AS-REQ.

        .PARAMETER ClientNameType
        Kerberos name-type for cname (RFC 4120 7.5.8). Defaults to NT-PRINCIPAL (1).
        For PKINIT client certificates bound via UPN (the common Windows/AD case),
        use NT-ENTERPRISE (10) with -ClientName set to the full UPN
        (e.g. 'user@adcs.goat') - a plain sAMAccountName-style name with an NT-PRINCIPAL
        type will not resolve and the KDC returns KDC_ERR_C_PRINCIPAL_UNKNOWN.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [string]$ClientName,
        [Parameter(Mandatory)] [string]$Realm,
        [Parameter(Mandatory)] [uint32]$Nonce,
        [Parameter()] [int[]]$EncryptionTypes = @(18, 17),
        [Parameter()] [uint32]$KdcOptions = 0,
        [Parameter()] [int]$ClientNameType = 1
    )

    $sname = ConvertTo-KerberosPrincipalName -NameType 2 -NameStrings @('krbtgt', $Realm)
    $cname = ConvertTo-KerberosPrincipalName -NameType $ClientNameType -NameStrings @($ClientName)

    # Special epoch value meaning "the maximum endtime permitted by KDC policy" (RFC 4120 5.4.1).
    $till = [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)

    $etypeChildren = $EncryptionTypes | ForEach-Object { ConvertTo-Asn1Integer -Value $_ }

    $children = @(
        (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-KerberosFlags -Value $KdcOptions))
        (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv $cname)
        (ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1GeneralString -Value $Realm))
        (ConvertTo-Asn1ContextExplicit -TagNumber 3 -InnerTlv $sname)
        (ConvertTo-Asn1ContextExplicit -TagNumber 5 -InnerTlv (ConvertTo-Asn1GeneralizedTime -Value $till))
        (ConvertTo-Asn1ContextExplicit -TagNumber 7 -InnerTlv (ConvertTo-Asn1Integer -Value ([long]$Nonce)))
        (ConvertTo-Asn1ContextExplicit -TagNumber 8 -InnerTlv (ConvertTo-Asn1Sequence -Children $etypeChildren))
    )

    return ConvertTo-Asn1Sequence -Children $children
}

function New-AsReq {
    <#
        .SYNOPSIS
        Builds a complete AS-REQ ::= [APPLICATION 10] KDC-REQ, with optional PA-DATA.

        .PARAMETER PaData
        Array of already-encoded PA-DATA TLVs (see New-PaData) to include in the
        padata [3] field. May be empty/omitted for an unauthenticated first request.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$KdcReqBody,
        [Parameter()] [byte[][]]$PaData = @()
    )

    $children = [System.Collections.Generic.List[byte[]]]::new()
    $children.Add((ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1Integer -Value 5)))
    $children.Add((ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1Integer -Value 10)))
    if ($PaData.Count -gt 0) {
        $paDataSeq = ConvertTo-Asn1Sequence -Children $PaData
        $children.Add((ConvertTo-Asn1ContextExplicit -TagNumber 3 -InnerTlv $paDataSeq))
    }
    $children.Add((ConvertTo-Asn1ContextExplicit -TagNumber 4 -InnerTlv $KdcReqBody))

    $kdcReq = ConvertTo-Asn1Sequence -Children $children.ToArray()
    return ConvertTo-Asn1ApplicationConstructed -TagNumber 10 -InnerTlv $kdcReq
}

function New-PaData {
    <#
        .SYNOPSIS
        PA-DATA ::= SEQUENCE { padata-type [1] Int32, padata-value [2] OCTET STRING }
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [int]$PaDataType,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]]$PaDataValue
    )

    return ConvertTo-Asn1Sequence -Children @(
        (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1Integer -Value $PaDataType))
        (ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1OctetString -Bytes $PaDataValue))
    )
}

function Send-KerberosTcpMessage {
    <#
        .SYNOPSIS
        Sends a DER-encoded Kerberos message to a KDC over TCP (RFC 4120 7.2.2:
        4-byte big-endian length prefix, high bit reserved/zero) and returns the
        raw response message bytes (length prefix stripped).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [string]$KdcHostname,
        [Parameter()] [int]$Port = 88,
        [Parameter(Mandatory)] [byte[]]$Message,
        [Parameter()] [int]$TimeoutSeconds = 10
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connectTask = $client.ConnectAsync($KdcHostname, $Port)
        if (-not $connectTask.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            throw "Timed out connecting to $KdcHostname`:$Port"
        }

        $stream = $client.GetStream()

        $lengthPrefix = [BitConverter]::GetBytes([uint32]$Message.Length)
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($lengthPrefix)
        }
        $stream.Write($lengthPrefix, 0, 4)
        $stream.Write($Message, 0, $Message.Length)
        $stream.Flush()

        $lengthBuffer = New-Object byte[] 4
        $readTotal = 0
        while ($readTotal -lt 4) {
            $readTask = $stream.ReadAsync($lengthBuffer, $readTotal, 4 - $readTotal)
            if (-not $readTask.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
                throw "Timed out reading response length from $KdcHostname`:$Port"
            }
            $n = $readTask.Result
            if ($n -eq 0) { throw 'Connection closed while reading response length.' }
            $readTotal += $n
        }
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($lengthBuffer)
        }
        $responseLength = [BitConverter]::ToUInt32($lengthBuffer, 0)

        $responseBuffer = New-Object byte[] $responseLength
        $readTotal = 0
        while ($readTotal -lt $responseLength) {
            $readTask = $stream.ReadAsync($responseBuffer, $readTotal, $responseLength - $readTotal)
            if (-not $readTask.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
                throw "Timed out reading response body from $KdcHostname`:$Port"
            }
            $n = $readTask.Result
            if ($n -eq 0) { throw 'Connection closed while reading response body.' }
            $readTotal += $n
        }

        return $responseBuffer
    } finally {
        $client.Dispose()
    }
}

function ConvertFrom-PaData {
    <#
        .SYNOPSIS
        Decodes a single PA-DATA element (RFC 4120 5.2.7:
        SEQUENCE { padata-type [1] Int32, padata-value [2] OCTET STRING })
        into its type number and raw value bytes.

        .PARAMETER Content
        The content bytes of the PA-DATA SEQUENCE TLV (i.e. Read-Asn1Tlv's
        .Content for a single child of the padata SEQUENCE OF).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$Content
    )

    $fields = Read-Asn1Sequence -Content $Content
    $result = [PSCustomObject]@{ Type = $null; Value = $null }
    foreach ($field in $fields) {
        $tagNumber = $field.Tag -band 0x1f
        $inner = Read-Asn1Tlv -Bytes $field.Content -Offset 0
        switch ($tagNumber) {
            1 { $result.Type = [int](ConvertFrom-Asn1Integer -Content $inner.Content) }
            2 { $result.Value = $inner.Content }
            default { }
        }
    }
    return $result
}

function ConvertFrom-KerberosPrincipalName {
    <#
        .SYNOPSIS
        Decodes a PrincipalName (RFC 4120 5.2.2) into its name-type and
        name-string components.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$Content
    )

    $fields = Read-Asn1Sequence -Content $Content
    $result = [PSCustomObject]@{ NameType = $null; NameStrings = @() }
    foreach ($field in $fields) {
        $tagNumber = $field.Tag -band 0x1f
        $inner = Read-Asn1Tlv -Bytes $field.Content -Offset 0
        switch ($tagNumber) {
            0 { $result.NameType = [int](ConvertFrom-Asn1Integer -Content $inner.Content) }
            1 {
                $strs = Read-Asn1Sequence -Content $inner.Content
                $result.NameStrings = @($strs | ForEach-Object { ConvertFrom-Asn1GeneralString -Content $_.Content })
            }
            default { }
        }
    }
    return $result
}

function ConvertFrom-EncryptedData {
    <#
        .SYNOPSIS
        Decodes an EncryptedData (RFC 4120 5.2.9:
        SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$Content
    )

    $fields = Read-Asn1Sequence -Content $Content
    $result = [PSCustomObject]@{ EType = $null; Kvno = $null; Cipher = $null }
    foreach ($field in $fields) {
        $tagNumber = $field.Tag -band 0x1f
        $inner = Read-Asn1Tlv -Bytes $field.Content -Offset 0
        switch ($tagNumber) {
            0 { $result.EType = [int](ConvertFrom-Asn1Integer -Content $inner.Content) }
            1 { $result.Kvno = [int](ConvertFrom-Asn1Integer -Content $inner.Content) }
            2 { $result.Cipher = $inner.Content }
            default { }
        }
    }
    return $result
}

function ConvertFrom-KdcRep {
    <#
        .SYNOPSIS
        Parses a KDC-REP (RFC 4120 5.4.2 - AS-REP or TGS-REP) into its
        component fields.

        .PARAMETER ExpectedApplicationTag
        11 for AS-REP, 13 for TGS-REP.

        .OUTPUTS
        PSCustomObject with PvNo, MsgType, PaData (array of type/value pairs
        from ConvertFrom-PaData), CRealm, CName (from ConvertFrom-KerberosPrincipalName),
        Ticket (raw [APPLICATION 1] Ticket TLV bytes, opaque/encrypted under the
        service key - not decodable by the client), and EncPart (from ConvertFrom-EncryptedData).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$Message,
        [Parameter(Mandatory)] [int]$ExpectedApplicationTag
    )

    $outer = Read-Asn1Tlv -Bytes $Message -Offset 0
    $expectedTag = [byte](0x60 -bor $ExpectedApplicationTag)
    if ($outer.Tag -ne $expectedTag) {
        throw ("ConvertFrom-KdcRep: expected [APPLICATION {0}] (tag 0x{1:X2}), got tag 0x{2:X2}." -f $ExpectedApplicationTag, $expectedTag, $outer.Tag)
    }
    $seqTlv = Read-Asn1Tlv -Bytes $outer.Content -Offset 0
    $fields = Read-Asn1Sequence -Content $seqTlv.Content

    $result = [PSCustomObject]@{
        PvNo    = $null
        MsgType = $null
        PaData  = @()
        CRealm  = $null
        CName   = $null
        Ticket  = $null
        EncPart = $null
    }

    foreach ($field in $fields) {
        $tagNumber = $field.Tag -band 0x1f
        $inner = Read-Asn1Tlv -Bytes $field.Content -Offset 0
        switch ($tagNumber) {
            0 { $result.PvNo = [int](ConvertFrom-Asn1Integer -Content $inner.Content) }
            1 { $result.MsgType = [int](ConvertFrom-Asn1Integer -Content $inner.Content) }
            2 {
                $paSeq = Read-Asn1Sequence -Content $inner.Content
                $result.PaData = @($paSeq | ForEach-Object { ConvertFrom-PaData -Content $_.Content })
            }
            3 { $result.CRealm = ConvertFrom-Asn1GeneralString -Content $inner.Content }
            4 { $result.CName = ConvertFrom-KerberosPrincipalName -Content $inner.Content }
            5 { $result.Ticket = $field.Content }
            6 { $result.EncPart = ConvertFrom-EncryptedData -Content $inner.Content }
            default { }
        }
    }

    return $result
}

function ConvertFrom-EncKdcRepPart {
    <#
        .SYNOPSIS
        Parses a decrypted EncKDCRepPart (RFC 4120 5.4.2 - the plaintext
        recovered from an AS-REP/TGS-REP's enc-part).

        .PARAMETER ExpectedApplicationTag
        25 for EncASRepPart, 26 for EncTGSRepPart.

        .OUTPUTS
        PSCustomObject with Key (@{ KeyType; KeyValue }), Nonce, Flags (uint32
        TicketFlags), AuthTime, StartTime, EndTime, RenewTill (datetime or $null),
        SRealm, and SName (from ConvertFrom-KerberosPrincipalName).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$Message,
        [Parameter(Mandatory)] [int]$ExpectedApplicationTag
    )

    $outer = Read-Asn1Tlv -Bytes $Message -Offset 0
    $expectedTag = [byte](0x60 -bor $ExpectedApplicationTag)
    if ($outer.Tag -ne $expectedTag) {
        throw ("ConvertFrom-EncKdcRepPart: expected [APPLICATION {0}] (tag 0x{1:X2}), got tag 0x{2:X2}." -f $ExpectedApplicationTag, $expectedTag, $outer.Tag)
    }
    $seqTlv = Read-Asn1Tlv -Bytes $outer.Content -Offset 0
    $fields = Read-Asn1Sequence -Content $seqTlv.Content

    $result = [PSCustomObject]@{
        Key       = $null
        Nonce     = $null
        Flags     = $null
        AuthTime  = $null
        StartTime = $null
        EndTime   = $null
        RenewTill = $null
        SRealm    = $null
        SName     = $null
    }

    foreach ($field in $fields) {
        $tagNumber = $field.Tag -band 0x1f
        $inner = Read-Asn1Tlv -Bytes $field.Content -Offset 0
        switch ($tagNumber) {
            0 {
                $keyFields = Read-Asn1Sequence -Content $inner.Content
                $keyType = $null
                $keyValue = $null
                foreach ($kf in $keyFields) {
                    $kfTag = $kf.Tag -band 0x1f
                    $kfInner = Read-Asn1Tlv -Bytes $kf.Content -Offset 0
                    if ($kfTag -eq 0) { $keyType = [int](ConvertFrom-Asn1Integer -Content $kfInner.Content) }
                    if ($kfTag -eq 1) { $keyValue = $kfInner.Content }
                }
                $result.Key = [PSCustomObject]@{ KeyType = $keyType; KeyValue = $keyValue }
            }
            2 { $result.Nonce = [uint32](ConvertFrom-Asn1Integer -Content $inner.Content) }
            4 {
                $bits = $inner.Content
                $flagBytes = if ($bits.Length -gt 1) { [byte[]]$bits[1..($bits.Length - 1)] } else { [byte[]]@() }
                if ($flagBytes.Length -lt 4) {
                    $padded = New-Object byte[] 4
                    [Array]::Copy($flagBytes, 0, $padded, 0, $flagBytes.Length)
                    $flagBytes = $padded
                }
                $be = [byte[]]$flagBytes[0..3]
                if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($be) }
                $result.Flags = [BitConverter]::ToUInt32($be, 0)
            }
            5 { $result.AuthTime = ConvertFrom-Asn1GeneralizedTime -Content $inner.Content }
            6 { $result.StartTime = ConvertFrom-Asn1GeneralizedTime -Content $inner.Content }
            7 { $result.EndTime = ConvertFrom-Asn1GeneralizedTime -Content $inner.Content }
            8 { $result.RenewTill = ConvertFrom-Asn1GeneralizedTime -Content $inner.Content }
            9 { $result.SRealm = ConvertFrom-Asn1GeneralString -Content $inner.Content }
            10 { $result.SName = ConvertFrom-KerberosPrincipalName -Content $inner.Content }
            default { }
        }
    }

    return $result
}

function ConvertFrom-KrbError {
    <#
        .SYNOPSIS
        Parses a KRB-ERROR ::= [APPLICATION 30] SEQUENCE (RFC 4120 5.9.1) into a
        PSCustomObject with the fields most useful for diagnostics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$Message
    )

    $outer = Read-Asn1Tlv -Bytes $Message -Offset 0
    if ($outer.Tag -ne 0x7e) {
        throw ("ConvertFrom-KrbError: expected [APPLICATION 30] (tag 0x7E), got tag 0x{0:X2}." -f $outer.Tag)
    }
    $seqTlv = Read-Asn1Tlv -Bytes $outer.Content -Offset 0
    $fields = Read-Asn1Sequence -Content $seqTlv.Content

    $result = [PSCustomObject]@{
        ErrorCode = $null
        ErrorText = $null
        CRealm    = $null
        CName     = $null
        Realm     = $null
        SName     = $null
    }

    foreach ($field in $fields) {
        $tagNumber = $field.Tag -band 0x1f
        $inner = Read-Asn1Tlv -Bytes $field.Content -Offset 0
        switch ($tagNumber) {
            6 { $result.ErrorCode = ConvertFrom-Asn1Integer -Content $inner.Content }
            9 { $result.Realm = ConvertFrom-Asn1GeneralString -Content $inner.Content }
            11 { $result.ErrorText = ConvertFrom-Asn1GeneralString -Content $inner.Content }
            default { }
        }
    }

    return $result
}
