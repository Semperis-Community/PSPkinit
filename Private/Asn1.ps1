<#
    Minimal DER (Distinguished Encoding Rules) ASN.1 encode/decode helpers, sufficient
    for the Kerberos (RFC 4120) and PKINIT (RFC 4556) structures used by this module.

    The Kerberos ASN.1 modules are declared "DEFINITIONS EXPLICIT TAGS", so unless a
    field is explicitly marked IMPLICIT in the module text, context tags wrap a
    complete inner TLV (tag+length+value) rather than replacing the universal tag.
#>

function Get-Asn1LengthBytes {
    <#
        .SYNOPSIS
        DER length-of-length encoding for a given content length.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [int]$Length
    )

    if ($Length -lt 0) {
        throw "Length cannot be negative: $Length"
    }

    if ($Length -lt 0x80) {
        return [byte[]]@([byte]$Length)
    }

    $bytes = [System.Collections.Generic.List[byte]]::new()
    $remaining = $Length
    while ($remaining -gt 0) {
        $bytes.Insert(0, [byte]($remaining -band 0xff))
        $remaining = $remaining -shr 8
    }
    return [byte[]]@([byte](0x80 -bor $bytes.Count)) + $bytes.ToArray()
}

function New-Asn1Tlv {
    <#
        .SYNOPSIS
        Builds a single DER TLV (tag, length, value) from a raw tag byte and content.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte]$Tag,
        [Parameter()] [byte[]]$Content = @()
    )

    $lengthBytes = Get-Asn1LengthBytes -Length $Content.Length
    return [byte[]]@($Tag) + $lengthBytes + $Content
}

function ConvertTo-Asn1Integer {
    <#
        .SYNOPSIS
        DER INTEGER encoding (tag 0x02) from a non-negative value, expressed as
        minimal big-endian two's-complement bytes (leading 0x00 added if the
        high bit of the most significant byte would otherwise be set).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Int64')] [long]$Value,
        [Parameter(Mandatory, ParameterSetName = 'Bytes')] [byte[]]$Bytes
    )

    if ($PSCmdlet.ParameterSetName -eq 'Int64') {
        if ($Value -lt 0) {
            throw "ConvertTo-Asn1Integer only supports non-negative Int64 values; got $Value."
        }
        $Bytes = [System.Numerics.BigInteger]::new($Value).ToByteArray()
        [Array]::Reverse($Bytes)
        # BigInteger.ToByteArray() is little-endian and already includes a sign byte
        # when needed; after reversing to big-endian, strip any redundant leading
        # 0x00 bytes beyond the one needed to keep the value non-negative.
        while ($Bytes.Length -gt 1 -and $Bytes[0] -eq 0 -and $Bytes[1] -lt 0x80) {
            $Bytes = $Bytes[1..($Bytes.Length - 1)]
        }
    }

    if ($Bytes.Length -eq 0) {
        $Bytes = [byte[]]@(0)
    } elseif ($Bytes[0] -ge 0x80) {
        $Bytes = [byte[]]@(0) + $Bytes
    }

    return New-Asn1Tlv -Tag 0x02 -Content $Bytes
}

function ConvertTo-Asn1OctetString {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]]$Bytes
    )

    return New-Asn1Tlv -Tag 0x04 -Content $Bytes
}

function ConvertTo-Asn1BitString {
    <#
        .SYNOPSIS
        DER BIT STRING encoding (tag 0x03). Content is prefixed with a single
        "unused bits" octet (0 for byte-aligned data, which is all Kerberos/PKINIT
        uses this for: DH public values and signatures).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$Bytes,
        [Parameter()] [byte]$UnusedBits = 0
    )

    return New-Asn1Tlv -Tag 0x03 -Content ([byte[]]@($UnusedBits) + $Bytes)
}

function ConvertTo-Asn1GeneralString {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [string]$Value
    )

    return New-Asn1Tlv -Tag 0x1B -Content ([System.Text.Encoding]::ASCII.GetBytes($Value))
}

function ConvertTo-Asn1GeneralizedTime {
    <#
        .SYNOPSIS
        KerberosTime encoding: GeneralizedTime with no fractional seconds, UTC ("Z").
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [datetime]$Value
    )

    $utc = $Value.ToUniversalTime()
    $text = $utc.ToString('yyyyMMddHHmmss') + 'Z'
    return New-Asn1Tlv -Tag 0x18 -Content ([System.Text.Encoding]::ASCII.GetBytes($text))
}

function ConvertTo-Asn1Oid {
    <#
        .SYNOPSIS
        DER OBJECT IDENTIFIER encoding (tag 0x06) from dotted-decimal notation.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [string]$Dotted
    )

    $arcs = $Dotted.Split('.') | ForEach-Object { [long]$_ }
    if ($arcs.Count -lt 2) {
        throw "OID must have at least two arcs: $Dotted"
    }

    $content = [System.Collections.Generic.List[byte]]::new()
    $content.Add([byte](($arcs[0] * 40) + $arcs[1]))

    for ($i = 2; $i -lt $arcs.Count; $i++) {
        $arc = [long]$arcs[$i]
        $arcBytes = [System.Collections.Generic.List[byte]]::new()
        $arcBytes.Add([byte]($arc -band 0x7f))
        $arc = $arc -shr 7
        while ($arc -gt 0) {
            $arcBytes.Insert(0, [byte](0x80 -bor ($arc -band 0x7f)))
            $arc = $arc -shr 7
        }
        $content.AddRange($arcBytes)
    }

    return New-Asn1Tlv -Tag 0x06 -Content $content.ToArray()
}

function ConvertTo-Asn1Sequence {
    <#
        .SYNOPSIS
        Wraps a set of already-encoded child TLVs in a DER SEQUENCE (tag 0x30).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter()] [byte[][]]$Children = @()
    )

    $content = [System.Collections.Generic.List[byte]]::new()
    foreach ($child in $Children) {
        if ($null -ne $child -and $child.Length -gt 0) {
            $content.AddRange($child)
        }
    }
    return New-Asn1Tlv -Tag 0x30 -Content $content.ToArray()
}

function ConvertTo-Asn1ContextExplicit {
    <#
        .SYNOPSIS
        Wraps an already-encoded inner TLV in an EXPLICIT context-specific
        constructed tag ([N] under a DEFINITIONS EXPLICIT TAGS module).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [ValidateRange(0, 30)] [int]$TagNumber,
        [Parameter(Mandatory)] [byte[]]$InnerTlv
    )

    return New-Asn1Tlv -Tag ([byte](0xA0 -bor $TagNumber)) -Content $InnerTlv
}

function ConvertTo-Asn1ContextImplicitPrimitive {
    <#
        .SYNOPSIS
        Encodes content under an IMPLICIT primitive context-specific tag ([N] IMPLICIT
        OCTET STRING, etc.), replacing the universal tag entirely rather than wrapping it.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [ValidateRange(0, 30)] [int]$TagNumber,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]]$Content
    )

    return New-Asn1Tlv -Tag ([byte](0x80 -bor $TagNumber)) -Content $Content
}

function ConvertTo-Asn1ApplicationConstructed {
    <#
        .SYNOPSIS
        Wraps an already-encoded inner TLV (typically a SEQUENCE) in an
        [APPLICATION N] constructed tag, e.g. AS-REQ ::= [APPLICATION 10] KDC-REQ.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [ValidateRange(0, 30)] [int]$TagNumber,
        [Parameter(Mandatory)] [byte[]]$InnerTlv
    )

    return New-Asn1Tlv -Tag ([byte](0x60 -bor $TagNumber)) -Content $InnerTlv
}

function Read-Asn1Tlv {
    <#
        .SYNOPSIS
        Reads a single DER TLV from a byte array starting at Offset, returning the
        tag byte, the content bytes, and the offset immediately following the TLV.
        Supports single-byte tags (0-30) and both short- and long-form DER lengths,
        which is sufficient for every structure defined in RFC 4120 / RFC 4556.

        .OUTPUTS
        PSCustomObject with Tag ([byte]), Content ([byte[]]), and NextOffset ([int]).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$Bytes,
        [Parameter(Mandatory)] [int]$Offset
    )

    if ($Offset -ge $Bytes.Length) {
        throw "Read-Asn1Tlv: offset $Offset is at or past end of buffer (length $($Bytes.Length))."
    }

    $tag = $Bytes[$Offset]
    if (($tag -band 0x1f) -eq 0x1f) {
        throw 'Read-Asn1Tlv: multi-byte (high) tag numbers are not supported.'
    }
    $pos = $Offset + 1

    $lengthByte = $Bytes[$pos]
    $pos++
    if ($lengthByte -lt 0x80) {
        $length = [int]$lengthByte
    } else {
        $numLengthBytes = $lengthByte -band 0x7f
        if ($numLengthBytes -eq 0) {
            throw 'Read-Asn1Tlv: indefinite-length DER encodings are not supported.'
        }
        $length = 0
        for ($i = 0; $i -lt $numLengthBytes; $i++) {
            $length = ($length -shl 8) -bor $Bytes[$pos]
            $pos++
        }
    }

    if ($pos + $length -gt $Bytes.Length) {
        throw "Read-Asn1Tlv: declared length $length at offset $pos exceeds buffer length $($Bytes.Length)."
    }

    $content = if ($length -eq 0) { [byte[]]@() } else { $Bytes[$pos..($pos + $length - 1)] }

    return [PSCustomObject]@{
        Tag        = $tag
        Content    = $content
        NextOffset = $pos + $length
    }
}

function Read-Asn1Sequence {
    <#
        .SYNOPSIS
        Parses the content of a SEQUENCE (or SEQUENCE OF) TLV into a list of its
        immediate child TLVs.

        .OUTPUTS
        Array of the same PSCustomObject shape returned by Read-Asn1Tlv.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$Content
    )

    $children = [System.Collections.Generic.List[object]]::new()
    $offset = 0
    while ($offset -lt $Content.Length) {
        $tlv = Read-Asn1Tlv -Bytes $Content -Offset $offset
        $children.Add($tlv)
        $offset = $tlv.NextOffset
    }
    return $children.ToArray()
}

function ConvertFrom-Asn1Integer {
    <#
        .SYNOPSIS
        Decodes DER INTEGER content bytes (big-endian two's complement) to a
        signed 64-bit integer.
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)] [byte[]]$Content
    )

    $be = [byte[]]$Content.Clone()
    [Array]::Reverse($be)
    $big = [System.Numerics.BigInteger]::new($be)
    return [long]$big
}

function ConvertFrom-Asn1GeneralizedTime {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory)] [byte[]]$Content
    )

    $text = [System.Text.Encoding]::ASCII.GetString($Content)
    return [datetime]::ParseExact($text, 'yyyyMMddHHmmss\Z', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
}

function ConvertFrom-Asn1GeneralString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [byte[]]$Content
    )

    return [System.Text.Encoding]::ASCII.GetString($Content)
}
