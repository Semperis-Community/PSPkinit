<#
    .SYNOPSIS
    Pester tests for ASN.1 helper functions.
#>

BeforeAll {
    . $PSScriptRoot/../Private/Asn1.ps1
}

Describe 'ConvertTo-Asn1Integer' {
    It 'encodes 0 as 02 01 00' {
        [BitConverter]::ToString((ConvertTo-Asn1Integer -Value 0)).Replace('-', '') | Should -Be '020100'
    }

    It 'encodes 5 as 02 01 05' {
        [BitConverter]::ToString((ConvertTo-Asn1Integer -Value 5)).Replace('-', '') | Should -Be '020105'
    }

    It 'encodes 128 with a leading zero pad (high bit of 0x80 would look negative)' {
        [BitConverter]::ToString((ConvertTo-Asn1Integer -Value 128)).Replace('-', '') | Should -Be '02020080'
    }

    It 'encodes 256 as 02 02 01 00' {
        [BitConverter]::ToString((ConvertTo-Asn1Integer -Value 256)).Replace('-', '') | Should -Be '02020100'
    }

    It 'round-trips through ConvertFrom-Asn1Integer' {
        $tlv = ConvertTo-Asn1Integer -Value 123456789
        $parsed = Read-Asn1Tlv -Bytes $tlv -Offset 0
        ConvertFrom-Asn1Integer -Content $parsed.Content | Should -Be 123456789
    }
}

Describe 'ConvertTo-Asn1OctetString' {
    It 'encodes "AB" as 04 02 41 42' {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes('AB')
        [BitConverter]::ToString((ConvertTo-Asn1OctetString -Bytes $bytes)).Replace('-', '') | Should -Be '04024142'
    }

    It 'encodes empty content as 04 00' {
        [BitConverter]::ToString((ConvertTo-Asn1OctetString -Bytes @())).Replace('-', '') | Should -Be '0400'
    }
}

Describe 'ConvertTo-Asn1Sequence' {
    It 'encodes an empty sequence as 30 00' {
        [BitConverter]::ToString((ConvertTo-Asn1Sequence -Children @())).Replace('-', '') | Should -Be '3000'
    }

    It 'wraps children and sums their lengths' {
        $child1 = ConvertTo-Asn1Integer -Value 1
        $child2 = ConvertTo-Asn1Integer -Value 2
        $seq = ConvertTo-Asn1Sequence -Children @($child1, $child2)
        [BitConverter]::ToString($seq).Replace('-', '') | Should -Be '3006020101020102'
    }
}

Describe 'ConvertTo-Asn1Oid' {
    It 'encodes id-pkinit-authData (1.3.6.1.5.2.3.1) correctly' {
        [BitConverter]::ToString((ConvertTo-Asn1Oid -Dotted '1.3.6.1.5.2.3.1')).Replace('-', '') | Should -Be '06072b060105020301'
    }

    It 'encodes a well-known long OID with a multi-byte arc (sha256, 2.16.840.1.101.3.4.2.1)' {
        # 840 encodes to two base-128 bytes: 0x86 0x48
        [BitConverter]::ToString((ConvertTo-Asn1Oid -Dotted '2.16.840.1.101.3.4.2.1')).Replace('-', '') | Should -Be '0609608648016503040201'
    }
}

Describe 'Context and application tag wrapping' {
    It 'ConvertTo-Asn1ContextExplicit wraps with 0xA0-0xBE tags' {
        $inner = ConvertTo-Asn1Integer -Value 5
        $wrapped = ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv $inner
        [BitConverter]::ToString($wrapped).Replace('-', '') | Should -Be 'a003020105'
    }

    It 'ConvertTo-Asn1ContextImplicitPrimitive replaces the tag entirely' {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes('hi')
        $wrapped = ConvertTo-Asn1ContextImplicitPrimitive -TagNumber 0 -Content $bytes
        $expected = '8002' + [BitConverter]::ToString($bytes).Replace('-', '').ToLower()
        [BitConverter]::ToString($wrapped).Replace('-', '').ToLower() | Should -Be $expected
    }

    It 'ConvertTo-Asn1ApplicationConstructed uses 0x60-based tags' {
        $inner = ConvertTo-Asn1Sequence -Children @((ConvertTo-Asn1Integer -Value 1))
        $wrapped = ConvertTo-Asn1ApplicationConstructed -TagNumber 10 -InnerTlv $inner
        $wrapped[0] | Should -Be 0x6A
    }
}

Describe 'ConvertTo-Asn1GeneralizedTime' {
    It 'formats as yyyyMMddHHmmssZ' {
        $dt = [datetime]::new(1985, 11, 6, 21, 6, 27, [DateTimeKind]::Utc)
        $tlv = ConvertTo-Asn1GeneralizedTime -Value $dt
        $parsed = Read-Asn1Tlv -Bytes $tlv -Offset 0
        [System.Text.Encoding]::ASCII.GetString($parsed.Content) | Should -Be '19851106210627Z'
    }

    It 'round-trips through ConvertFrom-Asn1GeneralizedTime' {
        $dt = [datetime]::new(2026, 7, 9, 12, 0, 0, [DateTimeKind]::Utc)
        $tlv = ConvertTo-Asn1GeneralizedTime -Value $dt
        $parsed = Read-Asn1Tlv -Bytes $tlv -Offset 0
        $roundTripped = ConvertFrom-Asn1GeneralizedTime -Content $parsed.Content
        $roundTripped | Should -Be $dt
    }
}

Describe 'Read-Asn1Tlv' {
    It 'parses short-form length correctly' {
        $bytes = [byte[]](0x04, 0x02, 0x41, 0x42)
        $tlv = Read-Asn1Tlv -Bytes $bytes -Offset 0
        $tlv.Tag | Should -Be 0x04
        $tlv.Content | Should -Be ([byte[]](0x41, 0x42))
        $tlv.NextOffset | Should -Be 4
    }

    It 'parses long-form length correctly' {
        $content = New-Object byte[] 200
        $tlv = New-Asn1Tlv -Tag 0x04 -Content $content
        $parsed = Read-Asn1Tlv -Bytes $tlv -Offset 0
        $parsed.Content.Length | Should -Be 200
        $parsed.NextOffset | Should -Be $tlv.Length
    }

    It 'parses multiple sequential TLVs via Read-Asn1Sequence' {
        $seq = ConvertTo-Asn1Sequence -Children @((ConvertTo-Asn1Integer -Value 1), (ConvertTo-Asn1OctetString -Bytes @(0xAA, 0xBB)))
        $outer = Read-Asn1Tlv -Bytes $seq -Offset 0
        $children = Read-Asn1Sequence -Content $outer.Content
        $children.Count | Should -Be 2
        ConvertFrom-Asn1Integer -Content $children[0].Content | Should -Be 1
        $children[1].Content | Should -Be ([byte[]](0xAA, 0xBB))
    }
}

Describe 'ConvertTo-Asn1BitString' {
    It 'prefixes content with an unused-bits octet of 0 by default' {
        $bytes = [byte[]](0x01, 0x02, 0x03)
        $tlv = ConvertTo-Asn1BitString -Bytes $bytes
        [BitConverter]::ToString($tlv).Replace('-', '') | Should -Be '030400010203'
    }
}
