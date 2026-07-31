BeforeAll {
    . $PSScriptRoot/../Private/Asn1.ps1
    . $PSScriptRoot/../Private/KerberosCrypto.ps1
    . $PSScriptRoot/../Private/PkinitMessages.ps1
}

Describe 'ConvertFrom-KerberosPrincipalName' {
    It 'round-trips name-type and name-strings through ConvertTo-KerberosPrincipalName' {
        $encoded = ConvertTo-KerberosPrincipalName -NameType 10 -NameStrings @('user@adcs.goat')
        $tlv = Read-Asn1Tlv -Bytes $encoded -Offset 0
        $decoded = ConvertFrom-KerberosPrincipalName -Content $tlv.Content

        $decoded.NameType | Should -Be 10
        $decoded.NameStrings.Count | Should -Be 1
        $decoded.NameStrings[0] | Should -Be 'user@adcs.goat'
    }

    It 'round-trips multiple name-strings (e.g. service/instance)' {
        $encoded = ConvertTo-KerberosPrincipalName -NameType 2 -NameStrings @('krbtgt', 'ADCS.GOAT')
        $tlv = Read-Asn1Tlv -Bytes $encoded -Offset 0
        $decoded = ConvertFrom-KerberosPrincipalName -Content $tlv.Content

        $decoded.NameType | Should -Be 2
        $decoded.NameStrings | Should -Be @('krbtgt', 'ADCS.GOAT')
    }
}

Describe 'ConvertFrom-PaData' {
    It 'round-trips padata-type and padata-value through New-PaData' {
        $value = [byte[]]@(1, 2, 3, 4)
        $encoded = New-PaData -PaDataType 16 -PaDataValue $value
        $tlv = Read-Asn1Tlv -Bytes $encoded -Offset 0
        $decoded = ConvertFrom-PaData -Content $tlv.Content

        $decoded.Type | Should -Be 16
        [BitConverter]::ToString($decoded.Value) | Should -Be ([BitConverter]::ToString($value))
    }
}

Describe 'ConvertFrom-EncryptedData' {
    It 'round-trips etype/kvno/cipher through a hand-built EncryptedData SEQUENCE' {
        $cipher = [byte[]]@(9, 9, 9, 9, 9)
        $encoded = ConvertTo-Asn1Sequence -Children @(
            (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-Asn1Integer -Value 18))
            (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1Integer -Value 2))
            (ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1OctetString -Bytes $cipher))
        )
        $tlv = Read-Asn1Tlv -Bytes $encoded -Offset 0
        $decoded = ConvertFrom-EncryptedData -Content $tlv.Content

        $decoded.EType | Should -Be 18
        $decoded.Kvno | Should -Be 2
        [BitConverter]::ToString($decoded.Cipher) | Should -Be ([BitConverter]::ToString($cipher))
    }
}

Describe 'ConvertFrom-KdcRep' {
    It 'round-trips a hand-built AS-REP ([APPLICATION 11]) into its component fields' {
        $cname = ConvertTo-KerberosPrincipalName -NameType 10 -NameStrings @('user@adcs.goat')
        $sname = ConvertTo-KerberosPrincipalName -NameType 2 -NameStrings @('krbtgt', 'ADCS.GOAT')
        $ticket = ConvertTo-Asn1ApplicationConstructed -TagNumber 1 -InnerTlv (ConvertTo-Asn1Sequence -Children @((ConvertTo-Asn1Integer -Value 5)))
        $encPart = ConvertTo-Asn1Sequence -Children @(
            (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-Asn1Integer -Value 18))
            (ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1OctetString -Bytes ([byte[]]@(7, 7, 7))))
        )
        $paData = New-PaData -PaDataType 17 -PaDataValue ([byte[]]@(1, 2, 3))

        $kdcRep = ConvertTo-Asn1Sequence -Children @(
            (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-Asn1Integer -Value 5))
            (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1Integer -Value 11))
            (ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1Sequence -Children @($paData)))
            (ConvertTo-Asn1ContextExplicit -TagNumber 3 -InnerTlv (ConvertTo-Asn1GeneralString -Value 'ADCS.GOAT'))
            (ConvertTo-Asn1ContextExplicit -TagNumber 4 -InnerTlv $cname)
            (ConvertTo-Asn1ContextExplicit -TagNumber 5 -InnerTlv $ticket)
            (ConvertTo-Asn1ContextExplicit -TagNumber 6 -InnerTlv $encPart)
        )
        $asRep = ConvertTo-Asn1ApplicationConstructed -TagNumber 11 -InnerTlv $kdcRep

        $decoded = ConvertFrom-KdcRep -Message $asRep -ExpectedApplicationTag 11

        $decoded.PvNo | Should -Be 5
        $decoded.MsgType | Should -Be 11
        $decoded.PaData.Count | Should -Be 1
        $decoded.PaData[0].Type | Should -Be 17
        $decoded.CRealm | Should -Be 'ADCS.GOAT'
        $decoded.CName.NameStrings[0] | Should -Be 'user@adcs.goat'
        $decoded.EncPart.EType | Should -Be 18
        $decoded.Ticket | Should -Not -BeNullOrEmpty
    }

    It 'throws when the outer application tag does not match' {
        $body = New-KdcReqBody -ClientName 'user' -Realm 'ADCS.GOAT' -Nonce 1
        $asReq = New-AsReq -KdcReqBody $body
        { ConvertFrom-KdcRep -Message $asReq -ExpectedApplicationTag 11 } | Should -Throw
    }
}

Describe 'ConvertFrom-EncKdcRepPart' {
    It 'round-trips a hand-built EncASRepPart ([APPLICATION 25])' {
        $sname = ConvertTo-KerberosPrincipalName -NameType 2 -NameStrings @('krbtgt', 'ADCS.GOAT')
        $keySeq = ConvertTo-Asn1Sequence -Children @(
            (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-Asn1Integer -Value 18))
            (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1OctetString -Bytes ([byte[]](1..32))))
        )
        $now = [datetime]::new(2026, 7, 10, 13, 0, 0, [DateTimeKind]::Utc)
        $later = $now.AddHours(10)

        $encKdcRepPart = ConvertTo-Asn1Sequence -Children @(
            (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv $keySeq)
            (ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1Integer -Value 424242))
            (ConvertTo-Asn1ContextExplicit -TagNumber 4 -InnerTlv (ConvertTo-KerberosFlags -Value 0x40810000))
            (ConvertTo-Asn1ContextExplicit -TagNumber 5 -InnerTlv (ConvertTo-Asn1GeneralizedTime -Value $now))
            (ConvertTo-Asn1ContextExplicit -TagNumber 7 -InnerTlv (ConvertTo-Asn1GeneralizedTime -Value $later))
            (ConvertTo-Asn1ContextExplicit -TagNumber 9 -InnerTlv (ConvertTo-Asn1GeneralString -Value 'ADCS.GOAT'))
            (ConvertTo-Asn1ContextExplicit -TagNumber 10 -InnerTlv $sname)
        )
        $message = ConvertTo-Asn1ApplicationConstructed -TagNumber 25 -InnerTlv $encKdcRepPart

        $decoded = ConvertFrom-EncKdcRepPart -Message $message -ExpectedApplicationTag 25

        $decoded.Key.KeyType | Should -Be 18
        $decoded.Key.KeyValue.Length | Should -Be 32
        $decoded.Nonce | Should -Be 424242
        $decoded.Flags | Should -Be 0x40810000
        $decoded.AuthTime | Should -Be $now
        $decoded.EndTime | Should -Be $later
        $decoded.SRealm | Should -Be 'ADCS.GOAT'
        $decoded.SName.NameStrings | Should -Be @('krbtgt', 'ADCS.GOAT')
    }
}
