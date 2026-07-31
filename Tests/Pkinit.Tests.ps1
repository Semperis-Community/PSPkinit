BeforeAll {
    . $PSScriptRoot/../Private/Asn1.ps1
    . $PSScriptRoot/../Private/Pkinit.ps1
}

Describe 'New-PkinitDiffieHellmanKeyPair / Get-PkinitDiffieHellmanSharedSecret' {
    It 'derives matching shared secrets from two independent key pairs (classic DH symmetry)' {
        $alice = New-PkinitDiffieHellmanKeyPair
        $bob = New-PkinitDiffieHellmanKeyPair

        $alice.P | Should -Be $bob.P
        $alice.G | Should -Be $bob.G

        $secretFromAlice = Get-PkinitDiffieHellmanSharedSecret -TheirPublicValue $bob.PublicValue -OurPrivateExponent $alice.PrivateExponent -P $alice.P -ModulusByteLength $alice.ModulusByteLength
        $secretFromBob = Get-PkinitDiffieHellmanSharedSecret -TheirPublicValue $alice.PublicValue -OurPrivateExponent $bob.PrivateExponent -P $bob.P -ModulusByteLength $bob.ModulusByteLength

        [BitConverter]::ToString($secretFromAlice) | Should -Be ([BitConverter]::ToString($secretFromBob))
    }

    It 'produces a shared secret padded to the full modulus byte length' {
        $alice = New-PkinitDiffieHellmanKeyPair
        $bob = New-PkinitDiffieHellmanKeyPair
        $secret = Get-PkinitDiffieHellmanSharedSecret -TheirPublicValue $bob.PublicValue -OurPrivateExponent $alice.PrivateExponent -P $alice.P -ModulusByteLength $alice.ModulusByteLength
        $secret.Length | Should -Be $alice.ModulusByteLength
    }

    It 'generates a public value less than the modulus' {
        $kp = New-PkinitDiffieHellmanKeyPair
        $kp.PublicValue | Should -BeLessThan $kp.P
        $kp.PrivateExponent | Should -BeLessThan $kp.P
    }
}

Describe 'ConvertTo-DhSubjectPublicKeyInfo' {
    It 'produces a parseable SEQUENCE containing the dhpublicnumber OID' {
        $kp = New-PkinitDiffieHellmanKeyPair
        $spki = ConvertTo-DhSubjectPublicKeyInfo -DhKeyPair $kp
        $outer = Read-Asn1Tlv -Bytes $spki -Offset 0
        $outer.Tag | Should -Be 0x30
        $children = Read-Asn1Sequence -Content $outer.Content
        $children.Count | Should -Be 2
        $algIdChildren = Read-Asn1Sequence -Content $children[0].Content
        $algIdChildren[0].Tag | Should -Be 0x06
    }
}

Describe 'ConvertFrom-PkinitDhRepInfo / ConvertFrom-PkinitKdcDhKeyInfo' {
    BeforeAll {
        function New-TestSigningCertificate {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Test PKINIT KDC', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            return $req.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
        }

        function New-TestDhRepInfoPaDataValue {
            param($ServerPublicValueBigInteger, [uint32]$Nonce, $SigningCert)

            $publicValueInteger = ConvertTo-Asn1Integer -Bytes (ConvertTo-BigEndianBytes -Value $ServerPublicValueBigInteger)
            $subjectPublicKey = ConvertTo-Asn1BitString -Bytes $publicValueInteger

            $kdcDhKeyInfo = ConvertTo-Asn1Sequence -Children @(
                (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv $subjectPublicKey)
                (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1Integer -Value ([long]$Nonce)))
            )

            $contentInfo = [System.Security.Cryptography.Pkcs.ContentInfo]::new(
                [System.Security.Cryptography.Oid]::new('1.3.6.1.5.2.3.2'), $kdcDhKeyInfo)
            $signedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $false)
            $signer = [System.Security.Cryptography.Pkcs.CmsSigner]::new(
                [System.Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber, $SigningCert)
            $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
            $signedCms.ComputeSignature($signer, $false)
            $dhSignedData = $signedCms.Encode()

            $dhRepInfo = ConvertTo-Asn1Sequence -Children @(
                (ConvertTo-Asn1ContextImplicitPrimitive -TagNumber 0 -Content $dhSignedData)
            )
            return ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv $dhRepInfo
        }
    }

    It 'round-trips server public value and nonce through a hand-built, self-signed DHRepInfo/KDCDHKeyInfo' {
        $cert = New-TestSigningCertificate
        $serverKp = New-PkinitDiffieHellmanKeyPair
        $paDataValue = New-TestDhRepInfoPaDataValue -ServerPublicValueBigInteger $serverKp.PublicValue -Nonce 12345 -SigningCert $cert

        $dhRepInfo = ConvertFrom-PkinitDhRepInfo -PaDataValue $paDataValue
        $dhRepInfo.DhSignedData | Should -Not -BeNullOrEmpty
        $dhRepInfo.ServerDHNonce | Should -BeNullOrEmpty

        $kdcDhKeyInfo = ConvertFrom-PkinitKdcDhKeyInfo -DhSignedData $dhRepInfo.DhSignedData
        $kdcDhKeyInfo.ServerPublicValue | Should -Be $serverKp.PublicValue
        $kdcDhKeyInfo.Nonce | Should -Be 12345
        $kdcDhKeyInfo.SignerCertificate.Thumbprint | Should -Be $cert.Thumbprint
    }

    It 'throws when the encKeyPack choice (tag [1]) is given instead of dhInfo' {
        $unsupported = ConvertTo-Asn1ContextImplicitPrimitive -TagNumber 1 -Content ([byte[]]@(1, 2, 3))
        { ConvertFrom-PkinitDhRepInfo -PaDataValue $unsupported } | Should -Throw
    }
}
