<#
    .SYNOPSIS
    Pester tests for Invoke-PkinitAuthentication.
#>

BeforeAll {
    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\PSPkinit.psd1'
    Import-Module -Name $modulePath -Force

    function New-TestSelfSignedCertificate {
        <#
            .SYNOPSIS
            Test-only helper: a throwaway self-signed cert with a private key,
            good enough to sign/verify a CMS AuthPack or KDCDHKeyInfo. Pure
            .NET - doesn't touch any PSPkinit internals, so it's a plain
            script-scoped function rather than something defined via
            InModuleScope (whose function definitions do NOT persist across
            separate InModuleScope invocations - each call gets its own,
            short-lived child scope of the module).
        #>
        param([Parameter(Mandatory)] [string] $Subject)

        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        return $req.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    }
}

Describe 'Invoke-PkinitAuthentication' {
    Context 'certificate resolution' {
        It 'throws a terminating CryptographicException when the thumbprint is not found' {
            {
                Invoke-PkinitAuthentication -CertificateThumbprint ('0' * 40) -ClientName 'user@test.local' -Realm 'TEST.LOCAL' -KdcHostname 'kdc.test.local'
            } | Should -Throw -ExceptionType ([System.Security.Cryptography.CryptographicException])
        }
    }

    Context 'when the KDC returns a KRB-ERROR' {
        BeforeAll {
            $script:clientCert = New-TestSelfSignedCertificate -Subject 'CN=Test Client'

            # Building the KRB-ERROR bytes needs the module's (private) ASN.1 helpers,
            # so this one construction step runs inside module scope; the result
            # (plain bytes) is handed back out to ordinary test scope.
            # $global: (not $script:) because Mock -ModuleName runs -MockWith bound to
            # the module's own session state, where $script: would resolve against the
            # module's script scope rather than this test file's.
            $global:PkinitTestKrbErrorBytes = InModuleScope PSPkinit {
                ConvertTo-Asn1ApplicationConstructed -TagNumber 30 -InnerTlv (ConvertTo-Asn1Sequence -Children @(
                        (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-Asn1Integer -Value 5))
                        (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1Integer -Value 30))
                        (ConvertTo-Asn1ContextExplicit -TagNumber 4 -InnerTlv (ConvertTo-Asn1GeneralizedTime -Value (Get-Date).ToUniversalTime()))
                        (ConvertTo-Asn1ContextExplicit -TagNumber 6 -InnerTlv (ConvertTo-Asn1Integer -Value 25))
                        (ConvertTo-Asn1ContextExplicit -TagNumber 9 -InnerTlv (ConvertTo-Asn1GeneralString -Value 'TEST.LOCAL'))
                        (ConvertTo-Asn1ContextExplicit -TagNumber 11 -InnerTlv (ConvertTo-Asn1GeneralString -Value 'Preauthentication required'))
                    ))
            }

            Mock -CommandName Send-KerberosTcpMessage -ModuleName PSPkinit -MockWith { $global:PkinitTestKrbErrorBytes }
        }

        AfterAll {
            Remove-Variable -Name PkinitTestKrbErrorBytes -Scope Global -ErrorAction SilentlyContinue
        }

        It 'throws a terminating SecurityError carrying the parsed KRB-ERROR details' {
            $errorRecord = $null
            try {
                Invoke-PkinitAuthentication -Certificate $script:clientCert -ClientName 'user@test.local' -Realm 'TEST.LOCAL' -KdcHostname 'kdc.test.local' -ErrorAction Stop
            } catch {
                $errorRecord = $_
            }

            $errorRecord | Should -Not -BeNullOrEmpty
            $errorRecord.CategoryInfo.Category | Should -Be 'SecurityError'
            $errorRecord.TargetObject.ErrorCode | Should -Be 25
        }
    }

    Context 'happy path - full AS-REQ/AS-REP round trip' {
        BeforeAll {
            $script:clientCert = New-TestSelfSignedCertificate -Subject 'CN=Test Client'
            $script:kdcCert = New-TestSelfSignedCertificate -Subject 'CN=Test KDC'
            # $global: because Mock -ModuleName runs -MockWith bound to the module's own
            # session state, where $script: would resolve against the module's script
            # scope rather than this test file's.
            $global:PkinitTestKdcCert = $script:kdcCert

            # Mock -ModuleName only controls which command instance gets replaced; the
            # -MockWith body itself does NOT get automatic access to the module's
            # private functions, so the actual fake-KDC logic runs via an explicit
            # InModuleScope call (with data handed in via -Parameters), which does
            # give access to PSPkinit's private ASN.1/CMS/crypto helpers.
            Mock -CommandName Send-KerberosTcpMessage -ModuleName PSPkinit -MockWith {
                InModuleScope -ModuleName PSPkinit -Parameters @{ Message = $Message; KdcCert = $global:PkinitTestKdcCert } -ScriptBlock {
                    param($Message, $KdcCert)
                    $kdcCert = $KdcCert

                    $outer = Read-Asn1Tlv -Bytes $Message -Offset 0
                    $kdcReqSeq = Read-Asn1Tlv -Bytes $outer.Content -Offset 0
                    $kdcReqFields = Read-Asn1Sequence -Content $kdcReqSeq.Content
                $padataField = $kdcReqFields | Where-Object { ($_.Tag -band 0x1f) -eq 3 }
                $padataInner = Read-Asn1Tlv -Bytes $padataField.Content -Offset 0
                $paDataItems = Read-Asn1Sequence -Content $padataInner.Content
                $paPkAsReqItem = $paDataItems | ForEach-Object { ConvertFrom-PaData -Content $_.Content } | Where-Object { $_.Type -eq 16 }

                $paPkAsReqSeq = Read-Asn1Tlv -Bytes $paPkAsReqItem.Value -Offset 0
                $paPkAsReqFields = Read-Asn1Sequence -Content $paPkAsReqSeq.Content
                $signedAuthPackBytes = $paPkAsReqFields[0].Content

                $clientSignedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
                $clientSignedCms.Decode($signedAuthPackBytes)
                $authPack = $clientSignedCms.ContentInfo.Content

                $authPackSeq = Read-Asn1Tlv -Bytes $authPack -Offset 0
                $authPackFields = Read-Asn1Sequence -Content $authPackSeq.Content

                $pkAuthenticatorOuter = Read-Asn1Tlv -Bytes $authPackFields[0].Content -Offset 0
                $pkAuthenticatorFields = Read-Asn1Sequence -Content $pkAuthenticatorOuter.Content
                $nonceField = $pkAuthenticatorFields | Where-Object { ($_.Tag -band 0x1f) -eq 2 }
                $nonceInner = Read-Asn1Tlv -Bytes $nonceField.Content -Offset 0
                $clientNonce = [uint32](ConvertFrom-Asn1Integer -Content $nonceInner.Content)

                $spkiOuter = Read-Asn1Tlv -Bytes $authPackFields[1].Content -Offset 0
                $spkiFields = Read-Asn1Sequence -Content $spkiOuter.Content
                $integerTlv = Read-Asn1Tlv -Bytes $spkiFields[1].Content -Offset 1
                $clientPublicValue = ConvertTo-UnsignedBigInteger -BigEndianBytes $integerTlv.Content

                # Act as the KDC: fresh server DH keypair (same hardcoded Oakley Group 14 params), compute ZZ.
                $serverDh = New-PkinitDiffieHellmanKeyPair
                $sharedSecret = Get-PkinitDiffieHellmanSharedSecret -TheirPublicValue $clientPublicValue -OurPrivateExponent $serverDh.PrivateExponent -P $serverDh.P -ModulusByteLength $serverDh.ModulusByteLength

                $publicValueInteger = ConvertTo-Asn1Integer -Bytes (ConvertTo-BigEndianBytes -Value $serverDh.PublicValue)
                $subjectPublicKey = ConvertTo-Asn1BitString -Bytes $publicValueInteger
                $kdcDhKeyInfo = ConvertTo-Asn1Sequence -Children @(
                    (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv $subjectPublicKey)
                    (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1Integer -Value ([long]$clientNonce)))
                )
                $contentInfo = [System.Security.Cryptography.Pkcs.ContentInfo]::new([System.Security.Cryptography.Oid]::new('1.3.6.1.5.2.3.2'), $kdcDhKeyInfo)
                $kdcSignedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $false)
                $kdcSigner = [System.Security.Cryptography.Pkcs.CmsSigner]::new([System.Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber, $kdcCert)
                $kdcSigner.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
                $kdcSignedCms.ComputeSignature($kdcSigner, $false)
                $dhSignedData = $kdcSignedCms.Encode()

                $dhRepInfo = ConvertTo-Asn1Sequence -Children @(
                    (ConvertTo-Asn1ContextImplicitPrimitive -TagNumber 0 -Content $dhSignedData)
                )
                $paPkAsRepValue = ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv $dhRepInfo
                $paPkAsRepPaData = New-PaData -PaDataType 17 -PaDataValue $paPkAsRepValue

                $replyKey = ConvertTo-OctetString2Key -InputBytes $sharedSecret -KeyByteLength 32

                $sessionKey = New-Object byte[] 32
                $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                try { $rng.GetBytes($sessionKey) } finally { $rng.Dispose() }

                $keySeq = ConvertTo-Asn1Sequence -Children @(
                    (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-Asn1Integer -Value 18))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1OctetString -Bytes $sessionKey))
                )
                $now = (Get-Date).ToUniversalTime()
                $sname = ConvertTo-KerberosPrincipalName -NameType 2 -NameStrings @('krbtgt', 'TEST.LOCAL')
                $encKdcRepPart = ConvertTo-Asn1Sequence -Children @(
                    (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv $keySeq)
                    (ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1Integer -Value ([long]$clientNonce)))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 4 -InnerTlv (ConvertTo-KerberosFlags -Value 0x40810000))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 5 -InnerTlv (ConvertTo-Asn1GeneralizedTime -Value $now))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 7 -InnerTlv (ConvertTo-Asn1GeneralizedTime -Value $now.AddHours(10)))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 9 -InnerTlv (ConvertTo-Asn1GeneralString -Value 'TEST.LOCAL'))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 10 -InnerTlv $sname)
                )
                $encKdcRepPartMessage = ConvertTo-Asn1ApplicationConstructed -TagNumber 25 -InnerTlv $encKdcRepPart
                $cipher = Protect-KerberosData -BaseKey $replyKey -KeyUsage 3 -Plaintext $encKdcRepPartMessage

                $encPartSeq = ConvertTo-Asn1Sequence -Children @(
                    (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-Asn1Integer -Value 18))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1OctetString -Bytes $cipher))
                )

                $cname = ConvertTo-KerberosPrincipalName -NameType 10 -NameStrings @('user@test.local')
                $ticket = ConvertTo-Asn1ApplicationConstructed -TagNumber 1 -InnerTlv (ConvertTo-Asn1Sequence -Children @((ConvertTo-Asn1Integer -Value 5)))

                $kdcRep = ConvertTo-Asn1Sequence -Children @(
                    (ConvertTo-Asn1ContextExplicit -TagNumber 0 -InnerTlv (ConvertTo-Asn1Integer -Value 5))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 1 -InnerTlv (ConvertTo-Asn1Integer -Value 11))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 2 -InnerTlv (ConvertTo-Asn1Sequence -Children @($paPkAsRepPaData)))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 3 -InnerTlv (ConvertTo-Asn1GeneralString -Value 'TEST.LOCAL'))
                    (ConvertTo-Asn1ContextExplicit -TagNumber 4 -InnerTlv $cname)
                    (ConvertTo-Asn1ContextExplicit -TagNumber 5 -InnerTlv $ticket)
                    (ConvertTo-Asn1ContextExplicit -TagNumber 6 -InnerTlv $encPartSeq)
                )

                ConvertTo-Asn1ApplicationConstructed -TagNumber 11 -InnerTlv $kdcRep
                }
            }
        }

        It 'returns the decrypted identity and session key from a successful AS-REP' {
            $result = Invoke-PkinitAuthentication -Certificate $script:clientCert -ClientName 'user@test.local' -Realm 'TEST.LOCAL' -KdcHostname 'kdc.test.local'

            $result.CName | Should -Be 'user@test.local'
            $result.SName | Should -Be 'krbtgt/TEST.LOCAL'
            $result.SRealm | Should -Be 'TEST.LOCAL'
            $result.SessionKeyType | Should -Be 18
            $result.SessionKey.Length | Should -Be 32
            $result.KdcSignerCertificate.Thumbprint | Should -Be $script:kdcCert.Thumbprint
        }

        AfterAll {
            Remove-Variable -Name PkinitTestKdcCert -Scope Global -ErrorAction SilentlyContinue
        }
    }
}
