<#
    .SYNOPSIS
    Pester tests for certificate enrollment helpers.
#>

BeforeAll {
    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\PSPkinit.psd1'
    Import-Module -Name $modulePath -Force
}

Describe 'ConvertTo-PkinitAlternativeNameTypeCode' {
    It 'maps UserPrincipalName to 11 (XCN_CERT_ALT_NAME_USER_PRINCIPAL_NAME)' {
        InModuleScope PSPkinit { ConvertTo-PkinitAlternativeNameTypeCode -SanType 'UserPrincipalName' } | Should -Be 11
    }

    It 'maps Dns to 3 (XCN_CERT_ALT_NAME_DNS_NAME)' {
        InModuleScope PSPkinit { ConvertTo-PkinitAlternativeNameTypeCode -SanType 'Dns' } | Should -Be 3
    }

    It 'maps Email to 2 (XCN_CERT_ALT_NAME_RFC822_NAME)' {
        InModuleScope PSPkinit { ConvertTo-PkinitAlternativeNameTypeCode -SanType 'Email' } | Should -Be 2
    }
}

Describe 'ConvertTo-PkinitSanAttributeString' {
    It 'builds a SAN:upn=... attribute string for UserPrincipalName' {
        InModuleScope PSPkinit { ConvertTo-PkinitSanAttributeString -SanType 'UserPrincipalName' -San 'user@adcs.goat' } |
            Should -Be 'SAN:upn=user@adcs.goat'
    }

    It 'builds a SAN:dns=... attribute string for Dns' {
        InModuleScope PSPkinit { ConvertTo-PkinitSanAttributeString -SanType 'Dns' -San 'host.adcs.goat' } |
            Should -Be 'SAN:dns=host.adcs.goat'
    }

    It 'builds a SAN:email=... attribute string for Email' {
        InModuleScope PSPkinit { ConvertTo-PkinitSanAttributeString -SanType 'Email' -San 'user@adcs.goat' } |
            Should -Be 'SAN:email=user@adcs.goat'
    }
}

Describe 'ConvertTo-PkinitSidSecurityExtensionValue' {
    It 'matches a real Windows CA-issued SID security extension byte-for-byte' {
        # Ground truth: captured live from an actual ADCSGoat-CA-issued certificate's
        # 1.3.6.1.4.1.311.25.2 extension earlier this session (via
        # $cert.Extensions | Where Oid.Value -eq '1.3.6.1.4.1.311.25.2' | Format(1)),
        # for SID 'S-1-5-21-2298154379-2017097123-1132854487-1105'. Structure confirmed
        # against GhostPack/Certify's CertSidExtension.EncodeSidExtension: a GeneralNames
        # SEQUENCE containing one otherName GeneralName (type-id 1.3.6.1.4.1.311.25.2.1,
        # value [0] EXPLICIT OCTET STRING of the SID's string form).
        $expectedHex = '30 40 a0 3e 06 0a 2b 06 01 04 01 82 37 19 02 01 a0 30 04 2e ' +
        '53 2d 31 2d 35 2d 32 31 2d 32 32 39 38 31 35 34 33 37 39 2d ' +
        '32 30 31 37 30 39 37 31 32 33 2d 31 31 33 32 38 35 34 34 38 ' +
        '37 2d 31 31 30 35'
        $expectedBytes = $expectedHex.Split(' ') | ForEach-Object { [byte]"0x$_" }

        $actualBytes = InModuleScope PSPkinit {
            ConvertTo-PkinitSidSecurityExtensionValue -Sid 'S-1-5-21-2298154379-2017097123-1132854487-1105'
        }

        [BitConverter]::ToString($actualBytes) | Should -Be ([BitConverter]::ToString($expectedBytes))
    }
}

Describe 'New-PkinitSidSecurityExtension' {
    BeforeAll {
        Mock -CommandName New-PkinitComObject -ModuleName PSPkinit -MockWith {
            switch ($ProgId)
            {
                'X509Enrollment.CObjectId'
                {
                    $fake = [PSCustomObject]@{}
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name InitializeFromValue -Value {
                        param($Value)
                        $global:PkinitTestSidExtensionOid = $Value
                    }
                    return $fake
                }
                'X509Enrollment.CX509Extension'
                {
                    $fake = [PSCustomObject]@{}
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name Initialize -Value {
                        param($Oid, $EncodingType, $Value)
                        $global:PkinitTestSidExtensionEncodingType = $EncodingType
                        $global:PkinitTestSidExtensionValue = $Value
                    }
                    return $fake
                }
                default { throw "Unexpected ProgId in test: $ProgId" }
            }
        }
    }

    AfterAll {
        Remove-Variable -Name PkinitTestSidExtensionOid, PkinitTestSidExtensionEncodingType, PkinitTestSidExtensionValue -Scope Global -ErrorAction SilentlyContinue
    }

    It 'initializes a CX509Extension with the NtdsCaSecurityExt OID and the encoded SID value' {
        $expectedValue = InModuleScope PSPkinit {
            [Convert]::ToBase64String((ConvertTo-PkinitSidSecurityExtensionValue -Sid 'S-1-5-21-2298154379-2017097123-1132854487-1105'))
        }

        InModuleScope PSPkinit {
            New-PkinitSidSecurityExtension -Sid 'S-1-5-21-2298154379-2017097123-1132854487-1105'
        }

        $global:PkinitTestSidExtensionOid | Should -Be '1.3.6.1.4.1.311.25.2'
        $global:PkinitTestSidExtensionEncodingType | Should -Be 1
        $global:PkinitTestSidExtensionValue | Should -Be $expectedValue
    }
}

Describe 'New-PkinitCertificateSigningRequest' {
    BeforeAll {
        # Fakes for every CertEnroll COM ProgId this function touches. Each fake
        # records what it was called with (via $global:, since these mock bodies
        # run bound to the module's scope, not this test file's) so the tests can
        # assert on the *values* passed through the whole chain, not just that
        # "some COM object was created."
        Mock -CommandName New-PkinitComObject -ModuleName PSPkinit -MockWith {
            switch ($ProgId)
            {
                'X509Enrollment.CX509PrivateKey'
                {
                    $fake = [PSCustomObject]@{ ProviderName = $null; Length = $null; KeySpec = $null; MachineContext = $null; ExportPolicy = $null }
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name Create -Value {
                        $global:PkinitTestPrivateKey = $this
                    }
                    return $fake
                }
                'X509Enrollment.CX500DistinguishedName'
                {
                    $fake = [PSCustomObject]@{ EncodedName = $null }
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name Encode -Value {
                        param($Name, $Flags)
                        $global:PkinitTestSubjectEncoded = $Name
                        $this.EncodedName = $Name
                    }
                    return $fake
                }
                'X509Enrollment.CAlternativeName'
                {
                    $fake = [PSCustomObject]@{}
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name InitializeFromString -Value {
                        param($AlternativeNameType, $Value)
                        $global:PkinitTestAltNameType = $AlternativeNameType
                        $global:PkinitTestAltNameValue = $Value
                    }
                    return $fake
                }
                'X509Enrollment.CAlternativeNames'
                {
                    $fake = [System.Collections.Generic.List[object]]::new()
                    $global:PkinitTestAltNamesList = $fake
                    # ",$fake" (not "$fake") - an empty List[object] returned bare would be
                    # enumerated by the pipeline and produce ZERO output objects, leaving the
                    # caller's assignment as $null. The comma operator wraps it so the single
                    # collection object itself is emitted, not its (currently empty) contents.
                    return , $fake
                }
                'X509Enrollment.CX509ExtensionAlternativeNames'
                {
                    $fake = [PSCustomObject]@{}
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name InitializeEncode -Value {
                        param($AlternativeNames)
                        $global:PkinitTestSanExtensionInitialized = $true
                    }
                    return $fake
                }
                'X509Enrollment.CX509CertificateRequestPkcs10'
                {
                    $extensions = [System.Collections.Generic.List[object]]::new()
                    $global:PkinitTestExtensionsList = $extensions
                    $fake = [PSCustomObject]@{ Subject = $null; X509Extensions = $extensions }
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name InitializeFromPrivateKey -Value {
                        param($Context, $PrivateKey, $TemplateName)
                        $global:PkinitTestPkcs10Context = $Context
                    }
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name Encode -Value { }
                    return $fake
                }
                'X509Enrollment.CX509Enrollment'
                {
                    $fake = [PSCustomObject]@{}
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name InitializeFromRequest -Value {
                        param($Request)
                        $global:PkinitTestEnrollmentInitialized = $true
                    }
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name CreateRequest -Value {
                        param($EncodingType)
                        $global:PkinitTestCreateRequestEncoding = $EncodingType
                        return 'ZmFrZS1jc3I='
                    }
                    return $fake
                }
                'X509Enrollment.CObjectId'
                {
                    $fake = [PSCustomObject]@{}
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name InitializeFromValue -Value { param($Value) }
                    return $fake
                }
                'X509Enrollment.CX509Extension'
                {
                    $fake = [PSCustomObject]@{}
                    Add-Member -InputObject $fake -MemberType ScriptMethod -Name Initialize -Value { param($Oid, $EncodingType, $Value) }
                    $global:PkinitTestSidExtensionObject = $fake
                    return $fake
                }
                default { throw "Unexpected ProgId in test: $ProgId" }
            }
        }
    }

    AfterEach {
        Remove-Variable -Name PkinitTestPrivateKey, PkinitTestSubjectEncoded, PkinitTestAltNameType, PkinitTestAltNameValue,
        PkinitTestAltNamesList, PkinitTestSanExtensionInitialized, PkinitTestPkcs10Context, PkinitTestExtensionsList,
        PkinitTestEnrollmentInitialized, PkinitTestCreateRequestEncoding, PkinitTestSidExtensionObject -Scope Global -ErrorAction SilentlyContinue
    }

    It 'builds a UPN SAN, encodes the subject, and returns the Base64 CSR from CreateRequest' {
        $result = InModuleScope PSPkinit {
            New-PkinitCertificateSigningRequest -Subject 'CN=Test User' -San 'user@adcs.goat' -SanType 'UserPrincipalName' -KeyLength 2048 -ProviderName 'Microsoft Software Key Storage Provider'
        }

        $result.Base64Csr | Should -Be 'ZmFrZS1jc3I='
        # Not -BeNullOrEmpty: Pester's BeNullOrEmpty matcher treats a PSCustomObject
        # with only ScriptMethod members (standing in for a COM object here, with no
        # NoteProperty data of its own) as "empty" even though it is not $null - so
        # compare directly against $null instead.
        ($null -eq $result.Enrollment) | Should -BeFalse
        $global:PkinitTestSubjectEncoded | Should -Be 'CN=Test User'
        $global:PkinitTestAltNameType | Should -Be 11
        $global:PkinitTestAltNameValue | Should -Be 'user@adcs.goat'
        $global:PkinitTestAltNamesList.Count | Should -Be 1
        $global:PkinitTestSanExtensionInitialized | Should -BeTrue
        $global:PkinitTestExtensionsList.Count | Should -Be 1
        $global:PkinitTestEnrollmentInitialized | Should -BeTrue
        $global:PkinitTestCreateRequestEncoding | Should -Be 1
    }

    It 'defaults to user context (ContextUser = 1) unless -MachineContext is set' {
        InModuleScope PSPkinit {
            New-PkinitCertificateSigningRequest -Subject 'CN=Test User' -San 'user@adcs.goat' -SanType 'UserPrincipalName'
        }

        $global:PkinitTestPkcs10Context | Should -Be 1
    }

    It 'uses machine context (ContextMachine = 2) when -MachineContext is set' {
        InModuleScope PSPkinit {
            New-PkinitCertificateSigningRequest -Subject 'CN=Test User' -San 'user@adcs.goat' -SanType 'UserPrincipalName' -MachineContext
        }

        $global:PkinitTestPkcs10Context | Should -Be 2
    }

    It 'adds a second (SID security) extension when -Sid is supplied' {
        InModuleScope PSPkinit {
            New-PkinitCertificateSigningRequest -Subject 'CN=Test User' -San 'user@adcs.goat' -SanType 'UserPrincipalName' -Sid 'S-1-5-21-1-2-3-1105'
        }

        $global:PkinitTestExtensionsList.Count | Should -Be 2
        $global:PkinitTestExtensionsList | Should -Contain $global:PkinitTestSidExtensionObject
    }

    It 'does not add a SID extension when -Sid is not supplied' {
        InModuleScope PSPkinit {
            New-PkinitCertificateSigningRequest -Subject 'CN=Test User' -San 'user@adcs.goat' -SanType 'UserPrincipalName'
        }

        $global:PkinitTestExtensionsList.Count | Should -Be 1
    }
}

Describe 'Submit-PkinitCertificateSigningRequest' {
    Context 'when the CA issues the certificate' {
        BeforeAll {
            Mock -CommandName New-PkinitComObject -ModuleName PSPkinit -ParameterFilter { $ProgId -eq 'CertificateAuthority.Request' } -MockWith {
                $fake = [PSCustomObject]@{}
                Add-Member -InputObject $fake -MemberType ScriptMethod -Name Submit -Value {
                    param($Flags, $Request, $Attributes, $Config)
                    $global:PkinitTestSubmitFlags = $Flags
                    $global:PkinitTestSubmitRequest = $Request
                    $global:PkinitTestSubmitAttributes = $Attributes
                    $global:PkinitTestSubmitConfig = $Config
                    return 3 # CR_DISP_ISSUED
                }
                Add-Member -InputObject $fake -MemberType ScriptMethod -Name GetCertificate -Value {
                    param($Flags)
                    $global:PkinitTestGetCertificateFlags = $Flags
                    return 'ZmFrZS1jZXJ0'
                }
                Add-Member -InputObject $fake -MemberType ScriptMethod -Name GetDispositionMessage -Value { return 'Issued' }
                return $fake
            }
        }

        AfterAll {
            Remove-Variable -Name PkinitTestSubmitFlags, PkinitTestSubmitRequest, PkinitTestSubmitAttributes,
            PkinitTestSubmitConfig, PkinitTestGetCertificateFlags -Scope Global -ErrorAction SilentlyContinue
        }

        It 'submits the CSR with a CertificateTemplate + SAN attribute string and returns the issued cert Base64' {
            $result = InModuleScope PSPkinit {
                Submit-PkinitCertificateSigningRequest -Base64Csr 'ZmFrZS1jc3I=' -Template 'UserWithSIDExtension' `
                    -San 'user@adcs.goat' -SanType 'UserPrincipalName' -CertificateAuthorityConfig 'ADCSGOAT-CA\LabRootCA1'
            }

            $result | Should -Be 'ZmFrZS1jZXJ0'
            $global:PkinitTestSubmitRequest | Should -Be 'ZmFrZS1jc3I='
            $global:PkinitTestSubmitConfig | Should -Be 'ADCSGOAT-CA\LabRootCA1'
            $global:PkinitTestSubmitAttributes | Should -Match 'CertificateTemplate:UserWithSIDExtension'
            $global:PkinitTestSubmitAttributes | Should -Match 'SAN:upn=user@adcs\.goat'
        }
    }

    Context 'when the CA denies the request' {
        BeforeAll {
            Mock -CommandName New-PkinitComObject -ModuleName PSPkinit -ParameterFilter { $ProgId -eq 'CertificateAuthority.Request' } -MockWith {
                $fake = [PSCustomObject]@{}
                Add-Member -InputObject $fake -MemberType ScriptMethod -Name Submit -Value { param($Flags, $Request, $Attributes, $Config) return 2 } # CR_DISP_DENIED
                Add-Member -InputObject $fake -MemberType ScriptMethod -Name GetDispositionMessage -Value { return 'Denied by policy module' }
                return $fake
            }
        }

        It 'throws with the CA disposition message' {
            {
                InModuleScope PSPkinit {
                    Submit-PkinitCertificateSigningRequest -Base64Csr 'ZmFrZS1jc3I=' -Template 'UserWithSIDExtension' `
                        -San 'user@adcs.goat' -SanType 'UserPrincipalName' -CertificateAuthorityConfig 'ADCSGOAT-CA\LabRootCA1'
                }
            } | Should -Throw '*Denied by policy module*'
        }
    }
}

Describe 'Install-PkinitCertificateResponse' {
    It 'calls InstallResponse on the supplied enrollment object with the issued certificate' {
        $fakeEnrollment = [PSCustomObject]@{}
        Add-Member -InputObject $fakeEnrollment -MemberType ScriptMethod -Name InstallResponse -Value {
            param($RestrictionFlags, $Certificate, $EncodingType, $Password)
            $global:PkinitTestInstallCertificate = $Certificate
        }

        InModuleScope PSPkinit -Parameters @{ Enrollment = $fakeEnrollment } -ScriptBlock {
            param($Enrollment)
            Install-PkinitCertificateResponse -Enrollment $Enrollment -Base64Certificate 'ZmFrZS1jZXJ0'
        }

        $global:PkinitTestInstallCertificate | Should -Be 'ZmFrZS1jZXJ0'
        Remove-Variable -Name PkinitTestInstallCertificate -Scope Global -ErrorAction SilentlyContinue
    }
}

Describe 'Get-PkinitCertificateFromStore' {
    It 'finds a certificate in Cert:\CurrentUser\My by thumbprint' {
        # Uses whatever's actually in the current user's store - if nothing matches
        # a bogus thumbprint, it should simply return nothing (not throw).
        $result = InModuleScope PSPkinit {
            Get-PkinitCertificateFromStore -Thumbprint ('0' * 40)
        }
        $result | Should -BeNullOrEmpty
    }
}

