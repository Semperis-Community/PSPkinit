BeforeAll {
    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\PSPkinit.psd1'
    Import-Module -Name $modulePath -Force

    function New-TestSelfSignedCertificate {
        <#
            .SYNOPSIS
            Test-only helper: a throwaway self-signed cert, used here purely to
            get realistic DER bytes/Base64 + a real thumbprint for the "issued
            certificate" the mocked CA hands back. Pure .NET, no module scope
            needed.
        #>
        param([Parameter(Mandatory)] [string] $Subject)

        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        return $req.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    }
}

Describe 'New-PkinitCertificateRequest' {
    Context 'happy path' {
        BeforeAll {
            $script:issuedCert = New-TestSelfSignedCertificate -Subject 'CN=Test User'
            $script:issuedCertBase64 = [Convert]::ToBase64String($script:issuedCert.RawData)
            $script:fakeEnrollment = [PSCustomObject]@{ WasUsedForInstall = $false }

            Mock -CommandName New-PkinitCertificateSigningRequest -ModuleName PSPkinit -MockWith {
                [PSCustomObject]@{ Enrollment = $script:fakeEnrollment; Base64Csr = 'ZmFrZS1jc3I=' }
            }
            Mock -CommandName Submit-PkinitCertificateSigningRequest -ModuleName PSPkinit -MockWith {
                $script:issuedCertBase64
            }
            Mock -CommandName Install-PkinitCertificateResponse -ModuleName PSPkinit -MockWith { }
            Mock -CommandName Get-PkinitCertificateFromStore -ModuleName PSPkinit -MockWith {
                $script:issuedCert
            }
        }

        It 'returns the installed certificate along with the Subject/San/SanType used to request it' {
            $result = New-PkinitCertificateRequest -Subject 'CN=Test User' -San 'user@adcs.goat' -SanType 'UserPrincipalName' `
                -Template 'UserWithSIDExtension' -CertificateAuthority 'ADCSGOAT-CA\LabRootCA1'

            $result.Certificate.Thumbprint | Should -Be $script:issuedCert.Thumbprint
            $result.Thumbprint | Should -Be $script:issuedCert.Thumbprint
            $result.Subject | Should -Be 'CN=Test User'
            $result.San | Should -Be 'user@adcs.goat'
            $result.SanType | Should -Be 'UserPrincipalName'
        }

        It 'passes -Sid through to New-PkinitCertificateSigningRequest when supplied' {
            New-PkinitCertificateRequest -Subject 'CN=Test User' -San 'user@adcs.goat' -SanType 'UserPrincipalName' `
                -Template 'UserWithSIDExtension' -CertificateAuthority 'ADCSGOAT-CA\LabRootCA1' -Sid 'S-1-5-21-1-2-3-1105'

            Should -Invoke -CommandName New-PkinitCertificateSigningRequest -ModuleName PSPkinit -ParameterFilter {
                $Sid -eq 'S-1-5-21-1-2-3-1105'
            }
        }

        It 'defaults -SanType to UserPrincipalName' {
            $result = New-PkinitCertificateRequest -Subject 'CN=Test User' -San 'user@adcs.goat' `
                -Template 'UserWithSIDExtension' -CertificateAuthority 'ADCSGOAT-CA\LabRootCA1'

            $result.SanType | Should -Be 'UserPrincipalName'
        }
    }

    Context 'when the CA submission fails' {
        BeforeAll {
            Mock -CommandName New-PkinitCertificateSigningRequest -ModuleName PSPkinit -MockWith {
                [PSCustomObject]@{ Enrollment = [PSCustomObject]@{}; Base64Csr = 'ZmFrZS1jc3I=' }
            }
            Mock -CommandName Submit-PkinitCertificateSigningRequest -ModuleName PSPkinit -MockWith {
                throw 'Certificate request was not issued (disposition 2): Denied by policy module'
            }
        }

        It 'surfaces a terminating InvalidOperation error' {
            $errorRecord = $null
            try {
                New-PkinitCertificateRequest -Subject 'CN=Test User' -San 'user@adcs.goat' `
                    -Template 'UserWithSIDExtension' -CertificateAuthority 'ADCSGOAT-CA\LabRootCA1' -ErrorAction Stop
            } catch {
                $errorRecord = $_
            }

            $errorRecord | Should -Not -BeNullOrEmpty
            $errorRecord.CategoryInfo.Category | Should -Be 'InvalidOperation'
            $errorRecord.Exception.Message | Should -Match 'Denied by policy module'
        }
    }

    Context 'when the certificate cannot be found in the store after install' {
        BeforeAll {
            Mock -CommandName New-PkinitCertificateSigningRequest -ModuleName PSPkinit -MockWith {
                [PSCustomObject]@{ Enrollment = [PSCustomObject]@{}; Base64Csr = 'ZmFrZS1jc3I=' }
            }
            Mock -CommandName Submit-PkinitCertificateSigningRequest -ModuleName PSPkinit -MockWith {
                [Convert]::ToBase64String((New-TestSelfSignedCertificate -Subject 'CN=Missing').RawData)
            }
            Mock -CommandName Install-PkinitCertificateResponse -ModuleName PSPkinit -MockWith { }
            Mock -CommandName Get-PkinitCertificateFromStore -ModuleName PSPkinit -MockWith { $null }
        }

        It 'surfaces a terminating error rather than returning a null certificate' {
            {
                New-PkinitCertificateRequest -Subject 'CN=Test User' -San 'user@adcs.goat' `
                    -Template 'UserWithSIDExtension' -CertificateAuthority 'ADCSGOAT-CA\LabRootCA1' -ErrorAction Stop
            } | Should -Throw
        }
    }
}
