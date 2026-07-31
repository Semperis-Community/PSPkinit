BeforeAll {
    . $PSScriptRoot/../Private/KerberosCrypto.ps1
}

Describe 'ConvertTo-NFold' {
    Context 'RFC 3961 Appendix A.1 test vectors' {
        It '64-fold("012345") = be072631276b1955' {
            $plaintextBytes = [byte[]](0x30, 0x31, 0x32, 0x33, 0x34, 0x35)
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 8
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be 'be072631276b1955'
        }

        It '56-fold("password") = 78a07b6caf85fa' {
            $plaintextBytes = [System.Text.Encoding]::ASCII.GetBytes('password')
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 7
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be '78a07b6caf85fa'
        }

        It '64-fold("Rough Consensus, and Running Code") = bb6ed30870b7f0e0' {
            $plaintextBytes = [System.Text.Encoding]::ASCII.GetBytes('Rough Consensus, and Running Code')
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 8
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be 'bb6ed30870b7f0e0'
        }

        It '168-fold("password") = 59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e' {
            $plaintextBytes = [System.Text.Encoding]::ASCII.GetBytes('password')
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 21
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be '59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e'
        }

        It '192-fold("MASSACHVSETTS INSTITVTE OF TECHNOLOGY") = db3b0d8f0b061e603282b308a50841229ad798fab9540c1b' {
            $plaintextBytes = [System.Text.Encoding]::ASCII.GetBytes('MASSACHVSETTS INSTITVTE OF TECHNOLOGY')
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 24
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be 'db3b0d8f0b061e603282b308a50841229ad798fab9540c1b'
        }

        It '168-fold("Q") = 518a54a215a8452a518a54a215a8452a518a54a215' {
            $plaintextBytes = [System.Text.Encoding]::ASCII.GetBytes('Q')
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 21
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be '518a54a215a8452a518a54a215a8452a518a54a215'
        }

        It '168-fold("ba") = fb25d531ae8974499f52fd92ea9857c4ba24cf297e' {
            $plaintextBytes = [System.Text.Encoding]::ASCII.GetBytes('ba')
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 21
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be 'fb25d531ae8974499f52fd92ea9857c4ba24cf297e'
        }

        It '64-fold("kerberos") = 6b65726265726f73' {
            $plaintextBytes = [System.Text.Encoding]::ASCII.GetBytes('kerberos')
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 8
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be '6b65726265726f73'
        }

        It '128-fold("kerberos") = 6b65726265726f737b9b5b2b93132b93' {
            $plaintextBytes = [System.Text.Encoding]::ASCII.GetBytes('kerberos')
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 16
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be '6b65726265726f737b9b5b2b93132b93'
        }

        It '168-fold("kerberos") = 8372c236344e5f1550cd0747e15d62ca7a5a3bcea4' {
            $plaintextBytes = [System.Text.Encoding]::ASCII.GetBytes('kerberos')
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 21
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be '8372c236344e5f1550cd0747e15d62ca7a5a3bcea4'
        }

        It '256-fold("kerberos") = 6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4' {
            $plaintextBytes = [System.Text.Encoding]::ASCII.GetBytes('kerberos')
            $result = ConvertTo-NFold -InputBytes $plaintextBytes -OutputByteLength 32
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be '6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4'
        }
    }
}

Describe 'Protect-AesCbcCts / Unprotect-AesCbcCts' {
    Context 'RFC 3962 Appendix B test vectors (AES-128, ciphertext stealing)' {
        BeforeAll {
            $script:Key = [byte[]](0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20, 0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69)
            $script:Iv = New-Object byte[] 16

            $script:Vectors = @(
                @{
                    Plaintext = [byte[]](0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20)
                    Ciphertext = 'c6353568f2bf8cb4d8a580362da7ff7f97'
                    NextIv = 'c6353568f2bf8cb4d8a580362da7ff7f'
                }
                @{
                    Plaintext = [byte[]](0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c, 0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20)
                    Ciphertext = 'fc00783e0efdb2c1d445d4c8eff7ed229768726 8d6ecccc0c07b25e25ecfe5'.Replace(' ', '')
                    NextIv = 'fc00783e0efdb2c1d445d4c8eff7ed22'
                }
                @{
                    Plaintext = [byte[]](0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c, 0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43)
                    Ciphertext = '393125 23a78662d5be7fcbcc98ebf5a89768726 8d6ecccc0c07b25e25ecfe584'.Replace(' ', '')
                    NextIv = '39312523a78662d5be7fcbcc98ebf5a8'
                }
                @{
                    Plaintext = [byte[]](0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c, 0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c)
                    Ciphertext = '97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5'
                    NextIv = 'b3fffd940c16a18c1b5549d2f838029e'
                }
                @{
                    Plaintext = [byte[]](0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c, 0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x77, 0x6f, 0x6e, 0x74, 0x6f, 0x6e, 0x20, 0x73, 0x6f, 0x75, 0x70, 0x2e)
                    Ciphertext = '97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8'
                    NextIv = '4807efe836ee89a526730dbc2f7bc840'
                }
            )
        }

        It 'encrypts test vector <_> correctly' -TestCases @(0, 1, 2, 3, 4) {
            $vector = $script:Vectors[$_]
            $result = Protect-AesCbcCts -Key $script:Key -InitializationVector $script:Iv -Plaintext $vector.Plaintext
            [System.BitConverter]::ToString($result.Ciphertext).Replace('-', '').ToLower() | Should -Be $vector.Ciphertext
            [System.BitConverter]::ToString($result.NextIv).Replace('-', '').ToLower() | Should -Be $vector.NextIv
        }

        It 'decrypts test vector <_> correctly' -TestCases @(0, 1, 2, 3, 4) {
            $vector = $script:Vectors[$_]
            $cipherBytes = for ($i = 0; $i -lt $vector.Ciphertext.Length; $i += 2) { [Convert]::ToByte($vector.Ciphertext.Substring($i, 2), 16) }
            $result = Unprotect-AesCbcCts -Key $script:Key -InitializationVector $script:Iv -Ciphertext ([byte[]]$cipherBytes)
            [System.BitConverter]::ToString($result).Replace('-', '').ToLower() | Should -Be ([System.BitConverter]::ToString($vector.Plaintext).Replace('-', '').ToLower())
        }
    }
}

Describe 'ConvertTo-OctetString2Key (RFC 4556 section 3.2.3.1)' {
    <#
        NOTE: RFC 4556 Appendix B publishes known-answer test vectors for this function,
        but the exact byte length of the "Set 1..4" sample inputs could not be reliably
        extracted from the fetched RFC text (repeated all-zero/pattern lines were
        summarized rather than reproduced verbatim), so encoding them here risked
        enshrining an incorrect vector rather than a real regression test. Instead, this
        verifies the function against the formula in the RFC computed independently with
        the .NET SHA1 primitive directly, which validates the concatenation/counter/
        truncation logic without depending on an externally-sourced byte vector.
    #>
    Context 'formula: random-to-key(K-truncate(SHA1(0x00|x) | SHA1(0x01|x) | ...))' {
        It 'matches an independently computed SHA1 concatenation for a 32-octet key' {
            $sha1 = [System.Security.Cryptography.SHA1]::Create()
            $x = [System.Text.Encoding]::ASCII.GetBytes('pkinit-test-shared-secret')

            $expectedBytes = [System.Collections.Generic.List[byte]]::new()
            0..2 | ForEach-Object {
                $prefixed = [byte[]]@([byte]$_) + $x
                $expectedBytes.AddRange($sha1.ComputeHash($prefixed))
            }
            $sha1.Dispose()
            $expected = $expectedBytes.ToArray()[0..31]

            $result = ConvertTo-OctetString2Key -InputBytes $x -KeyByteLength 32
            [System.BitConverter]::ToString($result).Replace('-', '') | Should -Be ([System.BitConverter]::ToString($expected).Replace('-', ''))
        }

        It 'returns exactly the requested key length for a 16-octet key' {
            $x = [System.Text.Encoding]::ASCII.GetBytes('another-shared-secret')
            $result = ConvertTo-OctetString2Key -InputBytes $x -KeyByteLength 16
            $result.Length | Should -Be 16
        }
    }
}
