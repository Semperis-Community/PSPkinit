<#
    Kerberos cryptographic primitives per RFC 3961 (encryption/checksum framework) and
    RFC 3962 (AES enctypes). Implements only what PKINIT (RFC 4556) needs for the
    Diffie-Hellman key delivery method against aes128/aes256-cts-hmac-sha1-96.

    ConvertTo-NFold and Protect-/Unprotect-AesCbcCts are verified against the official
    test vectors published in RFC 3961 Appendix A.1 and RFC 3962 Appendix B respectively
    (see Tests/KerberosCrypto.Tests.ps1). Get-DK/Get-DR are compositions of those verified
    primitives per the RFC 3961 section 5.1 formula, but have no independent published
    test vector for the AES cipher (only DES3 vectors exist in RFC 3961 Appendix A.3) -
    correctness relies on the correctness of the underlying, independently-verified
    primitives plus faithful transcription of the formula.
#>

function XorBytes {
    param(
        [Parameter(Mandatory)] [byte[]]$A,
        [Parameter(Mandatory)] [byte[]]$B
    )

    $result = New-Object byte[] $A.Length
    for ($i = 0; $i -lt $A.Length; $i++) {
        $result[$i] = $A[$i] -bxor $B[$i]
    }
    return $result
}

function Get-Gcd {
    param([long]$A, [long]$B)
    while ($B -ne 0) {
        $t = $B
        $B = $A % $B
        $A = $t
    }
    return $A
}

function Invoke-AesBlockEncrypt {
    <#
        .SYNOPSIS
        Encrypts exactly one 16-byte block with a fresh ICryptoTransform, since
        TransformFinalBlock() must only be called once per transform instance -
        reusing one across multiple blocks silently produces wrong ciphertext.
    #>
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.Aes]$Aes,
        [Parameter(Mandatory)] [byte[]]$Block
    )

    $transform = $Aes.CreateEncryptor()
    try {
        return $transform.TransformFinalBlock($Block, 0, $Block.Length)
    } finally {
        $transform.Dispose()
    }
}

function Invoke-AesBlockDecrypt {
    <#
        .SYNOPSIS
        Decrypts exactly one 16-byte block with a fresh ICryptoTransform, since
        TransformFinalBlock() must only be called once per transform instance -
        reusing one across multiple blocks silently produces wrong plaintext.
    #>
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.Aes]$Aes,
        [Parameter(Mandatory)] [byte[]]$Block
    )

    $transform = $Aes.CreateDecryptor()
    try {
        return $transform.TransformFinalBlock($Block, 0, $Block.Length)
    } finally {
        $transform.Dispose()
    }
}

function ConvertTo-NFold {
    <#
        .SYNOPSIS
        Implements the "n-fold" algorithm from RFC 3961 section 5.1.

        .DESCRIPTION
        Stretches or shrinks an input octet string to a fixed-length output octet
        string, giving each input bit approximately equal weight in the output, per
        the algorithm attributed to Blumenthal/Bellovin as specified in RFC 3961.

        This is a direct, literal translation of the RFC's textual description
        (replicate the input to lcm(n, len(X)) bits, rotating right by 13 bits
        before each successive repetition, then sum the resulting n-bit chunks
        using one's-complement addition with end-around carry) rather than the
        bit-twiddling optimized reference C implementation, to keep the logic
        auditable against the spec text.

        .PARAMETER InputBytes
        The input octet string.

        .PARAMETER OutputByteLength
        The desired output length, in octets.

        .OUTPUTS
        System.Byte[]
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$InputBytes,
        [Parameter(Mandatory)] [int]$OutputByteLength
    )

    $inBytes = $InputBytes.Length
    $outBytes = $OutputByteLength

    if ($inBytes -eq $outBytes) {
        return [byte[]]$InputBytes.Clone()
    }

    $inBits = $inBytes * 8
    $outBits = $outBytes * 8
    $gcdBits = Get-Gcd -A $inBits -B $outBits
    $lcmBits = $inBits * $outBits / $gcdBits
    $repetitions = $lcmBits / $inBits

    # Build the replicated, cumulatively-rotated bit sequence (bigBits[0] = MSB).
    $bigBits = New-Object bool[] $lcmBits
    for ($rep = 0; $rep -lt $repetitions; $rep++) {
        $rotation = (13 * $rep) % $inBits
        for ($bit = 0; $bit -lt $inBits; $bit++) {
            $srcBit = (($bit - $rotation) % $inBits + $inBits) % $inBits
            $byteIdx = [int][Math]::Floor($srcBit / 8)
            $bitInByte = $srcBit % 8
            $bitValue = (($InputBytes[$byteIdx] -shr (7 - $bitInByte)) -band 1) -eq 1
            $bigBits[$rep * $inBits + $bit] = $bitValue
        }
    }

    # Split into outBits-sized chunks and sum with one's-complement (end-around-carry) addition.
    $numChunks = $lcmBits / $outBits
    $accumulator = New-Object byte[] $outBytes

    for ($chunk = 0; $chunk -lt $numChunks; $chunk++) {
        $chunkBytes = New-Object byte[] $outBytes
        for ($byteIdx = 0; $byteIdx -lt $outBytes; $byteIdx++) {
            $b = 0
            for ($bitIdx = 0; $bitIdx -lt 8; $bitIdx++) {
                $globalBit = $chunk * $outBits + $byteIdx * 8 + $bitIdx
                if ($bigBits[$globalBit]) {
                    $b = $b -bor (1 -shl (7 - $bitIdx))
                }
            }
            $chunkBytes[$byteIdx] = $b
        }

        [int]$carry = 0
        $newAcc = New-Object byte[] $outBytes
        for ($i = $outBytes - 1; $i -ge 0; $i--) {
            $sum = $accumulator[$i] + $chunkBytes[$i] + $carry
            $newAcc[$i] = $sum -band 0xff
            $carry = $sum -shr 8
        }
        while ($carry -gt 0) {
            $innerCarry = $carry
            $carry = 0
            for ($i = $outBytes - 1; $i -ge 0 -and $innerCarry -gt 0; $i--) {
                $sum = $newAcc[$i] + $innerCarry
                $newAcc[$i] = $sum -band 0xff
                $innerCarry = $sum -shr 8
            }
            $carry = $innerCarry
        }
        $accumulator = $newAcc
    }

    return $accumulator
}

function Protect-AesCbcCts {
    <#
        .SYNOPSIS
        AES-CBC encryption with ciphertext stealing (CTS), per RFC 3962 section 5.

        .OUTPUTS
        PSCustomObject with Ciphertext and NextIv byte[] properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$Key,
        [Parameter(Mandatory)] [byte[]]$InitializationVector,
        [Parameter(Mandatory)] [byte[]]$Plaintext
    )

    $blockSize = 16
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None

    try {
        $len = $Plaintext.Length

        if ($len -le $blockSize) {
            $padded = New-Object byte[] $blockSize
            [Array]::Copy($Plaintext, $padded, $len)
            $cipherBlock = Invoke-AesBlockEncrypt -Aes $aes -Block $padded
            return [PSCustomObject]@{
                Ciphertext = $cipherBlock[0..($len - 1)]
                NextIv     = $cipherBlock
            }
        }

        $blockCount = [int][Math]::Ceiling($len / [double]$blockSize)
        $d = $len - (($blockCount - 1) * $blockSize)

        $blocks = New-Object 'System.Collections.Generic.List[byte[]]'
        for ($b = 0; $b -lt $blockCount; $b++) {
            $chunk = New-Object byte[] $blockSize
            $start = $b * $blockSize
            $copyLen = [Math]::Min($blockSize, $len - $start)
            [Array]::Copy($Plaintext, $start, $chunk, 0, $copyLen)
            $blocks.Add($chunk)
        }

        $n = $blocks.Count
        $cipherBlocks = New-Object 'System.Collections.Generic.List[byte[]]'
        $prevCipher = $InitializationVector

        for ($b = 0; $b -lt ($n - 2); $b++) {
            $xored = XorBytes -A $blocks[$b] -B $prevCipher
            $c = Invoke-AesBlockEncrypt -Aes $aes -Block $xored
            $cipherBlocks.Add($c)
            $prevCipher = $c
        }

        $xSecondLast = XorBytes -A $blocks[$n - 2] -B $prevCipher
        $eSecondLast = Invoke-AesBlockEncrypt -Aes $aes -Block $xSecondLast

        $cLast = $eSecondLast[0..($d - 1)]

        # Dn = En-1 XOR P, where P is Pn zero-padded to a full block (RFC 2040 section 8, step 5).
        $dBlock = New-Object byte[] $blockSize
        for ($i = 0; $i -lt $d; $i++) {
            $dBlock[$i] = $eSecondLast[$i] -bxor $blocks[$n - 1][$i]
        }
        if ($d -lt $blockSize) {
            [Array]::Copy($eSecondLast, $d, $dBlock, $d, $blockSize - $d)
        }

        $cSecondLast = Invoke-AesBlockEncrypt -Aes $aes -Block $dBlock
        $cipherBlocks.Add($cSecondLast)
        $cipherBlocks.Add($cLast)

        $allBytes = [System.Collections.Generic.List[byte]]::new()
        foreach ($cb in $cipherBlocks) { $allBytes.AddRange($cb) }

        return [PSCustomObject]@{
            Ciphertext = $allBytes.ToArray()
            NextIv     = $cSecondLast
        }
    } finally {
        $aes.Dispose()
    }
}

function Unprotect-AesCbcCts {
    <#
        .SYNOPSIS
        AES-CBC decryption with ciphertext stealing (CTS), per RFC 3962 section 5.

        .OUTPUTS
        System.Byte[]
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$Key,
        [Parameter(Mandatory)] [byte[]]$InitializationVector,
        [Parameter(Mandatory)] [byte[]]$Ciphertext
    )

    $blockSize = 16
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None

    try {
        $len = $Ciphertext.Length

        if ($len -le $blockSize) {
            $padded = New-Object byte[] $blockSize
            [Array]::Copy($Ciphertext, $padded, $len)
            $plainBlock = Invoke-AesBlockDecrypt -Aes $aes -Block $padded
            return $plainBlock[0..($len - 1)]
        }

        $fullBlocks = [int][Math]::Floor($len / [double]$blockSize)
        $remainder = $len - ($fullBlocks * $blockSize)
        if ($remainder -eq 0) {
            $n = $fullBlocks
            $d = $blockSize
        } else {
            $n = $fullBlocks + 1
            $d = $remainder
        }

        $cBlocks = New-Object 'System.Collections.Generic.List[byte[]]'
        $pos = 0
        for ($b = 0; $b -lt ($n - 2); $b++) {
            $cBlocks.Add([byte[]]$Ciphertext[$pos..($pos + $blockSize - 1)])
            $pos += $blockSize
        }
        $cSecondLast = $Ciphertext[$pos..($pos + $blockSize - 1)]
        $pos += $blockSize
        $cLast = $Ciphertext[$pos..($pos + $d - 1)]

        $dBlock = Invoke-AesBlockDecrypt -Aes $aes -Block $cSecondLast

        # Pn = first Ln bytes of Xn, where Xn = Dn XOR C (Cn zero-padded) - so the leading
        # bytes must be XORed with the received Cn, not copied directly (RFC 2040 section 8).
        $pLastReal = New-Object byte[] $d
        for ($i = 0; $i -lt $d; $i++) {
            $pLastReal[$i] = $dBlock[$i] -bxor $cLast[$i]
        }

        $eSecondLast = New-Object byte[] $blockSize
        [Array]::Copy($cLast, 0, $eSecondLast, 0, $d)
        if ($d -lt $blockSize) {
            [Array]::Copy($dBlock, $d, $eSecondLast, $d, $blockSize - $d)
        }

        $xSecondLast = Invoke-AesBlockDecrypt -Aes $aes -Block $eSecondLast

        $prevCipher = if ($n -gt 2) { $cBlocks[$n - 3] } else { $InitializationVector }
        $pSecondLast = XorBytes -A $xSecondLast -B $prevCipher

        $plainBlocks = [System.Collections.Generic.List[byte]]::new()
        $prevC = $InitializationVector
        for ($b = 0; $b -lt ($n - 2); $b++) {
            $p = Invoke-AesBlockDecrypt -Aes $aes -Block $cBlocks[$b]
            $p = XorBytes -A $p -B $prevC
            $plainBlocks.AddRange([byte[]]$p)
            $prevC = $cBlocks[$b]
        }

        $plainBlocks.AddRange([byte[]]$pSecondLast)
        $plainBlocks.AddRange([byte[]]$pLastReal)

        return $plainBlocks.ToArray()
    } finally {
        $aes.Dispose()
    }
}

function Get-KerberosUsageConstant {
    <#
        .SYNOPSIS
        Builds the 5-octet "well-known constant" used by DK() for a given key usage
        number and derived-key type (Kc=0x99, Ke=0xAA, Ki=0x55), per RFC 3961 5.3.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [uint32]$KeyUsage,
        [Parameter(Mandatory)] [byte]$Suffix
    )

    $usageBytes = [BitConverter]::GetBytes($KeyUsage)
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($usageBytes)
    }
    return $usageBytes + [byte[]]@($Suffix)
}

function Get-DR {
    <#
        .SYNOPSIS
        RFC 3961 section 5.1 DR() (derived-random) function, specialised for AES
        (cipher block size 16 octets, random-to-key = identity).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$Key,
        [Parameter(Mandatory)] [byte[]]$Constant
    )

    $blockSize = 16
    $c = $Constant
    if ($c.Length -ne $blockSize) {
        $c = ConvertTo-NFold -InputBytes $c -OutputByteLength $blockSize
    }

    $needed = $Key.Length
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None

    try {
        $blocks = [System.Collections.Generic.List[byte]]::new()
        $prev = $c
        while ($blocks.Count -lt $needed) {
            # Explicit [byte[]] cast: a script function's `return $byteArray` can come back
            # through the pipeline as System.Object[] rather than byte[] (observed on Windows
            # PowerShell 5.1 / .NET Framework), and List[byte].AddRange(IEnumerable<byte>) is a
            # generic method call that does NOT get PowerShell's friendly Object[]->byte[] method
            # argument coercion, so it throws PSInvalidCastException without this cast.
            $block = [byte[]](Invoke-AesBlockEncrypt -Aes $aes -Block $prev)
            $blocks.AddRange($block)
            $prev = $block
        }
        return [byte[]]$blocks.ToArray()[0..($needed - 1)]
    } finally {
        $aes.Dispose()
    }
}

function Get-DK {
    <#
        .SYNOPSIS
        RFC 3961 section 5.1 DK() (derived-key) function, specialised for AES
        (random-to-key = identity, so DK == DR for this cipher).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$BaseKey,
        [Parameter(Mandatory)] [byte[]]$Constant
    )

    return Get-DR -Key $BaseKey -Constant $Constant
}

function Get-KerberosDerivedKeys {
    <#
        .SYNOPSIS
        Derives the Kc/Ke/Ki triple used by the RFC 3961 simplified encryption/checksum
        profile for a given base key and key usage number.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]]$BaseKey,
        [Parameter(Mandatory)] [uint32]$KeyUsage
    )

    return [PSCustomObject]@{
        Kc = Get-DK -BaseKey $BaseKey -Constant (Get-KerberosUsageConstant -KeyUsage $KeyUsage -Suffix 0x99)
        Ke = Get-DK -BaseKey $BaseKey -Constant (Get-KerberosUsageConstant -KeyUsage $KeyUsage -Suffix 0xAA)
        Ki = Get-DK -BaseKey $BaseKey -Constant (Get-KerberosUsageConstant -KeyUsage $KeyUsage -Suffix 0x55)
    }
}

function Get-HmacSha1_96 {
    <#
        .SYNOPSIS
        HMAC-SHA1 truncated to the first 96 bits (12 octets), as used by
        aes128/256-cts-hmac-sha1-96 per RFC 3962.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$Key,
        [Parameter(Mandatory)] [byte[]]$Message
    )

    $hmac = [System.Security.Cryptography.HMACSHA1]::new($Key)
    try {
        $full = $hmac.ComputeHash($Message)
        return $full[0..11]
    } finally {
        $hmac.Dispose()
    }
}

function ConvertTo-OctetString2Key {
    <#
        .SYNOPSIS
        RFC 4556 section 3.2.3.1 octetstring2key() function, used to derive the
        PKINIT AS reply key from the Diffie-Hellman shared secret (and DH nonces,
        if DH key reuse is negotiated).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$InputBytes,
        [Parameter(Mandatory)] [int]$KeyByteLength
    )

    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $output = [System.Collections.Generic.List[byte]]::new()
        $counter = 0
        while ($output.Count -lt $KeyByteLength) {
            $prefixed = [byte[]]@([byte]$counter) + $InputBytes
            $hash = $sha1.ComputeHash($prefixed)
            $output.AddRange($hash)
            $counter++
        }
        return $output.ToArray()[0..($KeyByteLength - 1)]
    } finally {
        $sha1.Dispose()
    }
}

function Protect-KerberosData {
    <#
        .SYNOPSIS
        RFC 3961 section 5.3 simplified-profile encryption: confounder + plaintext,
        AES-CBC-CTS encrypted under Ke, with an HMAC-SHA1-96 under Ki over the
        confounder+plaintext appended to the ciphertext.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$BaseKey,
        [Parameter(Mandatory)] [uint32]$KeyUsage,
        [Parameter(Mandatory)] [byte[]]$Plaintext
    )

    $keys = Get-KerberosDerivedKeys -BaseKey $BaseKey -KeyUsage $KeyUsage
    $confounder = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($confounder)
    } finally {
        $rng.Dispose()
    }

    $toEncrypt = $confounder + $Plaintext
    $iv = New-Object byte[] 16
    $encrypted = Protect-AesCbcCts -Key $keys.Ke -InitializationVector $iv -Plaintext $toEncrypt
    $mac = Get-HmacSha1_96 -Key $keys.Ki -Message $toEncrypt

    return $encrypted.Ciphertext + $mac
}

function Unprotect-KerberosData {
    <#
        .SYNOPSIS
        Reverses Protect-KerberosData: verifies the HMAC-SHA1-96 trailer under Ki,
        then AES-CBC-CTS decrypts under Ke and strips the 16-byte confounder.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] [byte[]]$BaseKey,
        [Parameter(Mandatory)] [uint32]$KeyUsage,
        [Parameter(Mandatory)] [byte[]]$Ciphertext
    )

    $keys = Get-KerberosDerivedKeys -BaseKey $BaseKey -KeyUsage $KeyUsage
    $macLength = 12
    $cipherLength = $Ciphertext.Length - $macLength
    if ($cipherLength -le 0) {
        throw 'Ciphertext too short to contain an HMAC-SHA1-96 trailer.'
    }

    $cipherOnly = $Ciphertext[0..($cipherLength - 1)]
    $receivedMac = $Ciphertext[$cipherLength..($Ciphertext.Length - 1)]

    $iv = New-Object byte[] 16
    $decrypted = Unprotect-AesCbcCts -Key $keys.Ke -InitializationVector $iv -Ciphertext $cipherOnly

    $computedMac = Get-HmacSha1_96 -Key $keys.Ki -Message $decrypted
    $macsMatch = [System.Linq.Enumerable]::SequenceEqual([byte[]]$computedMac, [byte[]]$receivedMac)
    if (-not $macsMatch) {
        throw 'Kerberos EncryptedData integrity check failed (HMAC mismatch) - wrong key or corrupted data.'
    }

    return $decrypted[16..($decrypted.Length - 1)]
}
