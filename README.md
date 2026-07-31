# PSPkinit

A from-scratch, pure PowerShell/.NET implementation of RFC 4556 PKINIT
(public-key cryptography for initial authentication in Kerberos), using the
Diffie-Hellman key delivery method. It builds and parses the raw ASN.1/CMS
wire format itself — no dependency on Rubeus, MIT `kinit`, or any other
external Kerberos tooling.

**What this is for:** authenticating to a KDC as *your own* certificate's
identity, and validating that a certificate/CA/KDC configuration actually
supports PKINIT end-to-end (cert chain, EKU, SID security extension, strong
mapping enforcement, etc.).

**What this is *not*:** a ticket-forging, ticket-injection, or credential-theft
tool. It only ever authenticates using a certificate and private key you
already legitimately possess in your own certificate store — there is no
mechanism here for using someone else's certificate or injecting a
KDC-issued ticket into another logon session.

`New-PkinitCertificateRequest`'s optional `-Sid` parameter is the one
exception worth calling out explicitly: it can embed an arbitrary SID into a
requested certificate's security extension. On a misconfigured CA/template
(one that also allows an arbitrary client-supplied SAN), that combination is
the same primitive behind real certificate SID-spoofing/impersonation
techniques. Only ever use it with the SID of an identity you already control -
see [Advanced Usage](docs/advanced-usage.md#if-the-catemplate-doesnt-add-the-sid-security-extension-itself)
for details.

## Requirements

- PowerShell 5.1+ (Windows PowerShell/.NET Framework) or PowerShell 7+ (Core)
  — code is written to run on both.
- Windows (client certificate lookups go through `Cert:\CurrentUser\My`).
- A client certificate with a private key in your certificate store, issued
  for smart-card-logon-style client authentication (Client Authentication
  EKU), from an AD CS CA.
- Network reachability to a KDC on TCP port 88.
- If the domain enforces [KB5014754](https://support.microsoft.com/topic/kb5014754)
  strong certificate mapping in Full Enforcement mode, the certificate must
  carry the SID security extension (OID `1.3.6.1.4.1.311.25.2`) or the KDC
  will reject it.
- Only if you're using `New-PkinitCertificateRequest` to request a certificate
  with a custom SAN: the template must allow the enrollee to supply the
  Subject Alternative Name - i.e. the template's Subject Name tab is set to
  "Supply in the request" rather than "Build from this Active Directory
  information" (`msPKI-Certificate-Name-Flag` bit `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`,
  `0x00000001`). See [Troubleshooting](docs/troubleshooting.md) if your
  template doesn't allow this.

## Installation

```powershell
git clone https://github.com/Semperis-Community/PSPkinit.git
Import-Module .\PSPkinit\PSPkinit.psd1
```

Or copy the `PSPkinit` folder into a directory on `$env:PSModulePath` and run
`Import-Module PSPkinit` instead.

## Quick start

```powershell
# Authenticating with a certificate already in Cert:\CurrentUser\My:
$params = @{
    CertificateThumbprint = '<YOUR_CERT_THUMBPRINT>'
    ClientName             = 'user@your.realm'
    Realm                  = 'YOUR.REALM'
    KdcHostname            = 'your-kdc.your.realm'
}
Invoke-PkinitAuthentication @params

# ...or straight from a PFX file:
$securePassword = Read-Host -AsSecureString -Prompt 'PFX password'
$params = @{
    PfxPath     = 'C:\certs\user.pfx'
    PfxPassword = $securePassword
    ClientName  = 'user@your.realm'
    Realm       = 'YOUR.REALM'
    KdcHostname = 'your-kdc.your.realm'
}
Invoke-PkinitAuthentication @params
```

A successful run returns an object with your client/service principal names,
ticket validity window, negotiated session key, and the KDC's PKINIT signing
certificate — proof the whole PKINIT round trip (DH exchange, CMS-signed
AuthPack, KDC signature verification, reply-key derivation, AS-REP
decryption) worked. A rejection (KRB-ERROR, missing/invalid certificate,
etc.) surfaces as a normal terminating PowerShell error - see
`Get-Help Invoke-PkinitAuthentication -Full` for every parameter, and
[Troubleshooting](docs/troubleshooting.md) for what specific errors usually
mean.

## Further Reading

- [Advanced Usage](docs/advanced-usage.md) - requesting a certificate with a
  custom SAN and chaining straight into authentication, embedding the SID
  security extension yourself, validating ESC1, and doing the PKINIT
  exchange by hand without the module's public cmdlets.
- [Troubleshooting](docs/troubleshooting.md) - symptom-to-cause table for
  common errors.

## Running the tests

```powershell
Invoke-Pester -Path .\Tests
```

All ASN.1, crypto, and message-parsing logic is covered against published RFC
test vectors (RFC 3961 Appendix A.1, RFC 3962 Appendix B) plus round-trip
tests for the Kerberos/PKINIT structures.

## Limitations / non-goals

- Only the Diffie-Hellman key delivery method (RFC 4556 §3.2.3.1) is
  implemented. The `encKeyPack` (key-transport/reuse) choice in PA-PK-AS-REP
  is explicitly rejected.
- The KDC's signing certificate is cryptographically verified
  (`SignedCms.CheckSignature($true)`) but its **trust chain is not
  validated** — this module doesn't manage a trust store. Don't point it at
  a KDC you don't already trust.
- No ticket cache, no AP-REQ/TGS exchange, no Kerberos armoring (FAST) — this
  covers the AS-REQ/AS-REP PKINIT exchange only.

## License

This project is licensed under the MIT License with the Commons Clause
License Condition v1.0. See [LICENSE](LICENSE) for details.

---

Made with 💜 by [Jake Hildreth](https://jakehildreth.com)
