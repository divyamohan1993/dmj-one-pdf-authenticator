# Data Flow Documentation

This document describes how data flows through the dmj-one PDF Authenticator system for all major operations.

## Table of Contents

- [System Overview](#system-overview)
- [1. Admin Authentication Flow](#1-admin-authentication-flow)
- [2. PDF Signing Flow](#2-pdf-signing-flow)
- [3. PDF Verification Flow](#3-pdf-verification-flow)
- [4. Document Revocation Flow](#4-document-revocation-flow)
- [5. Trust Kit Distribution Flow](#5-trust-kit-distribution-flow)
- [6. PKI Operations Flow](#6-pki-operations-flow)
- [7. TSA Timestamping Flow](#7-tsa-timestamping-flow)
- [8. OCSP Certificate Status Flow](#8-ocsp-certificate-status-flow)
- [9. Session Management Flow](#9-session-management-flow)
- [10. Data Cleanup Flow](#10-data-cleanup-flow)
- [11. Deployment Flow](#11-deployment-flow)

---

## System Overview

The dmj-one PDF Authenticator is a distributed system with the following components:

```
┌─────────────┐
│   Browser   │ (User interface)
└──────┬──────┘
       │ HTTPS
       ↓
┌─────────────┐
│  Cloudflare │ (Worker + D1 Database)
│   Workers   │
└──────┬──────┘
       │ HTTPS + HMAC
       ↓
┌─────────────┐
│    nginx    │ (Reverse proxy + static files)
└──────┬──────┘
       │ HTTP (loopback)
       ↓
┌──────────────────────────────────┐
│         VM Services              │
│  ┌────────────┐ ┌──────┐ ┌─────┐│
│  │Java Signer │ │ TSA  │ │OCSP ││
│  │  :18080    │ │:9090 │ │:9080││
│  └────────────┘ └──────┘ └─────┘│
│  ┌─────────────────────────────┐ │
│  │      PKI Infrastructure     │ │
│  │  - Root CA                  │ │
│  │  - Issuing CA               │ │
│  │  - Certificates & CRLs      │ │
│  └─────────────────────────────┘ │
└──────────────────────────────────┘
```

---

## 1. Admin Authentication Flow

**Purpose:** Authenticate administrators to access the signing portal.

### Step-by-Step Flow

```
┌─────────┐                           ┌─────────────┐                      ┌──────────┐
│ Browser │                           │   Worker    │                      │    D1    │
└────┬────┘                           └──────┬──────┘                      └────┬─────┘
     │                                       │                                   │
     │ 1. GET /admin                        │                                   │
     ├──────────────────────────────────────>│                                   │
     │                                       │                                   │
     │                                       │ 2. Generate CSRF token            │
     │                                       │    (32 random bytes)              │
     │                                       │                                   │
     │ 3. admin-login.html + cookie         │                                   │
     │    Set-Cookie: csrf=<token>          │                                   │
     │<──────────────────────────────────────┤                                   │
     │                                       │                                   │
     │ 4. POST /admin/auth                  │                                   │
     │    Body: password=<pass>             │                                   │
     │    Cookie: csrf=<token>              │                                   │
     │    Header: X-CSRF: <token>           │                                   │
     ├──────────────────────────────────────>│                                   │
     │                                       │                                   │
     │                                       │ 5. Validate CSRF token            │
     │                                       │    (cookie == header)             │
     │                                       │                                   │
     │                                       │ 6. Validate Origin/Referer        │
     │                                       │                                   │
     │                                       │ 7. Hash password with             │
     │                                       │    PBKDF2/Argon2                  │
     │                                       │                                   │
     │                                       │ 8. Compare with ADMIN_PASS_HASH   │
     │                                       │                                   │
     │                                       │ 9. Generate session token         │
     │                                       │    HMAC(SESSION_HMAC_KEY,         │
     │                                       │         timestamp + rand)         │
     │                                       │                                   │
     │                                       │ 10. Store session in D1           │
     │                                       ├──────────────────────────────────>│
     │                                       │    INSERT INTO sessions           │
     │                                       │    (token, expires_at)            │
     │                                       │                                   │
     │                                       │<──────────────────────────────────┤
     │                                       │    Session ID                     │
     │                                       │                                   │
     │ 11. Redirect to /admin/dashboard     │                                   │
     │     Set-Cookie: session=<token>      │                                   │
     │<──────────────────────────────────────┤                                   │
     │                                       │                                   │
```

### Data Elements

**Request (Step 4):**
- `password`: Plain text password (transmitted over HTTPS)
- `csrf`: CSRF token from cookie
- `X-CSRF` header: CSRF token for validation

**Processing (Steps 5-9):**
- Password hashing: `PBKDF2-SHA256` with 100,000 iterations (or Argon2)
- Session token: `HMAC-SHA256(SESSION_HMAC_KEY, timestamp || random_bytes)`
- Session expiry: Current time + 8 hours

**Response (Step 11):**
- Session cookie: `SameSite=Strict; Secure; HttpOnly`
- Expiry: 8 hours from authentication

---

## 2. PDF Signing Flow

**Purpose:** Sign a PDF document with a PAdES-compliant digital signature.

### Complete Flow Diagram

```
┌─────────┐         ┌─────────┐         ┌────────────┐         ┌─────┐         ┌─────┐         ┌──────┐
│ Browser │         │ Worker  │         │Java Signer │         │ TSA │         │OCSP │         │  D1  │
└────┬────┘         └────┬────┘         └─────┬──────┘         └──┬──┘         └──┬──┘         └───┬──┘
     │                   │                     │                   │               │                │
     │ 1. POST /admin/sign                    │                   │               │                │
     │    + PDF file (multipart)              │                   │               │                │
     │    Cookie: session=<token>             │                   │               │                │
     ├───────────────────>│                     │                   │               │                │
     │                   │                     │                   │               │                │
     │                   │ 2. Validate session │                   │               │                │
     │                   ├────────────────────────────────────────────────────────────────────────>│
     │                   │    SELECT * FROM sessions                                                │
     │                   │    WHERE token=? AND expires_at > NOW()                                  │
     │                   │<────────────────────────────────────────────────────────────────────────┤
     │                   │                     │                   │               │                │
     │                   │ 3. Compute SHA-256  │                   │               │                │
     │                   │    digest of PDF    │                   │               │                │
     │                   │                     │                   │               │                │
     │                   │ 4. Check for duplicate                 │               │                │
     │                   ├────────────────────────────────────────────────────────────────────────>│
     │                   │    SELECT * FROM documents                                               │
     │                   │    WHERE doc_sha256=?                                                    │
     │                   │<────────────────────────────────────────────────────────────────────────┤
     │                   │                     │                   │               │                │
     │                   │ 5. Generate HMAC    │                   │               │                │
     │                   │    timestamp=NOW()  │                   │               │                │
     │                   │    nonce=random()   │                   │               │                │
     │                   │    sig=HMAC-SHA256( │                   │               │                │
     │                   │      key,           │                   │               │                │
     │                   │      POST||path||   │                   │               │                │
     │                   │      ts||nonce||pdf)│                   │               │                │
     │                   │                     │                   │               │                │
     │                   │ 6. POST /sign       │                   │               │                │
     │                   │    Headers:         │                   │               │                │
     │                   │      x-worker-hmac  │                   │               │                │
     │                   │      x-worker-ts    │                   │               │                │
     │                   │      x-worker-nonce │                   │               │                │
     │                   │    Body: PDF bytes  │                   │               │                │
     │                   ├────────────────────>│                   │               │                │
     │                   │                     │                   │               │                │
     │                   │                     │ 7. Validate HMAC  │               │                │
     │                   │                     │    Check timestamp│               │                │
     │                   │                     │    (±5 minutes)   │               │                │
     │                   │                     │    Check nonce not│               │                │
     │                   │                     │    seen before    │               │                │
     │                   │                     │                   │               │                │
     │                   │                     │ 8. Load signer    │               │                │
     │                   │                     │    PKCS#12 +      │               │                │
     │                   │                     │    certificate    │               │                │
     │                   │                     │    chain          │               │                │
     │                   │                     │                   │               │                │
     │                   │                     │ 9. Create PAdES   │               │                │
     │                   │                     │    signature with │               │                │
     │                   │                     │    PDFBox         │               │                │
     │                   │                     │                   │               │                │
     │                   │                     │ 10. Request timestamp              │                │
     │                   │                     ├──────────────────>│               │                │
     │                   │                     │    POST /         │               │                │
     │                   │                     │    Body: TSQ      │               │                │
     │                   │                     │    (TimeStampReq) │               │                │
     │                   │                     │                   │               │                │
     │                   │                     │                   │ 11. Generate  │                │
     │                   │                     │                   │     timestamp │                │
     │                   │                     │                   │     token     │                │
     │                   │                     │                   │               │                │
     │                   │                     │<──────────────────┤               │                │
     │                   │                     │    TSR            │               │                │
     │                   │                     │    (TimeStampResp)│               │                │
     │                   │                     │                   │               │                │
     │                   │                     │ 12. Add signature-│               │                │
     │                   │                     │     time-stamp    │               │                │
     │                   │                     │     attribute     │               │                │
     │                   │                     │                   │               │                │
     │                   │                     │ 13. Query OCSP for signer cert    │                │
     │                   │                     ├───────────────────────────────────>│                │
     │                   │                     │    POST /         │               │                │
     │                   │                     │    Body: OCSPReq  │               │                │
     │                   │                     │                   │               │                │
     │                   │                     │                   │    14. Query  │                │
     │                   │                     │                   │        cert   │                │
     │                   │                     │                   │        status │                │
     │                   │                     │                   │        in DB  │                │
     │                   │                     │                   │               │                │
     │                   │                     │<───────────────────────────────────┤                │
     │                   │                     │    OCSPResp       │               │                │
     │                   │                     │                   │               │                │
     │                   │                     │ 15. Create/update │               │                │
     │                   │                     │     DSS dict      │               │                │
     │                   │                     │     - Add certs   │               │                │
     │                   │                     │     - Add CRLs    │               │                │
     │                   │                     │     - Add OCSP    │               │                │
     │                   │                     │     - Create VRI  │               │                │
     │                   │                     │                   │               │                │
     │                   │                     │ 16. Optional:     │               │                │
     │                   │                     │     Add DocTimeStamp              │                │
     │                   │                     │     (for LTA)     │               │                │
     │                   │                     ├──────────────────>│               │                │
     │                   │                     │    (repeat TSA)   │               │                │
     │                   │                     │                   │               │                │
     │                   │                     │ 17. Build ZIP     │               │                │
     │                   │                     │     bundle with   │               │                │
     │                   │                     │     Trust Kit     │               │                │
     │                   │                     │                   │               │                │
     │                   │ 18. Return signed PDF + bundle URL      │               │                │
     │                   │<────────────────────┤                   │               │                │
     │                   │                     │                   │               │                │
     │                   │ 19. Store metadata  │                   │               │                │
     │                   ├────────────────────────────────────────────────────────────────────────>│
     │                   │    INSERT INTO documents                                                 │
     │                   │    (id, doc_sha256, signed_at,                                           │
     │                   │     cert_serial, meta_json)                                              │
     │                   │<────────────────────────────────────────────────────────────────────────┤
     │                   │                     │                   │               │                │
     │ 20. JSON response │                     │                   │               │                │
     │     {             │                     │                   │               │                │
     │       "status":"ok"                     │                   │               │                │
     │       "download_url"                    │                   │               │                │
     │     }             │                     │                   │               │                │
     │<───────────────────┤                     │                   │               │                │
     │                   │                     │                   │               │                │
     │ 21. GET /download/bundle.zip           │                   │               │                │
     ├───────────────────>│                     │                   │               │                │
     │                   │                     │                   │               │                │
     │                   │ 22. Proxy to nginx  │                   │               │                │
     │                   │     /pki/pub/dl/    │                   │               │                │
     │                   │                     │                   │               │                │
     │ 23. ZIP bundle    │                     │                   │               │                │
     │     (PDF + Trust Kit)                  │                   │               │                │
     │<───────────────────┤                     │                   │               │                │
     │                   │                     │                   │               │                │
```

### Data Transformations

**Input PDF:**
- Original unsigned PDF document
- Size: Variable (typically 100KB - 10MB)
- Format: PDF 1.4 or higher

**SHA-256 Digest:**
- Computed by Worker before signing
- Length: 32 bytes (64 hex characters)
- Used for: Duplicate detection, D1 storage, HMAC input

**HMAC Signature:**
```
signature = HMAC-SHA256(
    key = SIGNING_GATEWAY_HMAC_KEY,
    data = "POST" || 0x00 ||
           "/sign" || 0x00 ||
           timestamp || 0x00 ||
           nonce || 0x00 ||
           pdf_bytes
)
```

**PAdES Signature Components:**
1. **CMS SignedData** (RFC 5652)
   - Signer certificate
   - Signature algorithm: SHA256withRSA
   - Signed attributes (message digest, signing time)
   - Optional: signature-time-stamp unsigned attribute

2. **DSS (Document Security Store)**
   - `/DSS/Certs`: Array of certificate streams
   - `/DSS/CRLs`: Array of CRL streams
   - `/DSS/OCSPs`: Array of OCSP response streams
   - `/DSS/VRIs/<digest>`: Validation-Related Information per signature

3. **VRI Entry** (per signature)
   - `/Cert`: Indices into `/DSS/Certs`
   - `/CRL`: Indices into `/DSS/CRLs`
   - `/OCSP`: Indices into `/DSS/OCSPs`
   - `/TU`: Timestamp of VRI creation

**Trust Kit Bundle:**
- Format: ZIP (uncompressed, STORE method)
- Contents:
  - `document-signed.pdf` (the signed PDF)
  - `trust-kit/dmj-one-root-ca-r1.cer`
  - `trust-kit/dmj-one-root-ca-r1.crt`
  - `trust-kit/dmj-one-issuing-ca-r1.crt`
  - `trust-kit/install-dmj-certificates.bat`
  - `trust-kit/README.txt`
  - `trust-kit/README.html`
  - `trust-kit/SHA256SUMS.txt`

**D1 Storage:**
```sql
INSERT INTO documents (
  id,           -- UUID v4
  doc_sha256,   -- Hex string (64 chars)
  signed_at,    -- Unix timestamp
  cert_serial,  -- Certificate serial number (hex)
  meta_json     -- JSON: {filename, size, issuer}
)
```

---

## 3. PDF Verification Flow

**Purpose:** Verify the authenticity and integrity of a signed PDF.

### Flow Diagram

```
┌─────────┐         ┌─────────┐         ┌────────────┐         ┌──────┐
│ Browser │         │ Worker  │         │Java Signer │         │  D1  │
└────┬────┘         └────┬────┘         └─────┬──────┘         └───┬──┘
     │                   │                     │                   │
     │ 1. POST /verify   │                     │                   │
     │    + PDF file     │                     │                   │
     ├───────────────────>│                     │                   │
     │                   │                     │                   │
     │                   │ 2. Compute SHA-256  │                   │
     │                   │    of uploaded PDF  │                   │
     │                   │                     │                   │
     │                   │ 3. Query D1         │                   │
     │                   ├─────────────────────────────────────────>│
     │                   │    SELECT * FROM documents              │
     │                   │    WHERE doc_sha256=?                   │
     │                   │<─────────────────────────────────────────┤
     │                   │    Result: FOUND / NOT_FOUND            │
     │                   │                     │                   │
     │                   │ 4. If FOUND:        │                   │
     │                   │    Check revoked_at │                   │
     │                   │                     │                   │
     │                   │ 5. Extract CMS from PDF                 │
     │                   │    (parse PDF structure)                │
     │                   │                     │                   │
     │                   │ 6. POST /verify     │                   │
     │                   │    Body: PDF bytes  │                   │
     │                   ├────────────────────>│                   │
     │                   │                     │                   │
     │                   │                     │ 7. Extract signature             │
     │                   │                     │    - Parse /ByteRange            │
     │                   │                     │    - Extract CMS blob            │
     │                   │                     │                   │
     │                   │                     │ 8. Validate signature            │
     │                   │                     │    - Verify CMS cryptographically│
     │                   │                     │    - Check certificate chain     │
     │                   │                     │    - Validate timestamps         │
     │                   │                     │                   │
     │                   │                     │ 9. Extract SPKI fingerprint      │
     │                   │                     │    from signer cert              │
     │                   │                     │                   │
     │                   │                     │ 10. Compare with known SPKI      │
     │                   │                     │                   │
     │                   │                     │ 11. Check certificate            │
     │                   │                     │     via CRL/OCSP │                   │
     │                   │                     │                   │
     │                   │                     │ 12. Return result│                   │
     │                   │<────────────────────┤                   │
     │                   │    {valid, spki_match, cert_status}    │
     │                   │                     │                   │
     │                   │ 13. Determine final status              │
     │                   │     GENUINE: valid && in_db && !revoked │
     │                   │     TAMPERED: !valid                    │
     │                   │     REVOKED: revoked_at != NULL         │
     │                   │     UNKNOWN: !in_db                     │
     │                   │                     │                   │
     │                   │ 14. Cache result    │                   │
     │                   ├─────────────────────────────────────────>│
     │                   │    INSERT INTO doc_verifications        │
     │                   │    (doc_sha256, has_signature, status)  │
     │                   │<─────────────────────────────────────────┤
     │                   │                     │                   │
     │ 15. JSON response │                     │                   │
     │     {             │                     │                   │
     │       "status":"GENUINE",               │                   │
     │       "signed_at":"2025-01-15T...",    │                   │
     │       "issuer":"dmj.one"                │                   │
     │     }             │                     │                   │
     │<───────────────────┤                     │                   │
     │                   │                     │                   │
```

### Verification Outcomes

| Condition | Status | HTTP Code | Description |
|-----------|--------|-----------|-------------|
| Valid signature + In DB + Not revoked | `GENUINE` | 200 | Document is authentic |
| Valid signature + Not in DB | `UNKNOWN` | 200 | Signature valid but not issued by us |
| Invalid signature or tampered | `TAMPERED` | 200 | Document has been modified |
| In DB + revoked_at != NULL | `REVOKED` | 200 | Document has been revoked |
| No signature found | `NO_SIGNATURE` | 200 | PDF is not signed |

---

## 4. Document Revocation Flow

**Purpose:** Revoke a previously signed document.

### Flow Diagram

```
┌─────────┐         ┌─────────┐         ┌────────────┐         ┌──────┐
│ Browser │         │ Worker  │         │Java Signer │         │  D1  │
└────┬────┘         └────┬────┘         └─────┬──────┘         └───┬──┘
     │                   │                     │                   │
     │ 1. POST /admin/revoke                  │                   │
     │    Body: {                              │                   │
     │      doc_id: "uuid",                    │                   │
     │      reason: "compromised",             │                   │
     │      totp: "123456"                     │                   │
     │    }                                    │                   │
     │    Cookie: session, csrf                │                   │
     │    Header: X-CSRF                       │                   │
     ├───────────────────>│                     │                   │
     │                   │                     │                   │
     │                   │ 2. Validate session │                   │
     │                   ├─────────────────────────────────────────>│
     │                   │<─────────────────────────────────────────┤
     │                   │                     │                   │
     │                   │ 3. Validate CSRF    │                   │
     │                   │    (cookie == header)                   │
     │                   │                     │                   │
     │                   │ 4. Validate Origin  │                   │
     │                   │    (same-origin)    │                   │
     │                   │                     │                   │
     │                   │ 5. Validate TOTP    │                   │
     │                   │    TOTP = HOTP(     │                   │
     │                   │      TOTP_MASTER_KEY,                   │
     │                   │      time_step)     │                   │
     │                   │                     │                   │
     │                   │ 6. Get document     │                   │
     │                   ├─────────────────────────────────────────>│
     │                   │    SELECT * FROM documents              │
     │                   │    WHERE id=?       │                   │
     │                   │<─────────────────────────────────────────┤
     │                   │                     │                   │
     │                   │ 7. Update D1 record │                   │
     │                   ├─────────────────────────────────────────>│
     │                   │    UPDATE documents │                   │
     │                   │    SET revoked_at=NOW(),                │
     │                   │        revoke_reason=?                  │
     │                   │    WHERE id=?       │                   │
     │                   │<─────────────────────────────────────────┤
     │                   │                     │                   │
     │                   │ 8. POST /revoke     │                   │
     │                   │    Body: {          │                   │
     │                   │      cert_serial    │                   │
     │                   │    }                │                   │
     │                   ├────────────────────>│                   │
     │                   │                     │                   │
     │                   │                     │ 9. Revoke certificate            │
     │                   │                     │    in ICA database               │
     │                   │                     │    openssl ca -revoke            │
     │                   │                     │                   │
     │                   │                     │ 10. Generate new CRL             │
     │                   │                     │     openssl ca -gencrl           │
     │                   │                     │                   │
     │                   │                     │ 11. Publish CRL  │                   │
     │                   │                     │     to /opt/dmj/pki/pub/         │
     │                   │                     │                   │
     │                   │<────────────────────┤                   │
     │                   │    {status: "ok"}   │                   │
     │                   │                     │                   │
     │ 12. JSON response │                     │                   │
     │     {             │                     │                   │
     │       "status":"revoked"                │                   │
     │     }             │                     │                   │
     │<───────────────────┤                     │                   │
     │                   │                     │                   │
```

### Revocation Data

**TOTP Algorithm:**
```
TOTP = HOTP(TOTP_MASTER_KEY, T)
where T = floor((current_time - T0) / X)
      T0 = Unix epoch (0)
      X = 30 seconds (time step)
```

**CRL Update:**
- Format: X.509 CRL (DER encoded)
- Published to: `/opt/dmj/pki/pub/ica.crl`
- Also as: `/opt/dmj/pki/pub/dmj-one-issuing-ca-r1.crl`
- OCSP service automatically reloads when CRL changes

---

## 5. Trust Kit Distribution Flow

**Purpose:** Distribute certificates and tools for trusting dmj.one signatures.

### Flow Diagram

```
┌─────────┐         ┌─────────┐         ┌───────┐
│ Browser │         │ Worker  │         │ nginx │
└────┬────┘         └────┬────┘         └───┬───┘
     │                   │                   │
     │ 1. Click "Download Trust Kit"        │
     │    on verification page               │
     │                   │                   │
     │ 2. GET /pki/dmj-one-trust-kit.zip    │
     ├───────────────────>│                   │
     │                   │                   │
     │                   │ 3. Redirect       │
     │                   │    to PKI domain  │
     │                   │                   │
     │ 4. HTTP 302       │                   │
     │    Location: https://pki.dmj.one/    │
     │              dmj-one-trust-kit.zip    │
     │<───────────────────┤                   │
     │                   │                   │
     │ 5. GET https://pki.dmj.one/          │
     │         dmj-one-trust-kit.zip         │
     ├───────────────────────────────────────>│
     │                   │                   │
     │                   │                   │ 6. Read file from
     │                   │                   │    /opt/dmj/pki/pub/
     │                   │                   │    dmj-one-trust-kit.zip
     │                   │                   │
     │ 7. ZIP file (200-300 KB)              │
     │    Content-Type: application/zip      │
     │<───────────────────────────────────────┤
     │                   │                   │
     │ 8. User extracts ZIP                  │
     │    and runs install-dmj-certificates.bat (Windows)
     │    or manually imports .crt files (macOS/Linux)
     │                   │                   │
```

### Trust Kit Contents

**ZIP Structure:**
```
dmj-one-trust-kit-r1.zip
├── dmj-one-root-ca-r1.cer           # DER format (binary)
├── dmj-one-root-ca-r1.crt           # PEM format (text)
├── dmj-one-issuing-ca-r1.crt        # PEM format
├── install-dmj-certificates.bat     # Windows installer script
├── README.txt                        # Plain text instructions
├── README.html                       # HTML instructions
└── SHA256SUMS.txt                    # Integrity checksums
```

**install-dmj-certificates.bat:**
```batch
@echo off
certutil -addstore -f "Root" dmj-one-root-ca-r1.cer
certutil -addstore -f "CA" dmj-one-issuing-ca-r1.crt
echo Certificates installed successfully!
pause
```

---

## 6. PKI Operations Flow

**Purpose:** Manage the certificate authority infrastructure.

### Certificate Issuance Flow

```
┌──────────────┐         ┌─────────────┐         ┌──────────┐
│ dmj-part2.sh │         │   OpenSSL   │         │   ICA    │
│  (Deployment)│         │             │         │ Database │
└──────┬───────┘         └──────┬──────┘         └────┬─────┘
       │                        │                     │
       │ 1. Check if cert exists                     │
       │    (e.g., signer.crt)  │                     │
       │                        │                     │
       │ 2. Generate private key│                     │
       │    openssl genrsa -out signer.key 4096      │
       ├───────────────────────>│                     │
       │                        │                     │
       │                        │ 3. Generate RSA key │
       │                        │    (4096 bits)      │
       │                        │                     │
       │<───────────────────────┤                     │
       │    signer.key          │                     │
       │                        │                     │
       │ 4. Create CSR          │                     │
       │    openssl req -new    │                     │
       │    -key signer.key     │                     │
       │    -out signer.csr     │                     │
       │    -subj "/C=IN/O=dmj.one/CN=dmj.one Signer"│
       ├───────────────────────>│                     │
       │                        │                     │
       │<───────────────────────┤                     │
       │    signer.csr          │                     │
       │                        │                     │
       │ 5. Sign CSR with ICA   │                     │
       │    openssl ca          │                     │
       │    -config ica.cnf     │                     │
       │    -in signer.csr      │                     │
       │    -out signer.crt     │                     │
       │    -days 825           │                     │
       │    -extensions signer_ext                    │
       ├───────────────────────>│                     │
       │                        │                     │
       │                        │ 6. Update ICA DB    │
       │                        ├────────────────────>│
       │                        │    Add to index.txt │
       │                        │    Increment serial │
       │                        │                     │
       │                        │<────────────────────┤
       │                        │                     │
       │<───────────────────────┤                     │
       │    signer.crt          │                     │
       │                        │                     │
       │ 7. Build PKCS#12       │                     │
       │    openssl pkcs12 -export                    │
       │    -in signer.crt      │                     │
       │    -inkey signer.key   │                     │
       │    -certfile ica.crt   │                     │
       │    -certfile root.crt  │                     │
       │    -out keystore.p12   │                     │
       ├───────────────────────>│                     │
       │                        │                     │
       │<───────────────────────┤                     │
       │    keystore.p12        │                     │
       │                        │                     │
```

### CRL Generation Flow

```
┌────────────┐         ┌─────────────┐         ┌──────────┐         ┌─────────┐
│Java Signer │         │   OpenSSL   │         │   ICA    │         │  nginx  │
│  /revoke   │         │             │         │ Database │         │         │
└─────┬──────┘         └──────┬──────┘         └────┬─────┘         └────┬────┘
      │                       │                     │                     │
      │ 1. Revoke certificate │                     │                     │
      │    openssl ca -revoke │                     │                     │
      │    -config ica.cnf    │                     │                     │
      │    -cert signer.crt   │                     │                     │
      ├──────────────────────>│                     │                     │
      │                       │                     │                     │
      │                       │ 2. Update index.txt │                     │
      │                       ├────────────────────>│                     │
      │                       │    Mark cert as 'R' │                     │
      │                       │    (Revoked)        │                     │
      │                       │<────────────────────┤                     │
      │                       │                     │                     │
      │ 3. Generate new CRL   │                     │                     │
      │    openssl ca -gencrl │                     │                     │
      │    -config ica.cnf    │                     │                     │
      │    -out ica.crl       │                     │                     │
      ├──────────────────────>│                     │                     │
      │                       │                     │                     │
      │                       │ 4. Read index.txt   │                     │
      │                       │    and build CRL    │                     │
      │                       ├────────────────────>│                     │
      │                       │<────────────────────┤                     │
      │                       │                     │                     │
      │<──────────────────────┤                     │                     │
      │    ica.crl            │                     │                     │
      │                       │                     │                     │
      │ 5. Copy to public dir │                     │                     │
      │    cp ica.crl /opt/dmj/pki/pub/            │                     │
      │    cp ica.crl /opt/dmj/pki/pub/dmj-one-issuing-ca-r1.crl        │
      │                       │                     │                     │
      │ 6. OCSP auto-reloads  │                     │                     │
      │    (watches file)     │                     │                     │
      │                       │                     │                     │
```

### ICA Database Format

**index.txt:**
```
V	260115120000Z		01	unknown	/C=IN/O=dmj.one/CN=dmj.one Signer
R	260115120000Z	250115120000Z	02	unknown	/C=IN/O=dmj.one/CN=revoked-cert
```

Fields:
1. Status: `V` (Valid), `R` (Revoked), `E` (Expired)
2. Expiration date: `YYMMDDHHmmssZ`
3. Revocation date: `YYMMDDHHmmssZ` (only if revoked)
4. Serial number: Hex string
5. Filename: `unknown` or path to certificate file
6. Subject DN: Distinguished Name

---

## 7. TSA Timestamping Flow

**Purpose:** Issue RFC 3161 timestamps for signatures.

### Flow Diagram

```
┌────────────┐         ┌───────────┐         ┌─────────┐
│Java Signer │         │TSA Service│         │ OpenSSL │
└─────┬──────┘         └─────┬─────┘         └────┬────┘
      │                      │                     │
      │ 1. Compute message digest                 │
      │    (signature value)                       │
      │                      │                     │
      │ 2. Build TimeStampReq                      │
      │    - version: 1      │                     │
      │    - messageImprint: │                     │
      │        hashAlgorithm: SHA-256              │
      │        hashedMessage: digest               │
      │    - reqPolicy: 1.3.6.1.4.1.55555.1.1      │
      │    - nonce: random   │                     │
      │    - certReq: true   │                     │
      │                      │                     │
      │ 3. POST http://127.0.0.1:9090/            │
      │    Content-Type: application/timestamp-query
      │    Body: TimeStampReq (DER)                │
      ├─────────────────────>│                     │
      │                      │                     │
      │                      │ 4. Parse TSQ        │
      │                      │                     │
      │                      │ 5. Write TSQ to tmp │
      │                      │    file             │
      │                      │                     │
      │                      │ 6. Call openssl ts -reply
      │                      ├────────────────────>│
      │                      │    openssl ts       │
      │                      │    -config ts.cnf   │
      │                      │    -reply           │
      │                      │    -queryfile req.tsq
      │                      │    -out resp.tsr    │
      │                      │                     │
      │                      │                     │ 7. Read tsa.key
      │                      │                     │    and tsa.crt
      │                      │                     │
      │                      │                     │ 8. Generate timestamp
      │                      │                     │    - Current time
      │                      │                     │    - Serial number
      │                      │                     │    - Sign with TSA key
      │                      │                     │
      │                      │<────────────────────┤
      │                      │    resp.tsr         │
      │                      │                     │
      │                      │ 9. Read TSR file    │
      │                      │                     │
      │<─────────────────────┤                     │
      │    Content-Type: application/timestamp-reply
      │    Body: TimeStampResp (DER)               │
      │                      │                     │
      │ 10. Parse TimeStampResp                    │
      │     - Extract TimeStampToken               │
      │     - Verify signature                     │
      │     - Embed in CMS as unsigned attribute   │
      │                      │                     │
```

### TSA Data Format

**TimeStampReq (ASN.1):**
```
TimeStampReq ::= SEQUENCE {
   version                  INTEGER  { v1(1) },
   messageImprint           MessageImprint,
   reqPolicy                TSAPolicyId              OPTIONAL,
   nonce                    INTEGER                  OPTIONAL,
   certReq                  BOOLEAN                  DEFAULT FALSE
}

MessageImprint ::= SEQUENCE {
   hashAlgorithm           AlgorithmIdentifier,
   hashedMessage           OCTET STRING
}
```

**TimeStampToken:**
- Embedded as unsigned attribute in CMS signature
- OID: `id-aa-timeStampToken` (1.2.840.113549.1.9.16.2.14)
- Contains: Signature timestamp, TSA certificate, serial number

---

## 8. OCSP Certificate Status Flow

**Purpose:** Query real-time certificate status.

### Flow Diagram

```
┌────────────┐         ┌──────────┐         ┌─────────┐
│Java Signer │         │   OCSP   │         │   ICA   │
│            │         │ Responder│         │ Database│
└─────┬──────┘         └─────┬────┘         └────┬────┘
      │                      │                    │
      │ 1. Build OCSPReq     │                    │
      │    - cert serial     │                    │
      │    - issuer name hash│                    │
      │    - issuer key hash │                    │
      │                      │                    │
      │ 2. POST http://127.0.0.1:9080/           │
      │    Content-Type: application/ocsp-request│
      │    Body: OCSPReq (DER)                    │
      ├─────────────────────>│                    │
      │                      │                    │
      │                      │ 3. Parse OCSPReq   │
      │                      │                    │
      │                      │ 4. Look up cert    │
      │                      │    in index.txt    │
      │                      ├───────────────────>│
      │                      │    Read status     │
      │                      │<───────────────────┤
      │                      │    V/R/E           │
      │                      │                    │
      │                      │ 5. Build OCSPResp  │
      │                      │    - responseStatus: successful
      │                      │    - certStatus:   │
      │                      │        good / revoked / unknown
      │                      │    - thisUpdate    │
      │                      │    - nextUpdate    │
      │                      │    - Sign with OCSP key
      │                      │                    │
      │<─────────────────────┤                    │
      │    Content-Type: application/ocsp-response
      │    Body: OCSPResp (DER)                   │
      │                      │                    │
      │ 6. Parse OCSPResp    │                    │
      │    - Verify signature│                    │
      │    - Extract certStatus                   │
      │    - Embed in DSS (if signing)            │
      │                      │                    │
```

### OCSP Response Status

```
CertStatus ::= CHOICE {
    good        [0]     IMPLICIT NULL,
    revoked     [1]     IMPLICIT RevokedInfo,
    unknown     [2]     IMPLICIT UnknownInfo
}

RevokedInfo ::= SEQUENCE {
    revocationTime              GeneralizedTime,
    revocationReason    [0]     EXPLICIT CRLReason OPTIONAL
}
```

---

## 9. Session Management Flow

**Purpose:** Manage admin session lifecycle.

### Session Creation

See [Admin Authentication Flow](#1-admin-authentication-flow) for session creation.

### Session Validation

```
For each authenticated request:
1. Extract session token from cookie
2. Query D1: SELECT * FROM sessions WHERE token=? AND expires_at > NOW()
3. If found and not expired: Continue
4. If not found or expired: Redirect to /admin/login
```

### Session Expiry

**Automatic Expiry:**
- TTL: 8 hours from creation
- Checked on every request
- Expired sessions rejected

**Manual Logout:**
```
POST /admin/logout
1. Delete session from D1
2. Clear session cookie
3. Redirect to /admin/login
```

**Cron Cleanup:**
```
Daily at 02:00 UTC:
DELETE FROM sessions WHERE expires_at < NOW()
```

---

## 10. Data Cleanup Flow

**Purpose:** Remove expired data to prevent database bloat.

### Scheduled Cleanup (Cron)

```
┌─────────────┐
│   Cron      │ (Cloudflare scheduled event)
└──────┬──────┘
       │
       │ Trigger: Daily at 02:00 UTC
       │
       ↓
┌─────────────┐
│   Worker    │
└──────┬──────┘
       │
       │ 1. Delete expired sessions
       │    DELETE FROM sessions WHERE expires_at < NOW()
       │
       │ 2. Delete old rate limit buckets
       │    DELETE FROM rate_limits WHERE reset_at < NOW() - 1 day
       │
       │ 3. Delete old replay nonces
       │    DELETE FROM nonces WHERE created_at < NOW() - 10 minutes
       │
       │ 4. Delete expired verification cache
       │    DELETE FROM doc_verifications WHERE created_at < NOW() - 7 days
       │
       ↓
┌─────────────┐
│     D1      │ (Execute deletions)
└─────────────┘
```

### Download Bundle Cleanup

```
On VM (via systemd timer or cron):
find /opt/dmj/pki/pub/dl -type f -mtime +1 -delete
```

Removes ZIP bundles older than 1 day to save disk space.

---

## 11. Deployment Flow

**Purpose:** Deploy all components from scratch.

### Complete Deployment Sequence

```
┌──────────────┐
│autoconfig.sh │ (Entry point)
└──────┬───────┘
       │
       │ 1. Validate CF_D1_DATABASE_ID
       │
       ├──> dmj-part1.sh
       │    ├─ Install Node.js 20.x
       │    ├─ Install Java 21
       │    ├─ Install Maven 3.9.x
       │    ├─ Install nginx
       │    ├─ Create dmjsvc user
       │    ├─ Install Wrangler globally
       │    ├─ Setup dmj-fetch-fresh utility
       │    └─ Create directory structure
       │
       │ 2. Check Wrangler authentication
       │    dmj-wrangler whoami
       │    ├─ If authenticated: Continue
       │    └─ If not: Prompt user to login
       │
       ├──> dmj-part2.sh
       │    ├─ Load vars.env
       │    ├─ Generate PKI hierarchy
       │    │  ├─ Root CA (if not exists)
       │    │  ├─ Issuing CA (if not exists)
       │    │  ├─ OCSP responder cert
       │    │  ├─ TSA cert
       │    │  └─ Signer leaf cert
       │    │
       │    ├─ Build Trust Kit ZIP
       │    │  ├─ Package certificates
       │    │  ├─ Include install scripts
       │    │  └─ Generate checksums
       │    │
       │    ├─ Write Java signer code
       │    │  ├─ Extract from dmj-part2.sh
       │    │  ├─ Create pom.xml
       │    │  └─ mvn clean package
       │    │
       │    ├─ Setup TSA service
       │    │  ├─ Write Node.js wrapper
       │    │  ├─ Create ts.cnf
       │    │  └─ Create systemd unit
       │    │
       │    ├─ Setup OCSP service
       │    │  ├─ Create systemd unit
       │    │  └─ Configure OpenSSL
       │    │
       │    ├─ Configure nginx
       │    │  ├─ Create vhosts
       │    │  ├─ Setup reverse proxy
       │    │  └─ Enable sites
       │    │
       │    ├─ Deploy Worker
       │    │  ├─ Write TypeScript code
       │    │  ├─ Create wrangler.toml
       │    │  ├─ Generate secrets
       │    │  │  ├─ SIGNING_GATEWAY_HMAC_KEY
       │    │  │  ├─ SESSION_HMAC_KEY
       │    │  │  ├─ TOTP_MASTER_KEY
       │    │  │  └─ ADMIN_PASS_HASH
       │    │  ├─ Run D1 migrations
       │    │  └─ dmj-wrangler deploy
       │    │
       │    ├─ Start services
       │    │  ├─ systemctl start dmj-signer
       │    │  ├─ systemctl start dmj-tsa
       │    │  ├─ systemctl start dmj-ocsp
       │    │  └─ systemctl reload nginx
       │    │
       │    └─ Post-deployment verification
       │       ├─ Install dmj-verify.sh
       │       ├─ Run health checks
       │       │  ├─ Signer /healthz
       │       │  ├─ TSA end-to-end
       │       │  ├─ OCSP query
       │       │  └─ Worker deployment
       │       └─ Display admin URL + key
       │
       └─ Deployment complete!
```

### Secret Generation

```bash
# HMAC keys (512-bit)
SIGNING_GATEWAY_HMAC_KEY=$(openssl rand -hex 64)
SESSION_HMAC_KEY=$(openssl rand -hex 64)
TOTP_MASTER_KEY=$(openssl rand -hex 32)

# Admin password
ADMIN_PASS=$(openssl rand -hex 16)
ADMIN_PASS_HASH=$(echo -n "$ADMIN_PASS" | argon2 salt -id -t 3 -m 16 -p 4 -l 32 -e)

# Store in Wrangler secrets
dmj-wrangler secret put SIGNING_GATEWAY_HMAC_KEY <<< "$SIGNING_GATEWAY_HMAC_KEY"
dmj-wrangler secret put SESSION_HMAC_KEY <<< "$SESSION_HMAC_KEY"
dmj-wrangler secret put TOTP_MASTER_KEY <<< "$TOTP_MASTER_KEY"
dmj-wrangler secret put ADMIN_PASS_HASH <<< "$ADMIN_PASS_HASH"
```

---

## Data Retention Policies

### Permanent Storage (D1)

**Documents table:**
- Retention: Indefinite
- Contains: SHA-256 digests, timestamps, revocation status
- Rationale: Audit trail and revocation checking

**Revoked documents:**
- Retention: Indefinite
- Rationale: Prevent replay attacks with revoked digests

### Temporary Storage (D1)

**Sessions:**
- TTL: 8 hours
- Cleanup: Daily cron (02:00 UTC)

**Rate limit buckets:**
- TTL: 1 day
- Cleanup: Daily cron

**Replay nonces:**
- TTL: 10 minutes
- Cleanup: Daily cron

**Verification cache:**
- TTL: 7 days
- Cleanup: Daily cron

### Temporary Files (VM)

**Download bundles:**
- Location: `/opt/dmj/pki/pub/dl/`
- TTL: 1 day
- Cleanup: systemd timer or cron

**Log files:**
- Location: `/var/log/dmj/`
- TTL: Deployment logs older than 1 day deleted
- Retention: Service logs managed by systemd/journald

---

## Security Considerations

### Data Protection

1. **No PDF Storage**: Only SHA-256 digests stored, never full PDFs
2. **Encrypted Transit**: All external communication over HTTPS
3. **Encrypted at Rest**: D1 database encrypted by Cloudflare
4. **Key Isolation**: Private keys never leave the VM
5. **Principle of Least Privilege**: Services run as non-root dmjsvc user

### Audit Trail

Every signature operation creates a permanent record in D1:
- Document digest (SHA-256)
- Timestamp (ISO 8601)
- Certificate serial number
- Issuer information
- Revocation status and reason (if applicable)

### Data Flow Security

All data flows implement multiple security layers:
- HTTPS for Worker↔Browser
- HMAC authentication for Worker↔Signer
- Session cookies with CSRF protection
- TOTP for sensitive operations (revocation)
- Origin validation on all state-changing requests

---

## Conclusion

This document describes the complete data flow for all major operations in the dmj-one PDF Authenticator system. Each flow is designed with security, reliability, and auditability in mind.

For architectural details, see [ARCHITECTURE.md](ARCHITECTURE.md).

For deployment instructions, see [QUICKSTART.md](QUICKSTART.md).
