# Architecture Overview

This document provides a high-level overview of the dmj-one PDF Authenticator system architecture.

## System Components

### 1. Cloudflare Worker (Embedded in `one-click-deployment/static/dmj-part2.sh`)

The serverless frontend and API layer running on Cloudflare's edge network.

**Responsibilities:**
- Admin portal for PDF signing with session-based authentication
- Public verification portal for document validation
- Session management with PBKDF2/Argon2 hashed secrets
- HMAC-protected communication with the signing service
- Rate limiting and replay attack prevention
- TOTP-secured revocation endpoint with CSRF protection
- Daily cron cleanup of expired data
- Trust Kit bundle generation and distribution
- Origin and same-site request validation
- Admin credential rotation on deployment

**Technology Stack:**
- TypeScript
- Cloudflare Workers runtime
- D1 (SQLite) database
- Scheduled events (cron)
- Web Crypto API for cryptographic operations

**Deployment:** Worker code and migrations are embedded within the `dmj-part2.sh` deployment script for automated setup.

### 2. Java Signing Service (Embedded in `one-click-deployment/static/dmj-part2.sh`)

A microservice responsible for the cryptographic operations and PDF signing.

**Responsibilities:**
- PAdES-LT and PAdES-LTA compliant PDF signature generation
- CMS signature creation using PKCS#12 private keys
- Certificate chain validation and embedding
- SPKI fingerprint generation and verification
- HMAC request authentication with timestamp and nonce validation
- RFC 3161 timestamp token integration (signature-time-stamp)
- Document timestamp (DocTimeStamp) for long-term archival (LTA)
- CRL (Certificate Revocation List) generation and embedding
- OCSP response fetching and embedding (optional)
- DSS (Document Security Store) creation with VRI entries
- Trust Kit bundle generation (PDF + certificates + tools)
- Certificate revocation checking and status updates
- Replay attack prevention with nonce tracking

**Technology Stack:**
- Java 21
- Apache PDFBox 3.0.2
- Bouncy Castle 1.78.1
- Javalin 6.7.0 web framework
- Maven build system
- OpenSSL integration for PKI operations

**Deployment:** Java signer code (Maven project) is embedded within the `dmj-part2.sh` deployment script for automated build and deployment.

### 3. Database (Cloudflare D1)

A serverless SQLite database storing metadata only.

**Data Stored:**
- Document SHA-256 digests (32 bytes per document)
- Signature metadata (timestamp, status, certificate serial)
- Session tokens and expiry
- Revocation status and reason
- Rate limiting buckets
- Replay prevention nonces
- Document verification cache
- CSRF tokens

**Key Feature:** No PDF files are stored, only cryptographic digests.

### 4. PKI Infrastructure (Two-Tier Certificate Authority)

A complete Public Key Infrastructure for signing and validation.

**Components:**

#### Root CA (dmj.one Root CA R1)
- Self-signed root certificate authority
- 4096-bit RSA key
- 10-year validity
- Stored securely in `/opt/dmj/pki/root/`
- Used to sign Issuing CA only

#### Issuing CA (dmj.one Issuing CA R1)
- Intermediate certificate authority
- 4096-bit RSA key
- Signs end-entity certificates (signer, OCSP, TSA)
- Maintains certificate database and serial numbers
- Generates and publishes CRLs
- AIA and CRL distribution point extensions

#### OCSP Responder (dmj.one OCSP Responder R1)
- Online Certificate Status Protocol responder
- Real-time certificate revocation checking
- HTTP endpoint on port 9080
- Responds to OCSP queries with certificate status
- Extended Key Usage: OCSPSigning

#### TSA Service (dmj.one TSA R1)
- RFC 3161 Time Stamp Authority
- Issues trusted timestamps for signatures
- HTTP endpoint on port 9090
- Node.js wrapper around OpenSSL `ts -reply`
- Provides proof of existence at a specific time
- Extended Key Usage: timeStamping

#### Leaf Certificates
- **Signer Certificate**: Used for PDF signing (dmj.one Signer)
- PKCS#12 format with private key
- Includes full certificate chain
- SPKI fingerprint tracked for validation

**PKI Files & Distribution:**
- Public certificates published to `/opt/dmj/pki/pub/`
- Served via nginx for public access
- CRLs updated dynamically via OpenSSL
- Trust Kit bundles for end-user installation

### 5. Support Services

#### dmj-fetcher.sh
A secure, POSIX-compliant file download utility with integrity verification.

**Features:**
- HTTPS-only downloads with HSTS support
- SHA-256 checksum verification
- Automatic retry with exponential backoff
- Variable substitution for configuration templates
- UTF-8 BOM and CRLF normalization
- Atomic file replacement
- Permission and ownership management

**Usage:** Central tool for fetching scripts, templates, and configuration files during deployment.

#### dmj-verify.sh
Post-deployment verification script ensuring all services are operational.

**Checks:**
- Signer service health (loopback and nginx)
- TSA health and RFC 3161 end-to-end flow
- OCSP responder functionality
- Certificate validation
- Service endpoint availability

**Deployment:** Generated from template and installed to `/usr/local/bin/`

#### Trust Kit Distribution
A curated package containing everything needed to trust dmj.one signed PDFs.

**Contents:**
- Root CA certificate (CER and CRT formats)
- Issuing CA certificate
- Windows installation batch script (`install-dmj-certificates.bat`)
- README documentation (TXT and HTML)
- SHA256SUMS for integrity verification

**Distribution:**
- Packaged as ZIP file per CA series (e.g., `dmj-one-trust-kit-r1.zip`)
- Stable symlink: `dmj-one-trust-kit.zip`
- Automatically included with signed PDF bundles
- Downloadable from PKI distribution point

### 6. nginx Reverse Proxy

HTTP/HTTPS reverse proxy and static file server.

**Responsibilities:**
- Proxies requests to Java signer service
- Serves PKI public files (certificates, CRLs, Trust Kits)
- SSL/TLS termination (with Let's Encrypt support)
- Access control and security headers
- Download bundle serving from `/opt/dmj/pki/pub/dl/`

**Configuration:**
- Dynamic port detection for signer service
- Automatic site enablement
- CORS headers for cross-origin requests
- Content-type headers for certificates and CRLs

## Security Architecture

### Authentication Flow

```
┌─────────────┐     PBKDF2/Argon2    ┌──────────────┐
│Admin Portal │ ──────────────────> │   Worker     │
│  (Browser)  │     + Session HMAC   │  (Cloudflare)│
└─────────────┘                      └──────────────┘
      ↑                                      │
      │ Session Cookie                       │ HMAC Auth
      │ + CSRF Token                         │ (method+path+ts+nonce+sha256)
      └──────────────────────────────────────┘
                                            │
                                            ↓
                                     ┌──────────────┐
                                     │Java Signing  │
                                     │   Service    │
                                     │  (systemd)   │
                                     └──────────────┘
```

### Verification Flow

```
┌─────────────┐                      ┌──────────────┐
│Public Portal│ ──────────────────> │   Worker     │
│  (Browser)  │                      │  (Cloudflare)│
└─────────────┘                      └──────────────┘
                                            │
                                     1. Compute SHA-256
                                     2. Check D1 digest
                                     3. Extract CMS from PDF
                                            │
                                            ↓
                                     ┌──────────────┐
                                     │Java Service  │
                                     │ - Validate   │
                                     │   signatures │
                                     │ - Check SPKI │
                                     │ - Check CRL  │
                                     │ - Query OCSP │
                                     └──────────────┘
                                            │
                                            ↓
                                     ┌──────────────┐
                                     │   Returns    │
                                     │  GENUINE /   │
                                     │  TAMPERED /  │
                                     │  REVOKED /   │
                                     │   UNKNOWN    │
                                     └──────────────┘
```

### Revocation Flow

```
┌─────────────┐     TOTP + CSRF      ┌──────────────┐
│Admin Portal │ ──────────────────> │   Worker     │
│  (Browser)  │   + Session Check    │  (Cloudflare)│
└─────────────┘   + Origin Check     └──────────────┘
                                            │
                                     1. Validate session
                                     2. Check CSRF token
                                     3. Verify origin/referer
                                     4. Validate TOTP
                                            │
                                            ↓
                                     ┌──────────────┐
                                     │   D1 Update  │
                                     │ + PKI Update │
                                     └──────────────┘
                                            │
                                            ↓
                                     ┌──────────────┐
                                     │Java Service  │
                                     │ - Update CRL │
                                     │ - Revoke in  │
                                     │   ICA index  │
                                     └──────────────┘
```

### PKI and Signing Flow

```
┌─────────────┐                      ┌──────────────┐
│   Worker    │ ────────────────────>│Java Service  │
│             │   HMAC + PDF bytes   │              │
└─────────────┘                      └──────────────┘
                                            │
                                     1. Validate HMAC
                                     2. Create PAdES signature
                                            │
                                            ↓
                                     ┌──────────────┐
                                     │ TSA Service  │
                                     │  (port 9090) │
                                     └──────────────┘
                                            │
                                     3. Get RFC 3161 timestamp
                                     4. Embed in signature
                                            │
                                            ↓
                                     ┌──────────────┐
                                     │Query OCSP for│
                                     │cert status   │
                                     │(port 9080)   │
                                     └──────────────┘
                                            │
                                     5. Fetch OCSP responses
                                     6. Embed in DSS
                                            │
                                            ↓
                                     ┌──────────────┐
                                     │Embed CRLs +  │
                                     │certificates  │
                                     │Create VRI    │
                                     └──────────────┘
                                            │
                                     7. Optional DocTimeStamp
                                     8. Build ZIP bundle
                                            │
                                            ↓
                                     ┌──────────────┐
                                     │ Return signed│
                                     │ PDF + bundle │
                                     └──────────────┘
```

## Deployment Architecture

### Automated Setup with autoconfig.sh

The deployment process is fully automated through `autoconfig.sh`, which orchestrates a two-phase installation:

```
                    autoconfig.sh
                         │
        ┌────────────────┴────────────────┐
        │                                 │
        ↓                                 ↓
   dmj-part1.sh                    dmj-part2.sh
   (System Setup)               (Service Deployment)
        │                                 │
        │ - Install dependencies          │ - Generate PKI hierarchy
        │ - Setup Node.js 20.x            │   * Root CA
        │ - Install Java 21               │   * Issuing CA
        │ - Install Maven 3.9.x           │   * OCSP responder cert
        │ - Configure nginx               │   * TSA certificate
        │ - Create dmjsvc user            │   * Signer leaf cert
        │ - Install Wrangler              │ - Build Trust Kit ZIP
        │ - Setup dmj-fetch-fresh         │ - Compile Java signer
        │   global utility                │ - Deploy Cloudflare Worker
        │ - Create secure directories     │ - Configure D1 migrations
        │                                 │ - Generate HMAC secrets
        │                                 │ - Configure OCSP service
        │                                 │ - Configure TSA service
        │                                 │ - Setup nginx vhosts
        │                                 │ - Create systemd services
        │                                 │ - Install dmj-verify.sh
        │                                 │ - Run post-deploy checks
        │                                 │
        └─────────────┬───────────────────┘
                      │
              Wrangler Auth Check
                (Virtual WildHogs)
                      │
                      ↓
            Full System Deployed
```

### Modular Script Architecture

The deployment uses a modular architecture with specialized components:

```
one-click-deployment/
├── static/
│   ├── autoconfig.sh          # Main orchestrator
│   ├── dmj-part1.sh            # System dependencies
│   ├── dmj-part2.sh            # Service deployment (4800+ lines)
│   ├── vars.env                # Configuration variables
│   ├── bin/
│   │   └── dmj-fetcher.sh.tmpl # Secure download utility
│   ├── modules/
│   │   └── dmj-verify.sh.tmpl  # Verification script
│   ├── templates/
│   │   ├── admin-login.html    # Admin login page
│   │   ├── admin-dashboard.html # Admin interface
│   │   ├── admin-bootstrap.html # Admin setup
│   │   ├── verify.html         # Public verification
│   │   └── home.html           # Landing page
│   └── docs/
│       ├── dmj-one-trust-kit-README.txt
│       ├── dmj-one-trust-kit-README.html
│       └── install-dmj-certificates.bat
```

**Key Features:**
- **Embedded Code**: Worker TypeScript and Java signer code embedded in `dmj-part2.sh`
- **Template Expansion**: Variables replaced at deployment time
- **Idempotent**: Can be re-run safely without breaking existing setup
- **Selective Reissuance**: Flags control which PKI components to regenerate
- **Atomic Operations**: File operations use atomic moves and proper umask

### Production Setup

```
                    Internet
                       │
                       ↓
            ┌──────────────────┐
            │ Cloudflare Edge  │
            │    (Workers)     │
            │  documents.dmj   │
            └──────────────────┘
                       │
            ┌──────────┴──────────────────┐
            │                             │
            ↓                             ↓
    ┌──────────────┐         ┌────────────────────┐
    │  D1 Database │         │   nginx (VM)       │
    │   (SQLite)   │         │  - pki.dmj.one     │
    │              │         │  - signer.dmj.one  │
    └──────────────┘         │  - tsa.dmj.one     │
                             │  - ocsp.dmj.one    │
                             └────────────────────┘
                                       │
                        ┌──────────────┼──────────────┐
                        │              │              │
                        ↓              ↓              ↓
                ┌──────────────┐ ┌──────────┐ ┌──────────┐
                │ Java Signer  │ │TSA (9090)│ │OCSP(9080)│
                │  (port 18080)│ │  Node.js │ │ OpenSSL  │
                │   systemd    │ │ systemd  │ │ systemd  │
                └──────────────┘ └──────────┘ └──────────┘
                        │
                        ↓
                ┌──────────────┐
                │ PKI Files    │
                │ /opt/dmj/pki │
                │ - Root CA    │
                │ - ICA        │
                │ - CRLs       │
                │ - Trust Kit  │
                └──────────────┘
```

### Communication Security

1. **Worker ↔ User**: HTTPS (Cloudflare Universal SSL)
2. **Worker ↔ Java Service**: HMAC-authenticated requests over HTTPS
   - HMAC includes: method, path, timestamp, nonce, and SHA-256 of body
   - Custom headers: `x-worker-hmac`, `x-worker-ts`, `x-worker-nonce`
   - 5-minute timestamp window
   - Nonce tracking prevents replay attacks
3. **Java Service ↔ TSA**: HTTP over loopback (127.0.0.1:9090)
   - Optional HTTP Basic Auth
   - RFC 3161 protocol
4. **Java Service ↔ OCSP**: HTTP over loopback (127.0.0.1:9080)
   - OpenSSL OCSP responder
   - GET or POST methods supported
5. **Browser ↔ Worker**: Session cookies + CSRF tokens
   - `SameSite=Strict` cookies
   - Double-submit CSRF protection
   - Origin and Referer validation
6. **Private Keys**: Stored securely on VM
   - Root CA key: `/opt/dmj/pki/root/root.key` (mode 0600)
   - ICA key: `/opt/dmj/pki/ica/ica.key` (mode 0600)
   - Signer key: `/opt/dmj/signer-vm/signer.key` (mode 0600)
   - TSA key: `/opt/dmj/pki/tsa/tsa.key` (mode 0600)
   - OCSP key: `/opt/dmj/pki/ocsp/ocsp.key` (mode 0600)
   - All owned by `dmjsvc` user (UID 900-999)
7. **Database**: Encrypted at rest by Cloudflare
8. **Secrets Management**:
   - HMAC keys generated with `openssl rand -hex 64`
   - Admin password hashed with PBKDF2/Argon2
   - Session HMAC key for cookie integrity
   - TOTP master key for revocation

## Data Flow Summary

Detailed data flows are documented in [DATAFLOW.md](DATAFLOW.md).

### Signing Process

1. User uploads PDF to Admin Portal (Worker)
2. Worker authenticates admin session (PBKDF2/Argon2)
3. Worker validates CSRF token and origin
4. Worker computes SHA-256 of PDF
5. Worker generates HMAC with timestamp and nonce
6. Worker sends HMAC-authenticated request to Java service
7. Java service validates HMAC and checks nonce
8. Java service creates PAdES-LT/LTA signature:
   - Signs with signer certificate
   - Requests RFC 3161 timestamp from TSA
   - Queries OCSP for certificate status
   - Embeds CRLs and certificates in DSS
   - Creates VRI entry
   - Optionally adds DocTimeStamp
9. Java service builds ZIP bundle with Trust Kit
10. Worker stores digest + metadata in D1
11. Signed PDF bundle returned to user (not stored permanently)

### Verification Process

1. User uploads PDF to Public Portal (Worker)
2. Worker computes SHA-256 of PDF
3. Worker checks digest against D1 database
4. If found, Worker forwards to Java service for validation
5. Java service:
   - Extracts CMS signature from PDF
   - Validates signature cryptographically
   - Checks SPKI fingerprint matches
   - Validates certificate chain
   - Checks CRL for revocation
   - Optionally queries OCSP
6. Worker returns verification status:
   - **GENUINE**: Valid signature, not revoked
   - **TAMPERED**: Signature invalid or PDF modified
   - **REVOKED**: Certificate or document revoked
   - **UNKNOWN**: Not in database

## Scalability

- **Cloudflare Workers**: Automatically scales globally
- **D1 Database**: Serverless with automatic scaling
- **Java Service**: Can be horizontally scaled with load balancer
- **Storage**: Minimal (only 32-byte digests)

## Security Features

### Core Security
- 🔐 **Zero-knowledge**: Server never stores PDFs, only SHA-256 digests
- 🔑 **HMAC authentication**: All Worker↔Signer requests authenticated
- 🔒 **TOTP + CSRF**: Multi-factor protection for revocation
- ⏱️ **Replay prevention**: Timestamp + nonce validation with 5-minute window
- 🚫 **Rate limiting**: D1-based rate limiting per client
- 🧹 **Auto-cleanup**: Daily cron purge of expired sessions and bundles
- 📝 **Audit trail**: All signatures tracked in D1 with timestamps

### PKI Security
- 🏛️ **Two-tier PKI**: Root CA and Issuing CA hierarchy
- 🔏 **Strong keys**: 4096-bit RSA keys for all certificates
- 📜 **CRL support**: Certificate Revocation Lists updated dynamically
- 🔍 **OCSP**: Online Certificate Status Protocol for real-time checks
- ⏰ **Timestamping**: RFC 3161 trusted timestamps for non-repudiation
- 🔗 **Certificate chain**: Full chain embedded in signatures
- 🎯 **SPKI pinning**: Subject Public Key Info fingerprint tracking

### PAdES Compliance
- 📄 **PAdES-B-LT**: Long-Term validation with embedded revocation info
- 📄 **PAdES-B-LTA**: Long-Term Archival with document timestamps
- 🗃️ **DSS**: Document Security Store with all validation material
- ✅ **VRI**: Validation-Related Information per signature
- 🏢 **Signature-time-stamp**: Optional signed attribute timestamp
- 📑 **DocTimeStamp**: Separate timestamp for entire document state

### Web Security
- 🌐 **CSP**: Content Security Policy with nonce-based script loading
- 🔐 **Session security**: PBKDF2/Argon2 password hashing
- 🍪 **Secure cookies**: `SameSite=Strict; Secure` attributes
- 🎫 **CSRF protection**: Double-submit cookie pattern
- 🔍 **Origin validation**: Referer and Origin header checks
- 🔒 **X-Frame-Options**: Clickjacking prevention
- 🚫 **No-cache headers**: Prevent sensitive data caching

### Operational Security
- 👤 **Locked service user**: Non-interactive `dmjsvc` account (UID 900-999)
- 🔑 **Admin rotation**: Admin credentials rotated on deployment
- 🔐 **Secrets isolation**: HMAC keys and passwords in environment variables
- 📁 **File permissions**: Strict 0600 for keys, 0750 for directories
- 🔒 **Minimal privileges**: Services run as non-root user
- 📋 **Verified downloads**: SHA-256 checksums for all remote fetches
- 🛡️ **Fail-secure**: Errors result in denial, never silent bypass

## Performance Considerations

- Worker responses (static): < 100ms (edge processing)
- Worker signing request: < 200ms (digest computation + HMAC + D1 write)
- Java signing: 1-5 seconds (depending on PDF size and TSA/OCSP latency)
  - PAdES-B: ~1-2 seconds
  - PAdES-LT (with OCSP): ~2-4 seconds
  - PAdES-LTA (with DocTimeStamp): ~3-5 seconds
- Verification: < 200ms (digest lookup + validation)
- Database queries: < 10ms (D1 local reads)
- TSA request: < 1 second (loopback + OpenSSL)
- OCSP query: < 500ms (loopback + database lookup)
- Trust Kit bundle: < 100ms (ZIP creation in-memory)
- CRL generation: < 2 seconds (OpenSSL ca command)

## High Availability

- **Workers**: 100% uptime SLA from Cloudflare
  - Global edge deployment
  - Automatic failover
  - Zero-downtime deployments
- **D1 Database**: Automatic replication and backups
  - Read replicas for scaling
  - Point-in-time recovery
- **Java Service**: Systemd with automatic restart
  - Can be horizontally scaled behind load balancer
  - Stateless design (no local state)
  - Health check endpoint: `/healthz`
- **TSA Service**: Systemd with automatic restart
  - Lightweight Node.js wrapper
  - Can be horizontally scaled
- **OCSP Service**: Systemd with automatic restart
  - OpenSSL native implementation
  - Auto-reloads on CRL update
- **nginx**: Systemd managed
  - Reverse proxy with automatic upstream retry
  - Static content caching
- **PKI Files**: Redundant storage
  - Backed up separately from services
  - Version-controlled trust kits

## Future Enhancements

- [ ] Multi-region Java service deployment with geo-routing
- [ ] Batch signing API for multiple documents
- [ ] Webhook notifications for revocations
- [ ] Advanced analytics dashboard
- [ ] Additional signature standards (XAdES, CAdES)
- [ ] Hardware Security Module (HSM) integration
- [ ] Support for multiple signing certificates
- [ ] Certificate transparency logging
- [ ] Automated certificate rotation
- [ ] GraphQL API for programmatic access
- [ ] Mobile app for on-the-go signing/verification
- [ ] Kubernetes deployment option
- [ ] Multi-tenant support with organization isolation

---

## Repository Structure

The repository uses an **automated deployment architecture** where all code is embedded within deployment scripts:

```
dmj-one-pdf-authenticator/
├── ARCHITECTURE.md              # This file - system architecture
├── DATAFLOW.md                  # Data flow diagrams and descriptions
├── QUICKSTART.md                # Quick start guide
├── CHANGELOG.md                 # Version history
├── ROADMAP.md                   # Future plans
├── .github/                     # GitHub configuration
│   ├── workflows/               # CI/CD pipelines
│   ├── CONTRIBUTING.md          # Contribution guidelines
│   ├── SECURITY.md              # Security policy
│   └── ...                      # Other community files
└── one-click-deployment/
    ├── readme.md                # Deployment documentation
    └── static/
        ├── autoconfig.sh        # Main orchestrator (two-phase)
        ├── dmj-part1.sh         # Phase 1: System setup (422 lines)
        ├── dmj-part2.sh         # Phase 2: Service deployment (4805 lines)
        │                        #   Embeds: Worker TS, Java signer, migrations
        ├── vars.env             # Configuration variables
        ├── bin/
        │   └── dmj-fetcher.sh.tmpl    # Secure download utility (358 lines)
        ├── modules/
        │   └── dmj-verify.sh.tmpl     # Post-deployment verification (82 lines)
        ├── templates/           # HTML UI templates
        │   ├── admin-login.html       # Admin authentication page
        │   ├── admin-dashboard.html   # Main admin interface
        │   ├── admin-bootstrap.html   # Initial admin setup
        │   ├── verify.html            # Public verification interface
        │   └── home.html              # Landing page
        └── docs/                # End-user documentation
            ├── dmj-one-trust-kit-README.txt
            ├── dmj-one-trust-kit-README.html
            └── install-dmj-certificates.bat
```

### Key Architectural Decisions

**Embedded Code Approach:**
- All production code embedded in `dmj-part2.sh` for single-command deployment
- Eliminates dependency on repository availability during deployment
- Ensures version consistency between deployment script and deployed code
- Simplifies backup and disaster recovery

**Modular Templates:**
- HTML templates separated from TypeScript for easier maintenance
- Template variables replaced at deployment time
- CSS and JavaScript embedded for offline operation

**Security-First Design:**
- dmj-fetcher.sh with SHA-256 verification for all remote downloads
- Automatic security hardening during deployment
- Least-privilege service accounts
- Defense-in-depth with multiple security layers

This approach allows for single-command deployment while maintaining separation of concerns within the scripts.
