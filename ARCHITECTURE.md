# Architecture Overview

This document provides a high-level overview of the dmj-one PDF Authenticator system architecture.

## System Components

### 1. Cloudflare Worker (`worker/`)

The serverless frontend and API layer running on Cloudflare's edge network.

**Responsibilities:**
- Admin portal for PDF signing
- Public verification portal
- Session management with PBKDF2/Argon2 hashing
- HMAC-protected communication with the signing service
- Rate limiting and replay attack prevention
- TOTP-secured revocation endpoint
- Daily cron cleanup of expired data

**Technology Stack:**
- TypeScript
- Cloudflare Workers runtime
- D1 (SQLite) database
- Scheduled events (cron)

### 2. Java Signing Service (`signer-vm/`)

A microservice responsible for the cryptographic operations.

**Responsibilities:**
- PAdES-style PDF signature generation
- CMS signature creation using private keys
- Certificate chain validation
- SPKI fingerprint verification
- HMAC request authentication

**Technology Stack:**
- Java 21
- Apache PDFBox 3.0.2
- Bouncy Castle 1.78.1
- Javalin 6.7.0 web framework
- Maven build system

### 3. Database (Cloudflare D1)

A serverless SQLite database storing metadata only.

**Data Stored:**
- Document SHA-256 digests (32 bytes per document)
- Signature metadata (timestamp, status)
- Session tokens and expiry
- Revocation status
- Rate limiting buckets
- Replay prevention nonces

**Key Feature:** No PDF files are stored, only cryptographic digests.

## Security Architecture

### Authentication Flow

```
┌─────────────┐     PBKDF2/Argon2    ┌──────────────┐
│Admin Portal │ ──────────────────> │   Worker     │
└─────────────┘                      └──────────────┘
                                            │
                                            │ HMAC Auth
                                            │ (timestamp+nonce+digest)
                                            ↓
                                     ┌──────────────┐
                                     │Java Signing  │
                                     │   Service    │
                                     └──────────────┘
```

### Verification Flow

```
┌─────────────┐                      ┌──────────────┐
│Public Portal│ ──────────────────> │   Worker     │
└─────────────┘                      └──────────────┘
                                            │
                                            │ Check D1
                                            │ + CMS validation
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
└─────────────┘                      └──────────────┘
                                            │
                                            │ Update D1
                                            │ + Origin check
                                            ↓
                                     ┌──────────────┐
                                     │Mark document │
                                     │  as REVOKED  │
                                     └──────────────┘
```

## Deployment Architecture

### Production Setup

```
                    Internet
                       │
                       ↓
            ┌──────────────────┐
            │ Cloudflare Edge  │
            │    (Workers)     │
            └──────────────────┘
                       │
            ┌──────────┴──────────┐
            │                     │
            ↓                     ↓
    ┌──────────────┐      ┌──────────────┐
    │  D1 Database │      │    nginx     │
    │   (SQLite)   │      │ Reverse Proxy│
    └──────────────┘      └──────────────┘
                                  │
                                  ↓
                          ┌──────────────┐
                          │ Java Service │
                          │  (systemd)   │
                          └──────────────┘
```

### Communication Security

1. **Worker ↔ User**: HTTPS (Cloudflare SSL)
2. **Worker ↔ Java Service**: HMAC-authenticated requests over HTTP/HTTPS
3. **Java Service**: Private key stored securely on VM
4. **Database**: Encrypted at rest by Cloudflare

## Data Flow

### Signing Process

1. User uploads PDF to Admin Portal (Worker)
2. Worker authenticates admin session
3. Worker computes SHA-256 of PDF
4. Worker sends HMAC-authenticated request to Java service
5. Java service signs PDF and returns signed document
6. Worker stores digest + metadata in D1
7. Signed PDF returned to user (not stored)

### Verification Process

1. User uploads PDF to Public Portal (Worker)
2. Worker computes SHA-256 of PDF
3. Worker checks digest against D1 database
4. Worker validates CMS signature in PDF
5. Worker checks SPKI fingerprint
6. Worker returns verification status

## Scalability

- **Cloudflare Workers**: Automatically scales globally
- **D1 Database**: Serverless with automatic scaling
- **Java Service**: Can be horizontally scaled with load balancer
- **Storage**: Minimal (only 32-byte digests)

## Security Features

- 🔐 **Zero-knowledge**: Server never stores PDFs
- 🔑 **HMAC authentication**: Prevents unauthorized signing
- 🔒 **TOTP + CSRF**: Secure revocation endpoint
- ⏱️ **Replay prevention**: Timestamp + nonce validation
- 🚫 **Rate limiting**: Prevents abuse
- 🧹 **Auto-cleanup**: Regular purge of expired data
- 📝 **Audit trail**: All signatures tracked in D1

## Performance Considerations

- Worker responses: < 100ms (edge processing)
- Java signing: 1-5 seconds (depending on PDF size)
- Verification: < 200ms (digest lookup + validation)
- Database queries: < 10ms (D1 is fast)

## High Availability

- Workers: 100% uptime SLA from Cloudflare
- D1: Automatic replication and backups
- Java Service: Requires systemd + monitoring (can add redundancy)

## Future Enhancements

- [ ] Multi-region Java service deployment
- [ ] Batch signing API
- [ ] Webhook notifications for revocations
- [ ] Advanced analytics dashboard
- [ ] Additional signature standards (XAdES, CAdES)

---

For implementation details, see the source code in:
- `worker/src/` - Worker implementation
- `signer-vm/src/` - Java service implementation
- `worker/migrations/` - Database schema
