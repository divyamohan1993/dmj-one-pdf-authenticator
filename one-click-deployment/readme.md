# One-Click Deployment Guide

Deploy dmj-one PDF Authenticator on a fresh VM with a single command using **`autoconfig.sh`**.

## 🚀 New Automated Deployment Architecture

The deployment system has been redesigned for maximum simplicity and reliability:

- **`autoconfig.sh`** - The main orchestrator that handles the entire deployment
- **`dmj-part1.sh`** - Automatically executed by autoconfig for system setup  
- **`dmj-part2.sh`** - Automatically executed by autoconfig for service deployment

All three scripts work together seamlessly to provide a zero-configuration deployment experience.

> **Zero‑knowledge / no static keys**
> *No secret, key, or password is hard‑coded in any file.* Everything is **generated at install time on your VM**, handed to Cloudflare **via `wrangler secret put` piping**, and stored only in account secrets / D1. The only thing you'll ever need to remember is the **admin portal login key** (displayed once, then removed from storage).

---

## 📋 Before You Start

### Prerequisites

1. **Fresh Ubuntu/Debian VM** (tested on GCP e2-micro)
2. **Cloudflare Account** with:
   - A D1 database created
   - DNS configured to point your domain to the VM
3. **Domain DNS Setup**:
   - Point `signer.dmj.one` (or your subdomain) to your VM IP via Cloudflare DNS (proxied/orange cloud)
   - Optionally set up `pki.dmj.one` and `ocsp.dmj.one` for full PKI support

### Get Your D1 Database ID

Create a D1 database and note its ID:

```bash
wrangler d1 create pdf-authenticator-db
# Copy the database_id from the output
```

Or list existing databases:

```bash
wrangler d1 list
```

---

## 🎯 Single-Command Deployment

Run this command on your fresh VM (replace `YOUR-D1-DATABASE-ID` with your actual D1 database ID):

```bash
sudo bash -lc 'curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/autoconfig.sh?nocache=$(date +%s) | sudo bash -s -- YOUR-D1-DATABASE-ID'
```

### Optional: Customize Domains

You can optionally specify custom domains as environment variables:

```bash
export DMJ_ROOT_DOMAIN="dmj.one"
export SIGNER_DOMAIN="signer.dmj.one"

sudo --preserve-env=DMJ_ROOT_DOMAIN,SIGNER_DOMAIN \
  bash -lc 'curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/autoconfig.sh?nocache=$(date +%s) | sudo bash -s -- YOUR-D1-DATABASE-ID'
```

---

## 🔄 What Happens During Deployment

### Phase 1: System Setup (dmj-part1.sh)

The script automatically:
1. ✅ Updates apt and installs base packages (Node.js, Java 21, Maven, nginx, certbot, etc.)
2. ✅ Installs Wrangler CLI globally
3. ✅ Creates a locked service user (`dmjsvc`) for security
4. ✅ Generates LetsEncrypt certificates for domains
5. ✅ Checks or initiates Wrangler authentication

### Wrangler Authentication

If Wrangler isn't already logged in, `autoconfig.sh` will:
- Launch the OAuth flow
- Display the authorization URL
- Wait for you to complete authentication

**To complete authentication:**
1. Open the displayed OAuth URL in your browser
2. Authorize the application
3. Copy the callback URL from your browser
4. Run `curl` on that callback URL from the VM (instructions are displayed)

Once authenticated as "Virtual WildHogs", the deployment continues automatically.

### Phase 2: Service Deployment (dmj-part2.sh)

After authentication is confirmed, `autoconfig.sh` automatically runs Part 2, which:
1. ✅ Generates all PKI certificates (Root CA, Issuing CA, OCSP responder, TSA)
2. ✅ Builds the Java signer microservice
3. ✅ Configures nginx as reverse proxy
4. ✅ Generates all secrets (HMAC keys, session keys, admin password hash)
5. ✅ Creates and configures the Cloudflare Worker
6. ✅ Deploys the Worker with all secrets
7. ✅ Sets up systemd service for the signer
8. ✅ Configures automatic log tailing

---

## ✅ Post-Deployment

After successful deployment, you'll see:

```
------------------------------------------------------------------
[✓] Done.
URL: https://documents.dmj.one
Signer URL (nginx): https://signer.dmj.one/healthz

NEXT STEPS:
1) Visit https://documents.dmj.one/admin-XXXXX — you will see the admin key ONCE.
2) In Cloudflare Dashboard, add a Route to bind this Worker to your domain.
------------------------------------------------------------------
```

### Access Your Admin Portal

1. Visit the displayed URL (includes a randomized admin path)
2. **Save the admin key** - it's shown only once!
3. Log in with the admin key
4. Start signing and verifying PDFs

### Configure Cloudflare Route (Optional)

To use a custom domain instead of `*.workers.dev`:
1. Go to Cloudflare Dashboard → Workers & Pages
2. Select your worker (`document-signer`)
3. Add a Route: `documents.dmj.one/*` → `document-signer`

---

## 🔍 What You Get

### Cloudflare Worker (TypeScript)

- ✅ **Admin Portal** - Password-protected with CSRF protection, signed sessions
- ✅ **Sign Endpoint** - HMAC-authenticated, admin-only PDF signing
- ✅ **Verify Endpoint** - Public PDF verification with embedded signature validation
- ✅ **Revoke Endpoint** - One-click document revocation (admin-only)
- ✅ **First-Visit Bootstrap** - Shows admin key once, then removes it

### Java Signer Microservice

- ✅ **PAdES-style Signatures** - Using Apache PDFBox 3 + BouncyCastle
- ✅ **POST /sign** - HMAC-gated PDF signing
- ✅ **POST /verify** - Embedded signature validation
- ✅ **GET /spki** - Public key fingerprint for verification
- ✅ **Systemd Service** - Auto-restart, log integration
- ✅ **Nginx Frontend** - SSL termination via Cloudflare

### PKI Infrastructure

- ✅ **Root CA** - dmj.one Root CA R1
- ✅ **Issuing CA** - dmj.one Issuing CA R1
- ✅ **OCSP Responder** - Certificate status checking
- ✅ **TSA Service** - RFC 3161 timestamping
- ✅ **Trust Kit** - User-friendly certificate installation bundle

### D1 Database

- ✅ **Document Registry** - SHA-256 hashes only (no PDF storage)
- ✅ **Audit Trail** - All signing and revocation events logged
- ✅ **Session Management** - Secure admin sessions
- ✅ **Bootstrap Storage** - One-time admin key delivery

---

## 🔒 Security Model

### Zero-Knowledge Design

- **No PDFs stored** - Only SHA-256 hashes (32 bytes per document)
- **Secrets generated on VM** - No hardcoded credentials
- **HMAC-protected signing** - Worker ↔ Signer authentication
- **Admin key shown once** - Displayed on first access, then deleted
- **Replay protection** - Timestamp + nonce validation

### Authentication Flow

```
User → Worker (admin login) → Session Cookie
       ↓
Worker → Signer (HMAC auth) → PDF Signature
       ↓
D1 Database (hash + metadata)
```

### Verification Flow

```
User → Worker (/verify endpoint)
       ↓
D1 Database (check hash) + Signer (validate CMS signature)
       ↓
Result: VALID / TAMPERED / REVOKED / UNKNOWN
```

---

## 🛠️ Management Commands

### Check Service Status

```bash
# Signer service
systemctl status dmj-signer

# View logs
journalctl -u dmj-signer -f

# Check nginx
systemctl status nginx
```

### Test Endpoints

```bash
# Test signer health
curl https://signer.dmj.one/healthz

# Test OCSP
curl https://ocsp.dmj.one/

# Test PKI
curl https://pki.dmj.one/dmj-one-root-ca-r1.crt
```

### View Worker Logs

```bash
# Real-time logs
wrangler tail document-signer

# Or use systemd service
systemctl status dmj-worker-tail
```

### Wrangler Commands

```bash
# Check authentication
dmj-wrangler whoami

# List D1 databases
dmj-wrangler d1 list

# Deploy Worker manually
cd /opt/dmj/worker && dmj-wrangler deploy
```

---

## 🐛 Troubleshooting

### Deployment Fails

**Check D1 database ID:**
```bash
dmj-wrangler d1 list
```

**Verify DNS:**
```bash
dig signer.dmj.one
# Should point to your VM IP
```

**Check Wrangler auth:**
```bash
dmj-wrangler whoami
# Should show "Virtual WildHogs" account
```

### Wrangler Authentication Issues

If authentication fails:
1. The script displays the OAuth URL
2. Open it in your browser and authorize
3. Copy the callback URL (`http://localhost:8976/oauth/callback?code=...`)
4. Run on the VM: `curl "PASTE-CALLBACK-URL-HERE"`

### Java Service Won't Start

```bash
# Check Java version
java -version  # Should be 21

# Check service logs
journalctl -u dmj-signer -n 50

# Try manual start
sudo systemctl restart dmj-signer
```

### Nginx Configuration Issues

```bash
# Test nginx config
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx

# Check site config
cat /etc/nginx/sites-enabled/dmj-signer
```

### Certificate Issues

```bash
# Check LetsEncrypt certificates
sudo certbot certificates

# Renew certificates manually
sudo certbot renew

# Check certificate expiry
openssl s_client -connect signer.dmj.one:443 -servername signer.dmj.one < /dev/null 2>/dev/null | openssl x509 -noout -dates
```

---

## 🔄 Re-running Deployment

All scripts are **idempotent** - you can safely re-run them:

### Re-run Part 2 Only

If Part 1 completed successfully and you only need to redeploy services:

```bash
export CF_D1_DATABASE_ID="your-database-id"
export DMJ_ROOT_DOMAIN="dmj.one"
export SIGNER_DOMAIN="signer.dmj.one"

sudo --preserve-env=CF_D1_DATABASE_ID,DMJ_ROOT_DOMAIN,SIGNER_DOMAIN \
  bash -lc 'curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/dmj-part2.sh?nocache=$(date +%s) | bash'
```

### Full Re-deployment

To start fresh, run `autoconfig.sh` again:

```bash
sudo bash -lc 'curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/autoconfig.sh?nocache=$(date +%s) | sudo bash -s -- YOUR-D1-DATABASE-ID'
```

---

## 📚 Technical Details

### Architecture Components

**Component** | **Technology** | **Purpose**
---|---|---
Worker | TypeScript + Cloudflare Workers | Admin portal, verification, API
Signer | Java 21 + Javalin | PDF signing microservice
PKI | OpenSSL + BouncyCastle | Certificate authority infrastructure
Database | Cloudflare D1 (SQLite) | Document registry, audit trail
Reverse Proxy | nginx | SSL termination, load balancing
Process Manager | systemd | Service lifecycle management

### File Locations

```
/opt/dmj/
├── signer/           # Java signer source & JAR (extracted during deployment)
└── pki/              # PKI certificates and keys
    ├── root/         # Root CA
    ├── ica/          # Issuing CA
    ├── ocsp/         # OCSP responder
    ├── tsa/          # Timestamp authority
    └── pub/          # Public certificates + CRL

/var/lib/dmj/         # Service user home, state files
/var/log/dmj/         # Application logs
/etc/dmj/             # Configuration files
```

**Note:** Worker code is embedded in the deployment scripts and deployed directly to Cloudflare. The Java signer is extracted and built during deployment from the embedded source in `dmj-part2.sh`.

### Environment Variables

Variable | Default | Description
---|---|---
`DMJ_ROOT_DOMAIN` | `dmj.one` | Base domain for services
`SIGNER_DOMAIN` | `signer.dmj.one` | Signer microservice domain
`PKI_DOMAIN` | `pki.dmj.one` | PKI certificate distribution
`OCSP_DOMAIN` | `ocsp.dmj.one` | OCSP responder domain
`TSA_DOMAIN` | `tsa.dmj.one` | Timestamp authority domain

---

## 🔐 Security Considerations

### What's Protected

✅ **Admin Portal** - PBKDF2-hashed password, signed sessions
✅ **Signing Gateway** - HMAC authentication with timestamp + nonce
✅ **Private Keys** - Stored with 0600 permissions, owned by service user
✅ **Service Account** - Locked, no shell access, minimal permissions
✅ **Replay Attacks** - Nonce tracking, timestamp validation
✅ **CSRF** - Same-origin checks, signed session tokens

### Secrets Storage

- **Worker Secrets** - Stored in Cloudflare (encrypted at rest)
- **VM Secrets** - Stored in `/etc/dmj/` (root-owned, 0600 permissions)
- **Session Keys** - Rotated on each deployment
- **Admin Key** - Shown once, then deleted from D1

### Network Security

- **Cloudflare Proxy** - DDoS protection, SSL termination
- **nginx** - Rate limiting, request filtering
- **Firewall** - Only ports 80/443 exposed
- **Internal Communication** - HMAC-authenticated

---

## 🆘 Getting Help

### Documentation

- [Architecture Overview](../ARCHITECTURE.md)
- [Quick Start Guide](../QUICKSTART.md)
- [Development Guide](../DEVELOPMENT.md)
- [Security Policy](../.github/SECURITY.md)

### Support Channels

- [GitHub Discussions](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/discussions) - Ask questions
- [GitHub Issues](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/issues) - Report bugs
- [Email Support](mailto:contact@dmj.one) - Direct assistance

### Common Issues

Check the [SUPPORT.md](../.github/SUPPORT.md) file for:
- Frequently asked questions
- Known issues and workarounds
- Community resources

---

## 📝 License & Attribution

This project uses the **Attribution Assurance License (AAL)**.

⚠️ **You must provide attribution** when using this software.

See [LICENSE](../LICENSE) for complete requirements.

---

## 🎉 Success!

Once deployment completes:

1. ✅ **Admin portal** is live at `https://documents.dmj.one/admin-XXXXX`
2. ✅ **Signer service** is running behind nginx
3. ✅ **PKI infrastructure** is fully operational
4. ✅ **Verification endpoint** is publicly accessible
5. ✅ **All secrets** are securely stored

**Next steps:**
- Visit your admin portal and save the key
- Upload a test PDF to sign
- Verify the signed PDF
- Configure custom domain routes in Cloudflare Dashboard

**Congratulations! Your dmj-one PDF Authenticator is ready to use! 🚀**
