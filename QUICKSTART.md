# Quick Start Guide

Get dmj-one PDF Authenticator up and running in minutes!

## 🚀 5-Minute Setup

### Prerequisites
- Node.js 20+ and npm
- Java 21
- Maven 3.9+
- Cloudflare account (free tier works!)

### Step 1: Clone and Install

```bash
git clone https://github.com/divyamohan1993/dmj-one-pdf-authenticator.git
cd dmj-one-pdf-authenticator

# Install Worker dependencies
cd worker && npm install

# Build Java signer
cd ../signer-vm && mvn clean package
```

### Step 2: Generate Secrets

```bash
# HMAC key
echo "HMAC_KEY=$(openssl rand -hex 32)"

# Admin password hash (replace 'mypassword' with your password)
node -e "const crypto = require('crypto'); \
  const password = 'mypassword'; \
  const salt = crypto.randomBytes(16).toString('hex'); \
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('hex'); \
  console.log('ADMIN_PASSWORD_HASH=' + salt + ':' + hash);"

# TOTP master key
node -e "console.log('TOTP_MASTER_KEY=' + require('crypto').randomBytes(20).toString('base32'))"
```

### Step 3: Configure Cloudflare

```bash
cd worker

# Create D1 database
wrangler d1 create pdf-authenticator-db

# Update wrangler.toml with database ID

# Set secrets
wrangler secret put ADMIN_PASSWORD_HASH
wrangler secret put HMAC_KEY
wrangler secret put TOTP_MASTER_KEY
wrangler secret put SIGNER_URL  # Your VM's public URL

# Run migrations
wrangler d1 migrations apply pdf-authenticator-db
```

### Step 4: Deploy Java Signer

```bash
cd signer-vm

# Generate PKI certificates (see pki/ directory)
cd pki && ./generate-certs.sh

# Start service
java -jar target/pdf-signer-1.0.0.jar
```

### Step 5: Deploy Worker

```bash
cd worker
npm run deploy
```

### Step 6: Test It!

Visit your Worker URL and:
1. Navigate to `/admin` and sign in
2. Upload a PDF to sign
3. Download signed PDF
4. Navigate to `/verify` and upload to verify

## 🎯 What's Next?

- **📖 Read the [Full Documentation](README.md)**
- **🏗️ Understand the [Architecture](ARCHITECTURE.md)**
- **🛠️ See [Development Guide](DEVELOPMENT.md)** for local development
- **🤝 Check [Contributing Guidelines](.github/CONTRIBUTING.md)**

## ⚡ Quick Commands

```bash
# Local development
cd worker && npm run dev

# Build Java signer
cd signer-vm && mvn clean package

# Deploy Worker
cd worker && npm run deploy

# Check logs
wrangler tail

# Run tests
cd signer-vm && mvn test
```

## 🐛 Troubleshooting

### Worker won't deploy
- Check Cloudflare account permissions
- Verify D1 database is created
- Ensure wrangler.toml is correct

### Java service fails
- Verify Java 21 is installed: `java -version`
- Check port availability
- Review certificate generation

### Signature fails
- Verify HMAC key matches on both sides
- Check signer service URL is reachable
- Review logs with `wrangler tail`

## 📚 More Resources

- [Full Setup Guide](one-click-deployment/readme.md)
- [Architecture Overview](ARCHITECTURE.md)
- [API Documentation](docs/API.md)
- [Security Policy](SECURITY.md)

## 💬 Need Help?

- [GitHub Discussions](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/discussions)
- [Open an Issue](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/issues/new/choose)
- [Email Support](mailto:contact@dmj.one)

## ⚖️ License

This project uses the **Attribution Assurance License**. 

⚠️ **You must provide attribution** when using this software. See [LICENSE](LICENSE) for details.

---

**Ready to go?** Star ⭐ the repo and start building!
