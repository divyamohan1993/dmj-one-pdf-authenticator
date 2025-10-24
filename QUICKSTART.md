# Quick Start Guide

Get dmj-one PDF Authenticator up and running in minutes!

## 🚀 Automated One-Command Setup

### Prerequisites
- A fresh Ubuntu/Debian VM (GCP e2-micro or similar)
- Cloudflare account (free tier works!)
- A D1 database created in Cloudflare Dashboard

### Step 1: Create D1 Database

Before running the installer, create a D1 database in your Cloudflare account:

```bash
wrangler d1 create pdf-authenticator-db
```

Note the database ID from the output - you'll need it for the next step.

### Step 2: Run Automated Deployment

Run the single `autoconfig.sh` command with your D1 database ID:

```bash
sudo bash -lc 'curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/autoconfig.sh?nocache=$(date +%s) | sudo bash -s -- YOUR-D1-DATABASE-ID'
```

Replace `YOUR-D1-DATABASE-ID` with your actual D1 database ID.

**What happens automatically:**
1. **Part 1** - Installs all dependencies (Node.js, Java, Maven, nginx, etc.)
2. **Wrangler Authentication** - Guides you through OAuth login if needed
3. **Part 2** - Builds everything, generates all secrets, deploys the Worker

### Step 3: Complete Wrangler OAuth (if needed)

If Wrangler isn't already authenticated, the script will:
1. Display an OAuth URL
2. Wait for you to open it in your browser
3. Guide you through completing the authentication

### Step 4: Access Your Portal

After deployment completes:
1. Visit your Worker URL at `https://documents.dmj.one/admin`
2. Save the one-time admin key displayed
3. Start signing and verifying PDFs!

## 🎯 Alternative: Local Development

For local development or customization, see the detailed steps in the [Development Guide](.github/DEVELOPMENT.md).

The repository uses an automated deployment architecture where Worker and Java signer code are embedded within the deployment scripts (`one-click-deployment/static/dmj-part2.sh`). For development:

1. Clone the repository
2. Extract the embedded code from `dmj-part2.sh` if needed
3. Follow the [Development Guide](.github/DEVELOPMENT.md) for local setup

The automated deployment approach streamlines production deployment while the embedded code can still be extracted for development purposes.

## 🎯 What's Next?

- **📖 Read the [Full Documentation](README.md)**
- **🏗️ Understand the [Architecture](ARCHITECTURE.md)**
- **🛠️ See [Development Guide](.github/DEVELOPMENT.md)** for local development
- **🤝 Check [Contributing Guidelines](.github/CONTRIBUTING.md)**

## ⚡ Quick Commands

```bash
# View deployment logs
wrangler tail

# Check signer service status
systemctl status dmj-signer

# View nginx configuration
cat /etc/nginx/sites-available/dmj-signer

# Test signer health
curl http://signer.dmj.one/healthz
```

## 🐛 Troubleshooting

### Deployment fails
- Ensure D1 database ID is correct
- Verify DNS: `signer.dmj.one` points to your VM
- Check Wrangler authentication: `dmj-wrangler whoami`

### Wrangler authentication issues
- The script handles OAuth automatically
- Follow the displayed OAuth URL if prompted
- Ensure you're logged in as the correct Cloudflare account

### Java service fails
- Verify Java 21 is installed: `java -version`
- Check service status: `systemctl status dmj-signer`
- Review logs: `journalctl -u dmj-signer -f`

### Signature fails
- Verify HMAC key matches on both sides
- Check signer service is reachable
- Review Worker logs with `wrangler tail`

## 📚 More Resources

- [Full Setup Guide](one-click-deployment/readme.md)
- [Architecture Overview](ARCHITECTURE.md)
- [Security Policy](.github/SECURITY.md)

## 💬 Need Help?

- [GitHub Discussions](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/discussions)
- [Open an Issue](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/issues/new/choose)
- [Email Support](mailto:contact@dmj.one)

## ⚖️ License

This project uses the **Attribution Assurance License**. 

⚠️ **You must provide attribution** when using this software. See [LICENSE](.github/LICENSE) for details.

---

**Ready to go?** Star ⭐ the repo and start building!
