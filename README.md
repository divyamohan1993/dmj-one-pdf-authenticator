# dmj-one PDF Authenticator

[![License: AAL](https://img.shields.io/badge/License-Attribution_Assurance-blue.svg)](LICENSE)
[![CI/CD Pipeline](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/actions/workflows/ci.yml)
[![CodeQL](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/actions/workflows/codeql-analysis.yml)
[![GitHub release](https://img.shields.io/github/v/release/divyamohan1993/dmj-one-pdf-authenticator)](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/releases)
[![GitHub stars](https://img.shields.io/github/stars/divyamohan1993/dmj-one-pdf-authenticator?style=social)](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/stargazers)

> **A serverless zero-knowledge document signing and verification system** built with Cloudflare Workers, D1, and a companion Java microservice.

🔐 **Secure** • ⚡ **Serverless** • 🌐 **Scalable** • 🔍 **Zero-Knowledge**

## Features

- **PAdES-style PDF signatures** using Apache PDFBox and Bouncy Castle.
- Password‑protected **admin portal** for signing, with PBKDF2/Argon2 hashed secret and server‑side session management.
- **HMAC‑protected signing gateway:** Cloudflare Worker sends a timestamp/nonce/sha256 digest to the microservice, authenticating each signing request.
- **Public verification portal** that validates the embedded CMS signature and checks a pinned SPKI fingerprint, returning **GENUINE**, **TAMPERED**, **REVOKED**, or **UNKNOWN**.
- **TOTP‑secured one‑click revocation** with CSRF protection and origin checking.
- **No PDF storage:** only 32‑byte SHA‑256 digests and metadata are stored in D1, making the solution lightweight and scalable.
- Daily **cron cleanup** purges expired sessions, replay nonces, and rate‑limit buckets.
- **Dynamic port detection** for the Java microservice and automatic nginx reload to avoid port conflicts.

## Structure

- `worker/` – Cloudflare Worker project (TypeScript) with D1 migrations and wrangler configuration.
- `signer-vm/` – Java microservice using PDFBox and Bouncy Castle, with Maven build, systemd unit, nginx site config, and PKI scripts.

## Getting started

🚀 **Quick Start:** See the [Quick Start Guide](QUICKSTART.md) for a 5-minute setup.

📖 **One-Click Deployment:** See the [one-click-deployment guide](one-click-deployment/readme.md) for automated deployment with a single command using `autoconfig.sh`.

🛠️ **Development:** See the [Development Guide](DEVELOPMENT.md) for local development setup.

The new automated deployment system uses `autoconfig.sh` which orchestrates the entire setup process, automatically executing both `dmj-part1.sh` (system setup) and `dmj-part2.sh` (service deployment) after Wrangler authentication is confirmed. All secrets are generated automatically and securely stored.

## Documentation

- 🚀 [Quick Start Guide](QUICKSTART.md) - Get started in 5 minutes
- 🛠️ [Development Guide](DEVELOPMENT.md) - Local development setup
- 📖 [Deployment Guide](one-click-deployment/readme.md) - Production deployment
- 🔧 [Configuration Reference](worker/wrangler.toml) - Worker configuration
- 🏗️ [Architecture Overview](ARCHITECTURE.md) - System design and components
- 🗺️ [Roadmap](ROADMAP.md) - Future plans and features
- 🤝 [Contributing Guidelines](.github/CONTRIBUTING.md) - How to contribute
- 🏛️ [Governance](.github/GOVERNANCE.md) - Project governance
- 🔒 [Security Policy](.github/SECURITY.md) - Security and vulnerability reporting
- 💬 [Support](.github/SUPPORT.md) - Getting help

## Community & Support

- 💡 [Discussions](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/discussions) - Ask questions and share ideas
- 🐛 [Issues](https://github.com/divyamohan1993/dmj-one-pdf-authenticator/issues) - Report bugs and request features
- ⭐ Star this repository if you find it useful!

## Attribution Required

⚠️ **Important:** This project uses the **Attribution Assurance License (AAL)**.

Any use of this software **requires mandatory attribution** to the original author. You must:
- Display attribution in user-facing documentation or interfaces
- Include attribution in the credits/about section of derivative works
- Maintain attribution in source code

See the [LICENSE](LICENSE) file for complete requirements.

## Citation

If you use this software in academic work, please cite it:

```bibtex
@software{dmj_one_pdf_authenticator,
  author = {Mohan, Divya},
  title = {dmj-one PDF Authenticator},
  year = {2025},
  url = {https://github.com/divyamohan1993/dmj-one-pdf-authenticator}
}
```

Or use the [CITATION.cff](CITATION.cff) file.
