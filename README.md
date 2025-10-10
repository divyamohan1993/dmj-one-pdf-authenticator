# dmj-one-pdf-authenticator

This repository contains a serverless zero‑knowledge document signing and verification system built with Cloudflare Workers, D1, and a companion Java microservice.

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

See the `ops/` directory inside `signer‑vm` for a bootstrap script to set up the microservice on a fresh VM. Cloudflare secrets (e.g., admin password hash, HMAC key, TOTP master key) should be injected using `wrangler secret put`.

## License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.
