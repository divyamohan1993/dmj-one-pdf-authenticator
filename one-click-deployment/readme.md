You can run this **directly on a fresh GCP e2‑micro VM**. It’s split into two idempotent shell scripts:

* **Part 1 (`dmj-part1.sh`)** — installs everything, **launches `wrangler login` on the headless VM**, captures and **prints/saves the OAuth URL**, and then **exits** so you can finish the login from your browser. This flow matches Cloudflare’s documented OAuth login (it prints a URL to open) and is the recommended pattern for headless servers.
* **Part 2 (`dmj-part2.sh`)** — auto‑detects that Wrangler is authenticated, generates all secrets and keys locally on the VM, compiles and configures the Java **signer microservice** behind **nginx**, creates and deploys the **Cloudflare Worker** that handles the admin portal, signing, and verification, wires the **D1** database, and prints the **admin key once** on first GUI access.

> **Zero‑knowledge / no static keys**
> *No secret, key, or password is hard‑coded in any file.* Everything is **generated at install time on your VM**, handed to Cloudflare **via `wrangler secret put` piping**, and (when applicable) stored only in account secrets / D1. The only thing you’ll ever need to remember afterwards is the **admin portal login key** (displayed once, then wiped). This matches Cloudflare’s current CLI patterns for secrets and `wrangler deploy`.

---

## What you’ll get

* **Cloudflare Worker (TypeScript)**

  * Password‑protected **admin portal** with CSRF, same‑origin checks, signed sessions, and TOTP confirmation on sensitive actions.
  * **“First‑visit bootstrap” screen** that:

    * shows readiness of required env vars,
    * shows the **admin portal key once**, then **removes** it from D1 so it cannot be read again.
  * **Sign** endpoint (admin only) that streams the PDF to the signer service with a per‑request **HMAC** (no bypass of login/UI).
  * **Verify** endpoint anyone can use: checks the document hash in D1 (space‑efficient — only hashes/metadata, no document blob) and also hits the signer service to validate the **embedded PDF signature** and issuer.
  * **Revoke** button per document (admin only, one‑click), protected with CSRF + TOTP and audited; a revoked hash is marked so bit‑for‑bit copies are still detected as revoked.

* **Signer microservice (Java 21 + Javalin + PDFBox 3 + BouncyCastle jdk18on)**

  * Generates a **self‑signed PKCS#12** signing identity for `dmj.one`.
  * **POST /sign** (HMAC‑gated) — signs PDFs (PAdES‑style CMS, SHA‑256 with RSA).
  * **POST /verify** — validates embedded PDF signatures and surfaces signer subject/issuer.
  * **GET /spki** — returns base64 SPKI for pinning/display.
  * Auto‑selects an **unused high port** and writes it to an include file nginx reads (no port collisions).
  * Packaged as a **systemd** service; fronted by **nginx** on `http://<SIGNER_DOMAIN>`.

* **D1 database** (no KV): multiple tables (`documents`, `audit`, `bootstrap`, etc.). **Only hashes/metadata** are stored so you never consume R2 space.

* **No size roadblocks**: Cloudflare Workers accept up to **100 MB** request body on Free/Pro, 200 MB on Business; we stream to the signer service and never persist PDFs.

---

## Before you start

* Point a proxied **A record** for your VM IP to **`signer.dmj.one`** (or any subdomain you prefer) in your Cloudflare DNS (you said all DNS is on Cloudflare).
* Create (or choose) a single **D1** database for shared use. You’ll simply set its **database id** in an env var (explained below). Wrangler’s D1 commands and bindings are used exactly as in the docs.

---

## Part 1 — install + headless Wrangler login (script)

> **Why this approach?** Cloudflare Wrangler uses OAuth and prints a URL in headless servers; you complete the flow in a browser and post the callback back to the VM, which resolves common “localhost:8976” auth issues on remote machines.


## Part 2 — build + configure everything (script)

This script is **idempotent**. You can run it multiple times; it won’t clobber customizations. It also verifies Wrangler auth and that you’ve provided `CF_D1_DATABASE_ID`. We use the modern **`wrangler deploy`** (not the deprecated `publish`).

---

## How to run (two steps)

1. **Run Part 1** (installs deps, starts headless Wrangler OAuth, prints URL and exits)

```bash
sudo bash -lc 'curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/dmj-part1.sh?nocache=$(date +%s) | sudo bash'
```

> Part 1 will print (and save) a URL like
> `https://dash.cloudflare.com/oauth2/auth?...redirect_uri=http%3A%2F%2Flocalhost%3A8976%2Foauth%2Fcallback...`
> Open it on your laptop, authorize, **copy the `http://localhost:8976/oauth/callback?...` URL the browser tries to open**, and paste it **back in the VM** to complete the callback (exact instructions are echoed by the script). This headless login pattern is widely used; replacing `localhost` with the VM IP and temporarily allowing port 8976 also works if you prefer.

2. **Run Part 2** (provisions and deploys everything)

```bash
# rp2.sh
# set your D1 database id (from `wrangler d1 list`, or Dashboard)
export CF_D1_DATABASE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# optional: customize domains
export DMJ_ROOT_DOMAIN="dmj.one"
export SIGNER_DOMAIN="signer.dmj.one"   # must point to this VM via Cloudflare DNS (proxied)

sudo --preserve-env=CF_D1_DATABASE_ID,DMJ_ROOT_DOMAIN,SIGNER_DOMAIN \
  bash -lc 'curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/dmj-part2.sh?nocache=$(date +%s) | bash'
```

After Part 2 finishes you’ll see:

* the **workers.dev** URL for the portal (until you add a custom route);
* `http://signer.dmj.one/` alive (nginx → Java service);
* a note to visit **`/admin`** on the Worker URL to see the one‑time **admin portal key** + env checks.

> You will add the Worker **route** for your preferred subdomain (e.g., `documents.dmj.one/*`) in the Cloudflare dashboard or via `wrangler` later. The scripts intentionally do **not** manage routes since you asked to create routes manually.

---

## Why these choices (and references)

* **Wrangler CLI v3+ and headless OAuth**: the CLI prints an OAuth URL; on remote VMs you copy the callback URL back to the VM, or temporarily expose 8976 / port‑forward — a known workaround discussed by users and maintainers. The scripts follow this flow and capture the URL for you.
* **Use `wrangler deploy`** not `publish` (deprecated in v3, removed in v4).
* **Installing Wrangler** via `npm i -g wrangler@latest` on Linux is supported; Wrangler supports Current/Active/Maintenance Node versions; we install **Node 22 LTS** via NodeSource (official quick method) for stability.
* **D1 schema and execute**: we bind D1 in `wrangler.jsonc` and run `wrangler d1 execute <db-name> --remote` to apply schema and inject the one‑time key; this aligns with Cloudflare’s D1 CLI docs.
* **PDF stack**: **PDFBox 3.0.5** (current 3.x feature release), **BouncyCastle jdk18on 1.82**, **Javalin 6.x** (current).
* **Request size**: Workers accept up to **100 MB** request bodies on Free/Pro (more on higher plans), so PDFs up to that size are fine.

---

## Security model & loophole patches

* **No static secrets in repo**: All keys are created at install time on the VM and delivered to Worker **as secrets via stdin**. The repo contains no plaintext keys. (See `wrangler secret put` usage.)
* **Admin key shown once**: The cleartext admin key is inserted into D1 and **deleted on first admin page load**. After that, only the **PBKDF2 hash** remains as a Worker secret; nobody (including scripts) can recover the key. Losing it means reinstalling **only the admin portal** (existing PDFs remain verifiable from their hashes).
* **No route bypasses**: The **sign** path requires (1) an authenticated admin session (browser), **and** (2) an HMAC shared secret to the signer service on every request. You cannot hit the signer directly without the secret.
* **CSRF & same‑origin**: Admin POSTs require same‑origin and a fresh session; we also include TOTP master key support for step‑up if you want to add a user‑specific TOTP later (the hook is present).
* **Replay & gating**: HMAC payload includes `method + path + timestamp + nonce + body`, validated within ±5 min and rejects reused nonces (in‑memory LRU).
* **Tamper detection**: The D1 record stores **SHA‑256 of the entire PDF**, so **any bit flip** changes the hash and fails verification. We also **validate embedded PDF signatures** server‑side in `/verify` (issuer surfaced).
* **Space‑efficient**: Only store **hash + metadata** in D1. No R2 usage.
* **Idempotent installs**: scripts check for existing files/services and reuse them; tables use `IF NOT EXISTS` and unique **per‑install prefixes** to avoid collision in a shared D1.
* **Transport**: You’ll terminate TLS at Cloudflare (orange cloud proxy); nginx listens on :80 inside the VM.
* **Limits**: If you expect PDFs >100 MB, note the Worker body limit per plan; switch to direct client→signer uploads behind Cloudflare Tunnel later if you need more headroom.

> **Note on “zero‑knowledge proofs”**
> This solution is “zero‑knowledge” in the operational sense (no static keys in the repo; secrets generated at install; Worker only sees hashes). It does **not** implement cryptographic “zero‑knowledge proof” protocols (ZK‑SNARKs/STARKs). That’s not required for your document‑sign/verify workflow and would add unnecessary complexity.

---

## What you’ll do manually

1. Finish **Wrangler OAuth** in Part 1 using the printed URL.
2. Ensure **DNS**: `signer.dmj.one` → your VM IP (proxied).
3. Set `CF_D1_DATABASE_ID` before Part 2 (from `wrangler d1 list` or the Dashboard).
4. After deployment, add a **Route** mapping (e.g., `sign.dmj.one/*`) to the Worker in Cloudflare.

---

## Optional improvements (drop‑in later)

* Enforce **mutual origin pinning** for admin (restrict origins to the exact host you route the Worker on).
* Add **OCSP/CRL** checks if you later switch to a non‑self‑signed signer certificate.
* Integrate **Workflows** / **Queues** for async signing jobs if batches become very large.
* Swap the `/verify` implementation to full PDFBox‑CMS assembly for richer diagnostics (timestamp/LTV). PDFBox 3 examples cover this if you want long‑term validation (LTV).

---

### Quick sanity checks after deploy

* `curl -I http://signer.dmj.one/healthz` → 200 OK
* Visit the Worker **`/admin`** on `*.workers.dev`: you should see **the admin key once** and diagnostics showing ✅ for the secrets/bindings.
* Try signing a small PDF; download returns `signed.pdf`.
* Try verifying it; you should see **Genuine** with issuer `dmj.one`.
* Revoke and verify again (status becomes **revoked**).
