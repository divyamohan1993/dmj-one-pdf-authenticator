#!/usr/bin/env bash
# autoconfig.sh
# Usage: sudo bash -lc 'curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/autoconfig.sh?nocache=$(date +%s) | sudo bash -s -- long-cf-id'

set -euo pipefail

# Must run as root
if [[ $EUID -ne 0 ]]; then
  echo "[x] This script must run as root (use sudo)."
  exit 1
fi

# Accept CF_D1_DATABASE_ID from $1 (preferred) or env var
CF_D1_DATABASE_ID="${1:-${CF_D1_DATABASE_ID:-}}"
if [[ -z "${CF_D1_DATABASE_ID}" ]]; then
  echo "[x] CF_D1_DATABASE_ID not provided."
  echo "    Usage via arg: ... | bash -s -- <CF_D1_DATABASE_ID>"
  echo "    Or via env:   CF_D1_DATABASE_ID=... curl ... | bash"
  exit 1
fi
export CF_D1_DATABASE_ID

# Optional domain overrides (envs)
DMJ_ROOT_DOMAIN="${DMJ_ROOT_DOMAIN:-dmj.one}"
SIGNER_DOMAIN="${SIGNER_DOMAIN:-signer.dmj.one}"
export DMJ_ROOT_DOMAIN SIGNER_DOMAIN

# Service account
DMJ_USER="dmjsvc"

# -------------------------------
# Part 1 (system setup)
# -------------------------------
echo "[+] Running Part 1 installer..."
curl -fsSL "https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/e16cff3280a6574df3a2d28b5928c8c87f2da8dd/one-click-deployment/static/dmj-part1.sh?nocache=$(date +%s)" \
  | bash

# -------------------------------
# Wrangler auth check (service acct)
# -------------------------------
echo "[+] Checking Wrangler for '${DMJ_USER}'..."

# Check if dmj-wrangler is installed and available in PATH
if ! command -v dmj-wrangler >/dev/null 2>&1; then 
  echo "[x] Wrangler not found on ${DMJ_USER}'s PATH. Aborting."
  exit 1
fi

# Run `dmj-wrangler whoami`, capturing output even if it fails
WHOAMI_OUTPUT="$(dmj-wrangler whoami 2>&1 || true)"

# Check for specific "Virtual WildHogs" account match
if echo "$WHOAMI_OUTPUT" | grep -q "Virtual WildHogs"; then
  echo "[✓] Wrangler is logged in as Virtual WildHogs. Proceeding to Part 2."

  echo "[+] Running Part 2..."
  curl -fsSL "https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/e16cff3280a6574df3a2d28b5928c8c87f2da8dd/one-click-deployment/static/dmj-part2.sh?nocache=$(date +%s)" \
    | env CF_D1_DATABASE_ID="$CF_D1_DATABASE_ID" DMJ_ROOT_DOMAIN="$DMJ_ROOT_DOMAIN" SIGNER_DOMAIN="$SIGNER_DOMAIN" bash

  echo "[✓] Both parts executed successfully."

else
  echo "[!] Wrangler authentication not detected for ${DMJ_USER}."
  echo "[!] Please log in with: sudo -u ${DMJ_USER} -H wrangler login"
  echo "[i] Exiting without running Part 2."
  exit 1
fi