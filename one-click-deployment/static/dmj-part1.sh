# dmj-part1.sh
#!/usr/bin/env bash
set -euo pipefail

### Constants / paths
LOG_DIR="/var/log/dmj"
STATE_DIR="/var/lib/dmj"
CONF_DIR="/etc/dmj"
INST_ENV="${CONF_DIR}/installer.env"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"

echo "[+] Updating apt and installing base packages..."
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates curl git jq unzip gnupg software-properties-common \
  openjdk-21-jdk maven nginx ufw util-linux moreutils

# Install Node.js (22.x LTS) via NodeSource
# (official quick method per NodeSource) 
if ! command -v node >/dev/null 2>&1; then
  echo "[+] Installing Node.js 22.x (NodeSource)..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi
echo "[+] Node: $(node -v); npm: $(npm -v)"

# Install Wrangler (modern) 
if ! command -v wrangler >/dev/null 2>&1; then
  echo "[+] Installing Wrangler CLI..."
  sudo npm i -g wrangler@latest
fi
echo "[+] Wrangler: $(wrangler --version)"

# Ensure nginx is running (we’ll use it in Part 2)
sudo systemctl enable --now nginx >/dev/null 2>&1 || true

# Save machine install id (used for DB table prefix / uniqueness)
if [ ! -f "$INST_ENV" ]; then
  INSTALLATION_ID="$(tr -dc 'a-f0-9' </dev/urandom | head -c 16)"
  {
    echo "INSTALLATION_ID=${INSTALLATION_ID}"
    # DB_PREFIX seeded with install id to avoid collisions in shared D1
    echo "DB_PREFIX=dmj_${INSTALLATION_ID}_"
  } | sudo tee "$INST_ENV" >/dev/null
else
  # shellcheck disable=SC1090
  source "$INST_ENV"
fi

echo "[+] Checking Wrangler auth..."
if wrangler whoami >/dev/null 2>&1; then
  echo "[✓] Wrangler already authenticated. You can proceed to Part 2."
  exit 0
fi

echo
echo "[!] Wrangler is not authenticated. Starting headless OAuth login..."
echo "    We will capture and save the login URL for you."

LOGIN_LOG="${LOG_DIR}/wrangler-login-$(date +%s).log"
# Start wrangler login in background, capture output (it prints the OAuth URL).
# Keep it running so the local callback server remains available.
( set -o pipefail; wrangler login 2>&1 | tee -a "$LOGIN_LOG" ) &
WRANGLER_PID=$!

# Give wrangler a moment to print the URL
sleep 3

# Extract the printed OAuth URL if present
if grep -Eo 'https://dash\.cloudflare\.com/oauth2/auth[^ ]+' "$LOGIN_LOG" | head -n1 | sponge "${STATE_DIR}/wrangler-oauth-url.txt"; then
  OAUTH_URL="$(cat "${STATE_DIR}/wrangler-oauth-url.txt")"
  echo
  echo "------------------------------------------------------------"
  echo "[ACTION REQUIRED]"
  echo "Open the following URL on your local machine to continue:"
  echo "$OAUTH_URL"
  echo "The login will attempt to redirect to:"
  echo "  http://localhost:8976/oauth/callback?code=...&state=..."
  echo
  echo "Since this is a headless VM, copy that entire callback URL"
  echo "from your browser and run (on this VM):"
  echo '  curl -fsSL "http://localhost:8976/oauth/callback?code=...&state=..."'
  echo
  echo "(Alternatively, temporarily open port 8976 and replace"
  echo " localhost with your VM IP—this is a known workaround)."
  echo "------------------------------------------------------------"
  echo
  echo "[i] The URL has also been saved to: ${STATE_DIR}/wrangler-oauth-url.txt"
  echo "[i] Wrangler login process is running in background (PID: ${WRANGLER_PID})."
else
  echo "[!] Could not detect OAuth URL yet. Check the live log at: $LOGIN_LOG"
  echo "    Wrangler login is running (PID: ${WRANGLER_PID})."
fi

echo "[*] Exiting Part 1 now. After you complete login, run Part 2."
exit 0
