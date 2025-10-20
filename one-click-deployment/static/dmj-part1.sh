#!/usr/bin/env bash
# dmj-part1.sh
set -euo pipefail
umask 077

### Constants / paths
LOG_DIR="/var/log/dmj"
STATE_DIR="/var/lib/dmj"
CONF_DIR="/etc/dmj"
INST_ENV="${CONF_DIR}/installer.env"

# Service account that will own ALL Wrangler auth/config
DMJ_USER="dmjsvc"
DMJ_HOME="/var/lib/${DMJ_USER}"
DMJ_XDG="${DMJ_HOME}/.config"                         # XDG base
DMJ_WR_CFG_DIR="${DMJ_XDG}/.wrangler/config"          # XDG-style path
DMJ_WR_CFG_FILE="${DMJ_WR_CFG_DIR}/default.toml"
# Legacy path (some Wrangler builds still use this)
DMJ_LEGACY_WR_DIR="${DMJ_HOME}/.wrangler"             # symlink to XDG
DMJ_LEGACY_CFG="${DMJ_LEGACY_WR_DIR}/config/default.toml"

mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"

echo "[+] Updating apt and installing base packages..."
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
  ca-certificates curl git jq openssl unzip gnupg software-properties-common \
  openjdk-21-jdk maven nginx ufw util-linux moreutils zip cron nano certbot python3-certbot-nginx

# Install/ensure Node.js (only if missing; Wrangler works on Node >=18)
if ! command -v node >/dev/null 2>&1; then
  echo "[+] Installing Node.js 22.x (NodeSource)..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt-get install -y -q nodejs
fi
echo "[+] Node: $(node -v); npm: $(npm -v)"

# Install Wrangler (global) if missing
if ! command -v wrangler >/dev/null 2>&1; then
  echo "[+] Installing Wrangler CLI..."
  sudo npm i -g wrangler@latest
fi
WRANGLER_BIN="$(command -v wrangler)"
echo "[+] Wrangler: $("$WRANGLER_BIN" --version)"

# Ensure nginx is running (used in Part 2)
sudo systemctl enable --now nginx >/dev/null 2>&1 || true

# Create locked service account for Wrangler auth (idempotent)
if ! id -u "$DMJ_USER" >/dev/null 2>&1; then
  echo "[+] Creating locked service user: ${DMJ_USER}"
  sudo useradd --system --home-dir "$DMJ_HOME" --create-home \
    --shell /usr/sbin/nologin "$DMJ_USER"
fi

# Harden service account (keep it non-interactive and locked) — idempotent
sudo usermod -s /usr/sbin/nologin "$DMJ_USER" || true
sudo passwd -l "$DMJ_USER" >/dev/null 2>&1 || true
sudo usermod -L "$DMJ_USER" >/dev/null 2>&1 || true

# Ensure service‑owned runtime/log state; /etc/dmj remains root‑owned
sudo install -d -m 0750 -o "$DMJ_USER" -g "$DMJ_USER" "$LOG_DIR" "$STATE_DIR"
# Base app prefix used in Part 2
sudo install -d -m 0755 -o "$DMJ_USER" -g "$DMJ_USER" /opt/dmj

# Prepare config dirs (XDG + legacy symlink), secure permissions
sudo mkdir -p "$DMJ_WR_CFG_DIR"
sudo chown -R "$DMJ_USER:$DMJ_USER" "$DMJ_HOME"
sudo chmod 700 "$DMJ_HOME"
sudo chmod -R go-rwx "$DMJ_HOME"

echo "[i] Generating ocsp and pki domain's LetsEncrypt Certificate"
sudo certbot --nginx -d ocsp.dmj.one --no-redirect --non-interactive --agree-tos -m contact@dmj.one 
sudo certbot --nginx -d pki.dmj.one --no-redirect --non-interactive --agree-tos -m contact@dmj.one 

# Ensure legacy ~/.wrangler points at XDG .wrangler
if [ ! -e "$DMJ_LEGACY_WR_DIR" ]; then
  sudo -u "$DMJ_USER" -H ln -s "${DMJ_XDG}/.wrangler" "$DMJ_LEGACY_WR_DIR" || true
fi

# Helper to run commands as the service user, with HOME/XDG set
as_dmj() {
  sudo -u "$DMJ_USER" -H env HOME="$DMJ_HOME" XDG_CONFIG_HOME="$DMJ_XDG" "$@"
}

# If root has a token file but service-user doesn't, migrate it (one-time)
ROOT_CFG1="/root/.wrangler/config/default.toml"
ROOT_CFG2="/root/.config/.wrangler/config/default.toml"
if [ ! -f "$DMJ_WR_CFG_FILE" ] && [ -f "$ROOT_CFG1" -o -f "$ROOT_CFG2" ]; then
  SRC="$ROOT_CFG1"
  [ -f "$ROOT_CFG2" ] && SRC="$ROOT_CFG2"
  echo "[i] Migrating existing root Wrangler credentials into ${DMJ_USER}..."
  sudo install -m 600 -o "$DMJ_USER" -g "$DMJ_USER" "$SRC" "$DMJ_WR_CFG_FILE" || true
fi

# Save machine install id (used for DB table prefix / uniqueness)
if [ ! -f "$INST_ENV" ]; then
  # Generate 16 hex chars (8 random bytes) without triggering pipefail/SIGPIPE
  INSTALLATION_ID="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  {
    echo "INSTALLATION_ID=${INSTALLATION_ID}"
    # echo "DB_PREFIX=dmj_${INSTALLATION_ID}_"
    echo "DB_PREFIX=documents_"
  } | sudo tee "$INST_ENV" >/dev/null
else
  # shellcheck disable=SC1090
  set +u
  source "$INST_ENV"
  set -u
fi

# === CONSOLIDATED AUTH CHECK (always as service user) =======================
echo "[+] Checking Wrangler auth (service acct: ${DMJ_USER})..."
WHOAMI_OUTPUT="$( (as_dmj "$WRANGLER_BIN" whoami 2>&1 || true) )"

if echo "$WHOAMI_OUTPUT" | grep -qiE 'You are not authenticated|not authenticated'; then
  echo "[!] Wrangler is NOT authenticated for ${DMJ_USER}."
else
  if echo "$WHOAMI_OUTPUT" | grep -qiE 'You are logged in|Account Name|Email|User'; then
    echo "[✓] Wrangler already authenticated (service user). You can proceed to Part 2."
    # Drop a small wrapper so future commands pin to the service user.
    if [ ! -x /usr/local/bin/dmj-wrangler ]; then
      echo "[+] Installing dmj-wrangler helper..."
      sudo bash -c "cat > /usr/local/bin/dmj-wrangler" <<'EOSH'
#!/usr/bin/env bash
exec sudo -u dmjsvc -H env HOME=/var/lib/dmjsvc XDG_CONFIG_HOME=/var/lib/dmjsvc/.config wrangler "$@"
EOSH
      sudo chmod 0755 /usr/local/bin/dmj-wrangler
    fi
    exit 0
  else
    echo "[!] Wrangler authentication status unclear; treating as NOT authenticated."
  fi
fi

# === HEADLESS LOGIN (service user) ==========================================
echo
echo "[!] Starting headless OAuth login for ${DMJ_USER}..."
echo "    We will capture and display the login URL for you."

LOGIN_LOG="${LOG_DIR}/wrangler-login-$(date +%s).log"
PID_FILE="${STATE_DIR}/wrangler-login.pid"
OAUTH_URL_FILE="${STATE_DIR}/wrangler-oauth-url.txt"

# Idempotency: stop any previous wrangler login process if running
if [ -f "$PID_FILE" ]; then
  OLD_PID="$(cat "$PID_FILE" || true)"
  if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" >/dev/null 2>&1; then
    echo "[i] Stopping previous 'wrangler login' (PID: $OLD_PID)..."
    kill "$OLD_PID" >/dev/null 2>&1 || true
    sleep 1
  fi
fi

# Start wrangler login as service user, write its real PID, and tee output
# into a root-writable log (login server listens on localhost:8976).
( set -o pipefail;
  as_dmj bash -lc 'echo $$ > "'"$PID_FILE"'"; exec '"$WRANGLER_BIN"' login --browser=false'
) 2>&1 | tee -a "$LOGIN_LOG" &

echo "[i] Waiting for OAuth URL from wrangler (PID file: $PID_FILE)..."
: > "$OAUTH_URL_FILE"
MAX_WAIT="${WRANGLER_LOGIN_MAX_WAIT:-90}"
for _ in $(seq 1 "$MAX_WAIT"); do
  if grep -Eo 'https://dash\.cloudflare\.com/oauth2/(auth|authorize)\?[^ ]+' "$LOGIN_LOG" \
      | head -n1 | sponge "$OAUTH_URL_FILE"; then
    break
  fi
  sleep 1
done

if [ -s "$OAUTH_URL_FILE" ]; then
  OAUTH_URL="$(cat "$OAUTH_URL_FILE")"
  echo
  echo "------------------------------------------------------------"
  echo "[ACTION REQUIRED] Open this URL in a local browser to continue:"
  echo "$OAUTH_URL"
  echo
  echo "After you approve, your browser will redirect to:"
  echo "  http://localhost:8976/oauth/callback?code=...&state=..."
  echo
  echo "Because this is a headless VM, copy that entire callback URL"
  echo "from your browser and run (on THIS VM):"
  echo '  curl -fsSL "http://localhost:8976/oauth/callback?code=...&state=..."'
  echo
  echo "[i] Saved URL: $OAUTH_URL_FILE"
  echo "[i] Live log : $LOGIN_LOG"
  echo "[i] Login PID: $(cat "$PID_FILE" 2>/dev/null || echo '?') (listens on 8976)"
  echo "------------------------------------------------------------"
else
  echo "[!] Could not detect the OAuth URL yet."
  echo "    Tail the log for updates:  tail -f \"$LOGIN_LOG\""
  echo "    'wrangler login' is still running (PID: $(cat "$PID_FILE" 2>/dev/null || echo '?'))."
fi

# Install the dmj-wrangler helper for consistent future use
if [ ! -x /usr/local/bin/dmj-wrangler ]; then
  echo "[+] Installing dmj-wrangler helper..."
  sudo bash -c "cat > /usr/local/bin/dmj-wrangler" <<'EOSH'
#!/usr/bin/env bash
exec sudo -u dmjsvc -H env HOME=/var/lib/dmjsvc XDG_CONFIG_HOME=/var/lib/dmjsvc/.config wrangler "$@"
EOSH
  sudo chmod 0755 /usr/local/bin/dmj-wrangler
fi

cd ~
curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/dmj-part1.sh?nocache=$(date +%s) &> dmj-part1.sh

sudo tee ${STATE_DIR}/rp2.sh >/dev/null <<RP2
# rp2.sh
# set your D1 database id (from `wrangler d1 list`, or Dashboard)
export CF_D1_DATABASE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# optional: customize domains
export DMJ_ROOT_DOMAIN="dmj.one"
export SIGNER_DOMAIN="signer.dmj.one"   # must point to this VM via Cloudflare DNS (proxied)

sudo --preserve-env=CF_D1_DATABASE_ID,DMJ_ROOT_DOMAIN,SIGNER_DOMAIN \
  bash -lc 'curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/dmj-part2.sh?nocache=$(date +%s) | bash'
RP2

echo "[*] Exiting Part 1 now. After you complete login, run Part 2. After login, edit the D1 id usint nano and once done, run: sudo bash ${STATE_DIR}/rp2.sh"
exit 0
