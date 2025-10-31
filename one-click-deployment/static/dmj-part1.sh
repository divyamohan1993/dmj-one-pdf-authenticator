#!/usr/bin/env bash
# dmj-part1.sh
set -euo pipefail
umask 077

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"

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

# Set this variable at the top (defaulting to 0, so safe)
GEN_STUBS=${GEN_STUBS:-1}

mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"

echo "[+] Updating apt and installing base packages..."
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
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
  ( umask 022; sudo npm i -g wrangler@latest )
fi
# Ensure PATH sees global npm bin (and typical system bins)
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH}"
WRANGLER_BIN="$(command -v wrangler)"
# Repair permissions in case global umask 077 impacted install
sudo chmod 0755 "$WRANGLER_BIN" || true
WR_GLOBAL_ROOT="$(npm root -g 2>/dev/null || echo /usr/local/lib/node_modules)"
[ -d "$WR_GLOBAL_ROOT/wrangler" ] && sudo chmod -R a+rX "$WR_GLOBAL_ROOT/wrangler" || true
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

if [ "$GEN_STUBS" -eq 1 ]; then

  echo "[+] Removing legacy/duplicate nginx site links to avoid 'conflicting server name' ..."
  sudo rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
  # Remove any old per-domain stubs (both exact and wildcard matches)
  sudo rm -f /etc/nginx/sites-enabled/pki* \
              /etc/nginx/sites-enabled/ocsp* \
              /etc/nginx/sites-enabled/signer* \
              /etc/nginx/sites-enabled/tsa* 2>/dev/null || true
  sudo rm -f /etc/nginx/sites-enabled/*pki* \
              /etc/nginx/sites-enabled/*ocsp* \
              /etc/nginx/sites-enabled/*signer* \
              /etc/nginx/sites-enabled/*tsa* 2>/dev/null || true

  echo "[+] Waiting 2 seconds..."
  sleep 2

  echo "[+] Create minimal stub HTTP blocks for Let's Encrypt if they don't already exist"
  for DOMAIN in ocsp.dmj.one pki.dmj.one signer.dmj.one tsa.dmj.one; do
    CONF="/etc/nginx/sites-available/${DOMAIN}.conf"
    ENABLED="/etc/nginx/sites-enabled/${DOMAIN}.conf"

    # (Re)write the stub if missing or if it doesn't declare the expected server_name
    if [ ! -f "${CONF}" ] || ! grep -qE "^[[:space:]]*server_name[[:space:]]+${DOMAIN};" "${CONF}" 2>/dev/null; then
      sudo tee "${CONF}" > /dev/null <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    root /var/www/html;
    location / {
        return 200 "ok\n";
    }
}
EOF
    fi
    # Always ensure the site is enabled (symlink present)
    sudo ln -sf "${CONF}" "${ENABLED}"
  done

  # test nginx config and reload to apply stubs
  sudo nginx -t && sudo systemctl reload nginx

  echo "[i] Generating ocsp, signer, tsa and pki domain's LetsEncrypt Certificate"
  sudo certbot --nginx -d ocsp.dmj.one    --no-redirect --non-interactive --agree-tos -m contact@dmj.one
  sudo certbot --nginx -d pki.dmj.one     --no-redirect --non-interactive --agree-tos -m contact@dmj.one
  sudo certbot --nginx -d signer.dmj.one  --no-redirect --non-interactive --agree-tos -m contact@dmj.one
  sudo certbot --nginx -d tsa.dmj.one     --no-redirect --non-interactive --agree-tos -m contact@dmj.one

fi

# Ensure legacy ~/.wrangler points at XDG .wrangler
if [ ! -e "$DMJ_LEGACY_WR_DIR" ]; then
  sudo -u "$DMJ_USER" -H ln -s "${DMJ_XDG}/.wrangler" "$DMJ_LEGACY_WR_DIR" || true
fi

# Helper to run commands as the service user, with HOME/XDG set
as_dmj() {
  # sudo -u "$DMJ_USER" -H env HOME="$DMJ_HOME" XDG_CONFIG_HOME="$DMJ_XDG" "$@"
  sudo --preserve-env=CLOUDFLARE_API_TOKEN \
    -u "$DMJ_USER" -H env \
    HOME="$DMJ_HOME" XDG_CONFIG_HOME="$DMJ_XDG" PATH="/usr/local/bin:/usr/bin:/bin" "$@"
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

# --- install dmj-fetch-fresh helper (global CLI) ----------------------------
echo "[+] Installing dmj-fetch-fresh helper..."
sudo bash -c "cat > /usr/local/bin/dmj-fetch-fresh" <<'EOSH'
#!/usr/bin/env bash

# dmj-fetch-fresh: fetch the latest dmj-fetcher.sh (with pinned SHA-256),
# source it, and delegate to the dmj_fetch_fresh() function.
# Usage: dmj-fetch-fresh URL DEST [-chmod OCTAL] [-chown USER[:GROUP]] [-hash sha256:HEX] [-replacevars true|false]

set -euo pipefail
umask 022
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Uniform behavior: re-exec as root so results are identical with or without sudo.
# Requires the sudoers drop-in installed by this patch.
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  exec sudo -n "$0" "$@"
fi

# Optional override/config file:
#   /etc/dmj/fetcher.env may define:
#     DMJ_FETCHER_URL, DMJ_FETCHER_URL_HASH,
#     DMJ_FETCH_CONNECT_TIMEOUT, DMJ_FETCH_MAX_TIME, DMJ_FETCH_RETRIES,
#     DMJ_FETCH_AUTH_HEADER, DMJ_FETCH_HSTS_FILE
if [ -f /etc/dmj/fetcher.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /etc/dmj/fetcher.env
  set +a
fi


# Fixed service identity for network I/O to keep HSTS/cache consistent for all callers
: "${DMJ_RUN_USER:=dmjsvc}"
: "${DMJ_RUN_HOME:=/var/lib/${DMJ_RUN_USER}}"
: "${DMJ_RUN_XDG:=${DMJ_RUN_HOME}/.config}"
: "${DMJ_RUN_CACHE:=${DMJ_RUN_HOME}/.cache}"

if ! id "${DMJ_RUN_USER}" >/dev/null 2>&1; then
  echo "[dmj-fetch-fresh] service user '${DMJ_RUN_USER}' does not exist" >&2
  exit 78
fi

# Default fetcher location + pinned hash (update hash when you update the script)
DMJ_FETCHER_URL="${DMJ_FETCHER_URL:-url}"
DMJ_FETCHER_URL_HASH="${DMJ_FETCHER_URL_HASH:-sha256:hash}"

t="$(mktemp -t dmj_fetcher.XXXXXXXX)" || { echo "mktemp failed" >&2; exit 70; }
trap 'rm -f "$t" "$t.n"' EXIT
log_err() {
  m="[dmj-fetch-fresh] $*"
  if command -v systemd-cat >/dev/null 2>&1; then
    systemd-cat --identifier=dmj-fetch-fresh --priority=err <<<"$m"
  else
    logger -t dmj-fetch-fresh -p user.err "$m" 2>/dev/null || echo "$m" >&2
  fi
}

command -v curl >/dev/null 2>&1 || { log_err "curl not installed"; exit 127; }

# Build curl argv (HTTPS enforced, retries, HSTS if supported, quiet unless TTY)
C=(curl --fail --location
    --connect-timeout "${DMJ_FETCH_CONNECT_TIMEOUT:-10}"
    --max-time "${DMJ_FETCH_MAX_TIME:-900}"
    --retry "${DMJ_FETCH_RETRIES:-6}" --retry-connrefused
    --proto '=https' --proto-redir '=https' --tlsv1.2
    -H 'Cache-Control: no-cache, no-store, must-revalidate'
    -H 'Pragma: no-cache' -H 'Expires: 0'
    -H 'Accept-Encoding: identity')

# Add retry-all-errors (curl >= 7.71.0) when available
curl --help all 2>/dev/null | grep -q -- '--retry-all-errors' && C+=('--retry-all-errors')

# Add HSTS cache (curl >= 7.74.0) when available
if curl --help all 2>/dev/null | grep -q -- '--hsts'; then
  # Pin HSTS to a shared, service-owned location so HTTPS behavior is the same for every user.
  HSTS_FILE="${DMJ_FETCH_HSTS_FILE:-${DMJ_RUN_CACHE}/dmj_fetch_hsts}"
  install -d -m 0755 -o "${DMJ_RUN_USER}" -g "${DMJ_RUN_USER}" "$(dirname "$HSTS_FILE")"
  C+=('--hsts' "$HSTS_FILE")
fi

# Progress behavior: --no-progress-meter (>= 7.67.0) or -sS fallback
if curl --help all 2>/dev/null | grep -q -- '--no-progress-meter'; then
  if [ -t 2 ]; then C+=('--progress-bar'); else C+=('--no-progress-meter'); fi
else
  C+=('-sS')
fi

# Optional single custom header (e.g., Authorization: Bearer ...)
[ -n "${DMJ_FETCH_AUTH_HEADER:-}" ] && C+=(-H "$DMJ_FETCH_AUTH_HEADER")

# Download the fetcher
"${C[@]}" -o "$t" "${DMJ_FETCHER_URL}?_=$(date +%s)" \
  || { log_err "download failed: $DMJ_FETCHER_URL"; exit 66; }

# Verify pinned SHA-256
exp="${DMJ_FETCHER_URL_HASH#sha256:}"
exp="$(printf %s "$exp" | tr -d '[:space:]' | tr 'A-F' 'a-f')"
printf %s "$exp" | grep -Eq '^[0-9a-f]{64}$' || { log_err "DMJ_FETCHER_URL_HASH must be 64-hex SHA-256"; exit 68; }

if command -v sha256sum >/dev/null 2>&1; then act="$(sha256sum "$t" | awk '{print tolower($1)}')"
elif command -v shasum    >/dev/null 2>&1; then act="$(shasum -a 256 "$t" | awk '{print tolower($1)}')"
elif command -v openssl   >/dev/null 2>&1; then act="$(openssl dgst -sha256 -r "$t" | awk '{print tolower($1)}')"
else log_err "no SHA-256 tool found"; exit 69; fi

[ "$act" = "$exp" ] || { log_err "authenticity of dmj-fetcher.sh could not be verified (got $act)"; exit 67; }

# Normalize (strip BOM, CRs) and syntax-check as POSIX sh
awk 'NR==1{sub(/^\xef\xbb\xbf/,"")} {sub(/\r$/,"")} 1' "$t" >"$t.n" && mv "$t.n" "$t"
sh -n "$t" || { log_err "syntax check failed for fetched dmj-fetcher.sh"; exit 65; }

# Source the fetcher and delegate
# shellcheck disable=SC1090
. "$t"

# Always do network transfers as the service user for uniform behavior.
# dmj_fetch_fresh honors DMJ_FETCH_CURL, which must be an executable path (not a command line).
export DMJ_FETCH_HSTS_FILE="${HSTS_FILE:-${DMJ_RUN_CACHE}/dmj_fetch_hsts}"
export DMJ_FETCH_CURL="/usr/local/libexec/dmj-curl-as-dmjsvc"


set +e
dmj_fetch_fresh "$@"
rc=$?
set -e
exit "$rc"
EOSH

sudo bash -c "cat > /etc/dmj/fetcher.env" <<'EENV'
# /etc/dmj/fetcher.env
# Update the hash whenever you update the fetcher:
#   curl -fsSL "$DMJ_FETCHER_URL" | sha256sum
DMJ_FETCHER_URL="https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/bin/dmj-fetcher.sh.tmpl"
DMJ_FETCHER_URL_HASH="sha256:3c28869907adc2dd9e87d21e86f772e289bc49b3cd79ce9a711b6d48babd4b3c"

# Runtime behavior (all optional)
DMJ_FETCH_CONNECT_TIMEOUT=10
DMJ_FETCH_MAX_TIME=30
DMJ_FETCH_RETRIES=3
# DMJ_FETCH_AUTH_HEADER="Authorization: Bearer <token>"
# Pin HSTS file for uniform HTTPS behavior across all users:
DMJ_FETCH_HSTS_FILE="/var/lib/dmjsvc/.cache/dmj_fetch_hsts
EENV

sudo bash -c "cat > /usr/local/libexec/dmj-curl-as-dmjsvc" <<'CASDMJSVC'
#!/usr/bin/env bash
# Helper used by dmj-fetch-fresh (run as root) to execute curl as the service user.
# Must be an executable file path because dmj_fetch_fresh expects DMJ_FETCH_CURL to be a program, not a shell snippet.
set -euo pipefail
umask 022
export PATH=/usr/local/bin:/usr/bin:/bin
# Drop privileges to dmjsvc and provide a stable HOME/XDG for caches and HSTS.
exec sudo -n -u dmjsvc -H \
  env HOME=/var/lib/dmjsvc XDG_CONFIG_HOME=/var/lib/dmjsvc/.config \
  "$(command -v curl)" "$@"
CASDMJSVC

sudo bash -c "cat > /etc/sudoers.d/dmj-fetch-fresh" <<'SUDOER'
# Let ANY user invoke dmj-fetch-fresh uniformly (no password prompt).
# Keep the rule narrow: only these exact commands are permitted.
# Manage sudoers via /etc/sudoers.d instead of editing /etc/sudoers directly. 
# Validate changes with: `visudo -f /etc/sudoers.d/dmj-fetch-fresh`
Defaults!/usr/local/bin/dmj-fetch-fresh !requiretty
Cmnd_Alias DMJ_FETCH_CMDS = /usr/local/bin/dmj-fetch-fresh, /usr/local/libexec/dmj-curl-as-dmjsvc
ALL ALL=(root) NOPASSWD: DMJ_FETCH_CMDS
SUDOER

sudo chown root:root /etc/sudoers.d/dmj-fetch-fresh
sudo chmod 0440 /etc/sudoers.d/dmj-fetch-fresh
sudo visudo -f /etc/sudoers.d/dmj-fetch-fresh   # validate syntax
sudo chmod 0755 /usr/local/libexec/dmj-curl-as-dmjsvc
sudo chmod 0755 /usr/local/bin/dmj-fetch-fresh

# --- /install dmj-fetch-fresh ------------------------------------------------


# === CONSOLIDATED AUTH CHECK (always as service user) =======================
echo "[+] Checking Wrangler auth (service acct: ${DMJ_USER})..."
# WHOAMI_OUTPUT="$( (as_dmj "$WRANGLER_BIN" whoami 2>&1 || true) )"
WHOAMI_OUTPUT="$( (as_dmj wrangler whoami 2>&1 || true) )"

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
# exec sudo -u dmjsvc -H env HOME=/var/lib/dmjsvc XDG_CONFIG_HOME=/var/lib/dmjsvc/.config wrangler "$@"
set -euo pipefail
# Optional token file support
if [ -f /etc/dmj/wrangler.env ]; then
  set -a
  . /etc/dmj/wrangler.env
  set +a
fi
exec sudo --preserve-env=CLOUDFLARE_API_TOKEN \
  -u dmjsvc -H env HOME=/var/lib/dmjsvc XDG_CONFIG_HOME=/var/lib/dmjsvc/.config PATH=/usr/local/bin:/usr/bin:/bin \
  "$(command -v wrangler)" "$@"
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
  # as_dmj bash -lc 'echo $$ > "'"$PID_FILE"'"; exec '"$WRANGLER_BIN"' login --browser=false'
  as_dmj bash -lc 'echo $$ > "'"$PID_FILE"'"; CI=0 exec wrangler login --browser=false'
) 2>&1 | tee -a "$LOGIN_LOG" &

echo "[i] Waiting for OAuth URL from wrangler (PID file: $PID_FILE)..."
: > "$OAUTH_URL_FILE"
MAX_WAIT="${WRANGLER_LOGIN_MAX_WAIT:-30}"
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
# exec sudo -u dmjsvc -H env HOME=/var/lib/dmjsvc XDG_CONFIG_HOME=/var/lib/dmjsvc/.config wrangler "$@"
set -euo pipefail
# Optional token file support
if [ -f /etc/dmj/wrangler.env ]; then
  set -a
  . /etc/dmj/wrangler.env
  set +a
fi
exec sudo --preserve-env=CLOUDFLARE_API_TOKEN \
  -u dmjsvc -H env HOME=/var/lib/dmjsvc XDG_CONFIG_HOME=/var/lib/dmjsvc/.config PATH=/usr/local/bin:/usr/bin:/bin \
  "$(command -v wrangler)" "$@"
EOSH
  sudo chmod 0755 /usr/local/bin/dmj-wrangler
fi

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