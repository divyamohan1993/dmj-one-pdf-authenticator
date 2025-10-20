#!/usr/bin/env bash
# dmj-part1.sh  — two modes: quiet (default) & verbose; always logs line-by-line
set -euo pipefail
umask 077

# ---- Mode selection ----------------------------------------------------------
DMJ_VERBOSE="${DMJ_VERBOSE:-0}"
if [[ "${1:-}" == "--verbose" ]]; then DMJ_VERBOSE=1; fi
if [[ "${1:-}" == "--quiet" ]];   then DMJ_VERBOSE=0; fi

# ---- Paths & log -------------------------------------------------------------
LOG_DIR="/var/log/dmj"
STATE_DIR="/var/lib/dmj"
CONF_DIR="/etc/dmj"
INST_ENV="${CONF_DIR}/installer.env"

mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"

# Dedicated per-run log file (always written)
LOG_FILE="${LOG_DIR}/dmj-part1-$(date +%Y%m%d-%H%M%S).log"

# Save the real console so we can selectively print to it (FD 3)
exec 9>&1
exec 3>&9

# Stream & timestamp all stdout/stderr into the log (and optionally to console)
if (( DMJ_VERBOSE )); then
  # Verbose: show everything AND log it
  exec > >(stdbuf -oL awk '{printf "[%s] %s\n", strftime("%F %T"), $0}' | tee -a "$LOG_FILE") 2>&1
else
  # Quiet: send everything to the log only; checkpoints use say() -> FD 3
  exec > >(stdbuf -oL awk '{printf "[%s] %s\n", strftime("%F %T"), $0}' >> "$LOG_FILE") 2>&1
fi

# Pretty xtrace for line-by-line visibility in the log (and console if verbose)
export PS4='+ [${BASH_SOURCE##*/}:${LINENO}] '
set -x

# ---- Checkpoint printers -----------------------------------------------------
# In quiet mode, say() prints to console; in verbose mode, it's suppressed.
say() { if (( DMJ_VERBOSE )); then :; else printf "%s\n" "$*" >&3; fi; }
# Always print to console (used for ACTION REQUIRED + trap)
say_always() { printf "%s\n" "$*" >&3; }

# ---- Fatal handler -----------------------------------------------------------
trap 'rc=$?; if (( rc != 0 )); then
         say_always ""
         say_always "[!] Failed at line ${LINENO}: ${BASH_COMMAND} (exit ${rc})"
         if (( DMJ_VERBOSE )); then :; else say_always "[i] See full log: ${LOG_FILE}"; fi
       fi
       exit $rc' ERR

# ---- Non-interactive installs: avoid prompts from debconf/needrestart --------
# (safe for scripted provisioning)
export DEBIAN_FRONTEND=noninteractive      # debconf frontend, noninteractive
export APT_LISTCHANGES_FRONTEND=none       # silence apt-listchanges if present
export NEEDRESTART_SUSPEND=1               # disable needrestart apt hook

# ---- App/service constants ---------------------------------------------------
DMJ_USER="dmjsvc"
DMJ_HOME="/var/lib/${DMJ_USER}"
DMJ_XDG="${DMJ_HOME}/.config"                         # XDG base
DMJ_WR_CFG_DIR="${DMJ_XDG}/.wrangler/config"          # XDG-style path
DMJ_WR_CFG_FILE="${DMJ_WR_CFG_DIR}/default.toml"
DMJ_LEGACY_WR_DIR="${DMJ_HOME}/.wrangler"             # legacy symlink target
DMJ_LEGACY_CFG="${DMJ_LEGACY_WR_DIR}/config/default.toml"

# ---- Base packages -----------------------------------------------------------
say "[+] Updating apt and installing base packages..."
sudo apt-get update -y
sudo apt-get install -y -qq \
  ca-certificates curl git jq openssl unzip gnupg software-properties-common \
  openjdk-21-jdk maven nginx ufw util-linux moreutils zip cron nano certbot python3-certbot-nginx

# ---- Node.js (needed by Wrangler) -------------------------------------------
if ! command -v node >/dev/null 2>&1; then
  say "[+] Installing Node.js 22.x (NodeSource)..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt-get install -y -q nodejs
fi
say "[i] Node: $(node -v); npm: $(npm -v)"

# ---- Wrangler CLI ------------------------------------------------------------
if ! command -v wrangler >/dev/null 2>&1; then
  say "[+] Installing Wrangler CLI..."
  sudo npm i -g wrangler@latest
fi
WRANGLER_BIN="$(command -v wrangler)"
say "[i] Wrangler: $("$WRANGLER_BIN" --version)"

# ---- Ensure nginx is running (used in Part 2) --------------------------------
sudo systemctl enable --now nginx >/dev/null 2>&1 || true

# ---- Service account for Wrangler auth --------------------------------------
if ! id -u "$DMJ_USER" >/dev/null 2>&1; then
  say "[+] Creating locked service user: ${DMJ_USER}"
  sudo useradd --system --home-dir "$DMJ_HOME" --create-home \
    --shell /usr/sbin/nologin "$DMJ_USER"
fi
sudo usermod -s /usr/sbin/nologin "$DMJ_USER" || true
sudo passwd -l "$DMJ_USER" >/dev/null 2>&1 || true
sudo usermod -L "$DMJ_USER" >/dev/null 2>&1 || true

# Service-owned runtime/log state; /etc/dmj remains root-owned
sudo install -d -m 0750 -o "$DMJ_USER" -g "$DMJ_USER" "$LOG_DIR" "$STATE_DIR"
sudo install -d -m 0755 -o "$DMJ_USER" -g "$DMJ_USER" /opt/dmj

# Prepare config dirs (XDG + legacy symlink), secure permissions
sudo mkdir -p "$DMJ_WR_CFG_DIR"
sudo chown -R "$DMJ_USER:$DMJ_USER" "$DMJ_HOME"
sudo chmod 700 "$DMJ_HOME"
sudo chmod -R go-rwx "$DMJ_HOME"

# ---- Certificates ------------------------------------------------------------
say "[i] Generating ocsp and pki domain Let's Encrypt certificates"
sudo certbot --nginx -d ocsp.dmj.one --no-redirect --non-interactive --agree-tos -m contact@dmj.one
sudo certbot --nginx -d pki.dmj.one  --no-redirect --non-interactive --agree-tos -m contact@dmj.one

# ---- Legacy ~/.wrangler -> XDG symlink --------------------------------------
if [ ! -e "$DMJ_LEGACY_WR_DIR" ]; then
  sudo -u "$DMJ_USER" -H ln -s "${DMJ_XDG}/.wrangler" "$DMJ_LEGACY_WR_DIR" || true
fi

# Run commands as the service user, with HOME/XDG set
as_dmj() {
  sudo -u "$DMJ_USER" -H env HOME="$DMJ_HOME" XDG_CONFIG_HOME="$DMJ_XDG" "$@"
}

# Migrate root Wrangler credentials (one-time)
ROOT_CFG1="/root/.wrangler/config/default.toml"
ROOT_CFG2="/root/.config/.wrangler/config/default.toml"
if [ ! -f "$DMJ_WR_CFG_FILE" ] && { [ -f "$ROOT_CFG1" ] || [ -f "$ROOT_CFG2" ]; }; then
  SRC="$ROOT_CFG1"; [ -f "$ROOT_CFG2" ] && SRC="$ROOT_CFG2"
  say "[i] Migrating existing root Wrangler credentials into ${DMJ_USER}..."
  sudo install -m 600 -o "$DMJ_USER" -g "$DMJ_USER" "$SRC" "$DMJ_WR_CFG_FILE" || true
fi

# Save machine install id (used for DB table prefix / uniqueness)
if [ ! -f "$INST_ENV" ]; then
  INSTALLATION_ID="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  {
    echo "INSTALLATION_ID=${INSTALLATION_ID}"
    echo "DB_PREFIX=documents_"
  } | sudo tee "$INST_ENV" >/dev/null
else
  set +u
  source "$INST_ENV"
  set -u
fi

# === CONSOLIDATED AUTH CHECK (always as service user) =========================
say "[+] Checking Wrangler auth (service acct: ${DMJ_USER})..."
WHOAMI_OUTPUT="$( (as_dmj "$WRANGLER_BIN" whoami 2>&1 || true) )"

if echo "$WHOAMI_OUTPUT" | grep -qiE 'You are not authenticated|not authenticated'; then
  say "[!] Wrangler is NOT authenticated for ${DMJ_USER}."
else
  if echo "$WHOAMI_OUTPUT" | grep -qiE 'You are logged in|Account Name|Email|User'; then
    say "[✓] Wrangler already authenticated (service user). You can proceed to Part 2."
    # Install wrapper so future commands pin to the service user.
    if [ ! -x /usr/local/bin/dmj-wrangler ]; then
      say "[+] Installing dmj-wrangler helper..."
      sudo bash -c "cat > /usr/local/bin/dmj-wrangler" <<'EOSH'
#!/usr/bin/env bash
exec sudo -u dmjsvc -H env HOME=/var/lib/dmjsvc XDG_CONFIG_HOME=/var/lib/dmjsvc/.config wrangler "$@"
EOSH
      sudo chmod 0755 /usr/local/bin/dmj-wrangler
    fi
    say_always "[*] Exiting Part 1 now. After you complete login, run Part 2:"
    say_always "    sudo bash /var/lib/dmj/rp2.sh"
    exit 0
  else
    say "[!] Wrangler authentication status unclear; treating as NOT authenticated."
  fi
fi

# === HEADLESS LOGIN (service user) ===========================================
say ""
say "[!] Starting headless OAuth login for ${DMJ_USER}..."
say "    We will capture and display the login URL for you."

LOGIN_LOG="${LOG_DIR}/wrangler-login-$(date +%s).log"
PID_FILE="${STATE_DIR}/wrangler-login.pid"
OAUTH_URL_FILE="${STATE_DIR}/wrangler-oauth-url.txt"

# Stop any previous wrangler login process if running
if [ -f "$PID_FILE" ]; then
  OLD_PID="$(cat "$PID_FILE" || true)"
  if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" >/dev/null 2>&1; then
    say "[i] Stopping previous 'wrangler login' (PID: $OLD_PID)..."
    kill "$OLD_PID" >/dev/null 2>&1 || true
    sleep 1
  fi
fi

# Start wrangler login as service user, write its real PID, tee to a log
( set -o pipefail;
  as_dmj bash -lc 'echo $$ > "'"$PID_FILE"'"; exec '"$WRANGLER_BIN"' login --browser=false'
) 2>&1 | tee -a "$LOGIN_LOG" &

say "[i] Waiting for OAuth URL from wrangler (PID file: $PID_FILE)..."
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
  say_always ""
  say_always "------------------------------------------------------------"
  say_always "[ACTION REQUIRED] Open this URL in a local browser to continue:"
  say_always "  $OAUTH_URL"
  say_always ""
  say_always "After you approve, your browser will redirect to:"
  say_always "  http://localhost:8976/oauth/callback?code=...&state=..."
  say_always ""
  say_always "Because this is a headless VM, copy that entire callback URL"
  say_always "from your browser and run (on THIS VM):"
  say_always '  curl -fsSL "http://localhost:8976/oauth/callback?code=...&state=..."'
  say_always ""
  say_always "[i] Saved URL: $OAUTH_URL_FILE"
  say_always "[i] Live log : $LOGIN_LOG"
  say_always "[i] Login PID: $(cat "$PID_FILE" 2>/dev/null || echo '?') (listens on 8976)"
  say_always "------------------------------------------------------------"
else
  say_always "[!] Could not detect the OAuth URL yet."
  say_always "    Tail the log for updates:  tail -f \"$LOGIN_LOG\""
  say_always "    'wrangler login' is still running (PID: $(cat "$PID_FILE" 2>/dev/null || echo '?'))."
fi

# Install the dmj-wrangler helper for consistent future use
if [ ! -x /usr/local/bin/dmj-wrangler ]; then
  say "[+] Installing dmj-wrangler helper..."
  sudo bash -c "cat > /usr/local/bin/dmj-wrangler" <<'EOSH'
#!/usr/bin/env bash
exec sudo -u dmjsvc -H env HOME=/var/lib/dmjsvc XDG_CONFIG_HOME=/var/lib/dmjsvc/.config wrangler "$@"
EOSH
  sudo chmod 0755 /usr/local/bin/dmj-wrangler
fi

# Prepare Part 2 runner
sudo tee ${STATE_DIR}/rp2.sh >/dev/null <<'RP2'
# rp2.sh
# set your D1 database id (from `wrangler d1 list`, or Dashboard)
export CF_D1_DATABASE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# optional: customize domains
export DMJ_ROOT_DOMAIN="dmj.one"
export SIGNER_DOMAIN="signer.dmj.one"   # must point to this VM via Cloudflare DNS (proxied)

sudo --preserve-env=CF_D1_DATABASE_ID,DMJ_ROOT_DOMAIN,SIGNER_DOMAIN \
  bash -lc 'curl -fsSL https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/dmj-part2.sh?nocache=$(date +%s) | bash'
RP2

say_always "[*] Exiting Part 1 now. After you complete login, run Part 2."
say_always "    Edit the D1 id:  sudo nano ${STATE_DIR}/rp2.sh"
say_always "    Then run:        sudo bash ${STATE_DIR}/rp2.sh"
exit 0
