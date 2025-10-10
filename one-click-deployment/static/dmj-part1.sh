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
  # INSTALLATION_ID="$(tr -dc 'a-f0-9' </dev/urandom | head -c 16)"
  # Generate 16 hex chars (8 random bytes) without triggering pipefail/SIGPIPE
  INSTALLATION_ID="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

  {
    echo "INSTALLATION_ID=${INSTALLATION_ID}"
    # DB_PREFIX seeded with install id to avoid collisions in shared D1
    echo "DB_PREFIX=dmj_${INSTALLATION_ID}_"
  } | sudo tee "$INST_ENV" >/dev/null
else
  # shellcheck disable=SC1090
  set +u
  source "$INST_ENV"
  set -u
fi

echo "[+] Checking Wrangler auth..."
# Capture output safely under `set -euo pipefail` without aborting the script.
WHOAMI_OUTPUT="$( (wrangler whoami 2>&1 || true) )"

if echo "$WHOAMI_OUTPUT" | grep -qiE 'You are not authenticated|not authenticated'; then
  echo "[!] Wrangler is NOT authenticated."
else
  # If output looks like real user info, consider it authenticated.
  if echo "$WHOAMI_OUTPUT" | grep -qiE 'Account|Email|User'; then
    echo "[✓] Wrangler already authenticated. You can proceed to Part 2."
    exit 0
  else
    echo "[!] Wrangler authentication status was unclear; treating as NOT authenticated."
  fi
fi

echo
echo "[!] Wrangler is not authenticated. Starting headless OAuth login..."
echo "    We will capture and display the login URL for you."

LOGIN_LOG="${LOG_DIR}/wrangler-login-$(date +%s).log"
PID_FILE="${STATE_DIR}/wrangler-login.pid"
OAUTH_URL_FILE="${STATE_DIR}/wrangler-oauth-url.txt"

# Idempotency: stop any previous wrangler login process if it is still running.
if [ -f "$PID_FILE" ]; then
  OLD_PID="$(cat "$PID_FILE" || true)"
  if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" >/dev/null 2>&1; then
    echo "[i] Stopping previous 'wrangler login' (PID: $OLD_PID)..."
    kill "$OLD_PID" >/dev/null 2>&1 || true
    sleep 1
  fi
fi

# Start wrangler login in headless mode; it will print the OAuth URL.
# (--browser=false is the headless switch; wrangler runs a local callback server on 8976)
( set -o pipefail; wrangler login --browser=false 2>&1 | tee -a "$LOGIN_LOG" ) &
WRANGLER_PID=$!
echo "$WRANGLER_PID" > "$PID_FILE"

# Poll the log for the printed OAuth URL and show it to the user.
: > "$OAUTH_URL_FILE"
echo "[i] Waiting for OAuth URL from wrangler (PID: ${WRANGLER_PID})..."
MAX_WAIT="${WRANGLER_LOGIN_MAX_WAIT:-60}"
for _ in $(seq 1 "$MAX_WAIT"); do
  if grep -Eo 'https://dash\.cloudflare\.com/oauth2/(auth|authorize)\?[^ ]+' "$LOGIN_LOG" \
      | head -n1 | tee "$OAUTH_URL_FILE" >/dev/null; then
    break
  fi
  sleep 1
done

if [ -s "$OAUTH_URL_FILE" ]; then
  OAUTH_URL="$(cat "$OAUTH_URL_FILE")"
  echo
  echo "------------------------------------------------------------"
  echo "[ACTION REQUIRED] Open this URL in a browser on your machine:"
  echo "$OAUTH_URL"
  echo
  echo "After you approve, your browser will redirect to:"
  echo "  http://localhost:8976/oauth/callback?code=...&state=..."
  echo
  echo "Since this VM is headless, copy that entire callback URL"
  echo "from the browser and run (on this VM):"
  echo '  curl -fsSL "http://localhost:8976/oauth/callback?code=...&state=..."'
  echo
  echo "[i] Saved URL: $OAUTH_URL_FILE"
  echo "[i] Live log : $LOGIN_LOG"
  echo "[i] Login PID: ${WRANGLER_PID} (keeps listening on 8976)"
  echo "------------------------------------------------------------"
else
  echo "[!] Could not detect the OAuth URL yet."
  echo "    Tail the log for updates:  tail -f \"$LOGIN_LOG\""
  echo "    'wrangler login' is still running (PID: ${WRANGLER_PID})."
fi

echo "[*] Exiting Part 1 now. After you complete login, run Part 2."
exit 0
