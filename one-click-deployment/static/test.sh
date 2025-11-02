# shellcheck source=/dev/null
# . <(curl -fsSL --retry 6 --retry-all-errors --proto '=https' --tlsv1.2 -H 'Cache-Control: no-cache, no-store, must-revalidate' "https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/bin/dmj-fetcher.sh?_=$(date +%s)")
# Robust loader for dmj-fetcher (copy/paste as-is)
DMJ_FETCHER_URL="https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/bin/dmj-fetcher.sh"

tmp="$(mktemp)"
if curl -fsSL --retry 6 --retry-all-errors --proto '=https' --tlsv1.2 \
        -H 'Cache-Control: no-cache, no-store, must-revalidate' \
        "${DMJ_FETCHER_URL}?_=$(date +%s)" \
  | sed -e '1s/^\xEF\xBB\xBF//' -e 's/\r$//' > "$tmp"; then
  if bash -n "$tmp"; then
    # shellcheck source=/dev/null
    . "$tmp"
  else
    systemd-cat --identifier=dmj-fetcher --priority=err \
      <<<"[dmj-fetcher] syntax check failed for $DMJ_FETCHER_URL"
  fi
else
  systemd-cat --identifier=dmj-fetcher --priority=err \
    <<<"[dmj-fetcher] download failed for $DMJ_FETCHER_URL"
fi
rm -f "$tmp"

dmj_fetch_fresh "https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/modules/dmj-verify.sh.tmpl" "dmj-verify.sh"










# Version 2.7
#!/usr/bin/env bash
set -eu

# Fetch a fresh copy and source it
DMJ_FETCHER_URL='https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/bin/dmj-fetcher.sh'
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT INT TERM
# -f = fail on 4xx/5xx, -s = quiet, -S = still show errors, -L = follow redirects
curl -fLsS -L -H 'Cache-Control: no-cache' -o "$tmp" "$DMJ_FETCHER_URL"
. "$tmp"

# ---- Use it ----
# URL  DESTINATION        [PERMISSION] [SHA256]
# dmj_fetch_fresh "https://example.com/small.tar.gz" "/tmp/small.tar.gz"
# dmj_fetch_fresh "https://example.com/tool.sh" "/usr/local/bin/tool.sh" 0755
# dmj_fetch_fresh "https://example.com/app.bin" "/opt/app.bin" 0755 "0123abcd...<64-hex>..."
dmj_fetch_fresh "https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/modules/dmj-verify.sh.tmpl" "dmj-verify.sh"















# Version 2.8
DMJ_FETCHER_URL="https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/bin/dmj-fetcher.sh"
# curl -fsSL "$DMJ_FETCHER_URL" | sha256sum
DMJ_FETCHER_URL_SHA256=""
# Robust temp + cleanup (works even if we exit early)
tmp="$(mktemp -t dmj_fetcher.XXXXXXXX)" || { echo "mktemp failed" >&2; exit 70; }
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT

# Build curl with feature gating (older curl may lack some flags)
CURL=(curl -fsSL --retry 6 --proto '=https' --tlsv1.2 \
      -H 'Cache-Control: no-cache, no-store, must-revalidate')
if curl --help all 2>/dev/null | grep -q -- '--retry-all-errors'; then
  CURL+=('--retry-all-errors')
fi

# Fetch, strip UTF-8 BOM on first line and CRLF at EOLs (portable), then syntax-check
if "${CURL[@]}" "${DMJ_FETCHER_URL}?_=$(date +%s)" \
   | awk 'NR==1{sub(/^\xef\xbb\xbf/,"")} {sub(/\r$/,"")} {print}' >"$tmp"; then
  if bash -n "$tmp"; then
    # shellcheck source=/dev/null
    . "$tmp"
  else
    if command -v systemd-cat >/dev/null 2>&1; then
      systemd-cat --identifier=dmj-fetcher --priority=err \
        <<<"[dmj-fetcher] syntax check failed for $DMJ_FETCHER_URL"
    else
      logger -t dmj-fetcher -p user.err "[dmj-fetcher] syntax check failed for $DMJ_FETCHER_URL" 2>/dev/null || \
      echo "[dmj-fetcher] syntax check failed for $DMJ_FETCHER_URL" >&2
    fi
    exit 65
  fi
else
  if command -v systemd-cat >/dev/null 2>&1; then
    systemd-cat --identifier=dmj-fetcher --priority=err \
      <<<"[dmj-fetcher] download failed for $DMJ_FETCHER_URL"
  else
    logger -t dmj-fetcher -p user.err "[dmj-fetcher] download failed for $DMJ_FETCHER_URL" 2>/dev/null || \
    echo "[dmj-fetcher] download failed for $DMJ_FETCHER_URL" >&2
  fi
  exit 66
fi














# Version 2.9
# --- required: set this to your trusted hash (raw bytes of the URL target) ---
# Accepts 'sha256:<64-hex>' or '<64-hex>'
DMJ_FETCHER_URL_HASH="${DMJ_FETCHER_URL_HASH:-}"

DMJ_FETCHER_URL="https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/bin/dmj-fetcher.sh"

set -euo pipefail

# Robust temp + cleanup (works even if we exit early)
tmp="$(mktemp -t dmj_fetcher.XXXXXXXX)" || { echo "mktemp failed" >&2; exit 70; }
tmp_raw="$(mktemp -t dmj_fetcher_raw.XXXXXXXX)" || { echo "mktemp failed" >&2; exit 70; }
cleanup() { rm -f "$tmp" "$tmp_raw"; }
trap cleanup EXIT

# Build curl with feature gating (older curl may lack some flags)
CURL=(curl -fsSL --retry 6 --proto '=https' --tlsv1.2 \
      -H 'Cache-Control: no-cache, no-store, must-revalidate')
if curl --help all 2>/dev/null | grep -q -- '--retry-all-errors'; then
  CURL+=('--retry-all-errors')
fi

# Helper: log error via systemd-cat/logger/echo
_log_err() {
  local msg="$1"
  if command -v systemd-cat >/dev/null 2>&1; then
    systemd-cat --identifier=dmj-fetcher --priority=err <<<"[dmj-fetcher] $msg"
  else
    logger -t dmj-fetcher -p user.err "[dmj-fetcher] $msg" 2>/dev/null || echo "[dmj-fetcher] $msg" >&2
  fi
}

# --- Validate expected hash format early ---
if [ -z "${DMJ_FETCHER_URL_HASH:-}" ]; then
  _log_err "DMJ_FETCHER_URL_HASH is not set; refusing to run without an expected hash"
  exit 68
fi
expected="${DMJ_FETCHER_URL_HASH#sha256:}"
# strip any whitespace and normalize case
expected="$(printf '%s' "$expected" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
if ! printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$'; then
  _log_err "DMJ_FETCHER_URL_HASH must be a 64-hex SHA-256 (optionally prefixed with 'sha256:')"
  exit 68
fi

# --- Fetch the raw script bytes to tmp_raw (no normalization yet) ---
if ! "${CURL[@]}" -o "$tmp_raw" "${DMJ_FETCHER_URL}?_=$(date +%s)"; then
  _log_err "download failed for $DMJ_FETCHER_URL"
  exit 66
fi

# --- Compute SHA-256 of the raw download and compare ---
_calc_sha256() {
  # Prefer GNU coreutils sha256sum; fall back to shasum or OpenSSL
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$1" | awk '{print tolower($1)}'
  elif command -v openssl >/dev/null 2>&1; then
    # -r prints "<hash> <filename>" similar to sha256sum
    openssl dgst -sha256 -r -- "$1" | awk '{print tolower($1)}'
  else
    return 127
  fi
}

if ! actual="$(_calc_sha256 "$tmp_raw" 2>/dev/null)"; then
  _log_err "no SHA-256 tool found (need sha256sum, shasum, or openssl)"
  exit 69
fi

if [ "$actual" != "$expected" ]; then
  _log_err "authenticity of dmj-fetcher.sh could not be verified and hence no scripts will be downloaded"
  exit 67
fi

# --- Only after hash verification: normalize BOM/CRLF for portability ---
# (Hash is over RAW bytes; normalization affects only what we execute locally.)
awk 'NR==1{sub(/^\xef\xbb\xbf/,"")} {sub(/\r$/,"")} {print}' "$tmp_raw" >"$tmp"

# --- Syntax-check and source the verified script ---
if bash -n "$tmp"; then
  # shellcheck source=/dev/null
  . "$tmp"
else
  _log_err "syntax check failed for $DMJ_FETCHER_URL"
  exit 65
fi






# Version 3.0

#!/usr/bin/env bash
# Fail hard, and *propagate* ERR into functions/subshells/$(...)
set -Eeuo pipefail
set -o errtrace
# (Bash ≥4.4) make "set -e" apply inside command substitutions too
shopt -s inherit_errexit 2>/dev/null || true
umask 077
# Replace <commit> with the 40-hex commit SHA for the exact file version you hashed
DMJ_FETCHER_URL="https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/<commit>/one-click-deployment/static/bin/dmj-fetcher.sh"
DMJ_FETCHER_URL="https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/static/bin/dmj-fetcher.sh"
# calculate using: curl -fsSL "url" | sha256sum
DMJ_FETCHER_URL_HASH="sha256:hash"

t="$(mktemp -t dmj_fetcher.XXXXXXXX)" || { echo "mktemp failed" >&2; exit 70; }
trap 'rm -f "$t" "$t.n"' EXIT
e(){ m="[dmj-fetcher] $*"; command -v systemd-cat >/dev/null && systemd-cat --identifier=dmj-fetcher --priority=err <<<"$m" || logger -t dmj-fetcher -p user.err "$m" 2>/dev/null || echo "$m" >&2; }

C=(curl -fsSL --retry 6 --proto '=https' --tlsv1.2 -H 'Cache-Control: no-cache, no-store, must-revalidate'); curl --help all 2>/dev/null | grep -q -- '--retry-all-errors' && C+=('--retry-all-errors')
"${C[@]}" -o "$t" "${DMJ_FETCHER_URL}?_=$(date +%s)" || { e "download failed for $DMJ_FETCHER_URL"; exit 66; }

exp="${DMJ_FETCHER_URL_HASH#sha256:}"; exp="$(printf %s "$exp" | tr -d '[:space:]' | tr A-F a-f)"; printf %s "$exp" | grep -Eq '^[0-9a-f]{64}$' || { e "DMJ_FETCHER_URL_HASH must be 64-hex SHA-256"; exit 68; }
if command -v sha256sum >/dev/null; then act="$(sha256sum "$t" | awk '{print tolower($1)}')"
elif command -v shasum >/dev/null; then act="$(shasum -a 256 "$t" | awk '{print tolower($1)}')"
elif command -v openssl >/dev/null; then act="$(openssl dgst -sha256 -r "$t" | awk '{print tolower($1)}')"
else e "no SHA-256 tool found"; exit 69; fi
[ "$act" = "$exp" ] || { e "authenticity of dmj-fetcher.sh could not be verified and hence no scripts will be downloaded"; exit 67; }

awk 'NR==1{sub(/^\xef\xbb\xbf/,"")} {sub(/\r$/,"")} 1' "$t" >"$t.n" && mv "$t.n" "$t"
bash -n "$t" || { e "syntax check failed for $DMJ_FETCHER_URL"; exit 65; }
. "$t"
