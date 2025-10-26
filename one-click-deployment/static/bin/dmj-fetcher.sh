# modules/dmj-fetcher.sh.tmpl
# Guard against double-loading
if [[ "${_DMJ_FETCHER_V26:-0}" -eq 1 ]]; then return 0; fi
readonly _DMJ_FETCHER_V26=1
readonly _DMJ_FETCHER_TAG="dmj-fetcher"
readonly _DMJ_FETCHER_VERSION="2.6.0"

# ── internal defaults ─────────────────────────────────────────────────────────
__DMJ_CONNECT_TIMEOUT=10         # s
__DMJ_MAX_TIME=60                # s per transfer
__DMJ_RETRIES=6                  # curl retries (incl. connrefused/all-errors)
__DMJ_LOCK_WAIT=20               # s
__DMJ_MAX_BYTES=$((50*1024*1024))# payload cap (0 = unlimited)
__DMJ_ALLOW_INSECURE=0           # 1 = allow http
__DMJ_PINNEDPUBKEY=""            # curl SPKI pin (sha256//...) (optional)
__DMJ_TLS_MIN="1.2"              # min TLS; set empty to disable constraint
__DMJ_TLS_MAX=""                 # max TLS (e.g., 1.3)
__DMJ_ALLOW_HTML=0               # block HTML payloads by default
__DMJ_EXPECT_TYPE=""             # optional Content-Type regex
__DMJ_BACKUP_ON_CHANGE=0         # 1 = keep .bak on change
__DMJ_UNIT_NAME="dmj-signer.service"  # visible in journal if sourced by that unit

# ── logging & helpers ─────────────────────────────────────────────────────────
__dmj_log_to_console(){ local L="$1"; shift
  if [[ -e /proc/$$/fd/3 ]]; then printf "%s\n" "[$_DMJ_FETCHER_TAG][$L] $*" >&3
  else printf "%s\n" "[$_DMJ_FETCHER_TAG][$L] $*" >&2; fi; }
__dmj_log_to_journal(){ local pri="$1"; shift; local msg="$*"
  if command -v systemd-cat >/dev/null 2>&1; then
    systemd-cat --identifier="$_DMJ_FETCHER_TAG" --priority="$pri" <<<"$msg" 2>/dev/null || true
  elif command -v logger >/dev/null 2>&1; then
    logger -t "$_DMJ_FETCHER_TAG" -p "user.$pri" -- "$msg" 2>/dev/null || true
  fi; }
__dmj_log(){ local p="$1"; shift; __dmj_log_to_console "$p" "$*"; __dmj_log_to_journal "$p" "$*"; }
__dmj_sudo(){ if command -v sudo >/dev/null 2>&1 && [ "${EUID:-$(id -u)}" -ne 0 ]; then sudo "$@"; else "$@"; fi; }
__dmj_where(){ local src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"; local line="${BASH_LINENO[0]:-0}"; printf '%s:%s' "$src" "$line"; }

# Detect file "kind": script/unit/nginx/other. Allow per-file override by header.
__dmj_detect_kind(){
  local f="$1"
  # explicit headers override auto-detect:
  if grep -qE '^\s*#\s*dmj:template\s*=\s*off\b' "$f" 2>/dev/null; then echo "no-template"; return; fi
  if grep -qE '^\s*#\s*dmj:template\s*=\s*on\b'  "$f" 2>/dev/null; then echo "force-template"; return; fi
  # script?
  if head -n1 "$f" 2>/dev/null | grep -qiE '^#!.*\b(bash|sh|dash|ksh|zsh|python|node)\b'; then echo "script"; return; fi
  # systemd unit?
  if grep -qE '^\s*\[(Unit|Service|Install|Socket|Timer|Path|Mount|Target|Slice|Scope)\]\s*$' "$f" 2>/dev/null; then echo "unit"; return; fi
  # nginx (heuristic): server { / http { / upstream {, etc.
  if grep -qE '^\s*(server|http|upstream)\s*\{' "$f" 2>/dev/null; then echo "nginx"; return; fi
  echo "other"
}

# Extract variable names that are *defined inside the file* so we do not substitute them.
# Matches: VAR=, export VAR=, local VAR=, declare VAR= ... (UPPERCASE only)
__dmj_protected_vars(){
  local f="$1"
  grep -oE '^\s*(export|local|declare([[:space:]]+-[A-Za-z])+)?[[:space:]]*([A-Z_][A-Z0-9_]*)[[:space:]]*=' "$f" 2>/dev/null \
    | sed -E 's/.*\b([A-Z_][A-Z0-9_]*)\s*=.*/\1/' \
    | sort -u
}

# Replace ${VAR} and $VAR (UPPERCASE) with shell values; preserve \$…; skip VARs we "protect".
__dmj_render_template(){
  local in="$1" out="$2"
  local tmpw="$in.work" tmp1="$in.render"
  __dmj_sudo sed -e 's/\\\$/__DMJ_ESC_DOLLAR__/g' "$in" > "$tmpw" 2>/dev/null || cp -f "$in" "$tmpw"
  local vars prot v val esc
  # Candidates found in text:
  vars="$(grep -oE '\$\{[A-Z_][A-Z0-9_]*\}|\$[A-Z_][A-Z0-9_]*' "$tmpw" \
           | sed -E 's/^\$\{([A-Z_][A-Z0-9_]*)\}$/\1/; s/^\$([A-Z_][A-Z0-9_]*)$/\1/' \
           | sort -u || true)"
  # Vars protected by in-file definitions:
  readarray -t prot < <(__dmj_protected_vars "$tmpw" || true)

  __dmj_sudo cp -f "$tmpw" "$tmp1" 2>/dev/null || { __dmj_sudo mv -f "$tmpw" "$out"; return 0; }

  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    # skip if defined inside the file
    if printf '%s\n' "${prot[@]}" | grep -qx "$v" 2>/dev/null; then continue; fi
    # only substitute if the variable exists in the *current* shell (even if empty)
    if [[ -n ${!v+x} ]]; then
      val="${!v}"
      esc="$(printf '%s' "$val" | sed -e 's/[\/&\\]/\\&/g')"
      # ${VAR}
      __dmj_sudo sed -E -e "s/\\$\\{${v}\\}/${esc}/g" -i "$tmp1" 2>/dev/null || true
      # $VAR followed by non-word boundary or EOL
      __dmj_sudo sed -E -e "s/\\$${v}([^A-Za-z0-9_]|$)/${esc}\1/g" -i "$tmp1" 2>/dev/null || true
    fi
  done <<< "$vars"

  __dmj_sudo sed -e 's/__DMJ_ESC_DOLLAR__/\$/g' -i "$tmp1" 2>/dev/null || true
  __dmj_sudo mv -f "$tmp1" "$out" 2>/dev/null || __dmj_sudo mv -f "$tmpw" "$out"
  __dmj_sudo rm -f "$tmpw" 2>/dev/null || true
  return 0
}

# Core: always-fresh, atomic, ACL-friendly fetch-and-install with smart templating
# Usage: dmj_fetch_fresh URL DEST [MODE] [EXPECTED_SHA256]
dmj_fetch_fresh(){
  ( set +e; set +o pipefail; trap - ERR; umask 077
    local url="${1:-}" dest_in="${2:-}" mode="${3:-}" expect_sha="${4:-}"
    if [[ -z "$url" || -z "$dest_in" ]]; then
      __dmj_log err "$(__dmj_where) usage: dmj_fetch_fresh <url> <dest> [mode] [sha256]"; exit 0; fi

    # If DEST is a dir or ends with '/', append basename
    local dest="$dest_in"
    if [[ -d "$dest_in" || "$dest_in" == */ ]]; then
      local base_from_url; base_from_url="$(basename "${url%%\?*}")"
      dest="${dest_in%/}/${base_from_url}"
    fi

    # HTTPS policy (unless explicitly allowed)
    if [[ "$__DMJ_ALLOW_INSECURE" != "1" && "$url" != https://* ]]; then
      __dmj_log warning "$(__dmj_where) blocked non-HTTPS URL: $url"; exit 0; fi

    # Prepare paths + lock
    local dir base; dir="$(dirname -- "$dest")"; base="$(basename -- "$dest")"
    __dmj_sudo install -d -m 0755 "$dir" 2>/dev/null || true
    local lockdir="/var/lock/dmj"; __dmj_sudo install -d -m 0755 "$lockdir" 2>/dev/null || true
    local h; h="$(printf '%s' "$dest" | (sha256sum 2>/dev/null || shasum -a 256 2>/dev/null || cksum) | awk '{print $1}')"
    local lock="${lockdir}/${h}.lock" lockfd=217
    if command -v flock >/dev/null 2>&1; then eval "exec ${lockfd}>'$lock'"; flock -w "$__DMJ_LOCK_WAIT" "${lockfd}" || { __dmj_log warning "$(__dmj_where) lock timeout; skipped $dest"; exit 0; }; fi

    # Stage temp (so default ACLs apply) + fetch fresh
    local tmp headers ts url_busted http_code fetch_rc=0
    tmp="$(__dmj_sudo mktemp -p "$dir" ".${base}.tmp.XXXXXXXX")" || { __dmj_log err "$(__dmj_where) mktemp failed in $dir"; exit 0; }
    headers="${tmp}.hdr"; ts="$(date +%s%N)"; [[ "$url" == *\?* ]] && url_busted="${url}&_=${ts}" || url_busted="${url}?_=${ts}"

    if command -v curl >/dev/null 2>&1; then
      local args=()
      args+=(-sSL --compressed -D "$headers" -o "$tmp" -w '%{http_code}')
      args+=(--connect-timeout "$__DMJ_CONNECT_TIMEOUT" --max-time "$__DMJ_MAX_TIME")
      args+=(--retry "$__DMJ_RETRIES" --retry-all-errors --retry-connrefused)  # robust retries :contentReference[oaicite:2]{index=2}
      [[ "$__DMJ_ALLOW_INSECURE" != "1" ]] && args+=(--proto '=https' --proto-redir '=https')
      [[ -n "$__DMJ_TLS_MIN" ]] && args+=(--tlsv"$__DMJ_TLS_MIN"); [[ -n "$__DMJ_TLS_MAX" ]] && args+=(--tls-max "$__DMJ_TLS_MAX")
      [[ -n "$__DMJ_PINNEDPUBKEY" ]] && args+=(--pinnedpubkey "$__DMJ_PINNEDPUBKEY") # SPKI pin :contentReference[oaicite:3]{index=3}
      args+=(-H 'Cache-Control: no-cache, no-store, must-revalidate' -H 'Pragma: no-cache' -H 'Accept: */*')
      http_code="$(__dmj_sudo curl "${args[@]}" "$url_busted" 2>/dev/null || echo '000')"; fetch_rc=$?
    elif command -v wget >/dev/null 2>&1; then
      __dmj_sudo wget -q -O "$tmp" --server-response --timeout="$__DMJ_MAX_TIME" --tries=$((__DMJ_RETRIES+1)) \
        --header='Cache-Control: no-cache, no-store, must-revalidate' --header='Pragma: no-cache' "$url_busted" 2>"$headers"; fetch_rc=$?
      http_code="$(grep -Eo 'HTTP/[0-9.]+[[:space:]]+[0-9]+' "$headers" | tail -1 | awk '{print $2}' 2>/dev/null || echo 000)"
      [[ -z "$http_code" ]] && http_code="000"
    else
      __dmj_log err "$(__dmj_where) neither curl(1) nor wget(1) found"; __dmj_sudo rm -f "$tmp" "$headers" || true; exit 0
    fi

    # HTTP decisioning (404/non-200 => no update)
    if [[ "$http_code" == "404" ]]; then __dmj_log warning "$(__dmj_where) $dest not updated (HTTP 404)"; __dmj_sudo rm -f "$tmp" "$headers" || true; exit 0; fi
    if [[ "$http_code" != "200" || "$fetch_rc" -ne 0 ]]; then __dmj_log warning "$(__dmj_where) $dest not updated (HTTP ${http_code}, rc=${fetch_rc})"; __dmj_sudo rm -f "$tmp" "$headers" || true; exit 0; fi

    # sanity: non-empty; content-type checks; size cap
    if ! __dmj_sudo test -s "$tmp"; then __dmj_log warning "$(__dmj_where) $dest not updated (empty payload)"; __dmj_sudo rm -f "$tmp" "$headers" || true; exit 0; fi
    local ct; ct="$(grep -i '^content-type:' "$headers" | tail -1 | tr -d '\r' | awk -F: '{print $2}' | xargs || true)"
    if echo "$ct" | grep -qiE 'text/html|application/xhtml|text/xml'; then
      if [[ "$__DMJ_ALLOW_HTML" != "1" ]]; then __dmj_log warning "$(__dmj_where) looks like HTML (${ct}); skip $dest"; __dmj_sudo rm -f "$tmp" "$headers" || true; exit 0; fi
    fi
    if [[ -n "$__DMJ_EXPECT_TYPE" ]] && ! echo "$ct" | grep -qiE "$__DMJ_EXPECT_TYPE"; then
      __dmj_log warning "$(__dmj_where) unexpected Content-Type '${ct}' (wanted /${__DMJ_EXPECT_TYPE}/); skip $dest"
      __dmj_sudo rm -f "$tmp" "$headers" || true; exit 0
    fi
    if [[ "$__DMJ_MAX_BYTES" -gt 0 ]]; then
      local sz; sz="$(__dmj_sudo wc -c < "$tmp" | tr -d '[:space:]' || echo 0)"
      if [[ "$sz" -gt "$__DMJ_MAX_BYTES" ]]; then __dmj_log warning "$(__dmj_where) payload too large (${sz} > ${__DMJ_MAX_BYTES}); skip $dest"; __dmj_sudo rm -f "$tmp" "$headers" || true; exit 0; fi
    fi

    # optional checksum
    if [[ -n "$expect_sha" ]]; then
      local got_sha=""
      if command -v sha256sum >/dev/null 2>&1; then got_sha="$(__dmj_sudo sha256sum "$tmp" | awk '{print $1}')"
      elif command -v shasum >/dev/null 2>&1; then got_sha="$(__dmj_sudo shasum -a 256 "$tmp" | awk '{print $1}')"; fi
      if [[ -n "$got_sha" && "${got_sha,,}" != "${expect_sha,,}" ]]; then __dmj_log warning "$(__dmj_where) checksum mismatch; skip $dest"; __dmj_sudo rm -f "$tmp" "$headers" || true; exit 0; fi
    fi

    # ── Smart template mode ──
    local kind; kind="$(__dmj_detect_kind "$tmp")"
    local rendered="$tmp"
    case "$kind" in
      no-template) : ;;                             # honor explicit off
      script)      : ;;                             # do NOT template scripts by default
      force-template|unit|nginx|other)
        # for nginx, escaped \$… are preserved; for all, in-file defined vars are protected
        local rfile; rfile="${tmp}.out"
        __dmj_render_template "$tmp" "$rfile" || true
        rendered="$rfile"
        ;;
    esac

    # No-op if identical (compare post-render)
    if [[ -f "$dest" ]] && __dmj_sudo cmp -s "$rendered" "$dest" 2>/dev/null; then
      __dmj_log info "$(__dmj_where) up-to-date: $dest"
      __dmj_sudo rm -f "$tmp" "$headers" "${tmp}.out" 2>/dev/null || true
      exit 0
    fi

    # optional backup
    if [[ -f "$dest" && "$__DMJ_BACKUP_ON_CHANGE" == "1" ]]; then
      local tsb; tsb="$(date +%Y%m%dT%H%M%S)"; __dmj_sudo cp -a -- "$dest" "${dest}.bak.${tsb}" 2>/dev/null || true
    fi

    # preserve owner:group if replacing an existing file
    local own="" grp=""
    if [[ -f "$dest" ]] && command -v stat >/dev/null 2>&1; then
      own="$(__dmj_sudo stat -c '%u' "$dest" 2>/dev/null || echo '')"
      grp="$(__dmj_sudo stat -c '%g' "$dest" 2>/dev/null || echo '')"
    fi

    # Atomic publish (same-dir rename → atomic on same FS) :contentReference[oaicite:4]{index=4}
    if ! __dmj_sudo mv -f -T -- "$rendered" "$dest" 2>/dev/null; then
      __dmj_sudo mv -f -- "$rendered" "$dest" 2>/dev/null || { __dmj_log err "$(__dmj_where) failed to install $dest"; __dmj_sudo rm -f "$tmp" "$headers" "${tmp}.out" 2>/dev/null || true; exit 0; }
    fi

    # restore owner/group if captured
    if [[ -n "$own" && -n "$grp" ]]; then __dmj_sudo chown "$own:$grp" "$dest" 2>/dev/null || true; fi

    # apply explicit mode or keep ACL-driven defaults; ensure ACL mask lets named entries take effect (m::rw) :contentReference[oaicite:5]{index=5}
    if [[ -n "$mode" ]]; then __dmj_sudo chmod "$mode" "$dest" 2>/dev/null || true
    else if command -v getfacl >/dev/null 2>&1 && command -v setfacl >/dev/null 2>&1; then
           if getfacl -p -d "$dir" 2>/dev/null | grep -q '^default:'; then __dmj_sudo setfacl -m m::rw "$dest" 2>/dev/null || true; fi
         fi
    fi

    # SELinux relabel + fsync
    command -v restorecon >/dev/null 2>&1 && __dmj_sudo restorecon -F "$dest" 2>/dev/null || true
    if sync --help 2>&1 | grep -q -- ' -f'; then __dmj_sudo sync -f "$dest" 2>/dev/null || true; else sync 2>/dev/null || true; fi

    __dmj_sudo rm -f "$tmp" "$headers" "${tmp}.out" 2>/dev/null || true
    __dmj_log notice "$(__dmj_where) updated: $dest"
    exit 0
  ); return 0
}
