# POSIX sh (no Bash-isms)
dmj_fetch_fresh() {
    # Usage: dmj_fetch_fresh URL DEST [PERM] [SHA256]
    #   URL     - source URL to download (HTTPS by default)
    #   DEST    - destination path including filename
    #   PERM    - optional file mode, e.g. 0755
    #   SHA256  - optional expected SHA-256 hex digest (with or without "sha256:" prefix)
    #
    # Environment variables (optional):
    #   DMJ_FETCH_CURL            path to curl (default: curl)
    #   DMJ_FETCH_CONNECT_TIMEOUT seconds (default: 10)
    #   DMJ_FETCH_MAX_TIME        seconds (default: 900)
    #   DMJ_FETCH_RETRIES         retry count (default: 5)
    #   DMJ_FETCH_HSTS_FILE       HSTS cache file (default: $HOME/.cache/dmj_fetch_hsts)
    #   DMJ_FETCH_INSECURE        set 1 to allow http / weak TLS (default: 0 = enforced HTTPS + HSTS)
    #   DMJ_FETCH_AUTH_HEADER     e.g. "Authorization: Bearer TOKEN" (optional)
    #   DMJ_FETCH_ALLOWED_HOSTS   comma-separated allowlist of hostnames (optional)

    # No global set/pipefail/traps here — do those in a subshell to avoid
    # side-effects on callers running strict mode.

    if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
        printf '%s\n' "usage: dmj_fetch_fresh URL DEST [PERM] [SHA256]" >&2
        return 64
    fi

    url=$1
    dest=$2
    perm=${3-}
    expected=${4-}

    # Validate permission (octal)
    if [ -n "$perm" ]; then
        case "$perm" in
            [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) : ;;
            *) printf '%s\n' "error: PERM must be octal like 0644 or 0755" >&2; return 64 ;;
        esac
    fi

    # Normalize expected checksum (allow "sha256:<hex>")
    if [ -n "$expected" ]; then
        case "$expected" in sha256:*) expected=${expected#sha256:} ;; esac
        expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
        case "$expected" in [0-9a-f][0-9a-f]*) : ;; *) printf '%s\n' "error: SHA256 must be hex" >&2; return 64 ;; esac
    fi

    # Optional host allowlist
    if [ -n "${DMJ_FETCH_ALLOWED_HOSTS-}" ]; then
        host=$(printf '%s' "$url" | sed -n 's,^[a-zA-Z][a-zA-Z0-9+.-]*://,,; s,/.*$,,; s,:.*$,,; p')
        allowed=0; oldIFS=$IFS; IFS=,
        for h in $DMJ_FETCH_ALLOWED_HOSTS; do [ "$host" = "$h" ] && { allowed=1; break; }; done
        IFS=$oldIFS
        [ $allowed -eq 1 ] || { printf '%s\n' "error: host '$host' not allowed"; return 65; }
    fi

    # Ensure destination directory
    dir=$(dirname "$dest"); base=$(basename "$dest"); [ -d "$dir" ] || mkdir -p "$dir"

    # Portable mktemp template in same dir (no GNU -p)
    umask 077
    tmp="${dir%/}/.${base}.tmp.XXXXXXXXXX"
    tmp=$(mktemp "$tmp") || { printf '%s\n' "error: mktemp failed in $dir" >&2; return 70; }

    # Do the risky work in a subshell with strict mode + cleanup trap,
    # so we don't alter caller shell options or traps.
    (
        set -eu
        # pipefail if available
        ( set -o pipefail ) >/dev/null 2>&1 && set -o pipefail || :
        trap 'rm -f "$tmp"' INT TERM HUP EXIT

        # Defaults
        curl_bin=${DMJ_FETCH_CURL-curl}
        : "${DMJ_FETCH_CONNECT_TIMEOUT:=10}"
        : "${DMJ_FETCH_MAX_TIME:=900}"
        : "${DMJ_FETCH_RETRIES:=5}"
        : "${DMJ_FETCH_INSECURE:=0}"
        : "${DMJ_FETCH_HSTS_FILE:=$HOME/.cache/dmj_fetch_hsts}"

        # Build argv for curl using "set --" (POSIX-safe)
        set -- "$curl_bin" \
            --fail --location \
            --connect-timeout "$DMJ_FETCH_CONNECT_TIMEOUT" \
            --max-time "$DMJ_FETCH_MAX_TIME" \
            --retry "$DMJ_FETCH_RETRIES" --retry-connrefused

        # Add retry-all-errors if supported by the installed curl (≥7.71.0)
        if "$curl_bin" --help all 2>/dev/null | grep -q -- "--retry-all-errors"; then
            set -- "$@" --retry-all-errors
        fi

        # Progress behavior; gate --no-progress-meter (≥7.67.0)
        if "$curl_bin" --help all 2>/dev/null | grep -q -- "--no-progress-meter"; then
            if [ -t 2 ]; then set -- "$@" --progress-bar; else set -- "$@" --no-progress-meter; fi
        else
            set -- "$@" -sS
        fi

        # Bypass caches & avoid content-encoding transformations
        set -- "$@" \
            -H "Cache-Control: no-cache, no-store" \
            -H "Pragma: no-cache" \
            -H "Expires: 0" \
            -H "Accept-Encoding: identity"

        # Optional Authorization (or any single custom header)
        [ -n "${DMJ_FETCH_AUTH_HEADER-}" ] && set -- "$@" -H "$DMJ_FETCH_AUTH_HEADER"

        # Enforce HTTPS; gate --hsts (≥7.74.0)
        if [ "$DMJ_FETCH_INSECURE" -eq 0 ]; then
            set -- "$@" --proto "=https" --proto-redir "=https" --tlsv1.2
            if "$curl_bin" --help all 2>/dev/null | grep -q -- "--hsts"; then
                set -- "$@" --hsts "$DMJ_FETCH_HSTS_FILE"
            fi
        fi

        # Output & URL
        set -- "$@" --output "$tmp" --url "$url"

        # Execute curl
        "$@"

        # Optional checksum verification
        if [ -n "$expected" ]; then
            if command -v sha256sum >/dev/null 2>&1; then
                got=$(sha256sum "$tmp" | awk '{print $1}')
            elif command -v shasum >/dev/null 2>&1; then
                got=$(shasum -a 256 "$tmp" | awk '{print $1}')
            elif command -v openssl >/dev/null 2>&1; then
                got=$(openssl dgst -sha256 "$tmp" | awk '{print $NF}' | tr 'A-F' 'a-f')
            else
                printf '%s\n' "error: no SHA-256 tool (sha256sum|shasum|openssl)" >&2; exit 69
            fi
            [ "$got" = "$expected" ] || {
                printf '%s\n' "error: checksum mismatch for %s" "$dest" >&2
                printf '  expected: %s\n' "$expected" >&2
                printf '  got:      %s\n' "$got" >&2
                exit 60
            }
        fi

        # Apply permission (set it on temp, then atomic rename)
        [ -n "$perm" ] && chmod "$perm" "$tmp"

        # Atomic install (rename on same FS; otherwise cp+rm)
        if mv -f "$tmp" "$dest" 2>/dev/null; then :; else
            cp "$tmp" "$dest" && rm -f "$tmp" || { printf '%s\n' "error: could not install $dest" >&2; exit 71; }
        fi

        trap - INT TERM HUP EXIT
    )
    return 0
}