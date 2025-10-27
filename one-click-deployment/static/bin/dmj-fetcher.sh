# Always download fresh; save exactly to the given DEST path;
# optionally chmod with PERMISSION like 0755; optionally verify SHA-256.
dmj_fetch_fresh() {
    # Usage: dmj_fetch_fresh URL DEST [PERM] [SHA256]
    dmj_url=$1
    dmj_dest=$2
    dmj_perm=$3
    dmj_sum=$4

    if [ -z "$dmj_url" ] || [ -z "$dmj_dest" ]; then
        echo "Usage: dmj_fetch_fresh URL DEST [PERMISSION] [SHA256]" >&2
        return 64
    fi

    dmj_dir=$(dirname "$dmj_dest")
    if [ ! -d "$dmj_dir" ]; then
        if ! mkdir -p "$dmj_dir"; then
            echo "Error: failed to create directory '$dmj_dir'." >&2
            return 1
        fi
    fi

    # --- Download fresh (no cache) with curl or wget ---
    if command -v curl >/dev/null 2>&1; then
        # Ask intermediaries to revalidate by sending request headers.
        # -f (fail on HTTP errors), -L (follow redirects), -sS (quiet but show errors)
        if ! curl -fLsS \
                 -H 'Cache-Control: no-cache' \
                 -H 'Pragma: no-cache' \
                 -o "$dmj_dest" \
                 "$dmj_url"
        then
            echo "Error: download failed (curl)." >&2
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        # --no-cache sends Cache-Control/Pragma directives to bypass caches.
        if ! wget --no-cache -O "$dmj_dest" "$dmj_url"; then
            echo "Error: download failed (wget)." >&2
            return 1
        fi
    else
        echo "Error: need either 'curl' or 'wget' installed." >&2
        return 127
    fi

    # --- Optional permission ---
    if [ -n "$dmj_perm" ]; then
        case "$dmj_perm" in
            [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7])
                if ! chmod "$dmj_perm" "$dmj_dest"; then
                    echo "Warning: failed to set permissions to $dmj_perm on '$dmj_dest'." >&2
                    return 1
                fi
                ;;
            *)
                echo "Warning: invalid permission '$dmj_perm' (expected 3–4 octal digits like 755 or 0755); ignoring." >&2
                ;;
        esac
    fi

    # --- Optional SHA-256 verification ---
    if [ -n "$dmj_sum" ]; then
        dmj_actual=""
        if command -v sha256sum >/dev/null 2>&1; then
            dmj_actual=$(sha256sum "$dmj_dest" | awk '{print $1}')
            dmj_tool="sha256sum"
        elif command -v shasum >/dev/null 2>&1; then
            dmj_actual=$(shasum -a 256 "$dmj_dest" | awk '{print $1}')
            dmj_tool="shasum -a 256"
        elif command -v openssl >/dev/null 2>&1; then
            dmj_actual=$(openssl dgst -sha256 "$dmj_dest" | awk '{print $NF}')
            dmj_tool="openssl dgst -sha256"
        else
            echo "Error: no SHA-256 tool found (need sha256sum, shasum, or openssl)." >&2
            return 127
        fi

        if [ "x$dmj_actual" != "x$dmj_sum" ]; then
            echo "ERROR: SHA-256 mismatch for '$dmj_dest'." >&2
            echo "       expected: $dmj_sum" >&2
            echo "       actual:   $dmj_actual  (via $dmj_tool)" >&2
            return 2
        fi
    fi

    echo "File downloaded from '$dmj_url' was successfully saved at '$dmj_dest'."
    ls -lh "$dmj_dest"
}
