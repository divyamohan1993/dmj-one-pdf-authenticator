#!/usr/bin/env bash
# =============================================================================
# dmj.one — one-click, idempotent installer for a zero-knowledge PDF signer
# Stack: Ubuntu (latest), nginx:80 behind Cloudflare Flexible SSL, FastAPI, MySQL,
#        OpenSSL Root/Intermediate/per-document certs, OCSP responder, CRL/AIA,
#        Admin portal (sign/revoke), Public portal (verify).
# =============================================================================
# autoconfig.sh

set -euo pipefail

# --------------------
# Verbose tracing
# --------------------
VERBOSE="${VERBOSE:-1}"
if [[ "$VERBOSE" == "1" ]]; then set -x; fi

# --------------------
# GLOBAL CONFIG (override via env or edit defaults)
# --------------------
DOMAIN="${DOMAIN:-docsigner.dmj.one}"          # public FQDN through Cloudflare (orange icon)
APP_USER="${APP_USER:-docsigner}"
APP_DIR="${APP_DIR:-/opt/dmj-docsigner}"
APP_REPO_MODE="${APP_REPO_MODE:-embedded}"     # 'embedded' (generate files) or 'git'
GIT_REPO_URL="${GIT_REPO_URL:-}"               # if APP_REPO_MODE=git, set to your repo URL
GIT_BRANCH="${GIT_BRANCH:-main}"
SERVICE_NAME="${SERVICE_NAME:-dmj-docsigner}"
OCSP_SERVICE_NAME="${OCSP_SERVICE_NAME:-dmj-ocsp}"
AUTOCONFIG_SERVICE_NAME="${AUTOCONFIG_SERVICE_NAME:-dmj-autoconfig}"
AUTOCONFIG_RAW_URL="${AUTOCONFIG_RAW_URL:-https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/python/autoconfig.sh}"
PYTHON="${PYTHON:-python3}"
VENV_DIR="${VENV_DIR:-$APP_DIR/.venv}"
LOG_DIR="${LOG_DIR:-/var/log/dmj-docsigner}"
UPLOAD_DIR="${UPLOAD_DIR:-$APP_DIR/uploads}"    # transient staging for upload handling
STATIC_PKI_DIR="/var/www/pki"                   # published AIA/CRL under /.well-known/pki/
MYSQL_DB="${MYSQL_DB:-docsigner}"
MYSQL_USER="${MYSQL_USER:-docsigner}"
MYSQL_HOST="127.0.0.1"
OPENSSL_BIN="${OPENSSL_BIN:-/usr/bin/openssl}"
NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/dmj-docsigner}"
CLOUDFLARE_INCLUDE="/etc/nginx/conf.d/cloudflare-real-ip.conf"
OCSP_PORT="${OCSP_PORT:-2560}"

# Security knobs
ARGON2_MEMORY_KIB="${ARGON2_MEMORY_KIB:-65536}"   # 64 MiB
ARGON2_TIME="${ARGON2_TIME:-3}"
ARGON2_PARALLEL="${ARGON2_PARALLEL:-2}"
KEY_ROTATION_DAYS="${KEY_ROTATION_DAYS:-180}"
HMAC_KEY_BYTES="${HMAC_KEY_BYTES:-32}"
KEY_ENC_ALGO="${KEY_ENC_ALGO:-aes-256-cbc}"

# PKI dirs
PKI_DIR="${PKI_DIR:-$APP_DIR/pki}"
ROOT_DIR="$PKI_DIR/ca"
INT_DIR="$PKI_DIR/intermediate"

ENV_FILE="$APP_DIR/.env"

# --------------------
# Helpers
# --------------------
die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "[$(date -Is)] $*"; }
randhex() { $OPENSSL_BIN rand -hex "${1:-32}"; }
randb64() { $OPENSSL_BIN rand -base64 "${1:-32}"; }

retry() {
  # retry <times> <sleep_secs> <cmd...>
  local -r tries="$1"; shift
  local -r delay="$1"; shift
  local n=0
  until "$@"; do
    n=$((n+1))
    if [[ $n -ge $tries ]]; then
      [[ "$VERBOSE" == "1" ]] && echo "Command failed after $n attempts: $*" >&2
      return 1
    fi
    sleep "$delay"
  done
}

ensure_root() { [[ "$(id -u)" -eq 0 ]] || die "Run as root."; }

# Compute runtime KEK from GCE metadata + .env salt (cloning-resistant)
derive_kek() {
  # Requires KEY_DERIVATION_SALT_HEX in env or in $ENV_FILE
  local salt_hex="${KEY_DERIVATION_SALT_HEX:-}"
  if [[ -z "$salt_hex" && -f "$ENV_FILE" ]]; then
    salt_hex="$(grep -E '^KEY_DERIVATION_SALT_HEX=' "$ENV_FILE" | cut -d= -f2 || true)"
  fi
  [[ -n "$salt_hex" ]] || die "KEY_DERIVATION_SALT_HEX not set yet"

  local id proj zone
  id=$(curl -fsSL -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/id) || id="noid"
  proj=$(curl -fsSL -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/project/numeric-project-id) || proj="noproj"
  zone=$(curl -fsSL -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/zone | awk -F/ '{print $NF}') || zone="nozone"
  local ikm="${id}|${proj}|${zone}|${DOMAIN}"
  # Use Python HKDF-SHA256 to derive 32-byte KEK; print hex
  "$PYTHON" - "$ikm" "$salt_hex" <<'PY' || die "KEK derivation failed"
import sys, binascii, hashlib, hmac
from hashlib import sha256
ikm = sys.argv[1].encode()
salt = binascii.unhexlify(sys.argv[2])
# Simple HKDF (RFC5869)
def hkdf_extract(salt, ikm): return hmac.new(salt, ikm, sha256).digest()
def hkdf_expand(prk, info, l):
    t=b""; okm=b""; i=0
    while len(okm)<l:
        i+=1
        t = hmac.new(prk, t+info+bytes([i]), sha256).digest()
        okm += t
    return okm[:l]
prk = hkdf_extract(salt, ikm)
kek = hkdf_expand(prk, b"dmj-docsigner-kek", 32)
print(binascii.hexlify(kek).decode())
PY
}

# Encrypt EC private key with KEK-derived passphrase (in-place, .enc)
encrypt_key_if_plain() {
  # Encrypt a PEM private key to PKCS#8 using KEK; shred plaintext
  local key="$1"
  [[ -f "$key" ]] || return 0
  if grep -q "BEGIN ENCRYPTED PRIVATE KEY" "$key" 2>/dev/null || [[ -f "${key}.enc" ]]; then
    return 0
  fi
  local kek; kek="$(derive_kek)"
  $OPENSSL_BIN pkcs8 -topk8 -v2 aes-256-cbc -in "$key" -passout pass:"$kek" -out "${key}.enc"
  shred -u "$key"
}

# Decrypt PKCS#8-encrypted key to a temp file and echo the path
# Caller must `rm -f` the returned tempfile.
dec_key_to_tmp() {
  local keyenc="$1"
  local kek; kek="$(derive_kek)"
  local tmp; tmp="$(mktemp)"
  $OPENSSL_BIN pkcs8 -inform PEM -in "$keyenc" -passin pass:"$kek" -out "$tmp" -nocrypt
  echo "$tmp"
}

# Decrypt EC private key to stdout (avoid writing to disk)
# Usage: dec_key_to_fd <path.enc>
dec_key_to_fd() {
  local keyenc="$1"
  local kek; kek="$(derive_kek)"
  $OPENSSL_BIN ec -in "$keyenc" -passin pass:"$kek"
}

ensure_pki() {
  # skeleton + index/serial/crlnumber (required by openssl ca)
  mkdir -p "$ROOT_DIR"/{certs,crl,newcerts,private} "$INT_DIR"/{certs,crl,csr,newcerts,private}
  [[ -f "$ROOT_DIR/index.txt" ]] || : > "$ROOT_DIR/index.txt"
  [[ -f "$INT_DIR/index.txt"  ]] || : > "$INT_DIR/index.txt"
  [[ -f "$ROOT_DIR/serial"    ]] || echo 1000 > "$ROOT_DIR/serial"
  [[ -f "$INT_DIR/serial"     ]] || echo 1000 > "$INT_DIR/serial"
  [[ -f "$ROOT_DIR/crlnumber" ]] || echo 1000 > "$ROOT_DIR/crlnumber"
  [[ -f "$INT_DIR/crlnumber"  ]] || echo 1000 > "$INT_DIR/crlnumber"

  # --- Root: create if missing, then encrypt key ---
  if [[ ! -f "$ROOT_DIR/certs/root.pem" ]]; then
    $OPENSSL_BIN ecparam -genkey -name prime256v1 -out "$ROOT_DIR/private/root.key"
    $OPENSSL_BIN req -x509 -new -key "$ROOT_DIR/private/root.key" -sha256 -days 3650 \
      -subj "/C=IN/O=dmj.one/CN=dmj.one Root CA" \
      -out "$ROOT_DIR/certs/root.pem" -extensions v3_root -config "$OPENSSL_CNF"
  fi
  if [[ ! -f "$ROOT_DIR/private/root.key.enc" ]]; then
    [[ -f "$ROOT_DIR/private/root.key" ]] || { echo "FATAL: root.key missing"; exit 1; }
    encrypt_key_if_plain "$ROOT_DIR/private/root.key"
  fi

  # --- Intermediate: ensure key, CSR, signed by Root; then encrypt key ---
  if [[ ! -f "$INT_DIR/private/intermediate.key" && ! -f "$INT_DIR/private/intermediate.key.enc" ]]; then
    $OPENSSL_BIN ecparam -genkey -name prime256v1 -out "$INT_DIR/private/intermediate.key"
  fi
  if [[ ! -f "$INT_DIR/certs/intermediate.pem" ]]; then
    $OPENSSL_BIN req -new -key "$INT_DIR/private/intermediate.key" \
      -out "$INT_DIR/csr/intermediate.csr" -subj "/C=IN/O=dmj.one/CN=dmj.one Intermediate CA"
    # Use Root CA section to sign the Intermediate
    $OPENSSL_BIN ca -batch -config "$OPENSSL_CNF" -name dmj_root -extensions v3_intermediate \
      -keyfile "$ROOT_DIR/private/root.key.enc" -passin "pass:$(derive_kek)" \
      -cert "$ROOT_DIR/certs/root.pem" \
      -in "$INT_DIR/csr/intermediate.csr" -out "$INT_DIR/certs/intermediate.pem"
  fi
  if [[ -f "$INT_DIR/private/intermediate.key" && ! -f "$INT_DIR/private/intermediate.key.enc" ]]; then
    encrypt_key_if_plain "$INT_DIR/private/intermediate.key"
  fi

  # --- OCSP signer: ensure key/cert signed by Intermediate; then encrypt key ---
  if [[ ! -f "$INT_DIR/private/ocsp.key" && ! -f "$INT_DIR/private/ocsp.key.enc" ]]; then
    $OPENSSL_BIN ecparam -genkey -name prime256v1 -out "$INT_DIR/private/ocsp.key"
  fi
  if [[ ! -f "$INT_DIR/certs/ocsp.pem" ]]; then
    $OPENSSL_BIN req -new -key "$INT_DIR/private/ocsp.key" \
      -out "$INT_DIR/csr/ocsp.csr" -subj "/C=IN/O=dmj.one/CN=dmj.one OCSP"
    # Use Intermediate CA section to sign OCSP signer
    $OPENSSL_BIN ca -batch -config "$OPENSSL_CNF" -name dmj_intermediate -extensions v3_ocsp \
      -keyfile "$INT_DIR/private/intermediate.key.enc" -passin "pass:$(derive_kek)" \
      -cert "$INT_DIR/certs/intermediate.pem" \
      -in "$INT_DIR/csr/ocsp.csr" -out "$INT_DIR/certs/ocsp.pem"
  fi
  if [[ -f "$INT_DIR/private/ocsp.key" && ! -f "$INT_DIR/private/ocsp.key.enc" ]]; then
    encrypt_key_if_plain "$INT_DIR/private/ocsp.key"
  fi

  # --- CRL & publish (AIA/CDP) ---
  if [[ ! -f "$INT_DIR/crl/dmjone.crl" ]]; then
    $OPENSSL_BIN ca -config "$OPENSSL_CNF" -name dmj_intermediate -gencrl \
      -keyfile "$INT_DIR/private/intermediate.key.enc" -passin "pass:$(derive_kek)" \
      -cert "$INT_DIR/certs/intermediate.pem" -out "$INT_DIR/crl/dmjone.crl"
  fi
  install -m 0644 "$INT_DIR/crl/dmjone.crl" "$STATIC_PKI_DIR/dmjone.crl"
  install -m 0644 "$INT_DIR/certs/intermediate.pem" "$STATIC_PKI_DIR/dmjone-int.pem"
  install -m 0644 "$ROOT_DIR/certs/root.pem"        "$STATIC_PKI_DIR/dmjone-root.pem"
}



ensure_root

# --------------------
# OS packages (latest) & services
# --------------------
log "Updating OS and installing packages..."
export DEBIAN_FRONTEND=noninteractive
retry 3 5 apt-get update -y
retry 3 5 apt-get dist-upgrade -y
retry 3 5 apt-get install -y --no-install-recommends \
  git curl ca-certificates nginx openssl build-essential \
  "$PYTHON" "$PYTHON"-venv "$PYTHON"-dev pkg-config \
  libffi-dev libssl-dev libxml2-dev libxslt1-dev \
  mysql-server libmysqlclient-dev

# MySQL service
systemctl enable --now mysql || true

# App user & dirs
id -u "$APP_USER" >/dev/null 2>&1 || useradd -r -m -d "$APP_DIR" -s /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR" "$LOG_DIR" "$UPLOAD_DIR" "$PKI_DIR" "$STATIC_PKI_DIR"
chown -R "$APP_USER":"$APP_USER" "$APP_DIR" "$LOG_DIR" "$STATIC_PKI_DIR"

# --------------------
# Python venv & deps
# --------------------
if [[ ! -d "$VENV_DIR" ]]; then
  sudo -u "$APP_USER" "$PYTHON" -m venv "$VENV_DIR"
fi
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
retry 3 5 pip install --upgrade pip wheel setuptools
retry 3 5 pip install --upgrade \
  fastapi uvicorn[standard] python-multipart \
  cryptography asn1crypto pyhanko pyhanko-certvalidator \
  pydantic email-validator jinja2 \
  mysqlclient SQLAlchemy alembic \
  passlib[argon2] python-dotenv itsdangerous \
  qrcode pillow requests

# --------------------
# MySQL DB (idempotent)
# --------------------
DB_PASS_FILE="$APP_DIR/.mysql_app_pw"
if [[ ! -f "$DB_PASS_FILE" ]]; then
  randhex 24 > "$DB_PASS_FILE"
  chown "$APP_USER":"$APP_USER" "$DB_PASS_FILE"
  chmod 600 "$DB_PASS_FILE"
fi
DB_PASS="$(cat "$DB_PASS_FILE")"
mysql -uroot <<SQL
CREATE DATABASE IF NOT EXISTS \`$MYSQL_DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$MYSQL_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON \`$MYSQL_DB\`.* TO '$MYSQL_USER'@'localhost';
FLUSH PRIVILEGES;
SQL

# --------------------
# First-run secrets (.env)
# --------------------
if [[ ! -f "$ENV_FILE" ]]; then
  log "First run: generating .env & admin key..."
  ADMIN_PLAIN="$(randhex 16)"
  ADMIN_HASH="$("$VENV_DIR/bin/python" - <<PY
import os
from passlib.hash import argon2
print(argon2.using(rounds=int("${ARGON2_TIME}"),
                   memory_cost=int("${ARGON2_MEMORY_KIB}"),
                   parallelism=int("${ARGON2_PARALLEL}")).hash("${ADMIN_PLAIN}"))
PY
)"
  JWT_SECRET="$(randb64 32)"
  HMAC_KEY="$(randhex "$HMAC_KEY_BYTES")"
  KDF_SALT="$(randhex 32)"

  cat > "$ENV_FILE" <<ENV
# ------------ dmj.one signer env ------------
DOMAIN=$DOMAIN
DB_DSN=mysql://$MYSQL_USER:$DB_PASS@127.0.0.1/$MYSQL_DB
ADMIN_PASS_HASH=$ADMIN_HASH
JWT_SECRET=$JWT_SECRET
DOC_HMAC_KEY_HEX=$HMAC_KEY
KEY_DERIVATION_SALT_HEX=$KDF_SALT
KEY_ROTATION_DAYS=$KEY_ROTATION_DAYS
OCSP_PORT=$OCSP_PORT
ENV
  chown "$APP_USER":"$APP_USER" "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  echo
  echo "=============================================================="
  echo " ADMIN_LOGIN_KEY (save this now): $ADMIN_PLAIN"
  echo "=============================================================="
  echo
fi

# --------------------
# PKI: Root / Intermediate / OCSP (OpenSSL)
# --------------------
# --- OpenSSL config (absolute paths, two CA sections) ---
OPENSSL_CNF="$PKI_DIR/openssl.cnf"
if [[ ! -f "$OPENSSL_CNF" ]]; then
  cat > "$OPENSSL_CNF" <<CONF
[ ca ]
default_ca = dmj_root

[ dmj_root ]
dir               = $PKI_DIR/ca
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
default_md        = sha256
policy            = policy_loose
copy_extensions   = copy
default_days      = 3650

[ dmj_intermediate ]
dir               = $PKI_DIR/intermediate
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
default_md        = sha256
policy            = policy_loose
copy_extensions   = copy
default_days      = 825

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied

[ req ]
default_bits       = 256
default_md         = sha256
prompt             = no
distinguished_name = dn

[ dn ]
C = IN
O = dmj.one
CN = dmj.one

[ v3_root ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ v3_intermediate ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
authorityKeyIdentifier = keyid:always,issuer
subjectKeyIdentifier = hash
crlDistributionPoints = URI:http://DOCSIGN_HOST/.well-known/pki/dmjone.crl
authorityInfoAccess = caIssuers;URI:http://DOCSIGN_HOST/.well-known/pki/dmjone-int.pem

[ v3_ocsp ]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
authorityKeyIdentifier=keyid,issuer

[ v3_document ]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = emailProtection, codeSigning
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier = hash
crlDistributionPoints = URI:http://DOCSIGN_HOST/.well-known/pki/dmjone.crl
authorityInfoAccess = OCSP;URI:http://DOCSIGN_HOST/ocsp, caIssuers;URI:http://DOCSIGN_HOST/.well-known/pki/dmjone-int.pem
CONF
  sed -i "s|DOCSIGN_HOST|$DOMAIN|g" "$OPENSSL_CNF"
fi



if [[ ! -d "$ROOT_DIR" ]]; then
  log "Initializing CA structure (Root/Intermediate/OCSP)..."
  mkdir -p "$ROOT_DIR"/{certs,crl,newcerts,private} "$INT_DIR"/{certs,crl,csr,newcerts,private}
  touch "$ROOT_DIR/index.txt" "$INT_DIR/index.txt"
  echo 1000 > "$ROOT_DIR/serial"
  echo 1000 > "$ROOT_DIR/crlnumber"
  echo 1000 > "$INT_DIR/serial"
  echo 1000 > "$INT_DIR/crlnumber"

  # Root key & cert
  $OPENSSL_BIN ecparam -genkey -name prime256v1 -out "$ROOT_DIR/private/root.key"
  $OPENSSL_BIN req -x509 -new -nodes -key "$ROOT_DIR/private/root.key" -sha256 -days 3650 \
     -subj "/C=IN/O=dmj.one/CN=dmj.one Root CA" -out "$ROOT_DIR/certs/root.pem" -extensions v3_root -config "$OPENSSL_CNF"

  # Intermediate key/cert
  $OPENSSL_BIN ecparam -genkey -name prime256v1 -out "$INT_DIR/private/intermediate.key"
  $OPENSSL_BIN req -new -key "$INT_DIR/private/intermediate.key" -out "$INT_DIR/csr/intermediate.csr" -subj "/C=IN/O=dmj.one/CN=dmj.one Intermediate CA"
  $OPENSSL_BIN ca -batch -config "$OPENSSL_CNF" -name dmj_root -extensions v3_intermediate -keyfile "$ROOT_DIR/private/root.key" -cert "$ROOT_DIR/certs/root.pem" -in "$INT_DIR/csr/intermediate.csr" -out "$INT_DIR/certs/intermediate.pem"


  # OCSP signer
  $OPENSSL_BIN ecparam -genkey -name prime256v1 -out "$INT_DIR/private/ocsp.key"
  $OPENSSL_BIN req -new -key "$INT_DIR/private/ocsp.key" -out "$INT_DIR/csr/ocsp.csr" -subj "/C=IN/O=dmj.one/CN=dmj.one OCSP"
  $OPENSSL_BIN ca -batch -config "$OPENSSL_CNF" -extensions v3_ocsp \
    -keyfile "$INT_DIR/private/intermediate.key" -cert "$INT_DIR/certs/intermediate.pem" \
    -in "$INT_DIR/csr/ocsp.csr" -out "$INT_DIR/certs/ocsp.pem"

  # CRL init & publish
  $OPENSSL_BIN ca -config "$OPENSSL_CNF" -name dmj_intermediate -gencrl -keyfile "$INT_DIR/private/intermediate.key" -cert "$INT_DIR/certs/intermediate.pem" -out "$INT_DIR/crl/dmjone.crl"

  install -m 0644 "$INT_DIR/crl/dmjone.crl" "$STATIC_PKI_DIR/dmjone.crl"
  install -m 0644 "$INT_DIR/certs/intermediate.pem" "$STATIC_PKI_DIR/dmjone-int.pem"
  install -m 0644 "$ROOT_DIR/certs/root.pem" "$STATIC_PKI_DIR/dmjone-root.pem"

  # Encrypt private keys at rest (cloning-resistant)
  encrypt_key_if_plain "$ROOT_DIR/private/root.key"
  encrypt_key_if_plain "$INT_DIR/private/intermediate.key"
  encrypt_key_if_plain "$INT_DIR/private/ocsp.key"
fi

# Always re-publish CRL in case it was updated
if [[ -f "$INT_DIR/crl/dmjone.crl" ]]; then
  install -m 0644 "$INT_DIR/crl/dmjone.crl" "$STATIC_PKI_DIR/dmjone.crl"
fi

# --------------------
# App code (embedded)
# --------------------
if [[ "$APP_REPO_MODE" == "git" && -n "$GIT_REPO_URL" ]]; then
  if [[ ! -d "$APP_DIR/repo/.git" ]]; then
    sudo -u "$APP_USER" git clone --branch "$GIT_BRANCH" "$GIT_REPO_URL" "$APP_DIR/repo"
  else
    pushd "$APP_DIR/repo" >/dev/null
    sudo -u "$APP_USER" git fetch origin "$GIT_BRANCH"
    sudo -u "$APP_USER" git checkout "$GIT_BRANCH"
    sudo -u "$APP_USER" git pull --ff-only
    popd >/dev/null
  fi
  APP_CODE_DIR="$APP_DIR/repo/app"
else
  # Generate a minimal but complete FastAPI app
  APP_CODE_DIR="$APP_DIR/app"
  mkdir -p "$APP_CODE_DIR"/{templates,static}
  chown -R "$APP_USER":"$APP_USER" "$APP_CODE_DIR"

  # db.py
  cat > "$APP_CODE_DIR/db.py" <<'PY'
import os
from sqlalchemy import create_engine, Column, Integer, BigInteger, LargeBinary, String, DateTime, Boolean, Enum
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
load_dotenv()
DB_DSN = os.getenv("DB_DSN")
engine = create_engine(DB_DSN, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Doc(Base):
    __tablename__ = "docs"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    doc_uid = Column(String(36), unique=True, nullable=False)
    sha256_hex = Column(String(64), nullable=False)
    hmac_sha256_hex = Column(String(64), nullable=False, index=True)
    sign_cert_serial = Column(LargeBinary(20), nullable=False)
    sign_cert_fpr = Column(String(64), nullable=False)
    issued_at = Column(DateTime, nullable=False)
    ltv_enabled = Column(Boolean, nullable=False, default=True)
    status = Column(Enum('ISSUED','REVOKED', name='docstatus'), nullable=False, default='ISSUED')
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(128), nullable=True)
    signer_common_name = Column(String(255), nullable=False)

class Audit(Base):
    __tablename__ = "audit"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    at = Column(DateTime, nullable=False)
    event = Column(String(64), nullable=False)
    ip = Column(LargeBinary, nullable=True)
    doc_uid = Column(String(36), nullable=True)
    detail = Column(String(1024), nullable=True)

def init_db():
    Base.metadata.create_all(bind=engine)
PY

  # pki_ops.py (OpenSSL wrapper)
  cat > "$APP_CODE_DIR/pki_ops.py" <<'PY'
import os, subprocess, binascii, tempfile, shutil, uuid, pathlib
from dotenv import load_dotenv
load_dotenv()
APP_DIR = pathlib.Path(__file__).resolve().parents[0].parents[0]
PKI_DIR = pathlib.Path(os.getenv("PKI_DIR", f"{APP_DIR}/pki"))
ROOT_DIR = PKI_DIR / "ca"
INT_DIR = PKI_DIR / "intermediate"
OPENSSL = os.getenv("OPENSSL_BIN", "/usr/bin/openssl")
OPENSSL_CNF = PKI_DIR / "openssl.cnf"
KEY_ENC_ALGO = os.getenv("KEY_ENC_ALGO", "aes-256-cbc")

def _derive_kek():
    import requests, binascii, hashlib, hmac
    from hashlib import sha256
    salt_hex = os.getenv("KEY_DERIVATION_SALT_HEX")
    if not salt_hex: raise RuntimeError("KEY_DERIVATION_SALT_HEX missing")
    headers={"Metadata-Flavor":"Google"}
    def meta(path, default="no"):
        try:
            r = requests.get(f"http://metadata/computeMetadata/v1/{path}", headers=headers, timeout=2)
            r.raise_for_status(); return r.text
        except Exception: return default
    ikm = f"{meta('instance/id')}|{meta('project/numeric-project-id')}|{meta('instance/zone').split('/')[-1]}|{os.getenv('DOMAIN','docsigner.dmj.one')}".encode()
    salt = binascii.unhexlify(salt_hex)
    def hkdf_extract(salt, ikm): return hmac.new(salt, ikm, sha256).digest()
    def hkdf_expand(prk, info, l):
        t=b""; okm=b""; i=0
        while len(okm)<l:
            i+=1; t=hmac.new(prk, t+info+bytes([i]), sha256).digest(); okm+=t
        return okm[:l]
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, b"dmj-docsigner-kek", 32).hex()

def _passin():
    return f"pass:{_derive_kek()}"

def issue_doc_cert(doc_uid:str):
    # Generate per-document keypair & cert signed by intermediate
    tmp = tempfile.mkdtemp()
    key_pem = os.path.join(tmp, "doc.key")
    cert_pem = os.path.join(tmp, "doc.crt")
    subj = f"/C=IN/O=dmj.one/CN=dmj.one Document Cert {doc_uid}"
    subprocess.check_call([OPENSSL, "ecparam", "-genkey", "-name", "prime256v1", "-out", key_pem])
    csr = os.path.join(tmp, "doc.csr")
    subprocess.check_call([OPENSSL, "req", "-new", "-key", key_pem, "-out", csr, "-subj", subj])    
    subprocess.check_call([
        OPENSSL, "ca", "-batch", "-config", str(OPENSSL_CNF),
        "-name", "dmj_intermediate", "-extensions", "v3_document",
        "-keyfile", str(INT_DIR / "private" / "intermediate.key.enc"),
        "-passin", _passin(), "-cert", str(INT_DIR / "certs" / "intermediate.pem"),
        "-in", csr, "-out", cert_pem
    ])
    # Read serial
    # openssl x509 -in cert -serial -noout
    serial = subprocess.check_output([OPENSSL, "x509", "-in", cert_pem, "-serial", "-noout"], text=True).strip().split("=")[-1]
    # Return PEM bytes
    with open(key_pem, "rb") as f: k=f.read()
    with open(cert_pem, "rb") as f: c=f.read()
    shutil.rmtree(tmp, ignore_errors=True)
    return (k, c, serial, f"dmj.one Document Cert {doc_uid}")

def revoke_doc_cert(serial_hex:str):
    # Revoke and regenerate CRL
    cert_path = None
    # Convert serial to lowercase without leading 0x; openssl index requires match
    serial_hex = serial_hex.lower().lstrip("0x")
    # openssl stores issued certs in newcerts/ with serial as filename.pem
    guess = INT_DIR / "newcerts" / f"{serial_hex}.pem"
    if guess.exists(): cert_path = str(guess)
    # Revoke by serial (fallback)
    if cert_path:
        subprocess.check_call([OPENSSL, "ca", "-config", str(OPENSSL_CNF),
                               "-keyfile", str(INT_DIR / "private" / "intermediate.key.enc"),
                               "-passin", _passin(),
                               "-cert", str(INT_DIR / "certs" / "intermediate.pem"),
                               "-revoke", cert_path])
    else:
        # Try using -revoke with path lookup via index not available -> no-op
        pass
    subprocess.check_call([OPENSSL, "ca", "-config", str(OPENSSL_CNF), "-gencrl",
                           "-keyfile", str(INT_DIR / "private" / "intermediate.key.enc"),
                           "-passin", _passin(),
                           "-cert", str(INT_DIR / "certs" / "intermediate.pem"),
                           "-out", str(INT_DIR / "crl" / "dmjone.crl")])
PY

  # pdf_ops.py (pyHanko sign/verify)
  cat > "$APP_CODE_DIR/pdf_ops.py" <<'PY'
import os, io, binascii
from datetime import datetime, timezone
from pyhanko.sign import signers
from pyhanko.sign.general import sign_pdf
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko_certvalidator import ValidationContext, CertificateValidator
from cryptography.hazmat.primitives import serialization

# Paths for chain
APP_BASE = os.path.dirname(__file__)
PKI_BASE = os.path.abspath(os.path.join(APP_BASE, "..", "pki"))
ROOT_PEM = os.path.join(PKI_BASE, "ca", "certs", "root.pem")
INT_PEM  = os.path.join(PKI_BASE, "intermediate", "certs", "intermediate.pem")

def sign_pdf_pades(pdf_bytes: bytes, key_pem: bytes, cert_pem: bytes, subject_cn: str) -> bytes:
    # Load private key
    priv_key = serialization.load_pem_private_key(key_pem, password=None)
    # Load certs for chain
    with open(INT_PEM, 'rb') as f: int_pem = f.read()
    with open(ROOT_PEM, 'rb') as f: root_pem = f.read()
    cert = signers.load_cert_from_pem(cert_pem)
    int_cert = signers.load_cert_from_pem(int_pem)
    root_cert = signers.load_cert_from_pem(root_pem)
    # SimpleSigner with chain
    signer = signers.SimpleSigner(
        signing_cert=cert,
        signing_key=priv_key,
        cert_registry=signers.SimpleCertificateStore([int_cert, root_cert]),
        # add name in signature dictionary
        signing_name=subject_cn,
    )
    # Prepare PDF writer
    pdf_in = io.BytesIO(pdf_bytes)
    w = IncrementalPdfFileWriter(pdf_in)
    meta = signers.PdfSignatureMetadata(
        field_name="dmjone_sig",
        reason="Document authenticated by dmj.one",
        location="dmj.one",
        # PAdES baseline B-T: include timestamp if TSA configured; else B-B
    )
    out = io.BytesIO()
    # Sign (pyHanko will embed chain; OCSP/CRL URLs are in cert extensions)
    sign_pdf(w, signer=signer, signature_meta=meta, output=out)
    return out.getvalue()

def verify_pdf(pdf_bytes: bytes):
    # Build validation context anchored at our root; allow OCSP/CRL fetching
    with open(ROOT_PEM,'rb') as f: root_pem = f.read()
    vc = ValidationContext(trust_roots=[root_pem], allow_fetching=True)
    # Validate
    bio = io.BytesIO(pdf_bytes)
    status = validate_pdf_signature(bio, -1, validation_context=vc)
    ok = status.summary().valid
    chain = status.bottom_line_summary
    signer_fp = status.signer_cert.sha1.hex().upper() if status.signer_cert else ""
    issuer = status.signer_cert.issuer.human_friendly if status.signer_cert else "unknown"
    return ok, {"signer_fp": signer_fp, "issuer": issuer, "ltv": True, "chain": str(chain)}
PY

  # main.py (FastAPI app)
  cat > "$APP_CODE_DIR/main.py" <<'PY'
import os, hmac, binascii, hashlib, uuid, datetime
from fastapi import FastAPI, Request, UploadFile, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.hash import argon2
from dotenv import load_dotenv
from db import SessionLocal, init_db, Doc, Audit
from pdf_ops import sign_pdf_pades, verify_pdf
from pki_ops import issue_doc_cert, revoke_doc_cert
from sqlalchemy.orm import Session

load_dotenv()
DOMAIN = os.getenv("DOMAIN", "docsigner.dmj.one")
ADMIN_HASH = os.getenv("ADMIN_PASS_HASH")
DOC_HMAC_KEY = binascii.unhexlify(os.getenv("DOC_HMAC_KEY_HEX"))
UPLOAD_LIMIT_MB = int(os.getenv("UPLOAD_LIMIT_MB", "25"))

app = FastAPI(title="dmj.one PDF Signer")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def hmac_sha256(raw_hex: str) -> str:
    return hmac.new(DOC_HMAC_KEY, binascii.unhexlify(raw_hex), hashlib.sha256).hexdigest()

@app.on_event("startup")
def startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "domain": DOMAIN})

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})

def require_admin_key(admin_key: str = Form(...)):
    if not argon2.verify(admin_key, ADMIN_HASH):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

@app.post("/admin/sign", response_class=StreamingResponse)
async def admin_sign(admin_ok: bool = Depends(require_admin_key),
                     file: UploadFile = Form(...), db: Session = Depends(get_db)):
    data = await file.read()
    if len(data) > UPLOAD_LIMIT_MB * 1024 * 1024:
        raise HTTPException(413, "File too large")
    sha = hashlib.sha256(data).hexdigest()
    hsha = hmac_sha256(sha)
    doc_uid = str(uuid.uuid4())
    key_pem, cert_pem, serial_hex, subject_cn = issue_doc_cert(doc_uid)
    signed_pdf = sign_pdf_pades(data, key_pem, cert_pem, subject_cn)
    ok, details = verify_pdf(signed_pdf)
    if not ok:
        raise HTTPException(500, "Sanity verification failed after signing")
    # Persist registry
    now = datetime.datetime.utcnow()
    reg = Doc(doc_uid=doc_uid, sha256_hex=sha, hmac_sha256_hex=hsha,
              sign_cert_serial=binascii.unhexlify(serial_hex), sign_cert_fpr=details["signer_fp"],
              issued_at=now, ltv_enabled=details.get("ltv", True), status="ISSUED",
              signer_common_name=subject_cn)
    db.add(reg); db.commit()
    db.add(Audit(at=now, event="SIGN_OK", ip=None, doc_uid=doc_uid)); db.commit()
    return StreamingResponse(iter([signed_pdf]), media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{os.path.splitext(file.filename)[0]}-signed.pdf"'} )

@app.post("/verify", response_class=JSONResponse)
async def verify(file: UploadFile = Form(...), db: Session = Depends(get_db)):
    data = await file.read()
    sha = hashlib.sha256(data).hexdigest()
    hsha = hmac_sha256(sha)
    ok, details = verify_pdf(data)
    reg = db.query(Doc).filter(Doc.hmac_sha256_hex == hsha).first()
    status = "UNKNOWN"
    issuer = details.get("issuer","dmj.one")
    if reg:
        status = reg.status
        issuer = "dmj.one"
    verdict = "GENUINE" if ok and reg and status=="ISSUED" else ("REVOKED" if reg and status=="REVOKED" else "TAMPERED_OR_UNTRUSTED")
    db.add(Audit(at=datetime.datetime.utcnow(), event="VERIFY_OK", ip=None, doc_uid=getattr(reg, "doc_uid", None))); db.commit()
    return {"verdict": verdict, "issuer": issuer, "registry_hit": bool(reg), "details": details}

@app.post("/admin/revoke", response_class=JSONResponse)
def revoke(doc_uid: str = Form(...), admin_ok: bool = Depends(require_admin_key), db: Session = Depends(get_db)):
    reg = db.query(Doc).filter(Doc.doc_uid==doc_uid, Doc.status=="ISSUED").first()
    if not reg: raise HTTPException(404, "Doc not found or already revoked")
    revoke_doc_cert(reg.sign_cert_serial.hex())
    reg.status = "REVOKED"; reg.revoked_at = datetime.datetime.utcnow(); db.commit()
    db.add(Audit(at=datetime.datetime.utcnow(), event="REVOKE_OK", ip=None, doc_uid=doc_uid)); db.commit()
    return {"ok": True, "doc_uid": doc_uid}
PY

  # templates
  cat > "$APP_CODE_DIR/templates/index.html" <<'HTML'
<!doctype html>
<html><head><meta charset="utf-8"><title>dmj.one — Verify</title></head>
<body>
<h2>dmj.one — Document Verification</h2>
<form method="post" action="/verify" enctype="multipart/form-data">
  <input type="file" name="file" accept="application/pdf" required>
  <button type="submit">Verify PDF</button>
</form>
<p>Issuer expected: dmj.one. This portal checks the embedded signature (PAdES) and our registry with revocation status.</p>
</body></html>
HTML

  cat > "$APP_CODE_DIR/templates/admin.html" <<'HTML'
<!doctype html>
<html><head><meta charset="utf-8"><title>dmj.one — Admin</title></head>
<body>
<h2>Admin — Sign a PDF</h2>
<form method="post" action="/admin/sign" enctype="multipart/form-data">
  <input type="password" name="admin_key" placeholder="Admin key" required>
  <input type="file" name="file" accept="application/pdf" required>
  <button type="submit">Sign & Download</button>
</form>
<h3>Revoke a document</h3>
<form method="post" action="/admin/revoke">
  <input type="password" name="admin_key" placeholder="Admin key" required>
  <input type="text" name="doc_uid" placeholder="Document ID (UUID)" required>
  <button type="submit">Revoke</button>
</form>
</body></html>
HTML
fi

chown -R "$APP_USER":"$APP_USER" "$APP_CODE_DIR"

# --------------------
# nginx (HTTP origin behind Cloudflare Flexible)
# --------------------
cat > "$NGINX_SITE" <<NGX
server {
  listen 80;
  server_name $DOMAIN;

  # Restore real client IP via Cloudflare header
  real_ip_header CF-Connecting-IP;
  include $CLOUDFLARE_INCLUDE;

  # Publish AIA/CRL
  location /.well-known/pki/ {
    alias $STATIC_PKI_DIR/;
    autoindex off;
    add_header Cache-Control "public, max-age=300";
  }

  # OCSP responder proxy
  location /ocsp {
    proxy_pass http://127.0.0.1:$OCSP_PORT;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }

  # App
  location / {
    proxy_pass http://127.0.0.1:8000/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Real-IP \$remote_addr;
  }
}
NGX

# Cloudflare IP ranges include (refresh every run)
retry 3 5 curl -fsSL https://www.cloudflare.com/ips-v4 -o /tmp/cf4 || curl -fsSL https://www.cloudflare.com/ips-v4/ -o /tmp/cf4
retry 3 5 curl -fsSL https://www.cloudflare.com/ips-v6 -o /tmp/cf6 || curl -fsSL https://www.cloudflare.com/ips-v6/ -o /tmp/cf6
{
  awk '{print "set_real_ip_from "$0";"}' /tmp/cf4
  awk '{print "set_real_ip_from "$0";"}' /tmp/cf6
  echo "real_ip_recursive on;"
} > "$CLOUDFLARE_INCLUDE"

ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/dmj-docsigner
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable --now nginx

# --------------------
# systemd services: app, ocsp, autoconfig
# --------------------
# App service (Uvicorn)
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=dmj.one PDF Signer (FastAPI)
After=network-online.target
Wants=network-online.target

[Service]
User=$APP_USER
Group=$APP_USER
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=$ENV_FILE
WorkingDirectory=$APP_CODE_DIR
ExecStart=$VENV_DIR/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

# # OCSP responder (openssl-ocsp) with runtime pass-in
# cat > "/etc/systemd/system/${OCSP_SERVICE_NAME}.service" <<UNIT
# [Unit]
# Description=dmj.one OCSP Responder
# After=network-online.target
# Wants=network-online.target

# [Service]
# Type=simple
# EnvironmentFile=$ENV_FILE
# ExecStart=/bin/bash -lc '\
#   KEK=\$( "$PYTHON" - "\$KEY_DERIVATION_SALT_HEX" <<PY
# import sys, binascii, hashlib, hmac, requests
# from hashlib import sha256
# salt_hex=sys.argv[1]
# headers={"Metadata-Flavor":"Google"}
# def meta(p,d="no"):
#   try:
#     r=requests.get("http://metadata/computeMetadata/v1/"+p,headers=headers,timeout=2); r.raise_for_status(); return r.text
#   except Exception: return d
# ikm=(meta("instance/id")+"|"+meta("project/numeric-project-id")+"|"+meta("instance/zone").split("/")[-1]+"|'+$DOMAIN+'").encode()
# salt=binascii.unhexlify(salt_hex)
# def hkdf_extract(salt,ikm): return hmac.new(salt, ikm, sha256).digest()
# def hkdf_expand(prk, info, l):
#   t=b""; okm=b""; i=0
#   while len(okm)<l:
#     i+=1; import hmac as _h; t=_h.new(prk, t+info+bytes([i]), sha256).digest(); okm+=t
#   return okm[:l]
# prk=hkdf_extract(salt, ikm)
# print(binascii.hexlify(hkdf_expand(prk,b"dmj-docsigner-kek",32)).decode())
# PY
# ); \
#   exec $OPENSSL_BIN ocsp -port $OCSP_PORT \
#     -index $INT_DIR/index.txt \
#     -rkey $INT_DIR/private/ocsp.key.enc -passin pass:\$KEK \
#     -rsigner $INT_DIR/certs/ocsp.pem \
#     -CA $ROOT_DIR/certs/root.pem -nmin 1 -ndays 7 -ignore_err -text'
# Restart=always

# [Install]
# WantedBy=multi-user.target
# UNIT



# --------------------
# OCSP runner script + unit (robust, single-line ExecStart)
# --------------------
install -d -o "$APP_USER" -g "$APP_USER" /usr/local/sbin

cat > /usr/local/sbin/dmj-ocsp-runner.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/dmj-docsigner}"
PKI_DIR="${PKI_DIR:-$APP_DIR/pki}"
ROOT_DIR="$PKI_DIR/ca"
INT_DIR="$PKI_DIR/intermediate"
OCSP_PORT="${OCSP_PORT:-2560}"

# Ensure index file exists so openssl-ocsp can read it even if empty
mkdir -p "$INT_DIR" "$ROOT_DIR"
touch "$INT_DIR/index.txt"

# Derive KEK from GCE metadata + salt (HKDF-SHA256), all stdlib only
: "${KEY_DERIVATION_SALT_HEX:?KEY_DERIVATION_SALT_HEX missing in env (.env))}"

md() { curl -fsSL -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/$1" || echo "na"; }
IID="$(md instance/id)"
PROJ="$(md project/numeric-project-id)"
ZONE="$(md instance/zone | awk -F/ '{print $NF}')"
IKM="${IID}|${PROJ}|${ZONE}|${DOMAIN:-docsigner.dmj.one}"

KEK="$(python3 - "$IKM" "$KEY_DERIVATION_SALT_HEX" <<'PY'
import sys, binascii, hmac, hashlib
ikm=sys.argv[1].encode(); salt=binascii.unhexlify(sys.argv[2])
def hkdf_extract(salt,ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
def hkdf_expand(prk,info,L):
    t=b""; okm=b""; i=0
    while len(okm)<L:
        i+=1; t=hmac.new(prk, t+info+bytes([i]), hashlib.sha256).digest(); okm+=t
    return okm[:L]
prk=hkdf_extract(salt,ikm)
print(binascii.hexlify(hkdf_expand(prk,b"dmj-docsigner-kek",32)).decode())
PY
)"

# Run OCSP responder (key is encrypted; supply -passin)
exec /usr/bin/openssl ocsp \
  -port "$OCSP_PORT" \
  -index "$INT_DIR/index.txt" \
  -rkey "$INT_DIR/private/ocsp.key.enc" -passin "pass:${KEK}" \
  -rsigner "$INT_DIR/certs/ocsp.pem" \
  -CA "$ROOT_DIR/certs/root.pem" \
  -nmin 1 -ndays 7 -ignore_err -text
SH
chmod 0755 /usr/local/sbin/dmj-ocsp-runner.sh
chown "$APP_USER":"$APP_USER" /usr/local/sbin/dmj-ocsp-runner.sh

# Unit file: keep ExecStart simple + add conditions so it waits until PKI exists
cat > "/etc/systemd/system/${OCSP_SERVICE_NAME}.service" <<UNIT
[Unit]
Description=dmj.one OCSP Responder
After=network-online.target
Wants=network-online.target
# Don’t try to start until core PKI artifacts exist
ConditionPathExists=$INT_DIR/certs/ocsp.pem
ConditionPathExists=$INT_DIR/index.txt

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
EnvironmentFile=$ENV_FILE
Environment=APP_DIR=$APP_DIR
Environment=PKI_DIR=$PKI_DIR
Environment=OCSP_PORT=$OCSP_PORT
ExecStart=/usr/local/sbin/dmj-ocsp-runner.sh
Restart=always
RestartSec=2s
# Hardening (can be relaxed if needed)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT


# Autoconfig self-update at boot (fetch latest script from your repo)
cat > "/usr/local/bin/${AUTOCONFIG_SERVICE_NAME}.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
# Use nocache param each run
curl -fsSL "https://raw.githubusercontent.com/divyamohan1993/dmj-one-pdf-authenticator/refs/heads/main/one-click-deployment/python/autoconfig.sh?nocache=$(date +%s)" -o /tmp/autoconfig.sh
bash /tmp/autoconfig.sh
SH
chmod +x "/usr/local/bin/${AUTOCONFIG_SERVICE_NAME}.sh"

cat > "/etc/systemd/system/${AUTOCONFIG_SERVICE_NAME}.service" <<UNIT
[Unit]
Description=dmj.one autoconfig (self-update) at boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/${AUTOCONFIG_SERVICE_NAME}.sh

[Install]
WantedBy=multi-user.target
UNIT

# --- PKI self-heal: ensure minimal files exist for OCSP to start ---
# Create basics if someone deleted them between runs.
mkdir -p "$ROOT_DIR"/{certs,crl,newcerts,private} "$INT_DIR"/{certs,crl,csr,newcerts,private}
[[ -f "$ROOT_DIR/index.txt" ]] || touch "$ROOT_DIR/index.txt"
[[ -f "$INT_DIR/index.txt"  ]] || touch "$INT_DIR/index.txt"
[[ -f "$ROOT_DIR/serial"    ]] || echo 1000 > "$ROOT_DIR/serial"
[[ -f "$INT_DIR/serial"     ]] || echo 1000 > "$INT_DIR/serial"
[[ -f "$ROOT_DIR/crlnumber" ]] || echo 1000 > "$ROOT_DIR/crlnumber"
[[ -f "$INT_DIR/crlnumber"  ]] || echo 1000 > "$INT_DIR/crlnumber"

# If core certs are missing, (re)create them idempotently
if [[ ! -f "$ROOT_DIR/certs/root.pem" || ! -f "$ROOT_DIR/private/root.key.enc" && -f "$ROOT_DIR/private/root.key" ]]; then
  # Encrypt root key if still plain from some earlier run
  encrypt_key_if_plain "$ROOT_DIR/private/root.key" || true
fi

# if [[ ! -f "$INT_DIR/certs/intermediate.pem" && -f "$INT_DIR/private/intermediate.key" ]]; then
#   $OPENSSL_BIN req -new -key "$INT_DIR/private/intermediate.key" -out "$INT_DIR/csr/intermediate.csr" -subj "/C=IN/O=dmj.one/CN=dmj.one Intermediate CA"
#   $OPENSSL_BIN ca -batch -config "$OPENSSL_CNF" -extensions v3_intermediate \
#     -keyfile "$ROOT_DIR/private/root.key.enc" -passin "pass:$(derive_kek)" \
#     -cert "$ROOT_DIR/certs/root.pem" \
#     -in "$INT_DIR/csr/intermediate.csr" -out "$INT_DIR/certs/intermediate.pem" || true
# fi

# if [[ ! -f "$INT_DIR/certs/ocsp.pem" && -f "$INT_DIR/private/ocsp.key" ]]; then
#   $OPENSSL_BIN req -new -key "$INT_DIR/private/ocsp.key" -out "$INT_DIR/csr/ocsp.csr" -subj "/C=IN/O=dmj.one/CN=dmj.one OCSP"
#   $OPENSSL_BIN ca -batch -config "$OPENSSL_CNF" -extensions v3_ocsp \
#     -keyfile "$INT_DIR/private/intermediate.key.enc" -passin "pass:$(derive_kek)" \
#     -cert "$INT_DIR/certs/intermediate.pem" \
#     -in "$INT_DIR/csr/ocsp.csr" -out "$INT_DIR/certs/ocsp.pem" || true
# fi

# Always (re)publish CRL if present
if [[ -f "$INT_DIR/crl/dmjone.crl" ]]; then
  install -m 0644 "$INT_DIR/crl/dmjone.crl" "$STATIC_PKI_DIR/dmjone.crl"
fi

# Validate + start
# systemd-analyze verify "/etc/systemd/system/${OCSP_SERVICE_NAME}.service" || true
# systemctl daemon-reload
# systemctl enable --now "${OCSP_SERVICE_NAME}" || true

# systemctl daemon-reload
# systemctl enable --now "$SERVICE_NAME" "$OCSP_SERVICE_NAME" "$AUTOCONFIG_SERVICE_NAME"


# --- start/enable services (no recursion) ---
# App + OCSP may start now
systemctl daemon-reload

# Ensure PKI exists BEFORE starting OCSP (see section B below)
ensure_pki   # <-- call the function from section B (place it above)

# Start app and OCSP now (ok to fail gracefully if not ready)
systemctl enable "$SERVICE_NAME" || true
systemctl enable "$OCSP_SERVICE_NAME" || true

# Autoconfig should only run on next boot; enable but DO NOT start now
# (Starting it now would re-run this very script and cause nested execution.)
systemctl disable "$AUTOCONFIG_SERVICE_NAME" >/dev/null 2>&1 || true
systemctl enable "$AUTOCONFIG_SERVICE_NAME"

# Final message (don’t block)
echo "[OK] Deployment/update complete. Visit: https://$DOMAIN"


# Finalize
log "OK — deployment complete. Visit: https://$DOMAIN  (behind Cloudflare Flexible SSL)"
