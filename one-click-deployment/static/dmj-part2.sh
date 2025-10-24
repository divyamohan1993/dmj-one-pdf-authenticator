# dmj-part2.sh
#!/usr/bin/env bash
set -euo pipefail
umask 077

### --- Config / Inputs -------------------------------------------------------
DMJ_USER="dmjsvc"
LOG_DIR="/var/log/dmj"
STATE_DIR="/var/lib/dmj"
CONF_DIR="/etc/dmj"
INST_ENV="${CONF_DIR}/installer.env"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"

### ---------- Logging / Verbosity ----------
LOG_DIR="/var/log/dmj"; STATE_DIR="/var/lib/dmj"; CONF_DIR="/etc/dmj"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"
LOG_FILE="${LOG_DIR}/part2-$(date +%Y%m%dT%H%M%S).log"
# cd $LOG_DIR && sudo rm -rf *
# keep last 10 logs; delete older
find "$LOG_DIR" -type f -name 'part2-*.log' -mtime +14 -delete

DMJ_VERBOSE="${DMJ_VERBOSE:-1}"

# Load installation id / DB_PREFIX
# shellcheck disable=SC1090
[ -f "$INST_ENV" ] && source "$INST_ENV" || { echo "[x] Missing ${INST_ENV}. Run Part 1 first."; exit 1; }

DMJ_ROOT_DOMAIN="${DMJ_ROOT_DOMAIN:-dmj.one}"
SIGNER_DOMAIN="${SIGNER_DOMAIN:-signer.${DMJ_ROOT_DOMAIN}}"

# Support/contact & Worker<->Signer header names (overrideable)
SUPPORT_EMAIL="${SUPPORT_EMAIL:-contact@${DMJ_ROOT_DOMAIN}}"
WORKER_HMAC_HEADER="${WORKER_HMAC_HEADER:-x-worker-hmac}"
WORKER_HMAC_TS_HEADER="${WORKER_HMAC_TS_HEADER:-x-worker-ts}"
WORKER_HMAC_NONCE_HEADER="${WORKER_HMAC_NONCE_HEADER:-x-worker-nonce}"

# WORKER_NAME="dmj-${INSTALLATION_ID}-docsign"
WORKER_NAME="document-signer"
WORKER_DIR="/opt/dmj/worker"
SIGNER_DIR="/opt/dmj/signer-vm"
NGINX_SITE="/etc/nginx/sites-available/dmj-signer"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/dmj-signer"
SIGNER_FIXED_PORT="${SIGNER_FIXED_PORT:-18080}"   # single, deterministic port (no file needed) 

# --- PKI / OCSP endpoints (brand + URLs) -------------------------------------
PKI_DOMAIN="${PKI_DOMAIN:-pki.${DMJ_ROOT_DOMAIN}}"
OCSP_DOMAIN="${OCSP_DOMAIN:-ocsp.${DMJ_ROOT_DOMAIN}}"
TSA_DOMAIN="${TSA_DOMAIN:-tsa.${DMJ_ROOT_DOMAIN}}"

OPT_DIR="/opt/dmj"
PKI_DIR="/opt/dmj/pki"
ROOT_DIR="${PKI_DIR}/root"
ICA_DIR="${PKI_DIR}/ica"
OCSP_DIR="${PKI_DIR}/ocsp"
PKI_PUB="${PKI_DIR}/pub"
TSA_DIR="${PKI_DIR}/tsa"

DL_DIR="${PKI_PUB}/dl"
sudo mkdir -p "${DL_DIR}"
sudo mkdir -p "${TSA_DIR}"
# dl/ must be writable by the non‑root service user for ad‑hoc bundles
sudo chown "${DMJ_USER}:${DMJ_USER}" "${DL_DIR}"
sudo chmod 755 "${PKI_PUB}" "${DL_DIR}"
sudo chown -R "${DMJ_USER}:${DMJ_USER}" "${TSA_DIR}"

find /opt/dmj/pki/pub/dl -type f -mtime +1 -delete

# Branded subject names (official)
ROOT_CN="${ROOT_CN:-dmj.one Root CA R1}"
ICA_CN="${ICA_CN:-dmj.one Issuing CA R1}"
OCSP_CN="${OCSP_CN:-dmj.one OCSP Responder R1}"
SIGNER_CN="${SIGNER_CN:-dmj.one Signer}"
ORG_NAME="${ORG_NAME:-dmj.one Trust Services}"
COUNTRY="${COUNTRY:-IN}"
# TSA (RFC 3161)
TSA_CN="${TSA_CN:-dmj.one TSA R1}"

# Optional: control AIA/CRL scheme for certificates (keep http as default)
AIA_SCHEME="${AIA_SCHEME:-http}"   # use http (recommended). Only set to https if you KNOW clients will follow.
OCSP_AIA_SCHEME="${OCSP_AIA_SCHEME:-http}"   # use http (recommended). Only set to https if you KNOW clients will follow.

PASS="$(openssl rand -hex 24)"
PKCS12_ALIAS="${PKCS12_ALIAS:-dmj-one}"

# ---- Shipping policy flags (pin end-user CA kit) ----
CA_SERIES="${CA_SERIES:-r1}"                    # Active CA on the server (may change in the future)
DMJ_SHIP_CA_SERIES="${DMJ_SHIP_CA_SERIES:-r1}"  # The end-user kit you ship. Pin this for years.
DMJ_REISSUE_ROOT="${DMJ_REISSUE_ROOT:-0}"       # 0 = never touch Root by default
DMJ_REISSUE_ICA="${DMJ_REISSUE_ICA:-0}"         # 0 = never touch Issuing by default
DMJ_REISSUE_OCSP="${DMJ_REISSUE_OCSP:-0}"       # 0 = rarely needed
DMJ_REISSUE_LEAF="${DMJ_REISSUE_LEAF:-0}"       # 1 = rotate signer freely - dont - invalidates files
DMJ_REGEN_TRUST_KIT="${DMJ_REGEN_TRUST_KIT:-1}" # 0 = never overwrite user Trust Kit ZIP

# Require D1 id (single shared DB)
CF_D1_DATABASE_ID="${CF_D1_DATABASE_ID:-}"
if [ -z "${CF_D1_DATABASE_ID}" ]; then
  echo "[x] Please export CF_D1_DATABASE_ID to your D1 database id (UUID)."
  echo "    You can run:  dmj-wrangler d1 list --json"
  exit 1
fi

# --- Admin credential rotation flags -----------------------------------------
# Rotate the admin login key on every deploy (recommended: keep =1)
DMJ_ROTATE_ADMIN_KEY="${DMJ_ROTATE_ADMIN_KEY:-1}"
# Also rotate the session HMAC so all existing admin sessions are forced to re-login
DMJ_FORCE_ADMIN_RELOGIN="${DMJ_FORCE_ADMIN_RELOGIN:-1}"


# Re-issue all PKI artifacts if you set DMJ_REISSUE_ALL_HARD_RESET=1 in the environment
################## DANGER ########################
DMJ_REISSUE_ALL_HARD_RESET="${DMJ_REISSUE_ALL_HARD_RESET:-1}" # Never enable this
if [[ "${DMJ_REISSUE_ALL_HARD_RESET}" == "1" ]]; then    
    DMJ_REISSUE_ROOT=1
    DMJ_REISSUE_ICA=1
    DMJ_REISSUE_OCSP=1
    DMJ_REISSUE_LEAF=1
    DMJ_REGEN_TRUST_KIT=1
    DMJ_VERBOSE=1

    echo "Hard reset confirmed. Proceeding with full PKI reissuance..."
fi
################## DANGER ENDS ########################

# Verbose to console? 1/true = yes, 0/false = minimal
case "${DMJ_VERBOSE,,}" in
  1|true|yes) VERBOSE=1 ;;
  *)          VERBOSE=0 ;;
esac

# Ensure base app dirs are owned by the locked user
sudo install -d -m 0755 -o "$DMJ_USER" -g "$DMJ_USER" "$WORKER_DIR" "$SIGNER_DIR" "$PKI_DIR"

# Keep a console FD before we redirect
exec 3>&1
if [ "$VERBOSE" -eq 1 ]; then
  echo "[i] Verbose logging enabled. Log: ${LOG_FILE}" >&3
  exec > >(tee -a "$LOG_FILE") 2>&1
  set -x
else
  echo "[i] Minimal console output. Full log at: ${LOG_FILE}" >&3
  exec >>"$LOG_FILE" 2>&1
fi

# Helper to print minimal progress to console
say(){ printf "%s\n" "$*" >&3; }

# Error trap prints a friendly pointer to the log
trap 'rc=$?; say ""; say "[!] Failed at line $LINENO: $BASH_COMMAND (exit $rc)"; say "[i] See full log: $LOG_FILE"; exit $rc' ERR

# Run commands as the locked-down service user
as_dmj() { sudo -u "$DMJ_USER" -H "$@"; }

# Idempotent permission fixer for all app paths
fix_perms() {
  set -e
  local u="$DMJ_USER"
  local paths=( "$OPT_DIR" "$WORKER_DIR" "$SIGNER_DIR" "$PKI_DIR" "$LOG_DIR" )

  # Ownership
  sudo chown -R "$u:$u" "${paths[@]}" 2>/dev/null || true

  # Directories: 0750 (+ setgid so new subdirs keep group)  
  sudo find "$OPT_DIR" -type d -exec chmod 0751 {} + 2>/dev/null || true   
  sudo find "$OPT_DIR" -type d -exec chmod g+s {} + 2>/dev/null || true  
  
  sudo chmod 0711 /opt

  # Generic files: 0640 (configs, sources, data)
  sudo find "$OPT_DIR" -type f -exec chmod 0640 {} + 2>/dev/null || true  
    
  # Public Folder Full access to allow nginx to read
  sudo find "$PKI_PUB"      -type d -exec chmod 0755 {} + 2>/dev/null || true
  sudo find "$PKI_PUB"      -type f -exec chmod 0644 {} + 2>/dev/null || true

  
  # Make all executables generated executable
  sudo find /usr/local/bin/ -type f -exec chmod 0755 {} + 2>/dev/null || true

  # Sensitive keys
  [ -f "$PKI_DIR/tsa/tsa.key" ] && sudo chmod 0600 "$PKI_DIR/tsa/tsa.key" 2>/dev/null || true
  [ -f "$SIGNER_DIR/keystore.pass" ] && sudo chmod 0600 "$SIGNER_DIR/keystore.pass" 2>/dev/null || true
  [ -f "$SIGNER_DIR/keystore.p12" ] && sudo chmod 0600 "$SIGNER_DIR/keystore.p12" 2>/dev/null || true
  [ -f "$SIGNER_DIR/signer.key" ] && sudo chmod 0600 "$SIGNER_DIR/signer.key" 2>/dev/null || true  
  [ -f "$PKI_DIR/ica/ica.key" ] && sudo chmod 0600 "$PKI_DIR/ica/ica.key" 2>/dev/null || true  
  [ -f "$PKI_DIR/ocsp/ocsp.key" ] && sudo chmod 0600 "$PKI_DIR/ocsp/ocsp.key" 2>/dev/null || true  

  # Built artifacts that must be world/group-readable for Java/classloader sanity
  [ -f "$SIGNER_DIR/target/dmj-signer-1.0.0.jar" ] && sudo chmod 0644 "$SIGNER_DIR/target/dmj-signer-1.0.0.jar"

  # Default ACLs so future files are immediately readable by dmjsvc even if created by root
  if command -v setfacl >/dev/null 2>&1; then
    for p in "$OPT_DIR"; do
      sudo setfacl -m "u:${u}:rwX" "$p" || true
      sudo setfacl -d -m "u:${u}:rwX" "$p" || true    # default ACL (inherit on new files/dirs)
    done
  fi

  # If index.txt.attr is missing, create it (OpenSSL reads it):
  sudo install -m 640 /dev/null /opt/dmj/pki/ica/index.txt.attr
}

# --- Use the Part 1 service-user Wrangler wrapper ----------------------------
WR="/usr/local/bin/dmj-wrangler"
if [ ! -x "$WR" ]; then
  # Fallback if the helper is missing (shouldn't happen if Part 1 ran)
  WR="$(command -v wrangler || true)"
fi
if [ -z "$WR" ]; then
  echo "[x] Wrangler CLI not found. Run Part 1 first."
  exit 1
fi

echo "[+] Verifying Wrangler auth..."
if ! "$WR" whoami >/dev/null 2>&1; then
  echo "[x] Wrangler is not authenticated yet. Finish Part 1 login first."
  exit 1
fi

### --- Resolve D1 database name (needed by wrangler d1 execute) --------------
echo "[+] Resolving D1 database name for id ${CF_D1_DATABASE_ID} ..."
D1_LIST_JSON="$("$WR" d1 list --json || true)"
if [ -z "$D1_LIST_JSON" ] || [ "$D1_LIST_JSON" = "null" ]; then
  echo "[x] Could not list D1 databases. Are you logged into the right account?"
  exit 1
fi
# Try multiple field names the CLI has used over time (uuid/id/database_id/name)
D1_NAME="$(echo "$D1_LIST_JSON" | jq -r --arg ID "$CF_D1_DATABASE_ID" '
  .[] | select((.uuid==$ID) or (.id==$ID) or (.database_id==$ID)) | .name // .database_name' | head -n1)"
if [ -z "$D1_NAME" ] || [ "$D1_NAME" = "null" ]; then
  echo "[x] Could not find a database with id ${CF_D1_DATABASE_ID} in your account."
  echo "    Run: dmj-wrangler d1 list --json   and copy the correct id."
  exit 1
fi
echo "[✓] D1: name=${D1_NAME}, id=${CF_D1_DATABASE_ID}"

# --- Secrets: generate once, but ALWAYS load into this shell -----------------
SECRETS_FILE="${CONF_DIR}/dmj-worker.secrets"
if [ ! -f "$SECRETS_FILE" ]; then
  echo "[+] Generating secrets (HMAC keys, session secret, TOTP master) ..."
  SIGNING_GATEWAY_HMAC_KEY="$(openssl rand -base64 32)"
  SESSION_HMAC_KEY="$(openssl rand -base64 32)"
  TOTP_MASTER_KEY="$(openssl rand -base64 32)"
  {
    echo "SIGNING_GATEWAY_HMAC_KEY=${SIGNING_GATEWAY_HMAC_KEY}"
    echo "SESSION_HMAC_KEY=${SESSION_HMAC_KEY}"
    echo "TOTP_MASTER_KEY=${TOTP_MASTER_KEY}"
  } | sudo tee "$SECRETS_FILE" >/dev/null
  sudo chmod 600 "$SECRETS_FILE"
fi
# Load them into the current shell so subsequent steps can use them
# shellcheck disable=SC1090
source "$SECRETS_FILE"

# If we rotate admin creds, also rotate the session cookie HMAC so old sessions die immediately.
if [ "${DMJ_ROTATE_ADMIN_KEY}" = "1" ] && [ "${DMJ_FORCE_ADMIN_RELOGIN}" = "1" ]; then
  say "[i] Rotating SESSION_HMAC_KEY to invalidate existing admin sessions..."
  SESSION_HMAC_KEY="$(openssl rand -base64 32)"
  # Rewrite the secrets file atomically with the new session key (preserve other keys)
  sudo tee "${SECRETS_FILE}" >/dev/null <<EOF
SIGNING_GATEWAY_HMAC_KEY=${SIGNING_GATEWAY_HMAC_KEY}
SESSION_HMAC_KEY=${SESSION_HMAC_KEY}
TOTP_MASTER_KEY=${TOTP_MASTER_KEY}
EOF
  sudo chmod 600 "${SECRETS_FILE}"
fi

# (Re)load to ensure current shell sees any rotation above
# shellcheck disable=SC1090
source "$SECRETS_FILE"

# --- Ephemeral randomized admin path (rotates on each run) -------------------
# Example: admin-1a2b3c4d5e6f  (12 hex chars)
ADMIN_PATH="admin-$(openssl rand -hex 6)"
ADMIN_PATH_FILE="${STATE_DIR}/admin-path.txt"
printf '%s\n' "$ADMIN_PATH" | sudo tee "$ADMIN_PATH_FILE" >/dev/null
sudo chmod 600 "$ADMIN_PATH_FILE"
say "[i] Admin portal path for this deploy: /${ADMIN_PATH}"

# ----------------------------------------------------------------------------


# Sanity-check: do not proceed with empty secrets (prevents bad deploys)
for v in SIGNING_GATEWAY_HMAC_KEY SESSION_HMAC_KEY TOTP_MASTER_KEY; do
  if [ -z "${!v:-}" ]; then
    echo "[x] $v is empty; aborting."
    echo "    Check ${SECRETS_FILE} or delete it and re-run Part 2 to regenerate."
    exit 1
  fi
done


# Admin portal key (cleartext shown once via GUI). We store a hash as a Worker secret.
ADMIN_KEY_FILE="${STATE_DIR}/admin-key.txt"


# Always rotate the admin key at each deploy (unless explicitly disabled)
if [ "${DMJ_ROTATE_ADMIN_KEY}" = "1" ]; then
  say "[i] Rotating admin portal key for this deploy..."
  ADMIN_PORTAL_KEY="$(openssl rand -hex 14)"   # 28 hex chars, keyboard‑friendly
  printf '%s\n' "$ADMIN_PORTAL_KEY" | sudo tee "$ADMIN_KEY_FILE" >/dev/null
  sudo chmod 600 "$ADMIN_KEY_FILE"
else
  # fallback: keep previous key or create one if missing
  ADMIN_PORTAL_KEY="$(cat "$ADMIN_KEY_FILE" 2>/dev/null || openssl rand -hex 14)"
  printf '%s\n' "$ADMIN_PORTAL_KEY" | sudo tee "$ADMIN_KEY_FILE" >/dev/null
fi

# Compute PBKDF2 hash for the admin key (same format Worker will verify):
# pbkdf2$sha256$<iters>$<base64(salt)>$<base64(derived)>
echo "[+] Deriving PBKDF2 hash for admin portal key..."
ADMIN_HASH="$(node -e 'const c=require("node:crypto");const key=process.argv[1];const iters=100000;const salt=c.randomBytes(16);const dk=c.pbkdf2Sync(Buffer.from(key,"utf8"),salt,iters,32,"sha256");console.log(`pbkdf2$sha256$${iters}$${salt.toString("base64")}$${dk.toString("base64")}`);' "$ADMIN_PORTAL_KEY")"

### --- Build signer microservice (Java) --------------------------------------
echo "[+] Preparing signer microservice at ${SIGNER_DIR} ..."
sudo mkdir -p "${SIGNER_DIR}/src/main/java/one/dmj/signer"
# as_dmj tee "${SIGNER_DIR}/pom.xml" >/dev/null <<'POM'
sudo tee "${SIGNER_DIR}/pom.xml" >/dev/null <<'POM'
<project xmlns="http://maven.apache.org/POM/4.0.0"  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0  http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>one.dmj</groupId>
  <artifactId>dmj-signer</artifactId>
  <version>1.0.0</version>

  <properties>
    <maven.compiler.source>21</maven.compiler.source>
    <maven.compiler.target>21</maven.compiler.target>
  </properties>

  <dependencies>
    <!-- PDF signing/verification -->
    <dependency>
      <groupId>org.apache.pdfbox</groupId>
      <artifactId>pdfbox</artifactId>
      <version>3.0.6</version>
    </dependency>
    <dependency>
      <groupId>org.apache.pdfbox</groupId>
      <artifactId>pdfbox-tools</artifactId>
      <version>3.0.6</version>
    </dependency>
    <!-- Crypto -->
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.82</version>
    </dependency>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcpkix-jdk18on</artifactId>
      <version>1.82</version>
    </dependency>
    <!-- Web framework -->
    <dependency>
      <groupId>io.javalin</groupId>
      <artifactId>javalin</artifactId>
      <version>6.7.0</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.18.1</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-simple</artifactId>
      <version>2.0.17</version>
    </dependency>    
    <dependency>
      <groupId>org.apache.pdfbox</groupId>
      <artifactId>xmpbox</artifactId>
      <version>3.0.6</version>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <!-- Build a single executable JAR with all deps -->      
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-shade-plugin</artifactId>
        <version>3.6.1</version>
        <executions>
          <execution>
            <phase>package</phase>
            <goals><goal>shade</goal></goals>
            <configuration>
              <createDependencyReducedPom>false</createDependencyReducedPom>
              <transformers>
                <!-- put your entry point here -->
                <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
                  <mainClass>one.dmj.signer.SignerServer</mainClass>
                </transformer>
              </transformers>
              <filters>
                <filter>
                  <artifact>*:*</artifact>
                  <excludes>
                    <exclude>META-INF/*.SF</exclude>
                    <exclude>META-INF/*.DSA</exclude>
                    <exclude>META-INF/*.RSA</exclude>
                  </excludes>
                </filter>
              </filters>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
POM


# Java server (sign, verify, spki) — trimmed for brevity but complete.
# --- REPLACE the Java heredoc in rp2.sh with this version ---
# as_dmj tee "${SIGNER_DIR}/src/main/java/one/dmj/signer/SignerServer.java" >/dev/null <<'JAVA'
sudo tee "${SIGNER_DIR}/src/main/java/one/dmj/signer/SignerServer.java" >/dev/null <<'JAVA'
package one.dmj.signer;

import io.javalin.Javalin;
import io.javalin.http.UploadedFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TSPException;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;

import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;


public class SignerServer {

  private static final Logger log = LoggerFactory.getLogger(SignerServer.class);

  static final String WORK_DIR = Optional.ofNullable(System.getenv("DMJ_SIGNER_WORK_DIR")).orElse("/opt/dmj/signer-vm");
  static final Path P12_PATH = Paths.get(WORK_DIR, "keystore.p12");
  static final Path P12_PASS = Paths.get(WORK_DIR, "keystore.pass");
  static final String P12_ALIAS = Optional.ofNullable(System.getenv("DMJ_P12_ALIAS")).orElse("dmj-one");
  static final String HMAC_HEADER = Optional.ofNullable(System.getenv("DMJ_HMAC_HEADER")).orElse("x-worker-hmac");
  static final String HMAC_TS = Optional.ofNullable(System.getenv("DMJ_HMAC_TS_HEADER")).orElse("x-worker-ts");
  static final String HMAC_NONCE = Optional.ofNullable(System.getenv("DMJ_HMAC_NONCE_HEADER")).orElse("x-worker-nonce");

  static final Path ICA_DIR  = Paths.get(Optional.ofNullable(System.getenv("DMJ_ICA_DIR")).orElse("/opt/dmj/pki/ica"));
  static final Path ROOT_DIR = Paths.get(Optional.ofNullable(System.getenv("DMJ_ROOT_DIR")).orElse("/opt/dmj/pki/root"));
  static final Path PKI_PUB  = Paths.get(Optional.ofNullable(System.getenv("DMJ_PKI_PUB")).orElse("/opt/dmj/pki/pub"));
  static final String OPENSSL = Optional.ofNullable(System.getenv("DMJ_OPENSSL_BIN")).orElse("openssl");

  static final Set<String> RECENT_NONCES = Collections.synchronizedSet(new LinkedHashSet<>());

  // TSA / LTV / LTA configuration
  static final String TSA_URL = Optional.ofNullable(System.getenv("DMJ_TSA_URL")).orElse("");
  static final String TSA_USER = Optional.ofNullable(System.getenv("DMJ_TSA_USER")).orElse("");
  static final String TSA_PASS = Optional.ofNullable(System.getenv("DMJ_TSA_PASS")).orElse("");
  static final String TSA_POLICY_OID = Optional.ofNullable(System.getenv("DMJ_TSA_POLICY_OID")).orElse("");
  static final String TSA_HASH = Optional.ofNullable(System.getenv("DMJ_TSA_HASH")).orElse("SHA-256"); // SHA-256/384/512
  static final int TSA_TIMEOUT_MS = Integer.parseInt(Optional.ofNullable(System.getenv("DMJ_TSA_TIMEOUT_MS")).orElse("10000"));
  static final boolean TS_ON_SIGNATURE = !"0".equals(Optional.ofNullable(System.getenv("DMJ_TS_ON_SIGNATURE")).orElse("0"));
  static final boolean ADD_DOC_TIMESTAMP = !"0".equals(Optional.ofNullable(System.getenv("DMJ_ADD_DOC_TIMESTAMP")).orElse("0")); // for B-LTA
  static final String OCSP_URL_ENV = Optional.ofNullable(System.getenv("DMJ_OCSP_URL")).orElse(""); // optional; CRL is used anyway

  static { Security.addProvider(new BouncyCastleProvider()); }

  // load ICA cert once for issuedByUs checks
  static X509Certificate readX509(Path p) throws Exception {
    try (InputStream in = Files.newInputStream(p)) {
      return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }
  }
  static final X509Certificate ICA_CERT;
  static {
    X509Certificate tmp;
    try { tmp = readX509(ICA_DIR.resolve("ica.crt")); } catch(Exception e){ tmp = null; }
    ICA_CERT = tmp;
  }

  // --- helper: generate per-document cert via OpenSSL CA ---
  static class DocMaterial {
    final PrivateKey priv; final X509Certificate leaf;
    final List<X509Certificate> chain; final String serialHex;
    DocMaterial(PrivateKey p, X509Certificate c, List<X509Certificate> ch, String s){priv=p;leaf=c;chain=ch;serialHex=s;}
  }
  static DocMaterial issueDocCert(String cn) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(3072);
    KeyPair kp = kpg.generateKeyPair();
    X500Name subject = new X500Name("C=IN,O=dmj.one Trust Services,OU=Document Signing,CN="+cn);
    PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic())
      .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate()));
    Path csrPem = Files.createTempFile("dmj", ".csr");
    try (JcaPEMWriter pw = new JcaPEMWriter(Files.newBufferedWriter(csrPem))) { pw.writeObject(csr); }
    Path certPem = Files.createTempFile("dmj", ".crt");
    Process p = new ProcessBuilder(
        OPENSSL, "ca", "-batch",
        "-config", ICA_DIR.resolve("openssl.cnf").toString(),
        "-extensions", "usr_cert", "-days", "365", "-md", "sha256", "-notext",
        "-in", csrPem.toString(), "-out", certPem.toString()
    ).inheritIO().start();
    if (p.waitFor() != 0) throw new RuntimeException("openssl ca failed");
    X509Certificate leaf = readX509(certPem);
    String serialHex = leaf.getSerialNumber().toString(16).toUpperCase(Locale.ROOT);
    List<X509Certificate> chain = new ArrayList<>();
    chain.add(leaf);
    chain.add(readX509(ICA_DIR.resolve("ica.crt")));
    try { Files.deleteIfExists(csrPem); } catch (Exception ignore) {}
    try { Files.deleteIfExists(certPem); } catch (Exception ignore) {}
    return new DocMaterial(kp.getPrivate(), leaf, chain, serialHex);
  }

  // --- revoke helpers (unchanged) ---
  static String normHex(String h) {
    String s = h.trim();
    if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
    s = s.replaceFirst("^[0]+", "");
    if (s.isEmpty()) s = "0";
    return s.toUpperCase(Locale.ROOT);
  }
  static class IndexRow { final char status; final String serial; final String filename;
    IndexRow(char status, String serial, String filename) { this.status = status; this.serial = serial; this.filename = filename; } }
  static IndexRow findInIndex(String serialHex) throws IOException {
    String want = normHex(serialHex);
    Path idx = ICA_DIR.resolve("index.txt");
    if (!Files.exists(idx)) return null;
    try (BufferedReader br = Files.newBufferedReader(idx)) {
      for (String ln; (ln = br.readLine()) != null; ) {
        if (ln.isBlank() || ln.startsWith("#")) continue;
        String[] parts = ln.split("\\t");
        if (parts.length < 5) parts = ln.split("\\s+");
        if (parts.length < 5) continue;
        String ser = normHex(parts[3]);
        if (ser.equalsIgnoreCase(want)) {
          char st = parts[0].isEmpty() ? '?' : parts[0].charAt(0);
          String fn = parts[4];
          return new IndexRow(st, ser, fn);
        }
      }
    }
    return null;
  }
  static boolean revokeBySerialHex(String serialHex) throws Exception {
    IndexRow row = findInIndex(serialHex);
    if (row != null && (row.status == 'R' || row.status == 'r')) { /* idempotent */ }
    else {
      Path certPath;
      if (row != null && !"unknown".equalsIgnoreCase(row.filename)) {
        certPath = ICA_DIR.resolve(row.filename);
        if (!certPath.isAbsolute()) certPath = ICA_DIR.resolve(row.filename);
      } else {
        String sHex = normHex(serialHex);
        certPath = ICA_DIR.resolve("newcerts").resolve(sHex + ".pem");
      }
      ProcessBuilder pb = new ProcessBuilder(OPENSSL, "ca",
        "-config", ICA_DIR.resolve("openssl.cnf").toString(),
        "-revoke", certPath.toString(),
        "-crl_reason", "superseded");
      pb.redirectErrorStream(true);
      Process p = pb.start();
      String out;
      try (InputStream is = p.getInputStream()) { out = new String(is.readAllBytes(), StandardCharsets.UTF_8); }
      int rc = p.waitFor();
      if (rc != 0 && (row == null || row.status != 'R')) {
        log.error("openssl revoke failed rc={}, output={}", rc, out);
        if (out == null || !out.toLowerCase(Locale.ROOT).contains("already revoked")) {
          throw new RuntimeException("revoke failed: " + rc);
        }
      }
    }
    Process g = new ProcessBuilder(OPENSSL, "ca",
      "-config", ICA_DIR.resolve("openssl.cnf").toString(),
      "-gencrl", "-out", ICA_DIR.resolve("ica.crl").toString()
    ).inheritIO().start();
    if (g.waitFor()!=0) throw new RuntimeException("gencrl failed");
    Files.copy(ICA_DIR.resolve("ica.crl"),
               PKI_PUB.resolve("dmj-one-issuing-ca-r1.crl"),
               java.nio.file.StandardCopyOption.REPLACE_EXISTING,
               java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
    Files.copy(ICA_DIR.resolve("ica.crl"),
               PKI_PUB.resolve("ica.crl"),
               java.nio.file.StandardCopyOption.REPLACE_EXISTING,
               java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
    return (row == null || row.status != 'R');
  }

  static class Keys { final PrivateKey priv; final X509Certificate cert; final List<X509Certificate> chain;
    Keys(PrivateKey p, X509Certificate c, List<X509Certificate> ch){ this.priv=p; this.cert=c; this.chain=ch; } }
  static Keys loadKeys() throws Exception {
    char[] pass = Files.readString(P12_PASS).trim().toCharArray();
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(P12_PATH)) { ks.load(in, pass); }
    PrivateKey pk = (PrivateKey) ks.getKey(P12_ALIAS, pass);
    X509Certificate leaf = (X509Certificate) ks.getCertificate(P12_ALIAS);
    java.security.cert.Certificate[] chainArr = ks.getCertificateChain(P12_ALIAS);
    List<X509Certificate> chain = new ArrayList<>();
    if (chainArr != null) for (java.security.cert.Certificate c : chainArr) chain.add((X509Certificate) c);
    else chain.add(leaf);
    return new Keys(pk, leaf, chain);
  }

  static String spkiBase64(X509Certificate cert) throws IOException {
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(cert.getPublicKey().getEncoded());
    return Base64.toBase64String(spki.getEncoded());
  }

  static boolean verifyHmac(String sharedBase64, String method, String path, byte[] body, String ts, String nonceB64, String providedB64) throws Exception {
    long now = Instant.now().getEpochSecond();
    long t = Long.parseLong(ts);
    if (Math.abs(now - t) > 300) return false;
    synchronized (RECENT_NONCES) {
      if (RECENT_NONCES.contains(nonceB64)) return false;
      RECENT_NONCES.add(nonceB64);
      if (RECENT_NONCES.size() > 1000) RECENT_NONCES.iterator().remove();
    }
    byte[] secret = Base64.decode(sharedBase64);
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(secret, "HmacSHA256"));
    mac.update(method.getBytes(StandardCharsets.UTF_8)); mac.update((byte) 0);
    mac.update(path.getBytes(StandardCharsets.UTF_8));   mac.update((byte) 0);
    mac.update(ts.getBytes(StandardCharsets.UTF_8));     mac.update((byte) 0);
    mac.update(Base64.decode(nonceB64));                 mac.update((byte) 0);
    mac.update(body);
    byte[] expected = mac.doFinal();
    byte[] provided = java.util.Base64.getDecoder().decode(providedB64);
    return MessageDigest.isEqual(expected, provided);
  }

  // Build a detached CMS over the exact ByteRange bytes and embed the chain
  static byte[] buildDetachedCMS(InputStream content, PrivateKey pk, List<X509Certificate> chain) throws Exception {
    byte[] toSign = IOUtils.toByteArray(content);
    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pk);
    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    gen.addSignerInfoGenerator(
      new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
        .build(signer, chain.get(0)) // leaf
    );
    gen.addCertificates(new JcaCertStore(chain)); // include chain
    CMSTypedData msg = new CMSProcessableByteArray(toSign);
    CMSSignedData cms = gen.generate(msg, false); // detached

    // Optionally add RFC 3161 signature-time-stamp unsigned attribute (B-T-ish)
    if (!TSA_URL.isBlank() && TS_ON_SIGNATURE) {
      cms = addSignatureTimeStampAttribute(cms);
    }
    return cms.getEncoded();
  }

  // Optional: make it a certification signature (DocMDP). P=1/2/3.
  static void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions) {
    COSDictionary sigDict = signature.getCOSObject();
    COSDictionary transformParams = new COSDictionary();
    transformParams.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
    transformParams.setName(COSName.V, "1.2");
    transformParams.setInt(COSName.P, accessPermissions);
    COSDictionary refDict = new COSDictionary();
    refDict.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
    refDict.setItem(COSName.TRANSFORM_METHOD, COSName.DOCMDP);
    refDict.setItem(COSName.D, transformParams);
    COSArray refArray = new COSArray();
    refArray.add(refDict);
    sigDict.setItem(COSName.REFERENCE, refArray);
    COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
    COSDictionary perms = (COSDictionary) catalog.getDictionaryObject(COSName.PERMS);
    if (perms == null) { perms = new COSDictionary(); catalog.setItem(COSName.PERMS, perms); }
    perms.setItem(COSName.DOCMDP, sigDict);
  }

  static int resolveDocMDP() {
    String mode = Optional.ofNullable(System.getenv("DMJ_SIGN_MODE")).orElse("approval").toLowerCase(Locale.ROOT);
    return switch (mode) {
      case "certify-p1" -> 1;
      case "certify-p2" -> 2;
      case "certify-p3" -> 3;
      default -> 0;
    };
  }

  // Invisible approval/certification signature using external signing (PAdES subFilter)
  static byte[] signPdf(byte[] original, PrivateKey pk, List<X509Certificate> chain) throws Exception {
    String sigName = Optional.ofNullable(System.getenv("DMJ_SIG_NAME")).orElse("dmj.one");
    String sigLoc = Optional.ofNullable(System.getenv("DMJ_SIG_LOCATION")).orElse("IN");
    String sigReason = Optional.ofNullable(System.getenv("DMJ_SIG_REASON")).orElse("Contents securely verified by dmj.one against any tampering.");
    String contact = Optional.ofNullable(System.getenv("DMJ_CONTACT_EMAIL")).orElse("contact@dmj.one");

    try (PDDocument doc = Loader.loadPDF(original);
         ByteArrayOutputStream baos = new ByteArrayOutputStream(original.length + 65536)) {

      PDSignature sig = new PDSignature();
      sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      // ← switch to ETSI.CAdES.detached (PAdES)
      sig.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
      sig.setName(sigName);
      sig.setLocation(sigLoc);
      sig.setReason(sigReason);
      sig.setContactInfo(contact);
      sig.setSignDate(Calendar.getInstance());

      int mdp = resolveDocMDP();
      if (mdp != 0) setMDPPermission(doc, sig, mdp);

      SignatureOptions opts = new SignatureOptions();
      // generous space to allow signature-time-stamp attribute if enabled
      opts.setPreferredSignatureSize(131072);

      doc.addSignature(sig, opts); // invisible
      ExternalSigningSupport ext = doc.saveIncrementalForExternalSigning(baos);
      byte[] cms = buildDetachedCMS(ext.getContent(), pk, chain);
      ext.setSignature(cms);

      return baos.toByteArray();
    }
  }

  static String toHex(byte[] b){ StringBuilder sb=new StringBuilder(b.length*2); for(byte x:b) sb.append(String.format("%02x",x)); return sb.toString(); }
  static String toHexUpper(byte[] b){ StringBuilder sb=new StringBuilder(b.length*2); for(byte x:b) sb.append(String.format("%02X",x)); return sb.toString(); }
  static String jcaDigestNameFromOid(String oid){
    return switch (oid) {
      case "1.3.14.3.2.26" -> "SHA-1";
      case "2.16.840.1.101.3.4.2.1" -> "SHA-256";
      case "2.16.840.1.101.3.4.2.2" -> "SHA-384";
      case "2.16.840.1.101.3.4.2.3" -> "SHA-512";
      case "2.16.840.1.101.3.4.2.4" -> "SHA-224";
      default -> "SHA-256";
    };
  }

  static Map<String,Object> verifyPdf(byte[] input, X509Certificate ourCert) throws Exception {
    Map<String,Object> out = new LinkedHashMap<>();
    boolean any = false, anyValid = false, issuedByUs = false, coversDoc = false;
    String issuerDn = "", subFilter = "", errorMsg = "";
    Map<String,Object> debug = new LinkedHashMap<>();

    try (PDDocument doc = Loader.loadPDF(input)) {
      int sigIndex = 0;
      for (PDSignature s : doc.getSignatureDictionaries()) {
        any = true; sigIndex++;
        subFilter = String.valueOf(s.getSubFilter());

        int[] br = s.getByteRange();
        if (br != null && br.length == 4) {
          long len = input.length;
          long a = br[0], b = br[1], c = br[2], d = br[3];
          coversDoc = (a == 0) && (c + d == len) && (c >= b);
          debug.put("sig"+sigIndex+".byteRange", List.of(br[0],br[1],br[2],br[3]));
        }

        byte[] cms = s.getContents(input);
        byte[] signedContent = s.getSignedContent(new ByteArrayInputStream(input));

        debug.put("sig"+sigIndex+".cms.len", cms != null ? cms.length : 0);
        debug.put("sig"+sigIndex+".signedContent.len", signedContent.length);
        debug.put("sig"+sigIndex+".signedContent.prefix32.hex",
                  toHex(Arrays.copyOf(signedContent, Math.min(32, signedContent.length))));

        try {
          CMSSignedData sd = new CMSSignedData(new CMSProcessableByteArray(signedContent), cms);

          for (SignerInformation si : sd.getSignerInfos().getSigners()) {
            byte[] mdAttrBytes = null;
            AttributeTable at = si.getSignedAttributes();
            if (at != null) {
              Attribute md = at.get(CMSAttributes.messageDigest);
              if (md != null) {
                ASN1Primitive v = md.getAttrValues().getObjectAt(0).toASN1Primitive();
                mdAttrBytes = ((ASN1OctetString) v).getOctets();
              }
            }
            String jcaName = jcaDigestNameFromOid(si.getDigestAlgOID());
            byte[] calc = MessageDigest.getInstance(jcaName).digest(signedContent);
            debug.put("sig"+sigIndex+".recalc.messageDigest.hex", toHex(calc));

            Collection<X509CertificateHolder> matches = sd.getCertificates().getMatches(si.getSID());
            if (matches.isEmpty()) continue;
            X509CertificateHolder signerHolder = matches.iterator().next();
            boolean ok = si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerHolder));
            anyValid |= ok;

            if (ok) {
              try {
                if (ICA_CERT != null) {
                  var store = sd.getCertificates();
                  X509CertificateHolder issuerHolder = null;
                  for (var h : store.getMatches(null)) {
                    X509CertificateHolder ch = (X509CertificateHolder) h;
                    if (ch.getSubject().equals(signerHolder.getIssuer())) { issuerHolder = ch; break; }
                  }
                  if (issuerHolder != null) {
                    byte[] a = issuerHolder.getSubjectPublicKeyInfo().getEncoded();
                    byte[] b = SubjectPublicKeyInfo.getInstance(ICA_CERT.getPublicKey().getEncoded()).getEncoded();
                    if (java.util.Arrays.equals(a, b)) issuedByUs = true;
                  }
                }
              } catch (Exception ex) { /* ignore */ }
            }
            issuerDn = signerHolder.getIssuer().toString();
          }
        } catch (Exception e) {
          errorMsg = "exception: " + e.getClass().getSimpleName() + (e.getMessage()!=null?(" - " + e.getMessage()):"");
          e.printStackTrace();
        }
      }
    }

    out.put("hasSignature", any);
    out.put("isValid", anyValid);
    out.put("issuedByUs", issuedByUs);
    out.put("coversDocument", coversDoc);
    out.put("issuer", issuerDn);
    out.put("subFilter", subFilter);
    if (errorMsg != null) out.put("error", errorMsg);
    out.put("debug", debug);
    return out;
  }

  static final String PKI_BASE = Optional.ofNullable(System.getenv("DMJ_PKI_BASE"))
                                         .orElse("https://pki.dmj.one");

  static void addZipFile(ZipOutputStream zos, Path src, String name) throws IOException {
    if (!Files.exists(src)) return;
    zos.putNextEntry(new ZipEntry(name));
    Files.copy(src, zos);
    zos.closeEntry();
  }

  static Path writeBundleZip(byte[] signedPdf, String baseName) throws IOException {
    Files.createDirectories(PKI_PUB.resolve("dl"));
    String fname = baseName + ".zip";
    Path out = PKI_PUB.resolve("dl").resolve(fname);

    try (ZipOutputStream zos = new ZipOutputStream(
         Files.newOutputStream(out, java.nio.file.StandardOpenOption.CREATE,
                                    java.nio.file.StandardOpenOption.TRUNCATE_EXISTING))) {
      zos.putNextEntry(new ZipEntry("signed.pdf"));
      zos.write(signedPdf);
      zos.closeEntry();
      addZipFile(zos, PKI_PUB.resolve("dmj-one-root-ca-r1.cer"), "trust-kit/dmj-one-root-ca-r1.cer");
      addZipFile(zos, PKI_PUB.resolve("dmj-one-root-ca-r1.crt"), "trust-kit/dmj-one-root-ca-r1.crt");
      addZipFile(zos, PKI_PUB.resolve("dmj-one-issuing-ca-r1.crt"), "trust-kit/dmj-one-issuing-ca-r1.crt");
      addZipFile(zos, PKI_PUB.resolve("dmj-one-trust-kit-README.txt"), "trust-kit/README.txt");
      addZipFile(zos, PKI_PUB.resolve("dmj-one-trust-kit-README.html"), "trust-kit/README.html");
      addZipFile(zos, PKI_PUB.resolve("dmj-one-trust-kit-SHA256SUMS.txt"), "trust-kit/SHA256SUMS.txt");
    }
    return out;
  }

  // --- PDF metadata pre-sign (unchanged) ---
  static byte[] applyDocInfoPreSign(byte[] in) {
    String title    = Optional.ofNullable(System.getenv("DMJ_PDF_TITLE")).orElse("").trim();
    String author   = Optional.ofNullable(System.getenv("DMJ_PDF_AUTHOR")).orElse("").trim();
    String subject  = Optional.ofNullable(System.getenv("DMJ_PDF_SUBJECT")).orElse("").trim();
    String keywords = Optional.ofNullable(System.getenv("DMJ_PDF_KEYWORDS")).orElse("").trim();
    String creator  = Optional.ofNullable(System.getenv("DMJ_PDF_CREATOR")).orElse("").trim();
    String producer = Optional.ofNullable(System.getenv("DMJ_PDF_PRODUCER")).orElse("").trim();
    String verStr   = Optional.ofNullable(System.getenv("DMJ_PDF_VERSION")).orElse("").trim();
    String created  = Optional.ofNullable(System.getenv("DMJ_PDF_CREATED_ON")).orElse("").trim();
    String modified = Optional.ofNullable(System.getenv("DMJ_PDF_MODIFIED_ON")).orElse("").trim();
    boolean setDatesByDefault = !"0".equals(Optional.ofNullable(System.getenv("DMJ_PDF_SET_DATES")).orElse("1"));

    if (title.isEmpty() && author.isEmpty() && subject.isEmpty() && keywords.isEmpty()
        && creator.isEmpty() && producer.isEmpty() && verStr.isEmpty()
        && !setDatesByDefault && created.isEmpty() && modified.isEmpty()) {
      return in;
    }

    try (PDDocument doc = Loader.loadPDF(in);
         ByteArrayOutputStream out = new ByteArrayOutputStream(in.length + 8192)) {

      PDDocumentInformation info = doc.getDocumentInformation();
      if (!title.isEmpty())    info.setTitle(title);
      if (!author.isEmpty())   info.setAuthor(author);
      if (!subject.isEmpty())  info.setSubject(subject);
      if (!keywords.isEmpty()) info.setKeywords(keywords);
      if (!creator.isEmpty())  info.setCreator(creator);
      if (!producer.isEmpty()) info.setProducer(producer);

      Calendar now = Calendar.getInstance();
      if (setDatesByDefault) {
        if (info.getCreationDate() == null) info.setCreationDate(now);
        info.setModificationDate(now);
      }
      Calendar c;
      if (!(c = parseCal(created)).equals(NULL_CAL))  info.setCreationDate(c);
      if (!(c = parseCal(modified)).equals(NULL_CAL)) info.setModificationDate(c);
      if (!verStr.isEmpty()) { try { doc.setVersion(Float.parseFloat(verStr)); } catch (Exception ignore) {} }

      doc.setDocumentInformation(info);
      doc.save(out);
      return out.toByteArray();
    } catch (Exception e) {
      return in;
    }
  }

  private static final Calendar NULL_CAL = new Calendar.Builder().setInstant(0L).build();
  static Calendar parseCal(String txt) {
    if (txt == null || txt.isBlank()) return NULL_CAL;
    try {
      long secs = Long.parseLong(txt.trim());
      Calendar c = Calendar.getInstance(); c.setTimeInMillis(secs * 1000L); return c;
    } catch (Exception ignore) {}
    try {
      Instant i = Instant.parse(txt.trim());
      Calendar c = Calendar.getInstance(); c.setTime(Date.from(i)); return c;
    } catch (Exception ignore) {}
    return NULL_CAL;
  }

  // === TSA + DSS helpers =====================================================

  /** Map digest JCA name to OID used by RFC 3161 messageImprint */
  static String tsaDigestOid(String jca) {
    return switch (jca.toUpperCase(Locale.ROOT)) {
      case "SHA-1" -> "1.3.14.3.2.26";
      case "SHA-224" -> "2.16.840.1.101.3.4.2.4";
      case "SHA-256" -> "2.16.840.1.101.3.4.2.1";
      case "SHA-384" -> "2.16.840.1.101.3.4.2.2";
      case "SHA-512" -> "2.16.840.1.101.3.4.2.3";
      default -> "2.16.840.1.101.3.4.2.1";
    };
  }

  /** Basic RFC 3161 client (HTTP POST application/timestamp-query) */
  static TimeStampToken requestTSToken(byte[] dataToHash, String jcaDigest) throws Exception {
    String oid = tsaDigestOid(jcaDigest);
    byte[] imprint = MessageDigest.getInstance(jcaDigest).digest(dataToHash);

    TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
    gen.setCertReq(true);
    if (!TSA_POLICY_OID.isBlank()) gen.setReqPolicy(new ASN1ObjectIdentifier(TSA_POLICY_OID));
    TimeStampRequest req = gen.generate(new ASN1ObjectIdentifier(oid), imprint, new BigInteger(64, new SecureRandom()));
    byte[] body = req.getEncoded();

    HttpURLConnection conn = (HttpURLConnection) new URL(TSA_URL).openConnection();
    conn.setConnectTimeout(TSA_TIMEOUT_MS);
    conn.setReadTimeout(TSA_TIMEOUT_MS);
    conn.setDoOutput(true);
    conn.setRequestMethod("POST");
    conn.setRequestProperty("Content-Type", "application/timestamp-query");
    conn.setRequestProperty("Accept", "application/timestamp-reply");
    if (!TSA_USER.isBlank() || !TSA_PASS.isBlank()) {
      String basic = java.util.Base64.getEncoder().encodeToString((TSA_USER + ":" + TSA_PASS).getBytes(StandardCharsets.UTF_8));
      conn.setRequestProperty("Authorization", "Basic " + basic);
    }
    try (OutputStream os = conn.getOutputStream()) { os.write(body); }
    int code = conn.getResponseCode();
    if (code != 200) throw new IOException("TSA HTTP " + code);
    byte[] resp;
    try (InputStream is = conn.getInputStream()) { resp = is.readAllBytes(); }
    TimeStampResponse tsr = new TimeStampResponse(resp);
    tsr.validate(req);
    if (tsr.getTimeStampToken() == null) throw new IOException("TSA response without token, status=" + tsr.getStatus());
    return tsr.getTimeStampToken();
  }

  /** Add signature-time-stamp (id-aa-signatureTimeStampToken) to first signer. */
  static CMSSignedData addSignatureTimeStampAttribute(CMSSignedData cms) throws Exception {
    Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
    if (signers.isEmpty()) return cms;
    SignerInformation si = signers.iterator().next();

    // Hash the raw signature value per RFC 3161 guidance for signature-time-stamp
    byte[] sigValue = si.getSignature();
    TimeStampToken token = requestTSToken(sigValue, TSA_HASH);

    Attribute tsAttr = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
      new DERSet(ASN1Primitive.fromByteArray(token.getEncoded())));

    AttributeTable unsigned = si.getUnsignedAttributes();
    java.util.Hashtable<ASN1ObjectIdentifier, Attribute> ht =
        (unsigned != null) ? unsigned.toHashtable() : new java.util.Hashtable<>();
    ht.put(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, tsAttr);

    SignerInformation newSi =
        SignerInformation.replaceUnsignedAttributes(si, new AttributeTable(ht));

    SignerInformationStore newStore = new SignerInformationStore(Collections.singleton(newSi));
    return CMSSignedData.replaceSigners(cms, newStore);
  }

  /** Create (or reuse) DSS and add Certs/CRLs (+ optional OCSP), and a VRI entry for the latest signature. */
  static byte[] addDSS_LTV(byte[] pdf, List<X509Certificate> chain) throws Exception {
    try (PDDocument doc = Loader.loadPDF(pdf);
         ByteArrayOutputStream out = new ByteArrayOutputStream(pdf.length + 65536)) {

      // Find last signature dictionary
      PDSignature lastSig = null;
      for (PDSignature s : doc.getSignatureDictionaries()) lastSig = s;
      if (lastSig == null) return pdf;

      byte[] cms = lastSig.getContents(pdf);
      byte[] sigHash = MessageDigest.getInstance("SHA-1").digest(cms); // ETSI PAdES: VRI key = SHA-1 of signature value (hex, uppercase)
      String sigHashHex = toHexUpper(sigHash);

      // Prepare DSS containers
      COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
      catalog.setNeedToBeUpdated(true);
      COSDictionary dss = getOrCreateDict(catalog, "DSS");
      COSDictionary vriBase = getOrCreateDict(dss, "VRI");
      COSArray certsArr = getOrCreateArray(dss, "Certs");
      COSArray crlsArr = getOrCreateArray(dss, "CRLs");
      COSArray ocspsArr = getOrCreateArray(dss, "OCSPs"); // may remain empty

      // Write chain into Certs
      List<COSStream> chainStreams = new ArrayList<>();
      for (X509Certificate xc : chain) {
        COSStream s = doc.getDocument().createCOSStream();
        try (OutputStream os = s.createOutputStream(COSName.FLATE_DECODE)) { os.write(xc.getEncoded()); }
        chainStreams.add(s);
        certsArr.add(s);
      }

      // Add CRL if available (publishes at $ICA_DIR/ica.crl and $PKI_PUB/ica.crl)
      Path crlPath = Files.exists(ICA_DIR.resolve("ica.crl")) ? ICA_DIR.resolve("ica.crl") : PKI_PUB.resolve("ica.crl");
      List<COSStream> crlStreams = new ArrayList<>();
      if (Files.exists(crlPath)) {
        byte[] crlBytes = Files.readAllBytes(crlPath);
        COSStream cs = doc.getDocument().createCOSStream();
        try (OutputStream os = cs.createOutputStream(COSName.FLATE_DECODE)) { os.write(crlBytes); }
        crlsArr.add(cs);
        crlStreams.add(cs);
      }

      // (Optional) OCSP – if you expose an OCSP URL, you can query and embed here.
      // For B-LT CRL alone is sufficient per PAdES profile; keeping OCSP optional. (See PDFBox AddValidationInformation.) :contentReference[oaicite:3]{index=3}

      // Build VRI for this signature
      COSDictionary vri = new COSDictionary();
      COSArray vriCerts = new COSArray(); chainStreams.forEach(vriCerts::add);
      vri.setItem(COSName.CERT, vriCerts);
      if (!crlStreams.isEmpty()) {
        COSArray vriCrls = new COSArray(); crlStreams.forEach(vriCrls::add);
        vri.setItem(COSName.CRL, vriCrls);
      }
      vri.setDate(COSName.TU, Calendar.getInstance());
      vriBase.setItem(COSName.getPDFName(sigHashHex), vri);

      // Mark Extensions per PAdES (ADBE extension level 5) – as in PDFBox example.
      addPadesExtensions(doc);

      // Save incremental
      doc.saveIncremental(out);
      return out.toByteArray();
    }
  }

  static COSDictionary getOrCreateDict(COSDictionary parent, String name) {
    COSBase el = parent.getDictionaryObject(name);
    if (el instanceof COSDictionary d) { d.setNeedToBeUpdated(true); return d; }
    COSDictionary d = new COSDictionary(); d.setDirect(false);
    parent.setItem(COSName.getPDFName(name), d);
    return d;
  }
  static COSArray getOrCreateArray(COSDictionary parent, String name) {
    COSBase el = parent.getDictionaryObject(name);
    if (el instanceof COSArray a) { a.setNeedToBeUpdated(true); return a; }
    COSArray a = new COSArray(); parent.setItem(COSName.getPDFName(name), a); return a;
  }
  static void addPadesExtensions(PDDocument doc) {
    COSDictionary dssExtensions = new COSDictionary(); dssExtensions.setDirect(true);
    doc.getDocumentCatalog().getCOSObject().setItem(COSName.EXTENSIONS, dssExtensions);
    COSDictionary adbeExtension = new COSDictionary(); adbeExtension.setDirect(true);
    dssExtensions.setItem(COSName.ADBE, adbeExtension);
    adbeExtension.setName(COSName.BASE_VERSION, "1.7");
    adbeExtension.setInt(COSName.EXTENSION_LEVEL, 5);
    doc.getDocumentCatalog().setVersion("1.7");
  }

  /** Append an ETSI.RFC3161 DocTimeStamp covering the whole document (for B‑LTA). */
  static byte[] addDocumentTimeStamp(byte[] pdf) throws Exception {
    if (TSA_URL.isBlank()) return pdf;
    try (PDDocument doc = Loader.loadPDF(pdf);
         ByteArrayOutputStream baos = new ByteArrayOutputStream(pdf.length + 65536)) {

      PDSignature ts = new PDSignature();
      ts.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      ts.setSubFilter(COSName.getPDFName("ETSI.RFC3161"));
      ts.setName("Time Stamp");
      ts.setSignDate(Calendar.getInstance());

      SignatureOptions opts = new SignatureOptions();
      opts.setPreferredSignatureSize(65536);

      doc.addSignature(ts, opts);
      ExternalSigningSupport ext = doc.saveIncrementalForExternalSigning(baos);
      // Hash the exact byte ranges provided by PDFBox and ask TSA for a token over it.
      byte[] contentBytes = IOUtils.toByteArray(ext.getContent());
      TimeStampToken token = requestTSToken(contentBytes, TSA_HASH);
      ext.setSignature(token.getEncoded());

      return baos.toByteArray();
    }
  }

  /** LTV/LTA post-process: add DSS (B‑LT) and optional Document Time‑Stamp (B‑LTA). */
  static byte[] postProcessLTV_LTA(byte[] pdf, List<X509Certificate> chain) {
    byte[] out = pdf;
    try {
      out = addDSS_LTV(out, chain); // B‑LT
      if (ADD_DOC_TIMESTAMP && !TSA_URL.isBlank()) {
        out = addDocumentTimeStamp(out); // B‑LTA
      }
    } catch (Exception e) {
      log.warn("LTV/LTA post-processing failed: {}", String.valueOf(e));
    }
    return out;
  }

  // === HTTP API =============================================================

  public static void main(String[] args) throws Exception {
    String issuer = Optional.ofNullable(System.getenv("DMJ_ISSUER")).orElse("dmj.one");
    String shared = Optional.ofNullable(System.getenv("SIGNING_GATEWAY_HMAC_KEY")).orElse("");
    int port = choosePort();

    Keys keys = loadKeys();
    String spki = spkiBase64(keys.cert);

    Javalin app = Javalin.create(cfg -> {
      cfg.http.defaultContentType = "application/json";
      cfg.showJavalinBanner = false;
      boolean httpLog = !"0".equals(Optional.ofNullable(System.getenv("DMJ_HTTP_LOG")).orElse("1"));
      if (httpLog) { try { cfg.bundledPlugins.enableDevLogging(); } catch (Throwable t) { /* ignore */ } }
    });

    app.get("/", ctx -> ctx.result("ok"));
    app.get("/spki", ctx -> ctx.json(Map.of("spki", spki, "issuer", issuer)));

    app.post("/verify", ctx -> {
      try {
        UploadedFile f = ctx.uploadedFile("file");
        if (f == null) { ctx.status(400).json(Map.of("error","file missing")); return; }
        byte[] data = IOUtils.toByteArray(f.content());
        Map<String,Object> v = verifyPdf(data, keys.cert);
        ctx.json(v);
      } catch (Exception e) {
        ctx.status(200).json(Map.of("hasSignature", false,"isValid", false,"issuedByUs", false,"coversDocument", false,"issuer","", "subFilter","", "error","exception: " + e.getClass().getSimpleName()));
      }
    });

    app.post("/bundle", ctx -> {
      String hmac = ctx.header(HMAC_HEADER), ts = ctx.header(HMAC_TS), nonce = ctx.header(HMAC_NONCE);
      if (hmac==null || ts==null || nonce==null) { ctx.status(401).json(Map.of("error","missing auth")); return; }
      UploadedFile f = ctx.uploadedFile("file");
      if (f==null){ ctx.status(400).json(Map.of("error","file missing")); return; }
      byte[] original = IOUtils.toByteArray(f.content());

      boolean ok;
      try { ok = verifyHmac(Optional.ofNullable(System.getenv("SIGNING_GATEWAY_HMAC_KEY")).orElse(""),
                            "POST", "/bundle", original, ts, nonce, hmac);
      } catch(Exception e){ ok=false; }
      if (!ok) { ctx.status(401).json(Map.of("error","bad auth")); return; }

      try {
        byte[] prepared = applyDocInfoPreSign(original);
        byte[] signed = signPdf(prepared, keys.priv, keys.chain);
        signed = postProcessLTV_LTA(signed, keys.chain);
        String base = "dmj-one-" + java.util.UUID.randomUUID().toString().replace("-", "").substring(0,12);
        Path zipPath = writeBundleZip(signed, base);
        String rel = "/dl/" + zipPath.getFileName().toString();
        String url = PKI_BASE + rel;
        ctx.json(Map.of("download", url));
      } catch (Exception e) {
        e.printStackTrace();
        ctx.status(500).json(Map.of("error","bundle failed", "detail", String.valueOf(e)));
      }
    });

    app.post("/sign", ctx -> {
      if (shared.isBlank()) { ctx.status(500).json(Map.of("error","server not configured")); return; }
      String hmac = ctx.header(HMAC_HEADER), ts = ctx.header(HMAC_TS), nonce = ctx.header(HMAC_NONCE);
      if (hmac==null || ts==null || nonce==null) { ctx.status(401).json(Map.of("error","missing auth")); return; }
      UploadedFile f = ctx.uploadedFile("file");
      if (f==null){ ctx.status(400).json(Map.of("error","file missing")); return; }
      byte[] data = IOUtils.toByteArray(f.content());
      boolean ok = false;
      try { ok = verifyHmac(shared, "POST", "/sign", data, ts, nonce, hmac); } catch(Exception e){ ok=false; }
      if (!ok) { ctx.status(401).json(Map.of("error","bad auth")); return; }

      try {
        log.info("sign: issuing one-off doc cert, size={} bytes", data.length);
        String cn = "dmj.one Trusted File " + java.util.UUID.randomUUID().toString().substring(0,8).toUpperCase();
        DocMaterial dm = issueDocCert(cn);

        byte[] prepared = applyDocInfoPreSign(data);
        byte[] signed = signPdf(prepared, dm.priv, dm.chain);
        signed = postProcessLTV_LTA(signed, dm.chain);

        ctx.contentType("application/pdf");
        ctx.header("X-Signed-By", issuer);
        ctx.header("X-Cert-Serial", dm.serialHex);
        ctx.result(new ByteArrayInputStream(signed));
      } catch (Exception e){
        e.printStackTrace();
        ctx.status(500).json(Map.of("error","sign failed", "detail", String.valueOf(e)));
      }
    });

    // HMAC‑gated: revoke by serial (updates CRL and publishes)
    app.post("/revoke", ctx -> {
      String hmac = ctx.header(HMAC_HEADER), ts = ctx.header(HMAC_TS), nonce = ctx.header(HMAC_NONCE);
      if (hmac==null || ts==null || nonce==null) { ctx.status(401).json(Map.of("error","missing auth")); return; }
      String serial = Optional.ofNullable(ctx.formParam("serial")).orElse("");
      byte[] body = ("serial="+serial).getBytes(StandardCharsets.UTF_8);
      boolean ok=false;
      try { ok = verifyHmac(shared, "POST", "/revoke", body, ts, nonce, hmac); } catch(Exception ignore){}
      if (!ok || serial.isBlank()) { ctx.status(401).json(Map.of("error","bad auth or serial missing")); return; }
      try {
        String norm = normHex(serial);
        log.info("revoke: requested serial={} (norm={})", serial, norm);
        boolean changed = revokeBySerialHex(norm);
        ctx.json(Map.of("revoked", true, "already", !changed, "serial", norm));
      }
      catch(Exception e){ e.printStackTrace(); ctx.status(500).json(Map.of("error","revoke failed","detail", String.valueOf(e))); }
    });

    app.get("/healthz", ctx -> ctx.result("ok"));
    app.start(port);
  }

  static int choosePort(){
    int[] candidates;
    String portsEnv = Optional.ofNullable(System.getenv("DMJ_SIGNER_PORTS")).orElse("");
    if (!portsEnv.isBlank()) {
      String[] parts = portsEnv.split(",");
      int[] arr = new int[parts.length];
      for (int i=0;i<parts.length;i++) arr[i] = Integer.parseInt(parts[i].trim());
      candidates = arr;
    } else { candidates = new int[]{18080,18081,18100,18200,19080,28080}; }
    for(int p: candidates){
      try(java.net.ServerSocket s = new java.net.ServerSocket()){
        s.setReuseAddress(true);
        s.bind(new java.net.InetSocketAddress("127.0.0.1", p));
        try { Files.writeString(Paths.get(Optional.ofNullable(System.getenv("DMJ_SIGNER_PORT_FILE")).orElse("/etc/dmj/signer.port")), ""+p); } catch(IOException ignored){}
        return p;
      } catch(IOException ignored){}
    }
    return 18080;
  }
}
JAVA
fix_perms


### --- Build a branded two-tier PKI + OCSP + signer PKCS#12 -------------------
say "[+] Preparing dmj.one PKI under ${PKI_DIR} ..."
sudo mkdir -p "${ROOT_DIR}/"{certs,newcerts,private} "${ICA_DIR}/"{certs,newcerts,private} "${OCSP_DIR}" "${PKI_PUB}"
sudo touch "${ROOT_DIR}/index.txt" "${ICA_DIR}/index.txt"
# Use long, uppercase hex serials so we have room for millions of document certs.
# OpenSSL reads this serial file as a hex integer and increments for each issuance.
# The newcerts filename is <SERIAL>.pem, matching this value.
# Ref: openssl-ca(1), index/newcerts behavior.
[ -f "${ROOT_DIR}/serial" ]    || printf '%s\n' "$(openssl rand -hex 16 | tr '[:lower:]' '[:upper:]')" | sudo tee "${ROOT_DIR}/serial" >/dev/null
[ -f "${ROOT_DIR}/crlnumber" ] || printf '%s\n' "$(openssl rand -hex 8  | tr '[:lower:]' '[:upper:]')" | sudo tee "${ROOT_DIR}/crlnumber" >/dev/null
[ -f "${ICA_DIR}/serial" ]     || printf '%s\n' "$(openssl rand -hex 20 | tr '[:lower:]' '[:upper:]')" | sudo tee "${ICA_DIR}/serial" >/dev/null
[ -f "${ICA_DIR}/crlnumber" ]  || printf '%s\n' "$(openssl rand -hex 8  | tr '[:lower:]' '[:upper:]')" | sudo tee "${ICA_DIR}/crlnumber" >/dev/null


# OpenSSL configs (root + issuing)
sudo tee "${ROOT_DIR}/openssl.cnf" >/dev/null <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir               = ${ROOT_DIR}
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/root.crt
private_key       = \$dir/root.key
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
default_md        = sha256
policy            = policy_strict
unique_subject    = no
x509_extensions   = v3_ca
crl_extensions    = crl_ext
default_days      = 3650
default_crl_days  = 30
[ policy_strict ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = supplied
commonName              = supplied
organizationalUnitName  = optional
[ req ]
default_bits        = 4096
string_mask         = utf8only
distinguished_name  = dn
[ dn ]
organizationName            = Organization (O)
organizationName_default    = ${ORG_NAME}
commonName                  = Common Name (CN)
commonName_default          = ${ROOT_CN}
[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
[ v3_intermediate_ca ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
crlDistributionPoints = URI:${AIA_SCHEME}://${PKI_DOMAIN}/root.crl
authorityInfoAccess   = caIssuers;URI:${AIA_SCHEME}://${PKI_DOMAIN}/root.crt
[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

sudo tee "${ICA_DIR}/openssl.cnf" >/dev/null <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir               = ${ICA_DIR}
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/ica.crt
private_key       = \$dir/ica.key
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
default_md        = sha256
policy            = policy_loose
unique_subject    = no
x509_extensions   = v3_intermediate_ca
crl_extensions    = crl_ext
default_days      = 1825
default_crl_days  = 7
[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = supplied
commonName              = supplied
organizationalUnitName  = optional
[ req ]
default_bits        = 4096
string_mask         = utf8only
distinguished_name  = dn
[ dn ]
organizationName            = Organization (O)
organizationName_default    = ${ORG_NAME}
organizationalUnitName      = OU
organizationalUnitName_default = Public CA
commonName                  = Common Name (CN)
commonName_default          = ${ICA_CN}
[ v3_intermediate_ca ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
authorityInfoAccess = caIssuers;URI:${AIA_SCHEME}://${PKI_DOMAIN}/ica.crt, OCSP;URI:${OCSP_AIA_SCHEME}://${OCSP_DOMAIN}/
crlDistributionPoints = URI:${AIA_SCHEME}://${PKI_DOMAIN}/ica.crl
[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = emailProtection, codeSigning, 1.3.6.1.4.1.311.10.3.12
subjectKeyIdentifier = hash
authorityInfoAccess = caIssuers;URI:${AIA_SCHEME}://${PKI_DOMAIN}/ica.crt, OCSP;URI:${OCSP_AIA_SCHEME}://${OCSP_DOMAIN}/
crlDistributionPoints = URI:${AIA_SCHEME}://${PKI_DOMAIN}/ica.crl
[ ocsp ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
authorityInfoAccess = OCSP;URI:${OCSP_AIA_SCHEME}://${OCSP_DOMAIN}/
crlDistributionPoints = URI:${AIA_SCHEME}://${PKI_DOMAIN}/ica.crl
[ tsa ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
authorityInfoAccess = OCSP;URI:${OCSP_AIA_SCHEME}://${OCSP_DOMAIN}/
crlDistributionPoints = URI:${AIA_SCHEME}://${PKI_DOMAIN}/ica.crl
[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF


if [ "$DMJ_REISSUE_ALL_HARD_RESET" = "1" ]; then
  say "[i] HARD RESET. REISSUE ALL is True. All certificates will be reissued..."
fi

if [ ! -f "${ROOT_DIR}/root.crt" ] || [ "$DMJ_REISSUE_ROOT" = "1" ]; then
  say "[+] Creating Root CA ..."
  openssl genrsa -out "${ROOT_DIR}/root.key" 4096
  openssl req -new -x509 -days 3650 -sha256 \
    -subj "/C=${COUNTRY}/O=${ORG_NAME}/CN=${ROOT_CN}" \
    -key "${ROOT_DIR}/root.key" -out "${ROOT_DIR}/root.crt" \
    -config "${ROOT_DIR}/openssl.cnf" -extensions v3_ca
  openssl ca -config "${ROOT_DIR}/openssl.cnf" -gencrl -out "${ROOT_DIR}/root.crl"
fi

if [ ! -f "${ICA_DIR}/ica.crt" ] || [ "$DMJ_REISSUE_ICA" = "1" ]; then
  say "[+] Creating Issuing CA ..."
  openssl genrsa -out "${ICA_DIR}/ica.key" 4096
  openssl req -new -sha256 \
    -subj "/C=${COUNTRY}/O=${ORG_NAME}/OU=Public CA/CN=${ICA_CN}" \
    -key "${ICA_DIR}/ica.key" -out "${ICA_DIR}/ica.csr"
  openssl ca -batch -config "${ROOT_DIR}/openssl.cnf" \
    -extensions v3_intermediate_ca -in "${ICA_DIR}/ica.csr" \
    -out "${ICA_DIR}/ica.crt" -days 1825 -md sha256 -notext
  cat "${ICA_DIR}/ica.crt" "${ROOT_DIR}/root.crt" > "${PKI_PUB}/dmj-one-ica-chain.pem"
  openssl ca -config "${ICA_DIR}/openssl.cnf" -gencrl -out "${ICA_DIR}/ica.crl"
fi

# OCSP responder cert (EKU=OCSPSigning)
if [ ! -f "${OCSP_DIR}/ocsp.crt" ] || [ "$DMJ_REISSUE_OCSP" = "1" ]; then
  say "[+] Issuing OCSP responder cert ..."
  openssl genrsa -out "${OCSP_DIR}/ocsp.key" 4096
  openssl req -new -sha256 \
    -subj "/C=${COUNTRY}/O=${ORG_NAME}/CN=${OCSP_CN}" \
    -key "${OCSP_DIR}/ocsp.key" -out "${OCSP_DIR}/ocsp.csr"
  openssl ca -batch -config "${ICA_DIR}/openssl.cnf" -extensions ocsp \
    -in "${OCSP_DIR}/ocsp.csr" -out "${OCSP_DIR}/ocsp.crt" -days 825 -md sha256 -notext
fi

# TSA certificate (EKU=timeStamping)
if [ ! -f "${TSA_DIR}/tsa.crt" ] || [ "${DMJ_REISSUE_TSA:-0}" = "1" ]; then
  say "[+] Issuing TSA certificate ..."
  openssl genrsa -out "${TSA_DIR}/tsa.key" 4096
  openssl req -new -sha256 \
    -subj "/C=${COUNTRY}/O=${ORG_NAME}/CN=${TSA_CN}" \
    -key "${TSA_DIR}/tsa.key" -out "${TSA_DIR}/tsa.csr"
  openssl ca -batch -config "${ICA_DIR}/openssl.cnf" -extensions tsa \
    -in "${TSA_DIR}/tsa.csr" -out "${TSA_DIR}/tsa.crt" -days 825 -md sha256 -notext
  sudo chmod 0600 "${TSA_DIR}/tsa.key"
fi

# OpenSSL TS responder config (used by tiny TSA HTTP wrapper)
sudo tee "${TSA_DIR}/ts.cnf" >/dev/null <<EOF
[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
dir = ${TSA_DIR}
serial = \$dir/tsa-serial
signer_cert = \$dir/tsa.crt
certs = ${ICA_DIR}/ica.crt
signer_key = \$dir/tsa.key
default_policy = ${DMJ_TSA_POLICY_OID:-1.3.6.1.4.1.55555.1.1}
other_policies = 1.3.6.1.4.1.55555.1.2
digests = sha256, sha384, sha512
accuracy = secs:1, millisecs:1, microsecs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = yes
EOF
[ -f "${TSA_DIR}/tsa-serial" ] || echo 01 | sudo tee "${TSA_DIR}/tsa-serial" >/dev/null



# Signer (leaf) + PKCS#12 used by the Java service
if [ ! -f "${SIGNER_DIR}/keystore.p12" ] || [ "$DMJ_REISSUE_LEAF" = "1" ]; then
  sudo rm -f "${SIGNER_DIR}/signer.crt" "${SIGNER_DIR}/signer.csr" "${SIGNER_DIR}/keystore.p12" "${SIGNER_DIR}/keystore.pass"
  # Clean any failed/old leaf artifacts so re-issuing is idempotent
  say "[+] Issuing Document Signer leaf and building PKCS#12 ..."
  openssl genrsa -out "${SIGNER_DIR}/signer.key" 3072
  openssl req -new -sha256 \
    -subj "/C=${COUNTRY}/O=${ORG_NAME}/OU=Document Signing/CN=${SIGNER_CN}" \
    -key "${SIGNER_DIR}/signer.key" -out "${SIGNER_DIR}/signer.csr"
  # Use usr_cert extension (digitalSignature + nonRepudiation) + AIA/CDP
  openssl ca -batch -config "${ICA_DIR}/openssl.cnf" -extensions usr_cert \
    -in "${SIGNER_DIR}/signer.csr" -out "${SIGNER_DIR}/signer.crt" -days 730 -md sha256 -notext

  # Create PKCS#12 with the chain (alias dmj-one) and store password beside it  
  openssl pkcs12 -export -name "${PKCS12_ALIAS}" \
    -inkey "${SIGNER_DIR}/signer.key" -in "${SIGNER_DIR}/signer.crt" \
    -certfile "${ICA_DIR}/ica.crt" -passout pass:"$PASS" \
    -out "${SIGNER_DIR}/keystore.p12"
  echo "$PASS" | sudo tee "${SIGNER_DIR}/keystore.pass" >/dev/null
  sudo chmod 600 "${SIGNER_DIR}/keystore.p12" "${SIGNER_DIR}/keystore.pass" "${SIGNER_DIR}/signer.key"
fi

# 1) Confirm KU/EKU are exactly as intended
openssl x509 -in "${SIGNER_DIR}/signer.crt" -noout -text | \
  awk '/X509v3 Key Usage/ {p=1;print;next} /X509v3/ && p {p=0} p; /X509v3 Extended Key Usage/ {p=1;print;next} /X509v3/ && p {p=0} p'

# 2) Verify chain (leaf -> ICA -> Root)
openssl verify -CAfile <(cat "${ICA_DIR}/ica.crt" "${ROOT_DIR}/root.crt") "${SIGNER_DIR}/signer.crt"

say "[+] Publishing chain & CRL at ${AIA_SCHEME}://${PKI_DOMAIN}/ ..."

# Public files (for AIA/CDP/OCSP fetches)
sudo install -m 0644 "${ROOT_DIR}/root.crl" "${PKI_PUB}/dmj-one-root-ca-r1.crl"
sudo install -m 0644 "${ICA_DIR}/ica.crl"   "${PKI_PUB}/dmj-one-issuing-ca-r1.crl"
cat "${ICA_DIR}/ica.crt" "${ROOT_DIR}/root.crt" | sudo tee "${PKI_PUB}/dmj-one-ica-chain-r1.pem" >/dev/null

# Branded certs for users (do NOT rename once shipped)
sudo install -m 0644 "${ROOT_DIR}/root.crt" "${PKI_PUB}/dmj-one-root-ca-r1.crt"
sudo install -m 0644 "${ICA_DIR}/ica.crt"   "${PKI_PUB}/dmj-one-issuing-ca-r1.crt"
openssl x509 -in "${ROOT_DIR}/root.crt" -outform der -out "${PKI_PUB}/dmj-one-root-ca-r1.cer"
openssl x509 -in "${ICA_DIR}/ica.crt"   -outform der -out "${PKI_PUB}/dmj-one-issuing-ca-r1.cer"

# Build a “frozen” Trust Kit once per series and keep a stable symlink
TRUST_KIT_ZIP="${PKI_PUB}/dmj-one-trust-kit-${DMJ_SHIP_CA_SERIES}.zip"
if [ ! -f "$TRUST_KIT_ZIP" ] || [ "$DMJ_REGEN_TRUST_KIT" = "1" ]; then
  # fresh readmes
  sudo tee "${PKI_PUB}/dmj-one-trust-kit-README.txt" >/dev/null <<'TXT'
dmj.one Trust Kit — Quick Guide
================================

What this is
------------
• dmj.one Root CA (R1): install this once to trust dmj.one‑signed PDFs.
• dmj.one Issuing CA (R1): optional helper for some apps. Do NOT add to “Trusted Root”.

 Windows — ONE-CLICK (recommended)
----------------------------------
1) Right-click **install-dmj-certificates.bat** → **Run as administrator**.
2) The installer will:
   • import **dmj-one-root-ca-r1.(cer/crt)** into **Trusted Root Certification Authorities**
   • import **dmj-one-issuing-ca-r1.(cer/crt)** into **Intermediate Certification Authorities**
3) It prints success/failure for each step. Verify with **certmgr.msc** if desired.

 Windows — manual (alternative)
-------------------------------
Root CA (system-wide):
1) Double-click **dmj-one-root-ca-r1.cer** → **Install Certificate…**
2) Choose **Local Machine** (or **Current User**) → **Next**
3) **Place all certificates in the following store** → **Browse** → **Trusted Root Certification Authorities**
4) **OK** → **Next** → **Finish** → approve the warning (**Yes**)

Issuing CA (optional helper):
• Import **dmj-one-issuing-ca-r1.cer** into **Intermediate Certification Authorities**

macOS — system trust
--------------------
1) Double‑click  dmj-one-root-ca-r1.cer  (opens Keychain Access).
2) In the left bar, click the “System” keychain (or “login” if you don’t have admin rights).
3) Drag the certificate into the list (or use File → Import Items…).
4) Double‑click the “dmj.one Root CA R1” → expand “Trust” → set “When using this certificate” to “Always Trust”.
5) Close the window; enter your password to save. Done.

Linux (Ubuntu/Debian)
---------------------
1) Copy the Root CA (PEM) into the local trust store:
     sudo cp dmj-one-root-ca-r1.crt /usr/local/share/ca-certificates/
2) Update the system CA bundle:
     sudo update-ca-certificates

Acrobat only (no system changes)
--------------------------------
1) Adobe Acrobat/Reader → Edit → Preferences → Signatures → Identities & Trusted Certificates → More…
2) Trusted Certificates → Import → pick the Root (and Issuing CA if you want).
3) In “Trust”, tick “Use this certificate as a trusted root”. Save.

After installing
----------------
• Open your PDF again. It should show the signature as valid (trusted) and not changed.
• If a document is later revoked, Acrobat can flag it during verification (enable revocation checks in Preferences).

Files in this folder
--------------------
• dmj-one-root-ca-r1.cer  (DER – Windows)
• dmj-one-root-ca-r1.crt  (PEM)
• dmj-one-issuing-ca-r1.crt  (PEM, optional)
• dmj-one-ica-chain-r1.pem   (PEM chain)
• this guide (TXT/HTML) and SHA256SUMS

Security tip: Only install CAs you trust. This kit is published at pki.dmj.one.
TXT
  sudo tee "${PKI_PUB}/install-dmj-certificates.bat" >/dev/null <<'BAT'
@echo off
setlocal enabledelayedexpansion

REM -------------------------------------------------
REM  DMJ Root + Intermediate Certificate Importer
REM  Works even when elevated (uses %~dp0 for paths)
REM -------------------------------------------------

:: Re-run as admin if not already
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [!] Elevating... please accept the UAC prompt.
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

:: Folder where this script lives (always ends with backslash)
set "BASEDIR=%~dp0"

:: Candidate filenames (support .cer/.crt)
set "ROOT_CANDIDATES=dmj-one-root-ca-r1.cer dmj-one-root-ca-r1.crt"
set "ICA_CANDIDATES=dmj-one-issuing-ca-r1.crt dmj-one-issuing-ca-r1.cer"

:: Resolve actual files
set "ROOT_CERT="
for %%F in (%ROOT_CANDIDATES%) do (
  if exist "%BASEDIR%%%F" (
    set "ROOT_CERT=%BASEDIR%%%F"
    goto :gotRoot
  )
)
:gotRoot

set "ICA_CERT="
for %%F in (%ICA_CANDIDATES%) do (
  if exist "%BASEDIR%%%F" (
    set "ICA_CERT=%BASEDIR%%%F"
    goto :gotICA
  )
)
:gotICA

echo --------------------------------------------
echo Installing DMJ Certificates from:
echo   %BASEDIR%
echo --------------------------------------------

if defined ROOT_CERT (
  echo [+] Installing Root CA: "%ROOT_CERT%"
  certutil -addstore -enterprise -f "Root" "%ROOT_CERT%"
) else (
  echo [x] Root certificate not found in folder. Looked for:
  echo     %ROOT_CANDIDATES%
)

if defined ICA_CERT (
  echo [+] Installing Intermediate CA: "%ICA_CERT%"
  certutil -addstore -enterprise -f "CA" "%ICA_CERT%"
) else (
  echo [x] Intermediate certificate not found in folder. Looked for:
  echo     %ICA_CANDIDATES%
)

echo --------------------------------------------
echo [✓] Done. Verify with: certmgr.msc
echo   - Trusted Root Certification Authorities
echo   - Intermediate Certification Authorities
echo --------------------------------------------
pause
endlocal
BAT
  sudo tee "${PKI_PUB}/dmj-one-trust-kit-README.html" >/dev/null <<'HTML'
<!doctype html><meta charset="utf-8">
<title>dmj.one Trust Kit — Quick Guide</title>
<style>body{font-family:ui-sans-serif,system-ui;margin:40px;max-width:900px}code{background:#f6f6f6;padding:2px 4px;border-radius:4px}</style>
<h1>dmj.one Trust Kit — Quick Guide</h1>
<p><b>Install the dmj.one Root CA</b> once. Then dmj.one‑signed PDFs show as trusted.</p>

<h2>Windows — One-click (recommended)</h2>
<ol>
  <li>Right-click <code>install-dmj-certificates.bat</code> → <b>Run as administrator</b></li>
  <li>The installer adds:
    <ul>
      <li><b>dmj-one-root-ca-r1.(cer/crt)</b> → <b>Trusted Root Certification Authorities</b></li>
      <li><b>dmj-one-issuing-ca-r1.(cer/crt)</b> → <b>Intermediate Certification Authorities</b></li>
    </ul>
  </li>
  <li>Verify (optional) with <code>certmgr.msc</code></li>
</ol>

<h3>Manual alternative</h3>
<p><b>Root CA:</b> Double-click <code>dmj-one-root-ca-r1.cer</code> → <b>Install Certificate…</b> → <b>Local Machine</b> (or <b>Current User</b>) → 
<b>Place all certificates in the following store</b> → <b>Trusted Root Certification Authorities</b> → finish and approve.</p>
<p><b>Issuing CA (optional):</b> import <code>dmj-one-issuing-ca-r1.cer</code> into <b>Intermediate Certification Authorities</b>.</p>

<h2>macOS</h2>
<ol>
  <li>Double‑click <code>dmj-one-root-ca-r1.cer</code> (opens Keychain Access)</li>
  <li>Select the <b>System</b> keychain (or <b>login</b>)</li>
  <li>Drag the certificate in (or <b>File → Import Items…</b>)</li>
  <li>Double‑click it → <b>Trust</b> → set <b>Always Trust</b></li>
</ol>

<h2>Linux (Ubuntu/Debian)</h2>
<ol>
  <li>Copy Root (PEM): <code>sudo cp dmj-one-root-ca-r1.crt /usr/local/share/ca-certificates/</code></li>
  <li>Update: <code>sudo update-ca-certificates</code></li>
</ol>

<h2>Acrobat only (no system changes)</h2>
<ol>
  <li>Acrobat → <b>Edit → Preferences → Signatures → Identities &amp; Trusted Certificates → More…</b></li>
  <li><b>Trusted Certificates → Import</b> → select the Root</li>
  <li>Tick <b>Use this certificate as a trusted root</b> and save</li>
</ol>

<p>Reopen your PDF; it should show as trusted and unchanged.</p>
HTML

  ( cd "${PKI_PUB}" && sha256sum \
      dmj-one-root-ca-r1.cer dmj-one-root-ca-r1.crt \
      dmj-one-issuing-ca-r1.crt dmj-one-ica-chain-r1.pem \
      install-dmj-certificates.bat \
      > dmj-one-trust-kit-SHA256SUMS.txt )

  ( cd "${PKI_PUB}" && zip -q -r "dmj-one-trust-kit-${DMJ_SHIP_CA_SERIES}.zip" \
      dmj-one-root-ca-r1.cer dmj-one-root-ca-r1.crt \
      dmj-one-issuing-ca-r1.crt dmj-one-ica-chain-r1.pem \
      dmj-one-trust-kit-README.txt dmj-one-trust-kit-README.html \
      dmj-one-trust-kit-SHA256SUMS.txt install-dmj-certificates.bat ) && \
  sudo chmod 0644 "${PKI_PUB}/dmj-one-trust-kit-${DMJ_SHIP_CA_SERIES}.zip"
fi

# Always publish real files (no symlinks) so hardening like disable_symlinks doesn’t break serving
cd "${PKI_PUB}" && sudo rm -f "dmj-one-trust-kit.zip" && sudo cp -f "dmj-one-trust-kit-${DMJ_SHIP_CA_SERIES}.zip" "dmj-one-trust-kit.zip" && sudo chmod 0644 "dmj-one-trust-kit.zip"

# Provide files at the exact paths embedded in certificates (copies, not symlinks)
sudo rm -f "${PKI_PUB}/ica.crt" "${PKI_PUB}/root.crt" "${PKI_PUB}/ica.crl" "${PKI_PUB}/root.crl"
sudo install -m 0644 "${ICA_DIR}/ica.crt"   "${PKI_PUB}/ica.crt"
sudo install -m 0644 "${ROOT_DIR}/root.crt" "${PKI_PUB}/root.crt"
sudo install -m 0644 "${ICA_DIR}/ica.crl"   "${PKI_PUB}/ica.crl"
sudo install -m 0644 "${ROOT_DIR}/root.crl" "${PKI_PUB}/root.crl"

sudo tee /usr/local/bin/dmj-refresh-crl >/dev/null <<REFRESHCRL
#!/usr/bin/env bash
set -euo pipefail
ICA_DIR="/opt/dmj/pki/ica"; PKI_PUB="/opt/dmj/pki/pub"
openssl ca -config "${ICA_DIR}/openssl.cnf" -gencrl -out "${ICA_DIR}/ica.crl"
install -m 0644 "${ICA_DIR}/ica.crl" "${PKI_PUB}/dmj-one-issuing-ca-r1.crl"
install -m 0644 "${ICA_DIR}/ica.crl" "${PKI_PUB}/ica.crl"   # ensure AIA/CDP path stays readable
REFRESHCRL
sudo chmod +x /usr/local/bin/dmj-refresh-crl

# Minimal Node.js HTTP TSA (RFC 3161 over HTTP POST)
sudo tee /usr/local/bin/dmj-tsa.js >/dev/null <<'TSASRV'
#!/usr/bin/env node
"use strict";
const http = require('http'), { spawn } = require('child_process');
const PORT = parseInt(process.env.DMJ_TSA_PORT || "9090", 10);
const TS_CONF = process.env.DMJ_TSA_CONF || "/opt/dmj/pki/tsa/ts.cnf";
const BASIC_USER = process.env.DMJ_TSA_BASIC_USER || "";
const BASIC_PASS = process.env.DMJ_TSA_BASIC_PASS || "";
function unauthorized(res){ res.writeHead(401, {'www-authenticate':'Basic realm="dmj-tsa"'}); res.end(); }
function ok(res, body){ res.writeHead(200, {'content-type':'application/timestamp-reply','cache-control':'no-store'}); res.end(body); }
function bad(res, code, msg){ res.writeHead(code||500, {'content-type':'text/plain'}); res.end(msg||'error'); }
const server = http.createServer((req,res)=>{
  if(req.method==='GET' && req.url==='/healthz'){ res.writeHead(200,{'content-type':'text/plain'}); return res.end('ok'); }
  if(req.method!=='POST'){ return bad(res,405,'method not allowed'); }
  if((req.headers['content-type']||'').indexOf('application/timestamp-query')!==0){ return bad(res,415,'content-type'); }
  if(BASIC_USER){
    const hdr = req.headers['authorization']||'';
    const okAuth = hdr.startsWith('Basic ') && (()=>{
      try { const [u,p] = Buffer.from(hdr.slice(6),'base64').toString('utf8').split(':'); return u===BASIC_USER && p===BASIC_PASS; }
      catch(_){ return false; }
    })();
    if(!okAuth) return unauthorized(res);
  }
  const bufs=[]; req.on('data',c=>bufs.push(c)).on('end',()=>{
    const q = Buffer.concat(bufs);
    const openssl = spawn('openssl', ['ts','-reply','-config',TS_CONF,'-queryfile','-']);
    const outs=[]; let err='';
    openssl.stdout.on('data',d=>outs.push(d));
    openssl.stderr.on('data',d=>err+=d);
    openssl.on('close', rc=>{
      if(rc===0) return ok(res, Buffer.concat(outs));
      bad(res,500,'tsa failure'); 
    });
    openssl.stdin.end(q);
  });
});
server.listen(PORT,'127.0.0.1',()=>console.log(`dmj-tsa listening on :${PORT}`));
TSASRV
sudo chmod 0755 /usr/local/bin/dmj-tsa.js

say "[+] Building Java signer..."
( cd "$SIGNER_DIR" && mvn -q -DskipTests clean package )
fix_perms

### --- Single “stack” entrypoint and unit (Signer + OCSP under dmjsvc) -------
say "[+] Writing environment file for the stack..."
DMJ_ENV_FILE="${CONF_DIR}/dmj-signer.env"
sudo tee "$DMJ_ENV_FILE" >/dev/null <<ENV
# Non-secret runtime configuration for the Signer/stack
DMJ_PDF_TITLE=
DMJ_PDF_AUTHOR="Divya Mohan | dmj.one and its stakeholders."
DMJ_PDF_SUBJECT="Verified by ${DMJ_ROOT_DOMAIN} against any tampering."
DMJ_PDF_KEYWORDS=
DMJ_PDF_CREATOR="dmj.one Trust Services"
DMJ_PDF_PRODUCER="dmj.one Signer"
DMJ_PDF_VERSION=1.7
DMJ_PDF_SET_DATES=1
DMJ_PDF_CREATED_ON=
DMJ_PDF_MODIFIED_ON=
DMJ_ISSUER=${DMJ_ROOT_DOMAIN}
DMJ_PKI_PUB=${PKI_PUB}
DMJ_PKI_BASE=${AIA_SCHEME}://${PKI_DOMAIN}
DMJ_ICA_DIR=${ICA_DIR}
DMJ_OCSP_DIR=${OCSP_DIR}
DMJ_SIGNER_WORK_DIR=${SIGNER_DIR}
DMJ_P12_ALIAS=${PKCS12_ALIAS}
DMJ_HMAC_HEADER=${WORKER_HMAC_HEADER}
DMJ_HMAC_TS_HEADER=${WORKER_HMAC_TS_HEADER}
DMJ_HMAC_NONCE_HEADER=${WORKER_HMAC_NONCE_HEADER}
DMJ_SIGNER_PORTS=${SIGNER_FIXED_PORT}
DMJ_SIGNER_PORT_FILE=/run/dmj/signer.port
DMJ_OPENSSL_BIN=openssl
DMJ_SIG_NAME=${DMJ_ROOT_DOMAIN}
DMJ_SIG_LOCATION=${COUNTRY}
DMJ_CONTACT_EMAIL=${SUPPORT_EMAIL}
DMJ_SIG_REASON="Contents securely verified by ${DMJ_ROOT_DOMAIN} against any tampering."
DMJ_LOG_VERBOSE=0
DMJ_HTTP_LOG=0

# --- PAdES / TSA / LTV-LTA ---------------------------------------------------
# RFC 3161 TSA endpoint used for:
#  • Signature-time-stamp (unsigned attr id-aa-signatureTimeStampToken) → B‑T
#  • DocTimeStamp (ETSI.RFC3161) after DSS → B‑LTA
# Leave DMJ_TSA_URL empty to disable all timestamping.
DMJ_TSA_URL=
DMJ_TSA_USER=
DMJ_TSA_PASS=
DMJ_TSA_POLICY_OID=1.3.6.1.4.1.55555.1.1   # default private OID, change if you have a policy
DMJ_TSA_HASH=SHA-256
DMJ_TSA_TIMEOUT_MS=10000
DMJ_TS_ON_SIGNATURE=1
DMJ_ADD_DOC_TIMESTAMP=1

# Optional explicit OCSP URL for DSS/VRI (B‑LT). Defaults to local ocsp.*.
DMJ_OCSP_URL=${OCSP_AIA_SCHEME}://${OCSP_DOMAIN}/

ENV
sudo chmod 0640 "$DMJ_ENV_FILE"

say "[+] Creating dmj-stack supervisor..."
sudo tee /usr/local/bin/dmj-stack >/dev/null <<'STACK'
#!/bin/bash
set -euo pipefail
umask 077
mkdir -p /run/dmj

# Resolve paths from env (with sensible defaults)
ICA_DIR="${DMJ_ICA_DIR:-/opt/dmj/pki/ica}"
OCSP_DIR="${DMJ_OCSP_DIR:-/opt/dmj/pki/ocsp}"
SIGNER_DIR="${DMJ_SIGNER_WORK_DIR:-/opt/dmj/signer-vm}"
OPENSSL_BIN="${DMJ_OPENSSL_BIN:-/usr/bin/openssl}"
JAVA_BIN="${DMJ_JAVA_BIN:-/usr/bin/java}"

# Verbose journald toggle (1=debug, 0=info)
VERBOSE="${DMJ_LOG_VERBOSE:-1}"
[[ "$VERBOSE" = "1" ]] && set -x || true

# TSA env for the tiny HTTP service
export DMJ_TSA_PORT="${DMJ_TSA_PORT:-9090}"
export DMJ_TSA_CONF="${DMJ_TSA_CONF:-/opt/dmj/pki/tsa/ts.cnf}"
export DMJ_TSA_BASIC_USER="${DMJ_TSA_BASIC_USER:-}"
export DMJ_TSA_BASIC_PASS="${DMJ_TSA_BASIC_PASS:-}"


# Small in-memory ring log (journald still has the full stream)
LOG_RING="${LOG_RING:-/run/dmj/stack.log}"
LOG_MAX_LINES="${LOG_MAX_LINES:-10000}"
: > "$LOG_RING"; chmod 0640 "$LOG_RING" || true

trim_ring() {
  local tmp="${LOG_RING}.tmp"
  tail -n "$LOG_MAX_LINES" "$LOG_RING" > "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$LOG_RING" 2>/dev/null || true
}

prefix_stream() {
  local label="$1"; shift
  local cnt=0
  stdbuf -oL -eL "$@" 2>&1 | while IFS= read -r line; do
    ts=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    msg="[$ts][$label] $line"
    echo "$msg"
    printf '%s\n' "$msg" >> "$LOG_RING" || true
    cnt=$((cnt+1))
    if (( cnt % 200 == 0 )); then trim_ring; fi
  done
}

trap 'trap - TERM INT; kill 0' TERM INT

# Helper that keeps a process alive and logs every line with a prefix
run_forever() {
  local label="$1"; shift
  while true; do
    # Pipe child stdout+stderr through our prefixer; never exit the supervisor on child errors
    prefix_stream "$label" "$@"
    rc=$?
    ts=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    echo "[$ts][$label] process exited rc=${rc}; restarting in 1s..." | tee -a "$LOG_RING"
    sleep 1
  done
}

# OCSP (port 9080): OpenSSL OCSP children auto-reload index changes. No manual restart needed.
# Ref: docs.openssl.org 'openssl-ocsp' (children detect index changes).
#
# Use -nmin to refresh status frequently.
#
run_forever ocsp "$OPENSSL_BIN" ocsp \
  -index "${ICA_DIR}/index.txt" \
  -CA     "${ICA_DIR}/ica.crt" \
  -rsigner "${OCSP_DIR}/ocsp.crt" \
  -rkey    "${OCSP_DIR}/ocsp.key" \
  -port 9080 -text -nmin 5 -no_nonce &

# TSA (RFC 3161 over HTTP via Node -> openssl ts -reply)
run_forever tsa /usr/bin/node /usr/local/bin/dmj-tsa.js &

# Signer (Java) with configurable log level and HTTP access logging toggle
JAVA_LOG_LEVEL=$([[ "$VERBOSE" = "1" ]] && echo "debug" || echo "info")
run_forever signer "$JAVA_BIN" \
  -Dorg.slf4j.simpleLogger.defaultLogLevel="${JAVA_LOG_LEVEL}" \
  -jar "${SIGNER_DIR}/target/dmj-signer-1.0.0.jar" &

wait  # keep supervisor in the foreground
STACK
sudo chmod 0755 /usr/local/bin/dmj-stack

say "[+] Creating single hardened systemd unit (dmj.service)..."
sudo tee /etc/systemd/system/dmj-signer.service >/dev/null <<'UNIT'
[Unit]
Description=dmj.one stack (Signer + OCSP)
After=network-online.target
Wants=network-online.target

[Service]
User=dmjsvc
Group=dmjsvc
Type=simple
EnvironmentFile=-/etc/dmj/dmj-worker.secrets
EnvironmentFile=-/etc/dmj/dmj-signer.env
WorkingDirectory=/opt/dmj/signer-vm
ExecStart=/bin/bash /usr/local/bin/dmj-stack
Restart=on-failure
# log to journald; do not write local files
StandardOutput=journal
StandardError=inherit
# Avoid rate limiting the flood while debugging
LogRateLimitIntervalSec=0
LogRateLimitBurst=0
# expose ring size to the stack script
Environment=LOG_MAX_LINES=10000
Environment=LOG_RING=/run/dmj/stack.log
# --- hardening ---
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
PrivateDevices=yes
ProtectProc=invisible
MemoryDenyWriteExecute=no
# Narrow syscalls to a conservative baseline; adjust if you see denials in the journal
SystemCallFilter=@system-service @basic-io @file-system @network-io
RuntimeDirectory=dmj
RuntimeDirectoryMode=0750
ReadWritePaths=/var/log/dmj /var/lib/dmj /opt/dmj /run/dmj

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now dmj-signer.service
sudo systemctl restart dmj-signer
sudo systemctl status dmj-signer --no-pager


# nginx site (reverse proxy to dynamic port from /etc/dmj/signer.port)
say "[+] Creating dmj-signer nginx config..."
sudo tee "$NGINX_SITE" >/dev/null <<NGX
server {
  listen 80;
  server_name ${SIGNER_DOMAIN};
  
  client_max_body_size 25m;  
  client_header_timeout 30s;
  client_body_timeout   60s;

  access_log syslog:server=unix:/dev/log,facility=local7,tag=nginx_signer combined;
  error_log  syslog:server=unix:/dev/log warn;

  location / {
    proxy_request_buffering off;    # stream request body to Jetty
    proxy_read_timeout 60s;
    proxy_pass http://127.0.0.1:${SIGNER_FIXED_PORT};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
  }
}
server {
  listen 443 ssl;
  http2 on;
  server_name ${SIGNER_DOMAIN};

  ssl_certificate     /etc/letsencrypt/live/${SIGNER_DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${SIGNER_DOMAIN}/privkey.pem;

  access_log syslog:server=unix:/dev/log,facility=local7,tag=nginx_signer combined;
  error_log  syslog:server=unix:/dev/log warn;

  location / {
    proxy_pass http://127.0.0.1:${SIGNER_FIXED_PORT};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
  }
}
NGX
sudo ln -sf "$NGINX_SITE" "$NGINX_SITE_LINK"
sudo nginx -t && sudo systemctl reload nginx

say "[+] Signer at https://${SIGNER_DOMAIN}/healthz"


# --- NGINX: static PKI files host (pki.*) and OCSP proxy (ocsp.*) ----------
# First, remove conflicting/legacy sites so our servers aren't ignored.
say "[+] Removing legacy/duplicate nginx site links to avoid 'conflicting server name' ..."
sudo rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
sudo rm -f /etc/nginx/sites-enabled/pki* /etc/nginx/sites-enabled/ocsp* 2>/dev/null || true
sudo rm -f /etc/nginx/sites-enabled/*pki* /etc/nginx/sites-enabled/*ocsp* 2>/dev/null || true
sudo rm -f /etc/nginx/sites-enabled/*pki* /etc/nginx/sites-enabled/*ocsp* /etc/nginx/sites-enabled/*tsa* 2>/dev/null || true 

sudo tee /etc/nginx/sites-available/dmj-pki >/dev/null <<NGX
server {
  listen 80;
  server_name ${PKI_DOMAIN};

  root ${PKI_PUB};
  autoindex off;
  
  # Security & cache
  add_header X-Content-Type-Options "nosniff" always;
  add_header Content-Security-Policy "default-src 'none'" always;
  add_header Referrer-Policy "no-referrer" always;
  add_header Cache-Control "public, max-age=3600";
  merge_slashes on;
  disable_symlinks on;

  # send logs to journald via syslog
  access_log syslog:server=unix:/dev/log,facility=local7,tag=nginx_pki combined;
  error_log  syslog:server=unix:/dev/log warn;

  # Only GET/HEAD are valid for these endpoints
  location / {
    limit_except GET HEAD { deny all; }   # 403 to anything else
    try_files \$uri =404;
    types {
      application/pkix-cert crt cer;
      application/pkix-crl  crl;
      application/timestamp-reply tsr;
      application/timestamp-query tsq;
      application/zip       zip;
    }
  }

  # Ad-hoc bundles should not be cached
  location /dl/ {
    add_header Cache-Control "no-store" always;
    try_files \$uri =404;
  }
}
server {   
  listen 443 ssl;
  http2  on;   # modern enabling of HTTP/2 (listen ... http2 is deprecated)
  server_name ${PKI_DOMAIN};

  # ssl_certificate and ssl_certificate_key managed by certbot
  ssl_certificate /etc/letsencrypt/live/${PKI_DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${PKI_DOMAIN}/privkey.pem;
  
  root ${PKI_PUB};
  autoindex off;

  # Security & cache
  add_header X-Content-Type-Options "nosniff" always;
  add_header Content-Security-Policy "default-src 'none'" always;
  add_header Referrer-Policy "no-referrer" always;
  add_header Cache-Control "public, max-age=3600";
  merge_slashes on;
  disable_symlinks on;

  access_log syslog:server=unix:/dev/log,facility=local7,tag=nginx_pki combined;
  error_log  syslog:server=unix:/dev/log warn;

  location / {
    limit_except GET HEAD { deny all; }
    try_files \$uri =404;
    types {
      application/pkix-cert crt cer;
      application/pkix-crl  crl;
      application/timestamp-reply tsr;
      application/timestamp-query tsq;
      application/zip       zip;
    }
  }
  location /dl/ {
    add_header Cache-Control "no-store" always;
    try_files \$uri =404;
  }
}
NGX

sudo tee /etc/nginx/sites-available/dmj-ocsp >/dev/null <<NGX
server {
  listen 80;
  server_name ${OCSP_DOMAIN};

  gzip off;
  access_log syslog:server=unix:/dev/log,facility=local7,tag=nginx_ocsp combined;
  error_log  syslog:server=unix:/dev/log warn;

  location / {
    proxy_pass         http://127.0.0.1:9080/;
    proxy_http_version 1.1;
    proxy_set_header   Host \$host;
    proxy_set_header   Content-Length \$content_length;
    proxy_set_header   Content-Type \$http_content_type;
    proxy_buffering    off;
    add_header         Content-Type "application/ocsp-response" always;
  }
}
server {
  listen 443 ssl;
  http2  on;
  server_name ${OCSP_DOMAIN};

  # ssl_certificate and ssl_certificate_key managed by certbot
  ssl_certificate /etc/letsencrypt/live/${OCSP_DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${OCSP_DOMAIN}/privkey.pem;

  gzip off;
  access_log syslog:server=unix:/dev/log,facility=local7,tag=nginx_ocsp combined;
  error_log  syslog:server=unix:/dev/log warn;

  location / {
    proxy_pass         http://127.0.0.1:9080/;
    proxy_http_version 1.1;
    proxy_set_header   Host \$host;
    proxy_set_header   Content-Length \$content_length;
    proxy_set_header   Content-Type \$http_content_type;
    proxy_buffering    off;
    add_header         Content-Type "application/ocsp-response" always;
  }
}
NGX

# --- NGINX: TSA (HTTP RFC 3161) ---------------------------------------------
sudo tee /etc/nginx/sites-available/dmj-tsa >/dev/null <<NGX
server {
  listen 80;
  server_name ${TSA_DOMAIN};

  access_log syslog:server=unix:/dev/log,facility=local7,tag=nginx_tsa combined;
  error_log  syslog:server=unix:/dev/log warn;

  client_max_body_size 512k;
  client_body_timeout  30s;
  proxy_read_timeout   30s;

  location / {
    # Only POST / (application/timestamp-query) and GET /healthz
    if (\$request_method !~ ^(POST|GET)$) { return 405; }
    if (\$request_method = GET ) { try_files \$uri =404; }
    proxy_pass         http://127.0.0.1:9090;
    proxy_http_version 1.1;
    proxy_set_header   Host \$host;
    proxy_set_header   Content-Length \$content_length;
    proxy_set_header   Content-Type   \$http_content_type;
    proxy_buffering    off;
    add_header         X-Content-Type-Options "nosniff" always;
  }
}
server {
  listen 443 ssl;
  http2 on;
  server_name ${TSA_DOMAIN};

  ssl_certificate     /etc/letsencrypt/live/${TSA_DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${TSA_DOMAIN}/privkey.pem;

  access_log syslog:server=unix:/dev/log,facility=local7,tag=nginx_tsa combined;
  error_log  syslog:server=unix:/dev/log warn;

  client_max_body_size 512k;
  client_body_timeout  30s;
  proxy_read_timeout   30s;

  location / {
    if (\$request_method !~ ^(POST|GET)$) { return 405; }
    if (\$request_method = GET ) { try_files \$uri =404; }
    proxy_pass         http://127.0.0.1:9090;
    proxy_http_version 1.1;
    proxy_set_header   Host \$host;
    proxy_set_header   Content-Length \$content_length;
    proxy_set_header   Content-Type   \$http_content_type;
    proxy_buffering    off;
    add_header         X-Content-Type-Options "nosniff" always;
  }
}
NGX

sudo ln -sf /etc/nginx/sites-available/dmj-pki  /etc/nginx/sites-enabled/dmj-pki
sudo ln -sf /etc/nginx/sites-available/dmj-ocsp /etc/nginx/sites-enabled/dmj-ocsp
sudo ln -sf /etc/nginx/sites-available/dmj-tsa /etc/nginx/sites-enabled/dmj-tsa
sudo nginx -t && sudo systemctl reload nginx
sudo -u www-data test -r /opt/dmj/pki/pub/ica.crt && echo "WWW ZIP FAIL:nginx can read ica.crt" || echo "WWW ZIP FAIL: nginx cannot read ica.crt"

say "[+] Adding Cron Job..."
# Cron job schedule: Every day at 2:00 AM
echo "[+] Adding Cron Job..."

# Cron job schedules
CRON_SCHEDULE="0 2 * * *"
COMMAND="find /opt/dmj/pki/pub/dl -type f -mtime +1 -delete"
CRON_JOB="$CRON_SCHEDULE $COMMAND"

CRON_JOB2="0 */6 * * * /usr/local/bin/dmj-refresh-crl"

# # Safely get existing crontab or empty if none exists
# existing_cron=$(crontab -l 2>/dev/null || true)
# Install into dmjsvc's user crontab so tasks run under the locked user
existing_cron=$(sudo crontab -u "$DMJ_USER" -l 2>/dev/null || true)

# Filter out any existing lines matching the commands
filtered_cron=$(echo "$existing_cron" | grep -Fv "$COMMAND" | grep -Fv "$CRON_JOB2" || true)

# Add new cron job lines
new_cron=$(printf "%s\n%s\n%s\n" "$filtered_cron" "$CRON_JOB" "$CRON_JOB2")


# Install/replace user crontab
printf "%s\n" "$new_cron" | sudo crontab -u "$DMJ_USER" -

echo "Cron jobs added:"
echo "$CRON_JOB"
echo "$CRON_JOB2"

# Write the fixer script
sudo tee /usr/local/bin/dmj-fix-perms >/dev/null <<'SH'
#!/usr/bin/env bash
set -euo pipefail

# Require root so we don't sprinkle 'sudo' everywhere.
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "dmj-fix-perms must be run as root (try: sudo $0)" >&2
  exit 1
fi

# ---- Configurable inputs (override via env if desired) ----------------------
DMJ_USER="${DMJ_USER:-dmjsvc}"

OPT_DIR="${OPT_DIR:-/opt/dmj}"
WORKER_DIR="${WORKER_DIR:-$OPT_DIR/worker}"
SIGNER_DIR="${SIGNER_DIR:-$OPT_DIR/signer-vm}"
PKI_DIR="${PKI_DIR:-$OPT_DIR/pki}"
PKI_PUB="${PKI_PUB:-$PKI_DIR/pub}"
LOG_DIR="${LOG_DIR:-/var/log/dmj}"

paths=( "$OPT_DIR" "$WORKER_DIR" "$SIGNER_DIR" "$PKI_DIR" "$LOG_DIR" )

# ---- Ownership --------------------------------------------------------------
chown -R "$DMJ_USER:$DMJ_USER" "${paths[@]}" 2>/dev/null || true

# ---- Base perms under OPT_DIR ----------------------------------------------
# Directories: 0750 and setgid so new subdirs keep group
find "$OPT_DIR" -type d -exec chmod 0751 {} + 2>/dev/null || true
find "$OPT_DIR" -type d -exec chmod g+s {} + 2>/dev/null || true

# Generic files: 0640
find "$OPT_DIR" -type f -exec chmod 0640 {} + 2>/dev/null || true

# ---- Public PKI content (nginx-readable) -----------------------------------
find "$PKI_PUB" -type d -exec chmod 0755 {} + 2>/dev/null || true
find "$PKI_PUB" -type f -exec chmod 0644 {} + 2>/dev/null || true

# ---- Executables in /usr/local/bin -----------------------------------------
# Mark everything under /usr/local/bin executable (matches prior behavior)
find /usr/local/bin/ -type f -exec chmod 0755 {} + 2>/dev/null || true

# ---- Sensitive keys ---------------------------------------------------------
chmod 0600 "$SIGNER_DIR"/keystore.p12 "$SIGNER_DIR"/keystore.pass "$SIGNER_DIR"/signer.key 2>/dev/null || true
chmod 0600 "$PKI_DIR"/ica/ica.key "$PKI_DIR"/ocsp/ocsp.key 2>/dev/null || true

# ---- Built artifacts needed by classloaders ---------------------------------
[ -f "$SIGNER_DIR/target/dmj-signer-1.0.0.jar" ] && chmod 0644 "$SIGNER_DIR/target/dmj-signer-1.0.0.jar"

# ---- Default ACLs so files are readable by $DMJ_USER on creation -----------
if command -v setfacl >/dev/null 2>&1; then
  setfacl -m "u:${DMJ_USER}:rwX" "$OPT_DIR" || true
  setfacl -d -m "u:${DMJ_USER}:rwX" "$OPT_DIR" || true   # default (inherit) for new files/dirs
fi

# Create index.txt.attr only if missing (OpenSSL reads it)
if [[ ! -f "$PKI_DIR/ica/index.txt.attr" ]]; then
  install -m 640 /dev/null "$PKI_DIR/ica/index.txt.attr"
fi

exit 0
SH
sudo chmod 0755 /usr/local/bin/dmj-fix-perms

# Add to dmjsvc’s crontab (you already use per-user cron)
CRON_JOB3="*/15 * * * * /usr/local/bin/dmj-fix-perms"
existing_cron=$(sudo crontab -u "$DMJ_USER" -l 2>/dev/null || true)
printf "%s\n%s\n" "$(echo "$existing_cron" | grep -Fv '/usr/local/bin/dmj-fix-perms' || true)" "$CRON_JOB3" | sudo crontab -u "$DMJ_USER" -


### --- Worker project --------------------------------------------------------
say "[+] Preparing Cloudflare Worker at ${WORKER_DIR} ..."
sudo mkdir -p "${WORKER_DIR}/src"
sudo chown -R dmjsvc:dmjsvc "$WORKER_DIR"
# Worker TS (admin portal, sign, verify, revoke). Uses Web Crypto + D1.
# as_dmj tee "${WORKER_DIR}/src/index.ts" >/dev/null <<'TS'
sudo tee "${WORKER_DIR}/src/index.ts" >/dev/null <<'TS'
// DMJ Worker — admin portal, sign, verify
export interface Env {
  DB: D1Database
  ISSUER: string
  SIGNER_API_BASE: string
  DB_PREFIX: string
  SIGNING_GATEWAY_HMAC_KEY: string
  SESSION_HMAC_KEY: string
  TOTP_MASTER_KEY: string
  ADMIN_PASS_HASH: string
  PKI_BASE?: string
  BUNDLE_TRUST_KIT?: string
  DOWNLOAD_TTL?: string
  ADMIN_PATH?: string
  WORKER_HMAC_HEADER?: string
  WORKER_HMAC_TS_HEADER?: string
  WORKER_HMAC_NONCE_HEADER?: string
}

function genNonce(): string {
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return btoa(String.fromCharCode(...a)).replace(/=+$/,'');
}

// const text = (s: string) => new Response(s, { headers: { "content-type":"text/html; charset=utf-8", "x-frame-options":"DENY", "referrer-policy":"no-referrer", "content-security-policy":"default-src 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none'" }});
const text = (html: string, nonce: string) =>
  new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      "content-security-policy":
        "default-src 'self'; " +
        "style-src 'self' 'unsafe-inline' https:; " + // keep styles simple
        "font-src 'self' https: data:; " +
        "img-src 'self' https: data:; " +
        `script-src 'self' 'nonce-${nonce}' https://cdnjs.cloudflare.com https://static.cloudflareinsights.com https://dmj.one; ` +
        `script-src-elem 'self' 'nonce-${nonce}' https://cdnjs.cloudflare.com https://static.cloudflareinsights.com https://dmj.one; ` +
        "connect-src 'self' https: https://cloudflareinsights.com https://dmj.one; " +
        "frame-ancestors 'none'"
    }
  });

const json = (o: any, status=200) => new Response(JSON.stringify(o), {status, headers: {"content-type":"application/json"}});

async function hmac(env: Env, input: ArrayBuffer, method: string, path: string){
  const keyRaw = b64(env.SIGNING_GATEWAY_HMAC_KEY);
  const key = await crypto.subtle.importKey("raw", keyRaw, {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
  const ts = Math.floor(Date.now()/1000).toString();
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const toSign = concat(
    enc.encode(method), new Uint8Array([0]),
    enc.encode(path),   new Uint8Array([0]),
    enc.encode(ts),     new Uint8Array([0]),
    nonce,              new Uint8Array([0]),
    new Uint8Array(input)
  );
  const sig = await crypto.subtle.sign({name:"HMAC"}, key, toSign);
  return { ts, nonce: b64e(nonce), sig: b64e(new Uint8Array(sig)) };
}

function b64e(a: Uint8Array){ return btoa(String.fromCharCode(...a)); }
function b64(s: string){ return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function hex(a: ArrayBuffer){ return [...new Uint8Array(a)].map(x=>x.toString(16).padStart(2,"0")).join(""); }
function concat(...parts: Uint8Array[]){ let len=0; for(const p of parts) len+=p.length; const out=new Uint8Array(len); let off=0; for(const p of parts){ out.set(p, off); off+=p.length; } return out; }

function sameOrigin(req: Request){
  const u = new URL(req.url);
  const expected = `${u.protocol}//${u.host}`;

  const o = req.headers.get("origin");
  if (o) return o === expected;

  // Fallback for agents that omit Origin on same-origin form posts
  const r = req.headers.get("referer");
  if (r) {
    try { return new URL(r).origin === expected; } catch {/* ignore */}
  }

  // With SameSite=Strict cookies, a cross-site attacker won't send our cookie.
  // Treat absence of both headers as acceptable.
  return true;
}

// --- Minimal ZIP (STORE, no compression) for 2-3 files ---
// CRC32 table
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(u8: Uint8Array) {
  let c = 0 ^ -1;
  for (let i = 0; i < u8.length; i++) c = CRC_TABLE[(c ^ u8[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
function encDOSDate(d: Date) {
  const yr = d.getFullYear(); const mo = d.getMonth()+1; const da = d.getDate();
  const hh = d.getHours(); const mm = d.getMinutes(); const ss = Math.floor(d.getSeconds()/2);
  const dost = (hh<<11)|(mm<<5)|ss; const dosd = ((yr-1980)<<9)|(mo<<5)|da;
  return { time: dost, date: dosd };
}
function u16(v: number){ const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, v, true); return b; }
function u32(v: number){ const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, true); return b; }

type ZipEntry = { name: string, data: Uint8Array };
async function buildZip(entries: ZipEntry[]): Promise<Uint8Array> {
  const now = new Date(); const dos = encDOSDate(now);
  const files: {lfh: Uint8Array, data: Uint8Array, cdh: Uint8Array}[] = [];
  let offset = 0;
  for (const e of entries) {
    const n = new TextEncoder().encode(e.name);
    const c = crc32(e.data); const sz = e.data.length;
    // Local File Header
    const lfh = new Uint8Array([
      ...u32(0x04034b50), ...u16(20), ...u16(0), ...u16(0),
      ...u16(dos.time), ...u16(dos.date), ...u32(c), ...u32(sz), ...u32(sz),
      ...u16(n.length), ...u16(0), ...n
    ]);
    // Central Directory Header
    const cdh = new Uint8Array([
      ...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(0), ...u16(0),
      ...u16(dos.time), ...u16(dos.date), ...u32(c), ...u32(sz), ...u32(sz),
      ...u16(n.length), ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(0), ...u32(offset),
      ...n
    ]);
    files.push({ lfh, data: e.data, cdh });
    offset += lfh.length + sz;
  }
  const central = concat(...files.map(f => f.cdh));
  const body = concat(...files.flatMap(f => [f.lfh, f.data]));
  const eocd = new Uint8Array([
    ...u32(0x06054b50), ...u16(0), ...u16(0), ...u16(files.length), ...u16(files.length),
    ...u32(central.length), ...u32(body.length), ...u16(0)
  ]);
  return concat(body, central, eocd);
}

async function ensureSchema(env: Env) {
  const p = env.DB_PREFIX;

  const stmts = [
    `CREATE TABLE IF NOT EXISTS ${p}documents(
       id TEXT PRIMARY KEY,
       doc_sha256 TEXT UNIQUE,
       meta_json TEXT,
       signed_at INTEGER,
       revoked_at INTEGER,
       revoke_reason TEXT,
       cert_serial TEXT
     )`,
    `CREATE INDEX IF NOT EXISTS ${p}documents_sha_idx ON ${p}documents(doc_sha256)`,    
    `CREATE TABLE IF NOT EXISTS ${p}doc_verifications(
       doc_sha256 TEXT PRIMARY KEY,
       has_signature INTEGER,
       is_valid INTEGER,
       issued_by_us INTEGER,
       covers_document INTEGER,
       subfilter TEXT,
       issuer TEXT,
       verified_at INTEGER
     )`,
    `CREATE TABLE IF NOT EXISTS ${p}audit(
       id TEXT PRIMARY KEY,
       at INTEGER,
       action TEXT,
       doc_sha256 TEXT,
       ip TEXT,
       ua TEXT,
       detail TEXT
     )`,
    `CREATE TABLE IF NOT EXISTS ${p}bootstrap(
       k TEXT PRIMARY KEY,
       v TEXT,
       consumed INTEGER DEFAULT 0,
       created_at INTEGER
     )`,
    `CREATE TABLE IF NOT EXISTS ${p}sessions(
       sid TEXT PRIMARY KEY,
       created_at INTEGER,
       last_seen INTEGER,
       ip_hash TEXT,
       ua_hash TEXT
     )`,     
    `CREATE TABLE IF NOT EXISTS ${p}downloads(
       id TEXT PRIMARY KEY,
       mime TEXT,
       filename TEXT,
       body_base64 TEXT,
       expires_at INTEGER
     )`,
    `CREATE INDEX IF NOT EXISTS ${p}downloads_exp_idx ON ${p}downloads(expires_at)`
  ];

  for (const sql of stmts) {
    await env.DB.prepare(sql).run();
  }
  // Schema drift fixer: add 'cert_serial' to existing databases (no-op if present).
  // try {
  //   await env.DB.prepare(`ALTER TABLE ${p}documents ADD COLUMN cert_serial TEXT`).run();
  // } catch (e) {
  //   /* ignore: column already exists */
  // }
}

// Store a short-lived downloadable blob and return its id
async function putDownload(env: Env, bytes: Uint8Array, mime: string, filename: string){
  const p = env.DB_PREFIX;
  const ttl = parseInt(env.DOWNLOAD_TTL || "900", 10); // default 15 min
  const id = crypto.randomUUID();
  // Uint8Array -> base64 (chunked to avoid stack limits)
  let bin = "";
  const step = 0x8000;
  for (let i=0; i<bytes.length; i+=step){
    bin += String.fromCharCode(...bytes.subarray(i, i+step));
  }
  const b64 = btoa(bin);
  await env.DB.prepare(
    `INSERT INTO ${p}downloads(id,mime,filename,body_base64,expires_at) VALUES(?,?,?,?,?)`
  ).bind(id, mime, filename, b64, Math.floor(Date.now()/1000) + ttl).run();
  return id;
}

// Fetch (and optionally consume) a stored blob by id
async function getDownload(env: Env, id: string, consume = true){
  const p = env.DB_PREFIX;
  const row = await env.DB.prepare(
    `SELECT mime, filename, body_base64, expires_at FROM ${p}downloads WHERE id=?`
  ).bind(id).first() as any;
  if (!row) return null;
  if (row.expires_at && row.expires_at < Math.floor(Date.now()/1000)) {
    await env.DB.prepare(`DELETE FROM ${p}downloads WHERE id=?`).bind(id).run();
    return null;
  }
  if (consume) await env.DB.prepare(`DELETE FROM ${p}downloads WHERE id=?`).bind(id).run();
  const bin = atob(row.body_base64 as string);
  const data = new Uint8Array(bin.length);
  for (let i=0; i<bin.length; i++) data[i] = bin.charCodeAt(i);
  return { bytes: data, mime: String(row.mime), filename: String(row.filename) };
}



async function sha256(buf: ArrayBuffer){ return hex(await crypto.subtle.digest("SHA-256", buf)); }
function now(){ return Math.floor(Date.now()/1000); }

async function setOneTimeAdminKey(env: Env, keyClear: string){
  const p = env.DB_PREFIX;  
  await env.DB
    .prepare(`INSERT OR REPLACE INTO ${p}bootstrap(k,v,consumed,created_at)
              VALUES('ADMIN_PORTAL_KEY', ?, 0, ?)`)
    .bind(keyClear, now())
    .run();
}
async function consumeOneTimeAdminKey(env: Env): Promise<string|null>{
  const p = env.DB_PREFIX;
  const row = await env.DB.prepare(`SELECT v FROM ${p}bootstrap WHERE k='ADMIN_PORTAL_KEY' AND consumed=0`).first() as any;
  if(!row) return null;
  await env.DB.exec(`DELETE FROM ${p}bootstrap WHERE k='ADMIN_PORTAL_KEY'`);
  return row.v as string;
}

async function verifyPBKDF2(env: Env, candidate: string){
  const parts = env.ADMIN_PASS_HASH.split("$");
  // pbkdf2$sha256$iters$salt$dk
  if(parts.length !== 5) return false;
  const iters = parseInt(parts[2],10);
  const salt = b64(parts[3]);
  const want = b64(parts[4]);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(candidate), {name:"PBKDF2"}, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2", hash:"SHA-256", iterations: iters, salt}, key, want.length*8);
  const got = new Uint8Array(bits);
  return crypto.subtle.timingSafeEqual ? crypto.subtle.timingSafeEqual(got, want) : (got.every((b,i)=>b===want[i]));
}

function cookie(name:string, value:string, opts:Record<string,string|number|boolean>={}): string{
  const pairs = [`${name}=${value}`];
  if(opts["Path"]) pairs.push(`Path=${opts["Path"]}`);
  pairs.push("HttpOnly");
  pairs.push("SameSite=Strict");
  pairs.push("Secure");
  return pairs.join("; ");
}
async function signSession(env: Env, payload: any){
  const raw = new TextEncoder().encode(JSON.stringify(payload));
  const key = await crypto.subtle.importKey("raw", b64(env.SESSION_HMAC_KEY), {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, raw);
  return b64e(concat(raw, new Uint8Array(sig)));
}
async function verifySession(env: Env, b64v: string){
  try {
    const all = b64(b64v);
    const raw = all.slice(0, all.length-32);
    const sig = all.slice(all.length-32);
    const key = await crypto.subtle.importKey("raw", b64(env.SESSION_HMAC_KEY), {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
    const expect = new Uint8Array(await crypto.subtle.sign("HMAC", key, raw));
    if(!expect.every((v,i)=>v===sig[i])) return null;
    const obj = JSON.parse(new TextDecoder().decode(raw));
    return obj;
  } catch { return null; }
}

function renderHome(issuerDomain: string, nonce: string) {
  const pkiZip = `https://pki.${issuerDomain}/dmj-one-trust-kit.zip`;

  const html = `
  <!doctype html>
<html lang="en" data-bs-theme="dark">

    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <meta name="color-scheme" content="dark light" />
        <title>dmj.one Trust Services — Document Verification</title>

        <link rel="shortcut icon" href="//dmj.one/logo.png">
        <link rel="fluid-icon" href="//dmj.one//logo.png">
        <link rel="apple-touch-icon" href="//dmj.one//logo.png">

        <!-- Core CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet" />

        <!-- Animations (cdnjs as requested) -->
        <link href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css" rel="stylesheet" />
        <script nonce="__CSP_NONCE__" src="https://cdnjs.cloudflare.com/ajax/libs/particles.js/2.0.0/particles.min.js" crossorigin="anonymous"></script>

        <style>
            /* Keep tiny essentials only */
            :root {
                --brand: #60a5fa;
            }

            html,
            body {
                height: 100%
            }

            body {
                background: #0b0f14;
                color: #e7ebf2;
                overflow-x: hidden
            }

            /* particles canvas behind content */
            #particles-js {
                position: fixed;
                inset: 0;
                z-index: 0
            }

            /* subtle gradient overlay (optional) */
            .bg-gradient-overlay {
                position: fixed;
                inset: 0;
                z-index: 0;
                pointer-events: none;
                background: radial-gradient(800px 400px at 20% -10%, rgba(96, 165, 250, .08), transparent 60%),
                    radial-gradient(900px 500px at 80% -10%, rgba(34, 197, 94, .06), transparent 60%);
            }

            /* dashed helper (Bootstrap lacks a dashed utility) */
            .border-dashed {
                border-style: dashed !important
            }

            /* tiny dot for advanced stats; color comes from Bootstrap classes */
            .dot {
                width: .6rem;
                height: .6rem;
                border-radius: 50%;
                display: inline-block;
                margin-right: .4rem
            }

            /* === Check/Cross animations (derived from Codeconvey) === */
            /* Source pattern: circle spins; on completion, border freezes and mark draws. */
            /* Namespaced to avoid conflicts and keep everything else untouched. */

            .cc-circle-loader {
                /* 7em geometry from Codeconvey, scaled by font-size for ~42px circle */
                font-size: 6px;
                margin: 0;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-left-color: var(--bs-success, #5cb85c);
                animation: cc-loader-spin 1.2s infinite linear;
                position: relative;
                display: inline-block;
                vertical-align: middle;
                border-radius: 50%;
                width: 7em;
                height: 7em;
            }

            .cc-circle-loader.cc-fail {
                border-left-color: var(--bs-danger, #dc3545);
            }

            /* optional accent when we know it's a fail */

            .cc-circle-loader.cc-complete {
                animation: none;
                border-color: currentColor;
                /* turn circle to the final color */
                transition: border 500ms ease-out;
            }

            .cc-circle-loader .cc-mark {
                display: none;
            }

            .cc-circle-loader.cc-complete .cc-mark {
                display: block;
            }

            /* Checkmark (geometry + timing adapted from Codeconvey) */
            .cc-circle-loader.cc-success .cc-mark::after,
            .cc-verdict.cc-check::after {
                opacity: 1;
                height: 3.5em;
                width: 1.75em;
                transform-origin: left top;
                border-right: 3px solid currentColor;
                border-top: 3px solid currentColor;
                content: "";
                left: 1.75em;
                top: 3.5em;
                position: absolute;
            }

            .cc-circle-loader.cc-success .cc-mark::after {
                animation-duration: 800ms;
                animation-timing-function: ease;
                animation-name: cc-checkmark;
                /* Codeconvey checkmark timing */
                transform: scaleX(-1) rotate(135deg);
            }

            /* Cross (two strokes that draw in sequence) */
            .cc-circle-loader.cc-fail .cc-mark::before,
            .cc-circle-loader.cc-fail .cc-mark::after,
            .cc-verdict.cc-cross::before,
            .cc-verdict.cc-cross::after {
                content: "";
                position: absolute;
                left: 3.2em;
                /* tuned to center inside 7em circle */
                top: 2.1em;
                width: 0;
                height: 3.5em;
                border-right: 3px solid currentColor;
                transform-origin: left top;
                opacity: 1;
            }

            .cc-circle-loader.cc-fail .cc-mark::before,
            .cc-verdict.cc-cross::before {
                transform: rotate(45deg);
                animation: cc-stroke 650ms ease forwards;
            }

            .cc-circle-loader.cc-fail .cc-mark::after,
            .cc-verdict.cc-cross::after {
                transform: rotate(-45deg);
                animation: cc-stroke 650ms ease 150ms forwards;
            }

            /* Verdict icon (static ring that can draw the mark when shown) */
            .cc-verdict {
                font-size: 6px;
                /* same scale (~42px total) */
                display: inline-block;
                vertical-align: middle;
                position: relative;
                width: 7em;
                height: 7em;
                border-radius: 50%;
                border: 1px solid currentColor;
            }

            .cc-verdict.cc-check::after {
                animation: cc-checkmark 800ms ease 50ms both;
                transform: scaleX(-1) rotate(135deg);
            }

            /* Color helpers aligned with Bootstrap palette */
            .cc-success {
                color: var(--bs-success, #198754);
            }

            .cc-fail {
                color: var(--bs-danger, #dc3545);
            }

            /* Keyframes (renamed from Codeconvey to avoid collisions) */
            @keyframes cc-loader-spin {
                0% {
                    transform: rotate(0deg);
                }

                100% {
                    transform: rotate(360deg);
                }
            }

            @keyframes cc-checkmark {
                0% {
                    height: 0;
                    width: 0;
                    opacity: 1;
                }

                20% {
                    height: 0;
                    width: 1.75em;
                    opacity: 1;
                }

                40% {
                    height: 3.5em;
                    width: 1.75em;
                    opacity: 1;
                }

                100% {
                    height: 3.5em;
                    width: 1.75em;
                    opacity: 1;
                }
            }

            @keyframes cc-stroke {
                0% {
                    height: 0;
                }

                100% {
                    height: 3.5em;
                }
            }

            /* =========================
   LAYOUT TWEAKS (center & 3× size)
   ========================= */

            /* Center the uploading row content */
            #liveState .d-flex.align-items-center {
                flex-direction: column;
                align-items: center !important;
                text-align: center;
                gap: 1rem;
            }

            /* Center verdict row; put SHA under icon */
            #verdictCard .d-flex.align-items-center {
                flex-direction: column;
                align-items: center !important;
                text-align: center;
                gap: 1rem;
            }

            /* Hide VALID/TAMPERED text completely */
            /* #verdictText {
                display: none !important;
            } */

            /* Make both the waiting loader and the final verdict icon 3× */
            #uploadAnim,
            #verdictIcon.cc-verdict {
                font-size: 18px !important;
                /* default geometry is 6px -> 3× */
            }

            /* Ensure the ring blocks center themselves in their containers */
            .cc-circle-loader,
            .cc-verdict {
                display: inline-block;
                margin-inline: auto;
            }

            /* Nicer spacing for the SHA badge under the icon */
            #shaChip {
                display: inline-block;
                margin-top: .25rem;
            }

            /* =========================
   ANIMATION (Codeconvey-derived)
   ========================= */
            /* Circle loader & checkmark derived from Codeconvey:
   - spinning bordered circle
   - on completion freezes and draws a tick using :after height/width anim
   Ref: .circle-loader, .load-complete, .checkmark:after, @keyframes loader-spin/checkmark. :contentReference[oaicite:1]{index=1}
*/

            .cc-circle-loader {
                /* 7em geometry from Codeconvey, scaled by font-size for ~42px base (3× -> ~126px) */
                font-size: 6px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-left-color: var(--bs-success, #198754);
                animation: cc-loader-spin 1.2s infinite linear;
                position: relative;
                border-radius: 50%;
                width: 7em;
                height: 7em;
            }

            .cc-circle-loader.cc-fail {
                border-left-color: var(--bs-danger, #dc3545);
            }

            .cc-circle-loader.cc-complete {
                animation: none;
                border-color: currentColor;
                transition: border 500ms ease-out;
            }

            .cc-circle-loader .cc-mark {
                display: none;
            }

            .cc-circle-loader.cc-complete .cc-mark {
                display: block;
            }

            /* Checkmark (same geometry/timing pattern as Codeconvey) */
            .cc-circle-loader.cc-success .cc-mark::after,
            .cc-verdict.cc-check::after {
                opacity: 1;
                height: 3.5em;
                width: 1.75em;
                transform-origin: left top;
                border-right: 3px solid currentColor;
                border-top: 3px solid currentColor;
                content: "";
                left: 1.75em;
                top: 3.5em;
                position: absolute;
            }

            /* animate the check path */
            .cc-circle-loader.cc-success .cc-mark::after,
            .cc-verdict.cc-check::after {
                animation: cc-checkmark 800ms ease 50ms both;
                transform: scaleX(-1) rotate(135deg);
            }

            /* =========================
   FIXED CROSS ("X") — two centered strokes that draw
   ========================= */
            .cc-circle-loader.cc-fail .cc-mark::before,
            .cc-circle-loader.cc-fail .cc-mark::after,
            .cc-verdict.cc-cross::before,
            .cc-verdict.cc-cross::after {
                content: "";
                position: absolute;
                left: 50%;
                top: 50%;
                width: 0;
                /* animate width from 0 -> full length */
                height: 3px;
                background: currentColor;
                transform-origin: center;
                opacity: 1;
            }

            .cc-circle-loader.cc-fail .cc-mark::before,
            .cc-verdict.cc-cross::before {
                transform: translate(-50%, -50%) rotate(45deg);
                animation: cc-stroke-w 450ms ease forwards;
            }

            .cc-circle-loader.cc-fail .cc-mark::after,
            .cc-verdict.cc-cross::after {
                transform: translate(-50%, -50%) rotate(-45deg);
                animation: cc-stroke-w 450ms ease 120ms forwards;
            }

            /* Verdict ring (static) that can draw check/cross */
            .cc-verdict {
                font-size: 6px;
                /* base; bumped to 18px via rule above */
                position: relative;
                width: 7em;
                height: 7em;
                border-radius: 50%;
                border: 1px solid currentColor;
            }

            /* Palette helpers */
            .cc-success {
                color: var(--bs-success, #198754);
            }

            .cc-fail {
                color: var(--bs-danger, #dc3545);
            }

            /* Keyframes (renamed from Codeconvey to avoid collisions) */
            @keyframes cc-loader-spin {
                0% {
                    transform: rotate(0deg);
                }

                100% {
                    transform: rotate(360deg);
                }
            }

            @keyframes cc-checkmark {
                0% {
                    height: 0;
                    width: 0;
                    opacity: 1;
                }

                20% {
                    height: 0;
                    width: 1.75em;
                    opacity: 1;
                }

                40% {
                    height: 3.5em;
                    width: 1.75em;
                    opacity: 1;
                }

                100% {
                    height: 3.5em;
                    width: 1.75em;
                    opacity: 1;
                }
            }

            @keyframes cc-stroke-w {
                from {
                    width: 0;
                }

                to {
                    width: 4.6em;
                }

                /* tuned to span the ring */
            }
        </style>

    </head>

    <body class="only-one-btn">
        <!-- animated tech background -->
        <div id="particles-js" aria-hidden="true"></div>
        <div class="bg-gradient-overlay" aria-hidden="true"></div>

        <!-- Centered content -->
        <main class="min-vh-100 d-flex align-items-center justify-content-center position-relative">
            <section class="container" style="max-width: 920px;">
                <div class="card bg-body border-0 shadow-lg rounded-4 bg-opacity-10 backdrop-blur animate__animated animate__fadeInDown">
                    <div class="card-body p-4 p-md-5">

                        <section class="hero animate__animated animate__fadeInDown fade-slow">
                            <div class="text-center d-grid gap-2">
                                <img src="https://dmj.one/logo.png" alt="dmj.one logo" class="mx-auto d-block" style="height:64px" />
                                <h1 class="h4 mb-0">dmj.one Trust Services</h1>
                                <p class="text-secondary mb-0">
                                    Document Verification System: Upload a PDF to check if it is issued by
                                    <span class="fw-semibold">${issuerDomain}</span> and unaltered.
                                </p>
                            </div>


                            <!-- Upload -->
                            <div class="upload-wrap">
                                <input id="fileInput" class="d-none" type="file" name="file" accept="application/pdf" />
                                <label for="fileInput" id="dropzone" class="mt-3 w-100 text-center border border-secondary-subtle border-dashed rounded-3 p-4 p-md-5
                                              bg-body-tertiary bg-opacity-10 user-select-none" role="button" tabindex="0" aria-controls="fileInput">
                                    <div class="display-6 mb-2 text-primary"><i class="bi-upload"></i></div>
                                    <div class="fw-semibold">Drop your PDF here or click to upload</div>
                                    <div class="text-secondary small">We’ll verify the embedded signature and registry entries.</div>
                                </label>



                                <!-- subtle trust kit -->
                                <p class="text-center text-secondary small mt-2 mb-0">
                                    <i class="bi-shield-check me-1"></i>
                                    <a href="${pkiZip}" download class="link-light text-decoration-none">Install the Trust&nbsp;Kit (Root &amp; Issuing CA)</a>
                                    <span class="ms-1">to see “valid signature” in Acrobat/Reader automatically.</span>
                                </p>


                                <!-- live state -->
                                <div id="liveState" class="mt-3 border rounded-3 p-3 bg-body-tertiary bg-opacity-10 animate__animated animate__fadeIn" hidden>
                                    <div class="d-flex align-items-center gap-3">
                                        <div id="uploadAnim" class="cc-circle-loader cc-success fade-slow" aria-hidden="true">
                                            <div class="cc-mark"></div>
                                        </div>

                                        <div>
                                            <div class="fw-semibold d-none" id="stateLine">Starting verification…</div>
                                            <div class="small text-secondary" id="fileName"></div>
                                        </div>
                                    </div>
                                    <div class="progress mt-3 d-none" role="progressbar" aria-label="Verifying">
                                        <div class="progress-bar progress-bar-striped progress-bar-animated fade-slow" style="width:100%"></div>
                                    </div>
                                </div>


                                <!-- verdict -->
                                <div id="verdictWrap" class="mt-3 border rounded-3 p-3 bg-body-tertiary bg-opacity-10" hidden>
                                    <div id="verdictCard">
                                        <div class="d-flex align-items-center">
                                            <i id="verdictIcon" class="bi me-3 fs-1"></i>
                                            <div>
                                                <div id="verdictText" class="fw-bold fs-2 lh-1"></div>                                                
                                            </div>
                                        </div>

                                        <a href="#" id="toggleAdvanced" class="d-inline-flex align-items-center mt-3 text-decoration-none">
                                            <i class="bi-caret-right-fill me-1"></i><span>View advanced report</span>
                                        </a>

                                        <div id="advancedPanel" class="mt-3" hidden>
                                            <div class="mt-2">
                                                File Hash: <span id="shaChip" class="badge text-bg-secondary rounded-pill"></span>
                                            </div>
                                            <div class="row g-3">
                                                <div class="col-md-6">
                                                    <div class="p-3 rounded-3 border bg-body-tertiary bg-opacity-10">
                                                        <div class="mb-2 fw-semibold">Signature &amp; Document</div>
                                                        <ul class="list-unstyled mb-0 small">
                                                            <li><span class="dot bg-success me-1" id="sigObjDot"></span>Signature object present</li>
                                                            <li><span class="dot bg-success me-1" id="cryptoDot"></span>Embedded signature is cryptographically valid</li>
                                                            <li><span class="dot bg-success me-1" id="coverDot"></span>Signature covers the whole document</li>
                                                        </ul>
                                                    </div>
                                                </div>
                                                <div class="col-md-6">
                                                    <div class="p-3 rounded-3 border bg-body-tertiary bg-opacity-10">
                                                        <div class="mb-2 fw-semibold">Issuer &amp; Registry</div>
                                                        <ul class="list-unstyled mb-0 small">
                                                            <li><span class="dot bg-success me-1" id="oursDot"></span>Signed by dmj.one key</li>
                                                            <li><span class="dot bg-success me-1" id="regDot"></span>Registered by dmj.one</li>
                                                            <li><span class="dot bg-success me-1" id="revokedDot"></span>Revocation check</li>                                                            
                                                        </ul>
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="row mx-auto">
                                              <li class="mt-2 text-break text-center"><span class="text-secondary">Issuer DN:</span> <code id="issuerDn"></code></li>
                                            </div>
                                            <div class="mt-3 small text-secondary text-center">Tip: Install the Trust Kit so Acrobat/Reader shows “signature is valid” automatically.</div>
                                        </div>
                                    </div>
                                </div>

                            </div>
                        </section>
                    </div>
                </div>
            </section>
        </main>


        <!-- Distinct footer -->
        <footer class="position-relative z-1 border-top bg-body bg-opacity-10">
            <div class="container py-3 text-center text-secondary small">
                © dmj.one Trust Services <span class="mx-2">•</span>
                <a href="//dmj.one/privacy" class="link-light text-decoration-none">Privacy</a>
                <span class="mx-2">•</span>
                <a href="//dmj.one/tos" class="link-light text-decoration-none">Terms &amp; Conditions</a>
            </div>
        </footer>


        <script nonce="__CSP_NONCE__">
            // particles.js init (disabled if user prefers reduced motion)
            (function () {
                var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
                if (reduce) { document.getElementById('particles-js').style.display = 'none'; return; }
                if (window.particlesJS) {
                    particlesJS('particles-js', {
                        "particles": {
                            "number": { "value": 70, "density": { "enable": true, "value_area": 1000 } },
                            "color": { "value": ["#60a5fa", "#34d399", "#93c5fd"] },
                            "shape": { "type": "circle" },
                            "opacity": { "value": 0.35, "random": false },
                            "size": { "value": 2.5, "random": true },
                            "line_linked": { "enable": true, "distance": 130, "color": "#60a5fa", "opacity": 0.25, "width": 1 },
                            "move": { "enable": true, "speed": 1.2, "direction": "none", "out_mode": "out" }
                        },
                        "interactivity": {
                            "detect_on": "canvas",
                            "events": {
                                "onhover": { "enable": true, "mode": "grab" },
                                "onclick": { "enable": false },
                                "resize": true
                            },
                            "modes": { "grab": { "distance": 140, "line_linked": { "opacity": 0.35 } } }
                        },
                        "retina_detect": true
                    });
                }
            })();
        </script>

        <script nonce="__CSP_NONCE__">
            (function () {
                const fileInput = document.getElementById('fileInput');
                const dropzone = document.getElementById('dropzone');
                const liveState = document.getElementById('liveState');
                const stateLine = document.getElementById('stateLine');
                const fileNameEl = document.getElementById('fileName');
                const verdictWrap = document.getElementById('verdictWrap');
                const verdictCard = document.getElementById('verdictCard');
                const verdictIcon = document.getElementById('verdictIcon');
                const verdictText = document.getElementById('verdictText');
                const shaChip = document.getElementById('shaChip');

                const uploadAnim = document.getElementById('uploadAnim');


                const toggleAdvanced = document.getElementById('toggleAdvanced');
                const advancedPanel = document.getElementById('advancedPanel');

                const dots = {
                    sigObjDot: document.getElementById('sigObjDot'),
                    cryptoDot: document.getElementById('cryptoDot'),
                    coverDot: document.getElementById('coverDot'),
                    oursDot: document.getElementById('oursDot'),
                    regDot: document.getElementById('regDot'),
                    revokedDot: document.getElementById('revokedDot'),
                };
                const issuerDn = document.getElementById('issuerDn');

                // function setDot(el, ok) {
                //     el.classList.toggle('stat-yes', !!ok);
                //     el.classList.toggle('stat-no', !ok);
                // }
                function setDot(el, ok) {
                    el.classList.toggle('bg-success', !!ok);
                    el.classList.toggle('bg-danger', !ok);
                }

                // Put near your other functions:
                function setShaDisplay(fullSha) {
                    const mql = window.matchMedia('(min-width: 992px)'); // treat as "laptop"
                    const apply = () => {
                        if (!shaChip) return;
                        if (!fullSha) { shaChip.textContent = 'n/a'; return; }
                        shaChip.textContent = mql.matches
                            ? fullSha
                            : (fullSha.slice(0, 12) + '…' + fullSha.slice(-12)); // mobile-friendly
                    };
                    apply();
                    // bind once
                    if (!setShaDisplay._bound) {
                        mql.addEventListener('change', apply);
                        setShaDisplay._bound = true;
                    }
                }



                function show(state) {
                    if (state === 'busy') {
                        verdictWrap.hidden = true;
                        liveState.hidden = false;
                    } else if (state === 'done') {
                        liveState.hidden = true;
                        verdictWrap.hidden = false;
                        verdictCard.classList.remove('animate__fadeInUp');
                        void verdictCard.offsetWidth; // reflow
                        verdictCard.classList.add('animate__fadeInUp');
                    }
                }

                toggleAdvanced.addEventListener('click', function (e) {
                    e.preventDefault();
                    const open = advancedPanel.hidden;
                    advancedPanel.hidden = !open;
                    this.querySelector('i').className = open ? 'bi-caret-down-fill me-1' : 'bi-caret-right-fill me-1';
                    this.querySelector('span').textContent = open ? 'Hide advanced report' : 'View advanced report';
                });

                async function startVerification(f) {
                    if (!f) return;
                    stateLine.textContent = 'Uploading & verifying…';
                    dropzone.classList.add('d-none');
                    fileNameEl.textContent = f.name;
                    show('busy');
                    // uploadAnim.className = 'cc-circle-loader cc-success'; // spin in green by default
                    uploadAnim.className = 'cc-circle-loader';
                    try {
                        const fd = new FormData();
                        fd.set('file', f, f.name);

                        const res = await fetch('/verify?json=1', { method: 'POST', body: fd, headers: { 'Accept': 'application/json' } });
                        if (!res.ok) { throw new Error('Server returned ' + res.status); }
                        const r = await res.json();

                        //const isValid = (r && r.verdict === 'valid');
                        //// Convert the waiting circle to a green tick OR red cross
                        //uploadAnim.classList.add('cc-complete', isValid ? 'cc-success' : 'cc-fail');
//
                        //// Final verdict icon: animated ring + check/cross
                        //verdictIcon.className = isValid
                        //    ? 'cc-verdict cc-success cc-check me-3'
                        //    : 'cc-verdict cc-fail cc-cross me-3';
//
                        //// verdictIcon.className = isValid ? 'bi-shield-check text-success me-3' : 'bi-shield-x text-danger me-3';
                        //verdictText.className = 'verdict-badge fw-bold ' + (isValid ? 'text-success' : 'text-danger');
                        //verdictText.textContent = isValid ? 'VALID' : 'TAMPERED';

                        const isValid = (r && r.verdict === 'valid');

                        // Convert waiting circle to tick or cross
                        uploadAnim.classList.add('cc-complete', isValid ? 'cc-success' : 'cc-fail');

                        // Final verdict icon (centered ring that draws mark)
                        verdictIcon.className = isValid
                            ? 'cc-verdict cc-success cc-check'
                            : 'cc-verdict cc-fail cc-cross';

                        // Remove the text labels entirely
                        // verdictText.textContent = '';
                        // verdictText.hidden = true;
                        verdictText.className = 'verdict-badge fw-bold ' + (isValid ? 'text-success' : 'text-danger');
                        verdictText.textContent = isValid ? 'VALID' : 'TAMPERED';

                        // SHA under the icon: full on laptop, truncated on mobile
                        setShaDisplay(r.sha256 || '');
                        // shaChip.textContent = (r.sha256 || '').slice(0, 16) + '…' + (r.sha256 || '').slice(-16);

                        setDot(dots.sigObjDot, !!r.hasSignature);
                        setDot(dots.cryptoDot, !!r.isValid);
                        setDot(dots.coverDot, !!r.coversDocument);
                        setDot(dots.oursDot, !!r.issuedByUs);
                        setDot(dots.regDot, !!r.issued);
                        setDot(dots.revokedDot, !r.revoked);
                        issuerDn.textContent = r.issuer || '';

                        show('done');
                    } catch (err) {
                        // uploadAnim.classList.add('cc-complete', 'cc-fail');
                        // verdictIcon.className = 'cc-verdict cc-fail cc-cross me-3';
                        // // verdictIcon.className = 'bi-exclamation-triangle text-danger me-3';
                        // verdictText.className = 'verdict-badge fw-bold text-danger';
                        // verdictText.textContent = 'TAMPERED';
                        // shaChip.textContent = 'n/a';
                        uploadAnim.classList.add('cc-complete', 'cc-fail');
                        verdictIcon.className = 'cc-verdict cc-fail cc-cross';
                        verdictText.textContent = '';
                        verdictText.hidden = true;
                        setShaDisplay('');
                        setDot(dots.sigObjDot, false);
                        setDot(dots.cryptoDot, false);
                        setDot(dots.coverDot, false);
                        setDot(dots.oursDot, false);
                        setDot(dots.regDot, false);
                        setDot(dots.revokedDot, false);
                        issuerDn.textContent = 'Error: ' + (err && err.message ? err.message : 'Unknown error');
                        show('done');
                    } finally {
                        fileInput.value = ''; // reset input so same file again triggers 'change'
                    }
                }

                // Keyboard activation only (let the <label for=...> handle pointer clicks)
                dropzone.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
                });

                // Ensure selecting the *same* file fires 'change' next time
                fileInput.addEventListener('click', () => { fileInput.value = ''; });

                // Drag & drop support
                ['dragenter', 'dragover'].forEach(evt => dropzone.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); dropzone.classList.add('dragover'); }));
                ['dragleave', 'drop'].forEach(evt => dropzone.addEventListener(evt, (e) => { e.preventDefault(); e.stopPropagation(); dropzone.classList.remove('dragover'); }));
                dropzone.addEventListener('drop', (e) => {
                    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
                    if (f && f.type === 'application/pdf') { startVerification(f); }
                    else if (f) { alert('Please drop a PDF file.'); }
                });

                // Traditional file picker
                fileInput.addEventListener('change', function () {
                    const f = this.files && this.files[0];
                    if (!f) return;
                    startVerification(f);
                });
            })();
        </script>
    </body>

</html> `;

  return text(html.replaceAll("__CSP_NONCE__", nonce), nonce);
}



function renderAdminLogin(issuer: string, adminPath: string, nonce: string){
  const html = `<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Admin · dmj.one</title>
  <link rel="shortcut icon" href="//dmj.one/logo.png">
  <link rel="fluid-icon" href="//dmj.one//logo.png">
  <link rel="apple-touch-icon" href="//dmj.one//logo.png">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet" />
  <link href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css" rel="stylesheet" />
  <style>body{background:#fafbfc} .card{border:1px solid #edf0f3}</style>
</head>
<body class="d-flex align-items-center" style="min-height:100vh">
  <main class="container">
    <div class="row justify-content-center">
      <div class="col-md-6 col-lg-5">
        <div class="card shadow-sm animate__animated animate__fadeInDown">
          <div class="card-body p-4 p-md-5">
            <div class="d-flex align-items-center mb-3">
              <i class="bi-shield-lock me-2" style="font-size:1.5rem;color:#0d6efd"></i>
              <h1 class="h4 mb-0">dmj.one Admin</h1>
            </div>
            <p class="text-secondary">Enter the <b>admin portal key</b> to access the dashboard for <span class="text-nowrap">${issuer}</span>.</p>
            <form method="post" action="${adminPath}/login" class="mt-3">
              <div class="mb-3">
                <label class="form-label">Admin key</label>
                <div class="input-group">
                  <input type="password" class="form-control" name="password" required autocomplete="current-password" placeholder="••••••••••••••" />
                  <button class="btn btn-outline-secondary" type="button" id="togglePw"><i class="bi bi-eye"></i></button>
                </div>
              </div>
              <button class="btn btn-primary w-100">Login</button>
            </form>            
          </div>
        </div>
      </div>
    </div>
  </main>
  <script nonce="__CSP_NONCE__">
    document.getElementById('togglePw').addEventListener('click', function(){
      const i = document.querySelector('input[name="password"]'); 
      i.type = i.type==='password' ? 'text' : 'password';
      this.firstElementChild.className = i.type==='password' ? 'bi bi-eye' : 'bi bi-eye-slash';
    });
  </script>
</body></html>`;
return text(html.replaceAll("__CSP_NONCE__", nonce), nonce);
}

function renderAdminBootstrapOnce(key: string, issuer: string, adminPath: string, nonce: string){   
  const html = `<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Admin bootstrap · dmj.one</title>
  <link rel="shortcut icon" href="//dmj.one/logo.png">
  <link rel="fluid-icon" href="//dmj.one//logo.png">
  <link rel="apple-touch-icon" href="//dmj.one//logo.png">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet" />
  <style>code.key{font-size:1.15rem;padding:.6rem .8rem;background:#f6f7f9;border:1px solid #e9eef3;border-radius:.5rem;display:block}</style>
</head>
<body class="bg-light">
  <main class="container py-5">
    <div class="row justify-content-center">
      <div class="col-lg-8">
        <div class="alert alert-primary d-flex align-items-center" role="alert">
          <i class="bi-info-circle me-2"></i>
          <div><b>Shown once:</b> Save this admin portal key for <span class="text-nowrap">${issuer}</span>.</div>
        </div>
        <div class="card shadow-sm">
          <div class="card-body p-4">
            <h1 class="h4 mb-3">Your admin portal key</h1>
            <code class="key" id="theKey">${key}</code>
            <button class="btn btn-outline-secondary mt-3" id="copyBtn"><i class="bi-clipboard me-2"></i>Copy</button>
            <hr class="my-4" />
            <p class="text-secondary small mb-0">Treat this like a password. Rotation is automatic at each deploy; you’ll see a new key here next time.</p>
            <a class="btn btn-primary mt-3" href="${adminPath}">Continue to Admin login</a>
          </div>
        </div>
      </div>
    </div>
  </main>
  <script nonce="__CSP_NONCE__">
    document.getElementById('copyBtn').addEventListener('click', async ()=>{
      const t = document.getElementById('theKey').innerText.trim();
      try{ await navigator.clipboard.writeText(t); 
        const b = document.getElementById('copyBtn'); b.innerHTML='<i class="bi-check2 me-2"></i>Copied'; setTimeout(()=>b.innerHTML='<i class="bi-clipboard me-2"></i>Copy', 1800);
      }catch{}
    });
  </script>
</body></html>`;
return text(html.replaceAll("__CSP_NONCE__", nonce), nonce);
}

function renderAdminDashboard(issuer: string, adminPath: string, nonce: string){
  const html = `<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Admin Dashboard · dmj.one</title>
  <link rel="shortcut icon" href="//dmj.one/logo.png">
  <link rel="fluid-icon" href="//dmj.one//logo.png">
  <link rel="apple-touch-icon" href="//dmj.one//logo.png">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet" />
  <link href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css" rel="stylesheet" />
  <style>
    body{background:#fbfcfe}
    .card{border:1px solid #edf0f3}
    .dropzone{border:1.5px dashed #cfd6df;border-radius:.75rem;padding:1.25rem;background:#fff}
    .dropzone.drag{background:#f5f9ff;border-color:#91b8ff}
    .hash{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem;background:#f6f7f9;border:1px solid #edf0f3;border-radius:.4rem;padding:.25rem .4rem}
    .status-chip{font-size:.85rem}
    #toast{position:fixed;right:16px;bottom:16px;z-index:9999;min-width:260px;display:none}
    #toast.show{display:block}
    #liveRegion{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}
  </style>
</head>
<body>
  <div id="liveRegion" aria-live="polite"></div>
  <nav class="navbar navbar-expand-lg bg-white border-bottom">
    <div class="container">
      <a class="navbar-brand d-flex align-items-center" href="#"><i class="bi-shield-check me-2" style="color:#0d6efd"></i>dmj.one Admin</a>
      <form method="post" action="${adminPath}/logout" class="ms-auto"><button class="btn btn-outline-secondary"><i class="bi-box-arrow-right me-2"></i>Logout</button></form>
    </div>
  </nav>

  <main class="container py-4">
    <div class="row g-4">
      <div class="col-lg-5">
        <div class="card shadow-sm">
          <div class="card-body">
            <h2 class="h5 d-flex align-items-center"><i class="bi-pen me-2 text-primary"></i>Sign a new PDF</h2>
            <div id="dz" class="dropzone mt-3 text-secondary text-center">
              <div class="small">
                <i class="bi-cloud-arrow-up"></i>
                Drag & drop PDF here or
                <label for="filePick" class="link-primary" style="cursor:pointer">browse</label>
                <input id="filePick" type="file" class="d-none" accept="application/pdf" />
              </div>
            </div>
            <div class="mt-3">
              <label class="form-label">Optional metadata (JSON)</label>
              <input id="meta" class="form-control" placeholder='{"orderId":"123","user":"alice"}'>
            </div>
            <div class="d-grid mt-3 d-none"><button id="signBtn" class="btn btn-primary" disabled><i class="bi-check2-square me-2"></i>Sign & Download</button></div>
            <div class="progress mt-3 d-none" id="prog"><div class="progress-bar progress-bar-striped progress-bar-animated" style="width:100%"></div></div>
            <div class="form-text mt-2">Documents are signed by dmj.one and re‑verified before storing. Bundle includes the Trust Kit.</div>
          </div>
        </div>
      </div>

      <div class="col-lg-7">
        <div class="card shadow-sm">
          <div class="card-body">
            <div class="d-flex align-items-center justify-content-between">
              <h2 class="h5 d-flex align-items-center mb-0"><i class="bi-files me-2 text-primary"></i>Issued documents</h2>
              <input id="q" class="form-control form-control-sm" style="max-width:220px" placeholder="Filter by SHA…">
            </div>
            <div class="table-responsive mt-3">
              <table class="table align-middle table-hover mb-0">
                <thead><tr><th>SHA‑256</th><th>Signed</th><th>Status</th><th class="text-end">Action</th></tr></thead>
                <tbody id="tbody">
                  <tr><td colspan="4" class="text-secondary">Loading…</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  </main>

  <div id="toast" class="alert alert-primary shadow-sm" role="status"></div>

  <script nonce="__CSP_NONCE__">
    const AP = "${adminPath}"; // dynamic admin base path
    const toast = (msg, kind='primary') => {
      const t = document.getElementById('toast'); 
      t.className = 'alert alert-' + kind + ' shadow-sm'; 
      t.textContent = msg; t.classList.add('show');
      document.getElementById('liveRegion').textContent = msg; // aria-live
      setTimeout(()=>t.classList.remove('show'), 2200);
    };

    // ------- Table (load + filter + revoke) — unchanged -------
    let rows = [];
    async function loadRows(){
      const res = await fetch(AP+'?json=1', {headers:{'Accept':'application/json'}});      
      if(!res.ok){ toast('Failed to load documents','danger'); return; }
      const data = await res.json();
      rows = (data.documents||[]);
      renderRows();
    }
    function renderRows(){
      const q = (document.getElementById('q').value || '').toLowerCase().trim();
      const tb = document.getElementById('tbody');
      const fmt = ts => ts ? new Date(ts*1000).toISOString().replace('T',' ').replace(/\..+/, '') : '';
      const view = rows.filter(r => !q || r.sha.includes(q));
      tb.innerHTML = view.map(r=>{
        const active = !r.revoked_at;
        const chip = active ? '<span class="badge text-bg-success status-chip">Active</span>'
                            : '<span class="badge text-bg-danger status-chip">Revoked</span>';
        const btn = active ? '<button class="btn btn-sm btn-outline-danger revoke" data-sha="'+r.sha+'"><i class="bi-x-circle me-1"></i>Revoke</button>'
                           : '<button class="btn btn-sm btn-outline-secondary" disabled>Revoked</button>';
        return '<tr>' +
          '<td><span class="hash" title="'+r.sha+'">'+r.sha.slice(0,12)+'…'+r.sha.slice(-12)+'</span></td>' +
          '<td>'+fmt(r.signed_at)+'</td>' +
          '<td>'+chip+'</td>' +
          '<td class="text-end">'+btn+'</td>' +
        '</tr>';
      }).join('') || '<tr><td colspan="4" class="text-secondary">No documents</td></tr>';
    }
    document.getElementById('q').addEventListener('input', renderRows);
    document.getElementById('tbody').addEventListener('click', async (e)=>{
      const b = e.target.closest('button.revoke'); if(!b) return;
      const sha = b.getAttribute('data-sha');
      const fd = new FormData(); fd.set('sha', sha);      
      const res = await fetch(AP+'/revoke', {method:'POST', body:fd, headers:{'Accept':'application/json'}});
      if(!res.ok){ toast('Revoke failed','danger'); return; }
      const r = await res.json();
      toast('Revoked '+sha.slice(0,8)+'…','warning');
      const row = rows.find(x=>x.sha===sha); if(row){ row.revoked_at = r.revoked_at || Math.floor(Date.now()/1000); }
      renderRows();
    });

    // ------- Signer (auto-process) -------
    const dz   = document.getElementById('dz');
    const fp   = document.getElementById('filePick');
    const meta = document.getElementById('meta');
    const btn  = document.getElementById('signBtn');
    const prog = document.getElementById('prog');

    let file = null;
    const isPDF = f => f && (f.type === 'application/pdf' || /\.pdf$/i.test(f.name||'')); // NEW

    // Reusable signer — used by auto-flow AND the button
    async function signNow(){ // CHANGED (extracted from old btn handler)
      if(!file) return;
      prog.classList.remove('d-none');
      btn.disabled = true;
      try{
        const fd = new FormData();
        fd.set('file', file, file.name);
        const m = (meta.value||'').trim(); if(m) fd.set('meta', m); // uses whatever is in "Optional metadata" right now
        
        const res = await fetch(AP+'/sign', { method:'POST', body:fd });
        if(!res.ok){ const t = await res.text(); throw new Error(t||'sign error'); }

        const disp  = res.headers.get('content-disposition') || '';
        const match = /filename="?([^"]+)"?/i.exec(disp);
        const name  = match ? match[1] : ('signed-'+(file.name||'document')+(res.headers.get('content-type')?.includes('zip')?'.zip':''));
        const blob  = await res.blob();
        const url   = URL.createObjectURL(blob);
        const a     = Object.assign(document.createElement('a'), { href:url, download:name });
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
        toast('Signed & downloaded','success');
        loadRows(); // refresh issued list
      }catch(e){
        toast('Signing failed','danger');
      }finally{
        prog.classList.add('d-none');
        btn.disabled = false;
        file = null;
      }
    }

    // Set & auto-sign immediately
    const setFile = f => { // CHANGED (auto-trigger)
      if(!isPDF(f)){ toast('Please select a PDF','warning'); return; }
      file = f;
      toast('Processing '+(f?.name||'document')+'…');
      // no need to wait — start right away
      void signNow(); // NEW
    };

    // Drag & drop
    ['dragenter','dragover'].forEach(ev=>dz.addEventListener(ev, e=>{e.preventDefault(); dz.classList.add('drag');}));
    ['dragleave','drop'].forEach(ev=>dz.addEventListener(ev, e=>{e.preventDefault(); dz.classList.remove('drag');}));
    dz.addEventListener('drop', e=>{
      const f = e.dataTransfer.files?.[0];
      if(f) setFile(f); // CHANGED: auto process on drop
    });

    // File picker
    fp.addEventListener('change', ()=>{
      const f = fp.files?.[0];
      if(f) setFile(f);     // CHANGED: auto process on select
      fp.value = '';        // keep this so selecting the same file later retriggers "change"  // NEW
    });

    // REMOVE this line — the label already activates the input and this can cause awkward UX
    // dz.querySelector('label').addEventListener('click', ()=>fp.click());  // DELETED

    // Keep button as a fallback/manual trigger
    btn.addEventListener('click', signNow); // CHANGED

    // init
    loadRows();
  </script>

</body></html>`;
return text(html.replaceAll("__CSP_NONCE__", nonce), nonce);
}



function diagnostics(env: Env, haveDB=true){
  const reqd = [
    ["ISSUER", !!env.ISSUER],
    ["SIGNER_API_BASE", !!env.SIGNER_API_BASE],
    ["DB binding (DB)", haveDB],
    ["DB_PREFIX", !!env.DB_PREFIX],
    ["SIGNING_GATEWAY_HMAC_KEY", !!env.SIGNING_GATEWAY_HMAC_KEY],
    ["SESSION_HMAC_KEY", !!env.SESSION_HMAC_KEY],
    ["TOTP_MASTER_KEY", !!env.TOTP_MASTER_KEY],
    ["ADMIN_PASS_HASH", !!env.ADMIN_PASS_HASH],
  ];
  const li = reqd.map(([k,ok])=>`<li>${ok?"✅":"❌"} <code>${k}</code></li>`).join("");
  return `<ul>${li}</ul>`;
}

async function handleAdmin(env: Env, req: Request, adminPath: string){
  await ensureSchema(env);
  const u = new URL(req.url);
  const cookieHeader = req.headers.get("cookie") || "";
  const sid = cookieHeader.split(/;\s*/).find(x=>x.startsWith("admin_session="))?.split("=")[1];
  const session = sid ? await verifySession(env, sid) : null;

  if (req.method === "GET"){
    // one-time admin portal key display (first visit)
    const show = await consumeOneTimeAdminKey(env);
    if (show){      
      return renderAdminBootstrapOnce(show, env.ISSUER, adminPath);
    }
    // JSON feed for dashboard data
    if (u.searchParams.get("json") === "1") {
      if (!session) return json({error:"unauthorized"}, 401);
      const p = env.DB_PREFIX;
      const res = await env.DB.prepare(`SELECT doc_sha256, signed_at, revoked_at, meta_json FROM ${p}documents ORDER BY signed_at DESC`).all() as any;
      const docs = (res.results||[]).map((r:any)=>({ sha: r.doc_sha256, signed_at: r.signed_at, revoked_at: r.revoked_at || null, meta: r.meta_json||"{}" }));
      const active = docs.filter((d:any)=>!d.revoked_at).length;
      return json({ documents: docs, counts: { total: docs.length, active, revoked: docs.length-active } });
    }
    if (!session) return renderAdminLogin(env.ISSUER, adminPath);
    return renderAdminDashboard(env.ISSUER, adminPath);
  }


  if (req.method === "POST"){
    // if (!sameOrigin(req)) return new Response("bad origin", { status: 403 });
    const form = await req.formData();    
    if (u.pathname === adminPath + "/login"){
      const pass = String(form.get("password")||"");
      const ok = await verifyPBKDF2(env, pass);      
      if(!ok) {
        return new Response("<h1>Unauthorized</h1>", {
          status: 401,
          headers: { "content-type": "text/html; charset=utf-8" }
        });
      }
      const sidv = await signSession(env, {ok:true, t: now()});
      return new Response(null, { status:303, headers:{ "set-cookie": cookie("admin_session", sidv, {Path: adminPath}), "location": adminPath }});     
    }
    if (u.pathname === adminPath + "/logout"){
      return new Response(null, { status:303, headers:{ "set-cookie": "admin_session=; Max-Age=0; Path="+adminPath+"; HttpOnly; SameSite=Strict", "location": adminPath }});     
    }    
    if (!session) {
      return new Response("<h1>Unauthorized</h1>", {
        status: 401,
        headers: { "content-type": "text/html; charset=utf-8" }
      });
    }

    if (u.pathname === adminPath + "/sign"){
      const file = form.get("file") as File | null;
      if(!file) return json({error:"file missing"}, 400);
      // const buf = await file.arrayBuffer();
      // const sha = await sha256(buf);
      const buf = await file.arrayBuffer();          // original (unsigned)

      // HMAC gating to signer
      const { ts, nonce, sig } = await hmac(env, buf, "POST", "/sign");

      const HH = env.WORKER_HMAC_HEADER || "x-worker-hmac";
      const HT = env.WORKER_HMAC_TS_HEADER || "x-worker-ts";
      const HN = env.WORKER_HMAC_NONCE_HEADER || "x-worker-nonce";

      const res = await fetch(new URL("/sign", env.SIGNER_API_BASE).toString(), {
        method:"POST",
        headers:{
          [HH]: sig,
          [HT]: ts,
          [HN]: nonce
        },
        body: (()=>{ const fd = new FormData(); fd.set("file", new Blob([buf], {type:"application/pdf"}), "in.pdf"); return fd; })()
      });
      if(!res.ok) return json({error:"signer error", detail: await res.text()}, 502);
      const certSerial = res.headers.get("x-cert-serial") || "";
      const signed = await res.arrayBuffer();
      const sha = await sha256(signed);              // hash of the *signed* file

      // Verify the just-signed file server-side BEFORE persisting or offering for download
      const vf = new FormData();
      vf.set("file", new Blob([signed], {type:"application/pdf"}), "signed.pdf");
      const vres = await fetch(new URL("/verify", env.SIGNER_API_BASE).toString(), { method:"POST", body:vf });
      if(!vres.ok){
        return json({error:"verify failed (signer side)"}, 502);
      }
      const vinfo = await vres.json() as any;
      const okEmbedded = vinfo && vinfo.hasSignature && vinfo.isValid && vinfo.issuedByUs && vinfo.coversDocument;
      if(!okEmbedded){
        // Do NOT store an unverifiable artifact
        return json({error:"signer produced an unverifiable PDF", details:vinfo}, 502);
      }

      const meta = String(form.get("meta")||"").trim();
      const p = env.DB_PREFIX;

      await env.DB
        .prepare(`INSERT OR IGNORE INTO ${p}documents
                  (id,doc_sha256,meta_json,signed_at,revoked_at,cert_serial)
                  VALUES(?,?,?,?,NULL,?)`)
        .bind(crypto.randomUUID(), sha, meta || "{}", now(), certSerial)
        .run();
      // Upsert the verification result
      await env.DB
        .prepare(`INSERT OR REPLACE INTO ${p}doc_verifications
                  (doc_sha256,has_signature,is_valid,issued_by_us,covers_document,subfilter,issuer,verified_at)
                  VALUES(?,?,?,?,?,?,?,?)`)
        .bind(sha, vinfo.hasSignature?1:0, vinfo.isValid?1:0, vinfo.issuedByUs?1:0, vinfo.coversDocument?1:0,
              String(vinfo.subFilter||""), String(vinfo.issuer||""), now())
        .run();
      await env.DB
        .prepare(`INSERT INTO ${p}audit
                  (id,at,action,doc_sha256,ip,ua,detail)
                  VALUES(?,?,?,?,?,?,?)`)
        .bind(crypto.randomUUID(), now(), "sign", sha, "", "", "")
        .run();
      
      const wantZip = (env.BUNDLE_TRUST_KIT || "0") === "1";
      if (!wantZip) {
        // Old behavior: return the signed PDF directly
        return new Response(signed, {
          headers: {
            "content-type":"application/pdf",
            "content-disposition":`attachment; filename="signed.pdf"`,
            "x-doc-sha256": sha,
            "x-issuer": env.ISSUER,
            "x-doc-verified":"true"
          }
        });
      }

      // New behavior: return one ZIP that contains (1) signed.pdf and (2) Trust Kit ZIP + README-FIRST.txt
      const kitUrl = new URL("/dmj-one-trust-kit.zip", env.PKI_BASE).toString();
      // Try to fetch the Trust Kit; if it fails (TLS/DNS not ready), gracefully fall back to direct PDF.
      let kit: Uint8Array | null = null;
      try {
        const kitRes = await fetch(kitUrl);
        if (kitRes.ok) {
          kit = new Uint8Array(await kitRes.arrayBuffer());
        }
      } catch (_) { /* ignore bootstrap network/SSL errors */ }
      if (!kit) {
        return new Response(signed, {
          headers: {
            "content-type":"application/pdf",
            "content-disposition":`attachment; filename="signed.pdf"`,
            "x-doc-sha256": sha,
            "x-issuer": env.ISSUER,
            "x-doc-verified":"true",
            "x-note": "trust-kit-unavailable"
          }
        });
      }
      const readmeFirst = new TextEncoder().encode(
      `dmj.one - Digital Signature Root Certificate
=====================================================
1. Automatic Method
    - Unzip and Open the dmj-one-trust-kit folder. 
    - Double click "install-dmj-certificates.bat" to automatically install all certificates.

2. Manual Method
    - Unzip and Open the dmj-one-trust-kit folder.
    - Open the "dmj-one-trust-kit-README.html" and follow the steps for your device.
            
Install the dmj.one Root CA once. Then any dmj.one-signed PDF will verify as trusted.

You can reivew the codes to verify for any discrepencies. Use ChatGPT to check its authenticty!

Having problems installing? Mail us at contact@dmj.one 
      `);

      const zipBytes = await buildZip([
        { name: "Your Document (signed).pdf", data: new Uint8Array(signed) },
        { name: "Trust Kit/README-FIRST.txt", data: readmeFirst },
        { name: "Trust Kit/dmj-one-trust-kit.zip", data: kit }
      ]);

      // Persist briefly and redirect so download managers see a GET
      const filename = `dmj-one-signed-bundle-${sha.slice(0,8)}.zip`;
      const id = await putDownload(env, zipBytes, "application/zip", filename);
      return new Response(null, {
        status: 303, // See Other: follow-up with a GET to the Location
        headers: { "location": `/download/${id}/${encodeURIComponent(filename)}` }
      });

    }

    if (u.pathname === adminPath + "/revoke"){     
      const p = env.DB_PREFIX;
      const sha = String(form.get("sha")||"");
      // Look up certificate serial for this document
      const row = await env.DB
        .prepare(`SELECT cert_serial FROM ${p}documents WHERE doc_sha256=?`)
        .bind(sha)
        .first() as any;
      const serial = row?.cert_serial || "";
      if (!serial) return json({error:"no cert serial recorded for this document"}, 400);

      // HMAC‑gated call to signer /revoke
      const params = new URLSearchParams({ serial });
      const bodyBytes = new TextEncoder().encode(params.toString());
      const { ts, nonce, sig } = await hmac(env, bodyBytes, "POST", "/revoke");
      const HH = env.WORKER_HMAC_HEADER || "x-worker-hmac";
      const HT = env.WORKER_HMAC_TS_HEADER || "x-worker-ts";
      const HN = env.WORKER_HMAC_NONCE_HEADER || "x-worker-nonce";
      const r = await fetch(new URL("/revoke", env.SIGNER_API_BASE).toString(), {
        method: "POST",
        headers: {
          [HH]: sig,
          [HT]: ts,
          [HN]: nonce,
          "content-type": "application/x-www-form-urlencoded"
        },
        body: params
      });
      if (!r.ok) return json({error:"revoke failed at signer"}, 502);

      await env.DB
        .prepare(`UPDATE ${p}documents SET revoked_at=? WHERE doc_sha256=?`)
        .bind(now(), sha)
        .run();
      await env.DB
        .prepare(`INSERT INTO ${p}audit
                  (id,at,action,doc_sha256,ip,ua,detail)
                  VALUES(?,?,?,?,?,?,?)`)
        .bind(crypto.randomUUID(), now(), "revoke", sha, "", "", "")
        .run();
      // JSON for XHR, redirect for classic form posts
      const wantsJson = (req.headers.get("accept")||"").includes("application/json");
      if (wantsJson) return json({ ok:true, sha, revoked_at: now() });
      return new Response(null, { status:303, headers:{location: adminPath} });
    }
  }

  // return text("<h1>Not Found</h1>"), {status:404} as any;
  return new Response("<h1>Not Found</h1>", {
    status: 404,
    headers: { "content-type": "text/html; charset=utf-8" }
  });
}

async function handleVerify(env: Env, req: Request){
  await ensureSchema(env);

  const form = await req.formData();
  const f = form.get("file") as File | null;
  if (!f) return json({error:"file missing"}, 400);

  const buf = await f.arrayBuffer();
  const sha = await sha256(buf);

  const p = env.DB_PREFIX;
  const row = await env.DB.prepare(`SELECT signed_at, revoked_at FROM ${p}documents WHERE doc_sha256=?`).bind(sha).first() as any;

  // Ask signer to validate embedded signature/issuer
  const vf = new FormData(); vf.set("file", new Blob([buf],{type:"application/pdf"}), "doc.pdf");
  const vres = await fetch(new URL("/verify", env.SIGNER_API_BASE).toString(), { method:"POST", body:vf });
  const vinfo = vres.ok ? await vres.json() : { hasSignature:false, isValid:false, coversDocument:false, issuedByUs:false, issuer:"" };

  const issued  = !!row;
  const revoked = !!row?.revoked_at;
  const okSig   = vinfo.hasSignature && vinfo.isValid && vinfo.coversDocument && vinfo.issuedByUs;
  const verdict = (issued && !revoked && okSig) ? "valid" : "tampered";

  // JSON mode (for inline UX)
  const u = new URL(req.url);
  const wantsJson = u.searchParams.get("json") === "1" || (req.headers.get("accept")||"").includes("application/json");
  if (wantsJson) {
    return json({
      sha256: sha,
      verdict,
      issued,
      revoked,
      hasSignature: !!vinfo.hasSignature,
      isValid:      !!vinfo.isValid,
      coversDocument: !!vinfo.coversDocument,
      issuedByUs:   !!vinfo.issuedByUs,
      issuer:       String(vinfo.issuer || ""),
      verifiedAt:   now()
    });
  }

  // existing HTML path (unchanged), but you can keep your current markup here
  const statusHtml = revoked || !okSig ? '❌ <b>Revoked or altered</b>' : '✅ <b>Active</b>';
  const html = `<!doctype html><meta charset="utf-8"><title>Verify</title>
  <body style="font-family:ui-sans-serif;padding:32px">
  <h1>Verification result</h1>
  <p>SHA-256: <code>\${sha}</code></p>
  <p>Status: \${statusHtml}</p>
  <ul>
    <li>Registered by dmj.one: \${issued ? "✅" : "❌"}</li>
    <li>Revoked: \${revoked ? "❌ (revoked)" : "✅ (not revoked)"}</li>
    <li>Signature object present: \${vinfo.hasSignature ? "✅" : "❌"}</li>
    <li>Embedded signature cryptographically valid: \${vinfo.isValid ? "✅" : "❌"}</li>
    <li>Covers whole document (ByteRange): \${vinfo.coversDocument ? "✅" : "❌"}</li>
    <li>Signed by our key (dmj.one): \${vinfo.issuedByUs ? "✅" : "❌"}</li>
    <li>Issuer (from signature): <code>\${vinfo.issuer||""}</code></li>
  </ul>
  <h2>\${(verdict === "valid") ? "✅ Genuine (dmj.one)" : "❌ Not valid / tampered"}</h2>
  <p><a href="/">Back</a></p></body>`;
  return text(html);
}


export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const ap = '/' + (env.ADMIN_PATH || 'admin'); // dynamic admin path
    const nonce = genNonce();
    // --- IDM-friendly GET download endpoint -------------------------------
    // Supports GET and HEAD. One-shot: the first GET consumes the token.
    if (url.pathname.startsWith("/download/") && (req.method === "GET" || req.method === "HEAD")) {
      const parts = url.pathname.split("/");
      // /download/<id>[/<filename>]
      const id = parts[2] || "";
      const peek = await getDownload(env, id, /*consume*/ req.method === "GET");
      if (!peek) return new Response("Link expired or invalid", { status: 410 });
      const headers: Record<string,string> = {
        "content-type": peek.mime,
        "content-disposition": `attachment; filename="${peek.filename}"`,
        "cache-control": "no-store, private",
        "pragma": "no-cache",
        "x-content-type-options": "nosniff",
        "accept-ranges": "none",
        "content-length": String(peek.bytes.length)
      };
      if (req.method === "HEAD") return new Response(null, { headers });
      return new Response(peek.bytes, { headers });
    }
    if (url.pathname === "/") return renderHome(env.ISSUER, nonce);
    if (url.pathname === "/verify" && req.method === "POST") return handleVerify(env, req, nonce);    
    if (url.pathname === ap || url.pathname.startsWith(ap + "/")) return handleAdmin(env, req, ap, nonce);
    if (url.pathname === "/healthz") return new Response("ok");
    return new Response("Not found", {status:404});
  }
}
TS

# Detect reachable scheme for signer/pki to avoid TLS bootstrap race
SIGNER_PROTO="https"
if ! curl -fsS --max-time 5 "https://${SIGNER_DOMAIN}/healthz" >/dev/null 2>&1; then
  if curl -fsS --max-time 5 "http://${SIGNER_DOMAIN}/healthz" >/dev/null 2>&1; then SIGNER_PROTO="http"; fi
fi
PKI_PROTO="https"
if ! curl -fsS --max-time 5 "https://${PKI_DOMAIN}/root.crt" >/dev/null 2>&1; then
  if curl -fsS --max-time 5 "http://${PKI_DOMAIN}/root.crt" >/dev/null 2>&1; then PKI_PROTO="http"; fi
fi

TSA_PROTO="https"
if ! curl -fsS --max-time 5 "https://${TSA_DOMAIN}/healthz" >/dev/null 2>&1; then
  if curl -fsS --max-time 5 "http://${TSA_DOMAIN}/healthz" >/dev/null 2>&1; then TSA_PROTO="http"; fi
fi

# Patch signer env with the detected TSA URL (keep AIA scheme for PKI)
sudo sed -i "s|^DMJ_TSA_URL=.*|DMJ_TSA_URL=${TSA_PROTO}://${TSA_DOMAIN}/|" "${DMJ_ENV_FILE}"

# Optional Basic Auth credentials for TSA (if you set them, signer will use them)
if ! grep -q '^DMJ_TSA_USER=' "${DMJ_ENV_FILE}"; then
  echo "DMJ_TSA_USER=" | sudo tee -a "${DMJ_ENV_FILE}" >/dev/null
  echo "DMJ_TSA_PASS=" | sudo tee -a "${DMJ_ENV_FILE}" >/dev/null
fi

# wrangler configuration (use JSONC as per latest recommendation)
as_dmj tee "${WORKER_DIR}/wrangler.jsonc" >/dev/null <<JSON
{
  "\$schema": "node_modules/wrangler/config-schema.json",
  "name": "${WORKER_NAME}",
  "main": "src/index.ts",
  "compatibility_date": "2025-10-10",
  "observability": { "enabled": true },
  "d1_databases": [
    {
      "binding": "DB",
      "database_id": "${CF_D1_DATABASE_ID}",
      "database_name": "${D1_NAME}"
    }
  ],
  "vars": {
    "ISSUER":        "${DMJ_ROOT_DOMAIN}",
    "SIGNER_API_BASE": "${SIGNER_PROTO}://${SIGNER_DOMAIN}",
    "DB_PREFIX":     "${DB_PREFIX}",    
    "PKI_BASE":      "${PKI_PROTO}://${PKI_DOMAIN}",
    "BUNDLE_TRUST_KIT": "1",            // 1 = return a zip bundle (PDF + Trust Kit)
    "ADMIN_PATH":    "${ADMIN_PATH}",   // randomized each run
    "WORKER_HMAC_HEADER": "${WORKER_HMAC_HEADER}",
    "WORKER_HMAC_TS_HEADER": "${WORKER_HMAC_TS_HEADER}",
    "WORKER_HMAC_NONCE_HEADER": "${WORKER_HMAC_NONCE_HEADER}"
  }
}
JSON

# Seed schema remotely so we can insert bootstrap key
as_dmj tee "${WORKER_DIR}/schema.sql" >/dev/null <<SQL
CREATE TABLE IF NOT EXISTS ${DB_PREFIX}documents(
  id TEXT PRIMARY KEY,
  doc_sha256 TEXT UNIQUE,
  meta_json TEXT,
  signed_at INTEGER,
  revoked_at INTEGER,
  revoke_reason TEXT,
  cert_serial TEXT
);
CREATE INDEX IF NOT EXISTS ${DB_PREFIX}documents_sha_idx ON ${DB_PREFIX}documents(doc_sha256);
CREATE TABLE IF NOT EXISTS ${DB_PREFIX}doc_verifications(
  doc_sha256 TEXT PRIMARY KEY,
  has_signature INTEGER,
  is_valid INTEGER,
  issued_by_us INTEGER,
  covers_document INTEGER,
  subfilter TEXT,
  issuer TEXT,
  verified_at INTEGER
);
CREATE TABLE IF NOT EXISTS ${DB_PREFIX}audit(
  id TEXT PRIMARY KEY,
  at INTEGER,
  action TEXT,
  doc_sha256 TEXT,
  ip TEXT,
  ua TEXT,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS ${DB_PREFIX}bootstrap(
  k TEXT PRIMARY KEY,
  v TEXT,
  consumed INTEGER DEFAULT 0,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS ${DB_PREFIX}sessions(
  sid TEXT PRIMARY KEY,
  created_at INTEGER,
  last_seen INTEGER,
  ip_hash TEXT,
  ua_hash TEXT
);
SQL

say "[+] Applying schema to remote D1..."
( cd "$WORKER_DIR" && "$WR" d1 execute "${D1_NAME}" --remote --file ./schema.sql )

# Older databases may lack the new 'cert_serial' column.
# CREATE TABLE IF NOT EXISTS won't add columns, so add it explicitly and ignore errors if it exists.
# say "[i] Ensuring cert_serial column exists..."
# ( cd "$WORKER_DIR" && "$WR" d1 execute "${D1_NAME}" --remote --command "ALTER TABLE ${DB_PREFIX}documents ADD COLUMN cert_serial TEXT;" ) || true


# Optional clean-up: remove any server-side session records (not strictly required,
# since rotating SESSION_HMAC_KEY already invalidates cookies, but keeps table tidy).
if [ "${DMJ_FORCE_ADMIN_RELOGIN}" = "1" ]; then
  say "[i] Purging server-side session rows..."
  ( cd "$WORKER_DIR" && "$WR" d1 execute "${D1_NAME}" --remote --command "DELETE FROM ${DB_PREFIX}sessions;" ) || true
fi

# Insert one-time admin key for first GUI fetch
say "[+] Storing one-time admin portal key for first GUI access..."
( cd "$WORKER_DIR" && "$WR" d1 execute "${D1_NAME}" --remote --command \
"INSERT OR REPLACE INTO ${DB_PREFIX}bootstrap(k,v,consumed,created_at) VALUES('ADMIN_PORTAL_KEY','${ADMIN_PORTAL_KEY}',0,${EPOCHSECONDS:-$(date +%s)});" )

# Upload Worker secrets (pipe, non-interactive) 
say "[+] Pushing Worker secrets to Cloudflare..."
(
  cd "$WORKER_DIR"
  # turn off xtrace so secrets don't end up in logs
  _xtrace_state=$(set +o | grep xtrace); set +x

  printf '%s' "${SIGNING_GATEWAY_HMAC_KEY}" | "$WR" secret put SIGNING_GATEWAY_HMAC_KEY --name "${WORKER_NAME}"
  printf '%s' "${SESSION_HMAC_KEY}"        | "$WR" secret put SESSION_HMAC_KEY        --name "${WORKER_NAME}"
  printf '%s' "${TOTP_MASTER_KEY}"         | "$WR" secret put TOTP_MASTER_KEY         --name "${WORKER_NAME}"
  printf '%s' "${ADMIN_HASH}"              | "$WR" secret put ADMIN_PASS_HASH         --name "${WORKER_NAME}"
  # ^ Each 'secret put' creates a new Worker version with updated secrets.

  # restore previous xtrace state
  eval "$_xtrace_state"
)
fix_perms

# Deploy Worker (modern command) 
say "[+] Deploying Worker..."
( cd "$WORKER_DIR" && "$WR" deploy )

WORKER_URL="$("$WR" deployments list --format=json | jq -r '.[0].url' || true)"
echo "------------------------------------------------------------------"
echo "[✓] Done."
echo "URL: https://documents.dmj.one"
echo "Signer URL (nginx): https://${SIGNER_DOMAIN}/healthz"
echo
echo "NEXT STEPS:"
echo "1) Visit ${WORKER_URL:-your workers.dev URL}/${ADMIN_PATH}   — you will see the admin key ONCE."
echo "2) In Cloudflare Dashboard, add a Route to bind this Worker to your domain (e.g. https://documents.${DMJ_ROOT_DOMAIN}/*)."
echo "------------------------------------------------------------------"

say "[i] Admin Access: https://documents.dmj.one/${ADMIN_PATH}"
say "[✓] Done."

# --- Optional: systemd unit to tail Worker logs into journald ---------------
sudo tee /etc/systemd/system/dmj-worker-tail.service >/dev/null <<UNIT
[Unit]
Description=Cloudflare Worker tail -> journald
After=network-online.target
Wants=network-online.target

[Service]
User=${DMJ_USER}
Group=${DMJ_USER}
Type=simple
WorkingDirectory=${WORKER_DIR}
EnvironmentFile=-/etc/dmj/dmj-worker.secrets
StandardOutput=journal
StandardError=inherit
ExecStart=${WR} tail --name ${WORKER_NAME} --format=pretty
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

# Enable/disable wrangler tail based on verbosity toggle
if [ "\${DMJ_LOG_VERBOSE:-1}" = "1" ]; then
  sudo systemctl enable --now dmj-worker-tail.service || true
else
  sudo systemctl disable --now dmj-worker-tail.service 2>/dev/null || true
fi