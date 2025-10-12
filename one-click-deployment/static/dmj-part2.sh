# dmj-part2.sh
#!/usr/bin/env bash
set -euo pipefail

### --- Config / Inputs -------------------------------------------------------
LOG_DIR="/var/log/dmj"
STATE_DIR="/var/lib/dmj"
CONF_DIR="/etc/dmj"
INST_ENV="${CONF_DIR}/installer.env"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"

### ---------- Logging / Verbosity ----------
LOG_DIR="/var/log/dmj"; STATE_DIR="/var/lib/dmj"; CONF_DIR="/etc/dmj"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"
LOG_FILE="${LOG_DIR}/part2-$(date +%Y%m%dT%H%M%S).log"

DMJ_VERBOSE="${DMJ_VERBOSE:-0}"

# Load installation id / DB_PREFIX
# shellcheck disable=SC1090
[ -f "$INST_ENV" ] && source "$INST_ENV" || { echo "[x] Missing ${INST_ENV}. Run Part 1 first."; exit 1; }

DMJ_ROOT_DOMAIN="${DMJ_ROOT_DOMAIN:-dmj.one}"
SIGNER_DOMAIN="${SIGNER_DOMAIN:-signer.${DMJ_ROOT_DOMAIN}}"

WORKER_NAME="dmj-${INSTALLATION_ID}-docsign"
WORKER_DIR="/opt/dmj/worker"
SIGNER_DIR="/opt/dmj/signer-vm"
NGINX_SITE="/etc/nginx/sites-available/dmj-signer"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/dmj-signer"

# --- PKI / OCSP endpoints (brand + URLs) -------------------------------------
PKI_DOMAIN="${PKI_DOMAIN:-pki.${DMJ_ROOT_DOMAIN}}"
OCSP_DOMAIN="${OCSP_DOMAIN:-ocsp.${DMJ_ROOT_DOMAIN}}"

PKI_DIR="/opt/dmj/pki"
ROOT_DIR="${PKI_DIR}/root"
ICA_DIR="${PKI_DIR}/ica"
OCSP_DIR="${PKI_DIR}/ocsp"
PKI_PUB="${PKI_DIR}/pub"

DL_DIR="${PKI_PUB}/dl"
sudo mkdir -p "${DL_DIR}"
sudo chmod 755 "${PKI_PUB}" "${DL_DIR}"

find /opt/dmj/pki/pub/dl -type f -mtime +1 -delete

# Branded subject names (official)
ROOT_CN="${ROOT_CN:-dmj.one Root CA R1}"
ICA_CN="${ICA_CN:-dmj.one Issuing CA R1}"
OCSP_CN="${OCSP_CN:-dmj.one OCSP Responder R1}"
SIGNER_CN="${SIGNER_CN:-dmj.one Document Signer (Production)}"
ORG_NAME="${ORG_NAME:-dmj.one Trust Services}"
COUNTRY="${COUNTRY:-IN}"

# Optional: control AIA/CRL scheme for certificates (keep http as default)
AIA_SCHEME="${AIA_SCHEME:-https}"   # use http (recommended). Only set to https if you KNOW clients will follow.

PASS="$(openssl rand -hex 24)"
PKCS12_ALIAS="${PKCS12_ALIAS:-dmj-one}"

# ---- Shipping policy flags (pin end-user CA kit) ----
CA_SERIES="${CA_SERIES:-r1}"                    # Active CA on the server (may change in the future)
DMJ_SHIP_CA_SERIES="${DMJ_SHIP_CA_SERIES:-r1}"  # The end-user kit you ship. Pin this for years.
DMJ_REISSUE_ROOT="${DMJ_REISSUE_ROOT:-0}"       # 0 = never touch Root by default
DMJ_REISSUE_ICA="${DMJ_REISSUE_ICA:-0}"         # 0 = never touch Issuing by default
DMJ_REISSUE_OCSP="${DMJ_REISSUE_OCSP:-0}"       # 0 = rarely needed
DMJ_REISSUE_LEAF="${DMJ_REISSUE_LEAF:-1}"       # 1 = rotate signer freely
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
DMJ_REISSUE_ALL_HARD_RESET="${DMJ_REISSUE_ALL_HARD_RESET:-0}" # Never enable this
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
      <version>3.0.5</version>
    </dependency>
    <dependency>
      <groupId>org.apache.pdfbox</groupId>
      <artifactId>pdfbox-tools</artifactId>
      <version>3.0.5</version>
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
      <version>2.17.2</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-simple</artifactId>
      <version>2.0.13</version>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <!-- Build a single executable JAR with all deps -->      
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-shade-plugin</artifactId>
        <version>3.5.2</version>
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
sudo tee "${SIGNER_DIR}/src/main/java/one/dmj/signer/SignerServer.java" >/dev/null <<'JAVA'
package one.dmj.signer;

import io.javalin.Javalin;
import io.javalin.http.UploadedFile;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class SignerServer {

  static final String WORK_DIR = "/opt/dmj/signer-vm";
  static final Path P12_PATH = Paths.get(WORK_DIR, "keystore.p12");
  static final Path P12_PASS = Paths.get(WORK_DIR, "keystore.pass");
  static final String P12_ALIAS = "dmj-one";
  static final String HMAC_HEADER = "x-worker-hmac";
  static final String HMAC_TS = "x-worker-ts";
  static final String HMAC_NONCE = "x-worker-nonce";

  static final Set<String> RECENT_NONCES = Collections.synchronizedSet(new LinkedHashSet<>());

  static { Security.addProvider(new BouncyCastleProvider()); }

  static class Keys {
    final PrivateKey priv;
    final X509Certificate cert;
    final List<X509Certificate> chain;
    Keys(PrivateKey p, X509Certificate c, List<X509Certificate> ch){ this.priv=p; this.cert=c; this.chain=ch; }
  }

  static Keys loadKeys() throws Exception {
    char[] pass = Files.readString(P12_PASS).trim().toCharArray();
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(P12_PATH)) { ks.load(in, pass); }
    PrivateKey pk = (PrivateKey) ks.getKey(P12_ALIAS, pass);
    X509Certificate leaf = (X509Certificate) ks.getCertificate(P12_ALIAS);

    // IMPORTANT: use fully-qualified type to avoid ambiguity
    java.security.cert.Certificate[] chainArr = ks.getCertificateChain(P12_ALIAS);
    List<X509Certificate> chain = new ArrayList<>();
    if (chainArr != null) {
      for (java.security.cert.Certificate c : chainArr) {
        chain.add((X509Certificate) c);
      }
    } else {
      // Fall back to just the leaf if the P12 didn’t contain the chain
      chain.add(leaf);
    }
    return new Keys(pk, leaf, chain);
  }

  static String spkiBase64(X509Certificate cert) throws IOException {
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(cert.getPublicKey().getEncoded());
    return Base64.toBase64String(spki.getEncoded());
  }

  static boolean verifyHmac(String sharedBase64, String method, String path, byte[] body, String ts, String nonceB64, String providedB64) throws Exception {
    long now = Instant.now().getEpochSecond();
    long t = Long.parseLong(ts);
    if (Math.abs(now - t) > 300) return false; // 5 min skew

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
    gen.addCertificates(new JcaCertStore(chain)); // include ICA so validators can build the path

    CMSTypedData msg = new CMSProcessableByteArray(toSign);
    CMSSignedData cms = gen.generate(msg, false); // detached
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

  // Resolve desired signing mode from env
  static int resolveDocMDP() {
    String mode = Optional.ofNullable(System.getenv("DMJ_SIGN_MODE")).orElse("approval").toLowerCase(Locale.ROOT);
    return switch (mode) {
      case "certify-p1" -> 1;
      case "certify-p2" -> 2;
      case "certify-p3" -> 3;
      default -> 0; // approval (no DocMDP)
    };
  }

  // Invisible approval/certification signature using external signing
  static byte[] signPdf(byte[] original, PrivateKey pk, List<X509Certificate> chain) throws Exception {
    try (PDDocument doc = Loader.loadPDF(original);
         ByteArrayOutputStream baos = new ByteArrayOutputStream(original.length + 65536)) {

      PDSignature sig = new PDSignature();
      sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED); // Adobe-compatible detached CMS
      sig.setName("dmj.one");
      sig.setLocation("IN");
      sig.setReason("Contents securely verified by dmj.one against any tampering.");
      sig.setContactInfo("contact@dmj.one");
      sig.setSignDate(Calendar.getInstance());

      int mdp = resolveDocMDP();
      if (mdp != 0) setMDPPermission(doc, sig, mdp);

      SignatureOptions opts = new SignatureOptions();
      opts.setPreferredSignatureSize(65536);

      // Official external signing flow: addSignature → saveIncrementalForExternalSigning → getContent/setSignature
      doc.addSignature(sig, opts); // invisible (no visual template)
      ExternalSigningSupport ext = doc.saveIncrementalForExternalSigning(baos);
      byte[] cms = buildDetachedCMS(ext.getContent(), pk, chain);
      ext.setSignature(cms);

      return baos.toByteArray();
    }
  }

  static String toHex(byte[] b){ StringBuilder sb=new StringBuilder(b.length*2); for(byte x:b) sb.append(String.format("%02x",x)); return sb.toString(); }
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
            // Extract message-digest attr & recompute for diagnostics
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

            // Verify signer
            Collection<X509CertificateHolder> matches = sd.getCertificates().getMatches(si.getSID());
            if (matches.isEmpty()) continue;
            X509CertificateHolder signerHolder = matches.iterator().next();
            boolean ok = si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerHolder));
            anyValid |= ok;

            // SPKI match = "issuedByUs"
            String signerSpki = Base64.toBase64String(signerHolder.getSubjectPublicKeyInfo().getEncoded());
            String ourSpki = Base64.toBase64String(SubjectPublicKeyInfo.getInstance(ourCert.getPublicKey().getEncoded()).getEncoded());
            if (ok && signerSpki.equals(ourSpki)) issuedByUs = true;
            issuerDn = signerHolder.getSubject().toString();
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

  static final Path PKI_PUB = Paths.get(
    Optional.ofNullable(System.getenv("DMJ_PKI_PUB")).orElse("/opt/dmj/pki/pub")
  );
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
      // 1) signed PDF
      zos.putNextEntry(new ZipEntry("signed.pdf"));
      zos.write(signedPdf);
      zos.closeEntry();
      // 2) Trust kit files
      addZipFile(zos, PKI_PUB.resolve("dmj-one-root-ca-r1.cer"), "trust-kit/dmj-one-root-ca-r1.cer");
      addZipFile(zos, PKI_PUB.resolve("dmj-one-root-ca-r1.crt"), "trust-kit/dmj-one-root-ca-r1.crt");
      addZipFile(zos, PKI_PUB.resolve("dmj-one-issuing-ca-r1.crt"), "trust-kit/dmj-one-issuing-ca-r1.crt");
      addZipFile(zos, PKI_PUB.resolve("dmj-one-trust-kit-README.txt"), "trust-kit/README.txt");
      addZipFile(zos, PKI_PUB.resolve("dmj-one-trust-kit-README.html"), "trust-kit/README.html");
      addZipFile(zos, PKI_PUB.resolve("dmj-one-trust-kit-SHA256SUMS.txt"), "trust-kit/SHA256SUMS.txt");
    }
    return out;
  }

  public static void main(String[] args) throws Exception {
    String issuer = Optional.ofNullable(System.getenv("DMJ_ISSUER")).orElse("dmj.one");
    String shared = Optional.ofNullable(System.getenv("SIGNING_GATEWAY_HMAC_KEY")).orElse("");
    int port = choosePort();

    Keys keys = loadKeys();
    String spki = spkiBase64(keys.cert);

    Javalin app = Javalin.create(cfg -> {
      cfg.http.defaultContentType = "application/json";
      cfg.showJavalinBanner = false;
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

      // verify HMAC like /sign
      boolean ok;
      try { ok = verifyHmac(Optional.ofNullable(System.getenv("SIGNING_GATEWAY_HMAC_KEY")).orElse(""),
                            "POST", "/bundle", original, ts, nonce, hmac);
      } catch(Exception e){ ok=false; }
      if (!ok) { ctx.status(401).json(Map.of("error","bad auth")); return; }

      // sign and write bundle
      byte[] signed = signPdf(original, keys.priv, keys.chain);
      String base = "dmj-one-" + java.util.UUID.randomUUID().toString().replace("-", "").substring(0,12);
      Path zipPath = writeBundleZip(signed, base);
      String rel = "/dl/" + zipPath.getFileName().toString();
      String url = PKI_BASE + rel;

      ctx.json(Map.of("download", url));
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
        byte[] signed = signPdf(data, keys.priv, keys.chain); // ← pass chain here
        ctx.contentType("application/pdf");
        ctx.header("X-Signed-By", issuer);
        ctx.result(new ByteArrayInputStream(signed));
      } catch (Exception e){
        ctx.status(500).json(Map.of("error","sign failed", "detail", e.getMessage()));
      }
    });

    app.get("/healthz", ctx -> ctx.result("ok"));
    app.start(port);
  }

  static int choosePort(){
    int[] candidates = {18080,18081,18100,18200,19080,28080};
    for(int p: candidates){
      try(java.net.ServerSocket s = new java.net.ServerSocket()){
        s.setReuseAddress(true);
        s.bind(new java.net.InetSocketAddress("127.0.0.1", p));
        try { Files.writeString(Paths.get("/etc/dmj/signer.port"), ""+p); } catch(IOException ignored){}
        return p;
      } catch(IOException ignored){}
    }
    return 18080;
  }
}
JAVA

### --- Build a branded two-tier PKI + OCSP + signer PKCS#12 -------------------
say "[+] Preparing dmj.one PKI under ${PKI_DIR} ..."
sudo mkdir -p "${ROOT_DIR}/"{certs,newcerts,private} "${ICA_DIR}/"{certs,newcerts,private} "${OCSP_DIR}" "${PKI_PUB}"
sudo touch "${ROOT_DIR}/index.txt" "${ICA_DIR}/index.txt"
[ -f "${ROOT_DIR}/serial" ] || echo 1000 | sudo tee "${ROOT_DIR}/serial" >/dev/null
[ -f "${ROOT_DIR}/crlnumber" ] || echo 1000 | sudo tee "${ROOT_DIR}/crlnumber" >/dev/null
[ -f "${ICA_DIR}/serial" ] || echo 2000 | sudo tee "${ICA_DIR}/serial" >/dev/null
[ -f "${ICA_DIR}/crlnumber" ] || echo 2000 | sudo tee "${ICA_DIR}/crlnumber" >/dev/null

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
authorityInfoAccess = caIssuers;URI:${AIA_SCHEME}://${PKI_DOMAIN}/ica.crt, OCSP;URI:${AIA_SCHEME}://${OCSP_DOMAIN}/
crlDistributionPoints = URI:${AIA_SCHEME}://${PKI_DOMAIN}/ica.crl
[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = emailProtection, codeSigning, 1.3.6.1.4.1.311.10.3.12
subjectKeyIdentifier = hash
authorityInfoAccess = caIssuers;URI:${AIA_SCHEME}://${PKI_DOMAIN}/ica.crt, OCSP;URI:${AIA_SCHEME}://${OCSP_DOMAIN}/
crlDistributionPoints = URI:${AIA_SCHEME}://${PKI_DOMAIN}/ica.crl
[ ocsp ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
authorityInfoAccess = OCSP;URI:${AIA_SCHEME}://${OCSP_DOMAIN}/
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
  certutil -addstore -f "Root" "%ROOT_CERT%"
) else (
  echo [x] Root certificate not found in folder. Looked for:
  echo     %ROOT_CANDIDATES%
)

if defined ICA_CERT (
  echo [+] Installing Intermediate CA: "%ICA_CERT%"
  certutil -addstore -f "CA" "%ICA_CERT%"
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
      dmj-one-trust-kit-SHA256SUMS.txt install-dmj-certificates.bat )
fi

# Always point this public name at the pinned series
( cd "${PKI_PUB}" && ln -sf "dmj-one-trust-kit-${DMJ_SHIP_CA_SERIES}.zip" dmj-one-trust-kit.zip )




say "[+] Building Java signer..."
( cd "$SIGNER_DIR" && mvn -q -DskipTests clean package )

# Systemd service
say "[+] Creating dmj-signer Service..."
sudo tee /etc/systemd/system/dmj-signer.service >/dev/null <<SERVICE
[Unit]
Description=DMJ Signer Microservice
After=network.target

[Service]
User=root
Environment=SIGNING_GATEWAY_HMAC_KEY=${SIGNING_GATEWAY_HMAC_KEY}
Environment=DMJ_ISSUER=${DMJ_ROOT_DOMAIN}
Environment=DMJ_PKI_PUB=${PKI_PUB}
Environment=DMJ_PKI_BASE=${AIA_SCHEME}://${PKI_DOMAIN}
ExecStart=/usr/bin/java -jar ${SIGNER_DIR}/target/dmj-signer-1.0.0.jar
Restart=on-failure
WorkingDirectory=${SIGNER_DIR}

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable --now dmj-signer.service
# Restart Signer
sudo systemctl restart dmj-signer.service

# nginx site (reverse proxy to dynamic port from /etc/dmj/signer.port)
say "[+] Creating dmj-signer nginx config..."
SIGNER_PORT="$(cat /etc/dmj/signer.port 2>/dev/null || echo 18080)"
sudo tee "$NGINX_SITE" >/dev/null <<NGX
server {
  listen 80;
  server_name ${SIGNER_DOMAIN};
  client_max_body_size 25m;

  location / {
    proxy_pass http://127.0.0.1:${SIGNER_PORT};
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


# --- OCSP responder (OpenSSL) behind NGINX ocsp.${DMJ_ROOT_DOMAIN} ----------
say "[+] Creating OSCP Responder nginx..."
sudo tee /etc/systemd/system/dmj-ocsp.service >/dev/null <<OCSP
[Unit]
Description=dmj.one OCSP Responder
After=network.target

[Service]
ExecStart=/usr/bin/openssl ocsp -port 127.0.0.1:9080 \
 -index ${ICA_DIR}/index.txt -rsigner ${OCSP_DIR}/ocsp.crt -rkey ${OCSP_DIR}/ocsp.key \
 -CA ${ICA_DIR}/ica.crt -ignore_err -text
Restart=always
WorkingDirectory=${OCSP_DIR}

[Install]
WantedBy=multi-user.target
OCSP
sudo systemctl daemon-reload
sudo systemctl enable --now dmj-ocsp.service

# --- NGINX: static PKI files host (pki.*) and OCSP proxy (ocsp.*) ----------
sudo tee /etc/nginx/sites-available/dmj-pki >/dev/null <<NGX
server {
  listen 80;
  server_name ${PKI_DOMAIN};
  root ${PKI_PUB};
  autoindex off;
  add_header Cache-Control "public, max-age=3600";
  # correct content types
  types {
    application/pkix-cert crt cer;
    application/pkix-crl  crl;
  }
  location / { try_files \$uri =404; }
}
NGX

sudo tee /etc/nginx/sites-available/dmj-ocsp >/dev/null <<NGX
server {
  listen 80;
  server_name ${OCSP_DOMAIN};
  client_max_body_size 2m;
  # OCSP requests are small POST/GET; just proxy raw to OpenSSL ocsp at / 
  location / {
    proxy_pass http://127.0.0.1:9080;
    proxy_buffering off;
    proxy_set_header Connection "";
  }
}
NGX

sudo ln -sf /etc/nginx/sites-available/dmj-pki  /etc/nginx/sites-enabled/dmj-pki
sudo ln -sf /etc/nginx/sites-available/dmj-ocsp /etc/nginx/sites-enabled/dmj-ocsp
sudo nginx -t && sudo systemctl reload nginx


### --- Worker project --------------------------------------------------------
say "[+] Preparing Cloudflare Worker at ${WORKER_DIR} ..."
sudo mkdir -p "${WORKER_DIR}/src"
sudo chown -R dmjsvc:dmjsvc "$WORKER_DIR"
# Worker TS (admin portal, sign, verify, revoke). Uses Web Crypto + D1.
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
}

// const text = (s: string) => new Response(s, { headers: { "content-type":"text/html; charset=utf-8", "x-frame-options":"DENY", "referrer-policy":"no-referrer", "content-security-policy":"default-src 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none'" }});
const text = (s: string) =>
  new Response(s, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      // allow CSS/fonts from CDNs + our inline script/fetch to same-origin
      "content-security-policy":
        "default-src 'self'; " +
        "style-src 'self' 'unsafe-inline' https:; " +
        "font-src 'self' https: data:; " +
        "img-src 'self' https: data:; " +
        "script-src 'self' 'unsafe-inline'; " +
        "connect-src 'self' https:; " +
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
       revoke_reason TEXT
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

function renderHome(issuerDomain: string) {
  const pkiZip = `https://pki.${issuerDomain}/dmj-one-trust-kit.zip`;

  return text(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>dmj.one Trust Services — Document Verification</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet" />
<link href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css" rel="stylesheet" />

<style>
  :root { --brand: #0d6efd; }
  body {
    background: radial-gradient(1200px 600px at 20% -10%, rgba(13,110,253,.07), transparent 60%),
                radial-gradient(1200px 600px at 80% -10%, rgba(32,201,151,.06), transparent 60%),
                #ffffff;
  }
  .hero-card {
    backdrop-filter: saturate(140%) blur(8px);
    background: rgba(255,255,255,.85);
    border: 1px solid rgba(0,0,0,.06);
  }
  .upload-label { cursor: pointer; }
  .only-one-btn .btn:not(.upload-btn) { display: none !important; } /* keep the 'single button' rule */
  .verdict-badge {
    font-size: clamp(28px, 4.2vw, 48px);
    line-height: 1.1;
  }
  .hash-chip {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    font-size: .9rem; background: #f8f9fb; border: 1px solid #edf0f3; padding: .35rem .55rem; border-radius: .5rem;
  }
  .stat-dot { width: .6rem; height: .6rem; border-radius: 50%; display: inline-block; margin-right: .4rem; }
  .stat-yes { background: #17b26a; } .stat-no { background: #ef4343; }
  .fade-slow { animation-duration: .8s; }
</style>
</head>

<body class="only-one-btn">
  <header class="container py-5">
    <div class="row g-4 align-items-center">
      <div class="col-lg-7">
        <div class="p-4 p-md-5 rounded-4 shadow-sm hero-card animate__animated animate__fadeInDown fade-slow">
          <div class="d-flex align-items-center mb-3">
            <i class="bi-shield-check me-2" style="font-size:1.8rem;color:var(--brand)"></i>
            <h1 class="h3 mb-0">dmj.one Trust Services</h1>
          </div>
          <p class="text-secondary mb-4">Official Document Authenticity Verifier. Upload a PDF to check if it is issued by <span class="fw-semibold">${issuerDomain}</span> and unaltered.</p>

          <!-- Single action: Upload File -->
          <input id="fileInput" class="d-none" type="file" name="file" accept="application/pdf" />
          <label for="fileInput" class="btn btn-primary btn-lg px-4 upload-btn upload-label">
            <i class="bi-upload me-2"></i>Upload File
          </label>

          <!-- live state -->
          <div id="liveState" class="mt-4" hidden>
            <div class="d-flex align-items-center gap-3">
              <div class="spinner-border" role="status" aria-hidden="true"></div>
              <div>
                <div class="fw-semibold" id="stateLine">Starting verification…</div>
                <div class="small text-secondary" id="fileName"></div>
              </div>
            </div>
            <div class="progress mt-3" role="progressbar" aria-label="Verifying">
              <div class="progress-bar progress-bar-striped progress-bar-animated" style="width: 100%"></div>
            </div>
          </div>

          <!-- verdict -->
          <div id="verdictWrap" class="mt-4" hidden>
            <div class="p-4 rounded-4 border animate__animated animate__fadeInUp fade-slow" id="verdictCard">
              <div class="d-flex align-items-center">
                <i id="verdictIcon" class="bi me-3" style="font-size:2.25rem"></i>
                <div>
                  <div id="verdictText" class="verdict-badge fw-bold"></div>
                  <div class="mt-2">
                    <span class="hash-chip" id="shaChip" title="SHA‑256"></span>
                  </div>
                </div>
              </div>

              <!-- Advanced report link (not a button) -->
              <a href="#" id="toggleAdvanced" class="d-inline-flex align-items-center mt-3 text-decoration-none">
                <i class="bi-caret-right-fill me-1"></i><span>View advanced report</span>
              </a>

              <!-- Advanced panel -->
              <div id="advancedPanel" class="mt-3" hidden>
                <div class="row g-3">
                  <div class="col-md-6">
                    <div class="p-3 rounded-3 border bg-white h-100">
                      <div class="mb-2 fw-semibold">Signature & Document</div>
                      <ul class="list-unstyled mb-0 small">
                        <li><span class="stat-dot stat-yes" id="sigObjDot"></span>Signature object present</li>
                        <li><span class="stat-dot stat-yes" id="cryptoDot"></span>Embedded signature is cryptographically valid</li>
                        <li><span class="stat-dot stat-yes" id="coverDot"></span>Signature covers the whole document</li>
                      </ul>
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="p-3 rounded-3 border bg-white h-100">
                      <div class="mb-2 fw-semibold">Issuer & Registry</div>
                      <ul class="list-unstyled mb-0 small">
                        <li><span class="stat-dot stat-yes" id="oursDot"></span>Signed by dmj.one key</li>
                        <li><span class="stat-dot stat-yes" id="regDot"></span>Registered by dmj.one</li>
                        <li><span class="stat-dot stat-yes" id="revokedDot"></span>Revocation check</li>
                        <li class="mt-2 text-break"><span class="text-secondary">Issuer DN:</span> <code id="issuerDn"></code></li>
                      </ul>
                    </div>
                  </div>
                </div>
                <div class="mt-3 small text-secondary">Tip: Install the Trust Kit below so Acrobat/Reader shows “signature is valid” automatically.</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Trust Kit side card -->
      <div class="col-lg-5">
        <div class="p-4 rounded-4 shadow-sm hero-card animate__animated animate__fadeInRight fade-slow">
          <div class="d-flex align-items-center mb-2">
            <i class="bi-box-arrow-down me-2" style="font-size:1.5rem;color:var(--brand)"></i>
            <h2 class="h5 mb-0">Trust Kit (Root & Issuing CA)</h2>
          </div>
          <p class="small text-secondary mb-3">Install once so dmj.one‑signed PDFs show as trusted in Acrobat/Reader and system trust stores.</p>
          <div class="d-flex align-items-center">
            <a href="${pkiZip}" class="link-primary d-inline-flex align-items-center" download>
              <i class="bi-file-zip me-2"></i> Download <span class="ms-1">dmj‑one‑trust‑kit.zip</span>
            </a>
          </div>
          <div class="small text-secondary mt-2">
            Includes quick guides for Windows, macOS, Linux, and an Acrobat‑only path.
          </div>
        </div>
      </div>
    </div>

    <div class="text-center mt-4 small text-secondary">
      <span class="opacity-75">© dmj.one Trust Services</span>
      <span class="mx-2">•</span>
      <a class="link-secondary" href="/admin">Admin</a>
    </div>
  </header>

<script>
  (function(){
    const fileInput = document.getElementById('fileInput');
    const liveState = document.getElementById('liveState');
    const stateLine = document.getElementById('stateLine');
    const fileNameEl = document.getElementById('fileName');
    const verdictWrap = document.getElementById('verdictWrap');
    const verdictCard = document.getElementById('verdictCard');
    const verdictIcon = document.getElementById('verdictIcon');
    const verdictText = document.getElementById('verdictText');
    const shaChip = document.getElementById('shaChip');

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

    function setDot(el, ok){
      el.classList.toggle('stat-yes', !!ok);
      el.classList.toggle('stat-no', !ok);
    }

    function show(state){
      if(state === 'busy'){
        verdictWrap.hidden = true;
        liveState.hidden = false;
      } else if(state === 'done'){
        liveState.hidden = true;
        verdictWrap.hidden = false;
        verdictCard.classList.remove('animate__fadeInUp');
        void verdictCard.offsetWidth; // reflow
        verdictCard.classList.add('animate__fadeInUp');
      }
    }

    toggleAdvanced.addEventListener('click', function(e){
      e.preventDefault();
      const open = advancedPanel.hidden;
      advancedPanel.hidden = !open;
      this.querySelector('i').className = open ? 'bi-caret-down-fill me-1' : 'bi-caret-right-fill me-1';
      this.querySelector('span').textContent = open ? 'Hide advanced report' : 'View advanced report';
    });

    fileInput.addEventListener('change', async function(){
      const f = this.files && this.files[0];
      if(!f) return;
      stateLine.textContent = 'Uploading & verifying…';
      fileNameEl.textContent = f.name;
      show('busy');

      try{
        const fd = new FormData();
        fd.set('file', f, f.name);

        const res = await fetch('/verify?json=1', { method: 'POST', body: fd, headers: { 'Accept': 'application/json' } });
        if(!res.ok){
          throw new Error('Server returned ' + res.status);
        }
        const r = await res.json();

        // verdict
        const isValid = (r && r.verdict === 'valid');
        verdictIcon.className = isValid ? 'bi-shield-check text-success me-3' : 'bi-shield-x text-danger me-3';
        verdictText.className = 'verdict-badge fw-bold ' + (isValid ? 'text-success' : 'text-danger');
        verdictText.textContent = isValid ? 'VALID' : 'TAMPERED';
        shaChip.textContent = (r.sha256 || '').slice(0, 16) + '…' + (r.sha256 || '').slice(-16);

        // advanced
        setDot(dots.sigObjDot, !!r.hasSignature);
        setDot(dots.cryptoDot, !!r.isValid);
        setDot(dots.coverDot, !!r.coversDocument);
        setDot(dots.oursDot, !!r.issuedByUs);
        setDot(dots.regDot, !!r.issued);
        setDot(dots.revokedDot, !r.revoked); // green when not revoked
        issuerDn.textContent = r.issuer || '';

        show('done');
      } catch(err){
        verdictIcon.className = 'bi-exclamation-triangle text-danger me-3';
        verdictText.className = 'verdict-badge fw-bold text-danger';
        verdictText.textContent = 'TAMPERED';
        shaChip.textContent = 'n/a';
        setDot(dots.sigObjDot, false);
        setDot(dots.cryptoDot, false);
        setDot(dots.coverDot, false);
        setDot(dots.oursDot, false);
        setDot(dots.regDot, false);
        setDot(dots.revokedDot, false);
        issuerDn.textContent = 'Error: ' + (err && err.message ? err.message : 'Unknown error');
        show('done');
      } finally {
        // reset input so selecting the same file again still triggers 'change'
        this.value = '';
      }
    });
  })();
</script>
</body>
</html>`);
}


function renderAdminLogin(issuer: string){
  return text(`<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Admin · dmj.one</title>
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
            <form method="post" action="/admin/login" class="mt-3">
              <div class="mb-3">
                <label class="form-label">Admin key</label>
                <div class="input-group">
                  <input type="password" class="form-control" name="password" required autocomplete="current-password" placeholder="••••••••••••••" />
                  <button class="btn btn-outline-secondary" type="button" id="togglePw"><i class="bi bi-eye"></i></button>
                </div>
              </div>
              <button class="btn btn-primary w-100">Login</button>
            </form>
            <div class="small text-secondary mt-3">Your key is verified server‑side using PBKDF2‑HMAC‑SHA256.</div>
          </div>
        </div>
      </div>
    </div>
  </main>
  <script>
    document.getElementById('togglePw').addEventListener('click', function(){
      const i = document.querySelector('input[name="password"]'); 
      i.type = i.type==='password' ? 'text' : 'password';
      this.firstElementChild.className = i.type==='password' ? 'bi bi-eye' : 'bi bi-eye-slash';
    });
  </script>
</body></html>`);
}

function renderAdminBootstrapOnce(key: string, issuer: string){
  return text(`<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Admin bootstrap · dmj.one</title>
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
            <a class="btn btn-primary mt-3" href="/admin">Continue to Admin login</a>
          </div>
        </div>
      </div>
    </div>
  </main>
  <script>
    document.getElementById('copyBtn').addEventListener('click', async ()=>{
      const t = document.getElementById('theKey').innerText.trim();
      try{ await navigator.clipboard.writeText(t); 
        const b = document.getElementById('copyBtn'); b.innerHTML='<i class="bi-check2 me-2"></i>Copied'; setTimeout(()=>b.innerHTML='<i class="bi-clipboard me-2"></i>Copy', 1800);
      }catch{}
    });
  </script>
</body></html>`);
}

function renderAdminDashboard(issuer: string){
  return text(`<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Admin Dashboard · dmj.one</title>
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
      <form method="post" action="/admin/logout" class="ms-auto"><button class="btn btn-outline-secondary"><i class="bi-box-arrow-right me-2"></i>Logout</button></form>
    </div>
  </nav>

  <main class="container py-4">
    <div class="row g-4">
      <div class="col-lg-5">
        <div class="card shadow-sm">
          <div class="card-body">
            <h2 class="h5 d-flex align-items-center"><i class="bi-pen me-2 text-primary"></i>Sign a new PDF</h2>
            <div id="dz" class="dropzone mt-3 text-secondary text-center">
              <div class="small"><i class="bi-cloud-arrow-up"></i> Drag & drop PDF here or <label class="link-primary" style="cursor:pointer"><input id="filePick" type="file" class="d-none" accept="application/pdf" />browse</label></div>
            </div>
            <div class="mt-3">
              <label class="form-label">Optional metadata (JSON)</label>
              <input id="meta" class="form-control" placeholder='{"orderId":"123","user":"alice"}'>
            </div>
            <div class="d-grid mt-3"><button id="signBtn" class="btn btn-primary" disabled><i class="bi-check2-square me-2"></i>Sign & Download</button></div>
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

  <script>
    const toast = (msg, kind='primary') => {
      const t = document.getElementById('toast'); 
      t.className = 'alert alert-' + kind + ' shadow-sm'; 
      t.textContent = msg; t.classList.add('show');
      document.getElementById('liveRegion').textContent = msg; // aria-live
      setTimeout(()=>t.classList.remove('show'), 2200);
    };

    // ------- Table (load + filter + revoke)
    let rows = [];
    async function loadRows(){
      const res = await fetch('/admin?json=1', {headers:{'Accept':'application/json'}});
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
      const res = await fetch('/admin/revoke', {method:'POST', body:fd, headers:{'Accept':'application/json'}});
      if(!res.ok){ toast('Revoke failed','danger'); return; }
      const r = await res.json();
      toast('Revoked '+sha.slice(0,8)+'…','warning');
      // reflect locally
      const row = rows.find(x=>x.sha===sha); if(row){ row.revoked_at = r.revoked_at || Math.floor(Date.now()/1000); }
      renderRows();
    });

    // ------- Signer (dropzone + browse + download)
    const dz = document.getElementById('dz');
    const fp = document.getElementById('filePick');
    const meta = document.getElementById('meta');
    const btn = document.getElementById('signBtn');
    const prog = document.getElementById('prog');
    let file = null;
    const setFile = f => { file = f; btn.disabled = !file; toast('Ready to sign: '+(f?.name||'')); };
    ['dragenter','dragover'].forEach(ev=>dz.addEventListener(ev, e=>{e.preventDefault(); dz.classList.add('drag');}));
    ['dragleave','drop'].forEach(ev=>dz.addEventListener(ev, e=>{e.preventDefault(); dz.classList.remove('drag');}));
    dz.addEventListener('drop', e=>{ const f = e.dataTransfer.files?.[0]; if(f && f.type==='application/pdf') setFile(f); });
    fp.addEventListener('change', e=>{ const f = fp.files?.[0]; if(f && f.type==='application/pdf') setFile(f); fp.value=''; });
    dz.querySelector('label').addEventListener('click', ()=>fp.click());
    btn.addEventListener('click', async ()=>{
      if(!file) return;
      prog.classList.remove('d-none'); btn.disabled=true;
      try{
        const fd = new FormData(); fd.set('file', file, file.name);
        const m = (meta.value||'').trim(); if(m) fd.set('meta', m);
        const res = await fetch('/admin/sign', { method:'POST', body:fd });
        if(!res.ok){ const t = await res.text(); throw new Error(t||'sign error'); }
        const disp = res.headers.get('content-disposition') || '';
        const match = /filename="?([^"]+)"?/i.exec(disp); const name = match ? match[1] : ('signed-'+(file.name||'document')+(res.headers.get('content-type')?.includes('zip')?'.zip':'')); 
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = Object.assign(document.createElement('a'), { href:url, download:name });
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url); // avoid leaks
        toast('Signed & downloaded','success');
        loadRows(); // refresh list
      }catch(e){ toast('Signing failed','danger'); }
      finally{ prog.classList.add('d-none'); btn.disabled=false; file=null; }
    });
    // init
    loadRows();
  </script>
</body></html>`);
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

async function handleAdmin(env: Env, req: Request){
  await ensureSchema(env);
  const u = new URL(req.url);
  const cookieHeader = req.headers.get("cookie") || "";
  const sid = cookieHeader.split(/;\s*/).find(x=>x.startsWith("admin_session="))?.split("=")[1];
  const session = sid ? await verifySession(env, sid) : null;

  if (req.method === "GET"){
    // one-time admin portal key display (first visit)
    const show = await consumeOneTimeAdminKey(env);
    if (show){
      return renderAdminBootstrapOnce(show, env.ISSUER);
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
    if (!session) return renderAdminLogin(env.ISSUER);
    return renderAdminDashboard(env.ISSUER);
  }

  if (req.method === "POST"){
    const form = await req.formData();
    if (u.pathname.endsWith("/login")){
      const pass = String(form.get("password")||"");
      const ok = await verifyPBKDF2(env, pass);      
      if(!ok) {
        return new Response("<h1>Unauthorized</h1>", {
          status: 401,
          headers: { "content-type": "text/html; charset=utf-8" }
        });
      }
      const sidv = await signSession(env, {ok:true, t: now()});
      return new Response(null, { status:303, headers:{ "set-cookie": cookie("admin_session", sidv, {Path:"/"}), "location": "/admin" }});
    }
    if (u.pathname.endsWith("/logout")){
      return new Response(null, { status:303, headers:{ "set-cookie": "admin_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict", "location": "/admin" }});
    }    
    if (!session) {
      return new Response("<h1>Unauthorized</h1>", {
        status: 401,
        headers: { "content-type": "text/html; charset=utf-8" }
      });
    }

    if (u.pathname.endsWith("/sign")){
      const file = form.get("file") as File | null;
      if(!file) return json({error:"file missing"}, 400);
      // const buf = await file.arrayBuffer();
      // const sha = await sha256(buf);
      const buf = await file.arrayBuffer();          // original (unsigned)

      // HMAC gating to signer
      const { ts, nonce, sig } = await hmac(env, buf, "POST", "/sign");

      const res = await fetch(new URL("/sign", env.SIGNER_API_BASE).toString(), {
        method:"POST",
        headers:{
          "x-worker-hmac": sig,
          "x-worker-ts": ts,
          "x-worker-nonce": nonce
        },
        body: (()=>{ const fd = new FormData(); fd.set("file", new Blob([buf], {type:"application/pdf"}), "in.pdf"); return fd; })()
      });
      if(!res.ok) return json({error:"signer error", detail: await res.text()}, 502);
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
                  (id,doc_sha256,meta_json,signed_at,revoked_at)
                  VALUES(?,?,?,?,NULL)`)
        .bind(crypto.randomUUID(), sha, meta || "{}", now())
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
      const kitRes = await fetch(kitUrl);
      if (!kitRes.ok) return json({error:"trust-kit fetch failed", detail: await kitRes.text()}, 502);
      const kit = new Uint8Array(await kitRes.arrayBuffer());

      const readmeFirst = new TextEncoder().encode(
      `dmj.one — Make the signature show as trusted
      =============================================
      Open the "Trust Kit/dmj-one-trust-kit-README.txt" and follow the steps for your device.
      Install the dmj.one Root CA once. Then any dmj.one-signed PDF will verify as trusted.

      If you'd rather trust only inside Adobe Acrobat/Reader, see the "Acrobat-only" section.
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

    if (u.pathname.endsWith("/revoke")){      
      const p = env.DB_PREFIX;
      const sha = String(form.get("sha")||"");
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
      return new Response(null, { status:303, headers:{location:"/admin"} });
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
    if (url.pathname === "/") return renderHome(env.ISSUER);
    if (url.pathname === "/verify" && req.method === "POST") return handleVerify(env, req);
    if (url.pathname.startsWith("/admin")) return handleAdmin(env, req);
    if (url.pathname === "/healthz") return new Response("ok");
    return new Response("Not found", {status:404});
  }
}
TS

# wrangler configuration (use JSONC as per latest recommendation) 
sudo tee "${WORKER_DIR}/wrangler.jsonc" >/dev/null <<JSON
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
    "SIGNER_API_BASE": "https://${SIGNER_DOMAIN}",
    "DB_PREFIX":     "${DB_PREFIX}",
    "PKI_BASE":      "https://${PKI_DOMAIN}",
    "BUNDLE_TRUST_KIT": "1"            // 1 = return a zip bundle (PDF + Trust Kit)
  }
}
JSON

# Seed schema remotely so we can insert bootstrap key
sudo tee "${WORKER_DIR}/schema.sql" >/dev/null <<SQL
CREATE TABLE IF NOT EXISTS ${DB_PREFIX}documents(
  id TEXT PRIMARY KEY,
  doc_sha256 TEXT UNIQUE,
  meta_json TEXT,
  signed_at INTEGER,
  revoked_at INTEGER,
  revoke_reason TEXT
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

# Deploy Worker (modern command) 
say "[+] Deploying Worker..."
( cd "$WORKER_DIR" && "$WR" deploy )

WORKER_URL="$("$WR" deployments list --format=json | jq -r '.[0].url' || true)"
echo "------------------------------------------------------------------"
echo "[✓] Done."
echo "Worker URL (temporary workers.dev): ${WORKER_URL:-see dashboard}"
echo "Signer URL (nginx): https://${SIGNER_DOMAIN}/healthz"
echo
echo "NEXT STEPS:"
echo "1) Visit ${WORKER_URL:-your workers.dev URL}/admin   — you will see the admin key ONCE."
echo "2) In Cloudflare Dashboard, add a Route to bind this Worker to your domain (e.g. https://sign.${DMJ_ROOT_DOMAIN}/*)."
echo "------------------------------------------------------------------"

say "[✓] Done."