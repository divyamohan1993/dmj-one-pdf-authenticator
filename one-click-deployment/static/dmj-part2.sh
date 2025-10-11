# dmj-part2.sh
#!/usr/bin/env bash
set -euo pipefail

### --- Config / Inputs -------------------------------------------------------
LOG_DIR="/var/log/dmj"
STATE_DIR="/var/lib/dmj"
CONF_DIR="/etc/dmj"
INST_ENV="${CONF_DIR}/installer.env"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"

# Load installation id / DB_PREFIX
# shellcheck disable=SC1090
[ -f "$INST_ENV" ] && source "$INST_ENV" || { echo "[x] Missing ${INST_ENV}. Run Part 1 first."; exit 1; }


### ---------- Logging / Verbosity ----------
LOG_DIR="/var/log/dmj"; STATE_DIR="/var/lib/dmj"; CONF_DIR="/etc/dmj"
mkdir -p "$LOG_DIR" "$STATE_DIR" "$CONF_DIR"
LOG_FILE="${LOG_DIR}/part2-$(date +%Y%m%dT%H%M%S).log"

# Verbose to console? 1/true = yes, 0/false = minimal
DMJ_VERBOSE="${DMJ_VERBOSE:-1}"
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


DMJ_ROOT_DOMAIN="${DMJ_ROOT_DOMAIN:-dmj.one}"
SIGNER_DOMAIN="${SIGNER_DOMAIN:-signer.${DMJ_ROOT_DOMAIN}}"

WORKER_NAME="dmj-${INSTALLATION_ID}-docsign"
WORKER_DIR="/opt/dmj/worker"
SIGNER_DIR="/opt/dmj/signer-vm"
NGINX_SITE="/etc/nginx/sites-available/dmj-signer"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/dmj-signer"

# Require D1 id (single shared DB)
CF_D1_DATABASE_ID="${CF_D1_DATABASE_ID:-}"
if [ -z "${CF_D1_DATABASE_ID}" ]; then
  echo "[x] Please export CF_D1_DATABASE_ID to your D1 database id (UUID)."
  echo "    You can run:  dmj-wrangler d1 list --json"
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


# if [ ! -f "$ADMIN_KEY_FILE" ]; then
#   ADMIN_PORTAL_KEY="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 28)"
#   echo "$ADMIN_PORTAL_KEY" | sudo tee "$ADMIN_KEY_FILE" >/dev/null
# else
#   ADMIN_PORTAL_KEY="$(cat "$ADMIN_KEY_FILE")"
# fi

if [ ! -f "$ADMIN_KEY_FILE" ]; then
  # 28 hex chars, alphanumeric and safe for display/input
  ADMIN_PORTAL_KEY="$(openssl rand -hex 14)"
  printf '%s\n' "$ADMIN_PORTAL_KEY" | sudo tee "$ADMIN_KEY_FILE" >/dev/null
else
  ADMIN_PORTAL_KEY="$(cat "$ADMIN_KEY_FILE")"
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
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cert.X509CertificateHolder;          // <-- added
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Base64;


import org.apache.pdfbox.Loader;                               // <-- added
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.apache.pdfbox.io.IOUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;

public class SignerServer {

  static final String WORK_DIR = "/opt/dmj/signer-vm";
  static final Path P12_PATH = Paths.get(WORK_DIR, "keystore.p12");
  static final Path P12_PASS = Paths.get(WORK_DIR, "keystore.pass");
  static final String P12_ALIAS = "dmj-one";
  static final String HMAC_HEADER = "x-worker-hmac";
  static final String HMAC_TS = "x-worker-ts";
  static final String HMAC_NONCE = "x-worker-nonce";

  static final Set<String> RECENT_NONCES = Collections.synchronizedSet(new LinkedHashSet<>());

  static class Keys {
    final PrivateKey priv;
    final X509Certificate cert;
    Keys(PrivateKey p, X509Certificate c){ this.priv=p; this.cert=c; }
  }

  static Keys loadKeys() throws Exception {
    char[] pass = Files.readString(P12_PASS).trim().toCharArray();
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try(InputStream in = Files.newInputStream(P12_PATH)) { ks.load(in, pass); }
    PrivateKey pk = (PrivateKey) ks.getKey(P12_ALIAS, pass);
    X509Certificate cert = (X509Certificate) ks.getCertificate(P12_ALIAS);
    return new Keys(pk, cert);
  }

  static String spkiBase64(X509Certificate cert) throws Exception {
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(cert.getPublicKey().getEncoded());
    return Base64.toBase64String(spki.getEncoded());
  }

  static boolean verifyHmac(String sharedBase64, String method, String path, byte[] body, String ts, String nonceB64, String providedB64) throws Exception {

    long now = Instant.now().getEpochSecond();
    long t = Long.parseLong(ts);
    if (Math.abs(now - t) > 300) return false; // 5 min clock skew guard

    synchronized (RECENT_NONCES) {
      if (RECENT_NONCES.contains(nonceB64)) return false;
      RECENT_NONCES.add(nonceB64);
      if (RECENT_NONCES.size() > 1000) RECENT_NONCES.iterator().remove();
    }

    byte[] secret = Base64.decode(sharedBase64);
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(secret, "HmacSHA256"));

    mac.update(method.getBytes(StandardCharsets.UTF_8));
    mac.update((byte) 0);
    mac.update(path.getBytes(StandardCharsets.UTF_8));
    mac.update((byte) 0);
    mac.update(ts.getBytes(StandardCharsets.UTF_8));
    mac.update((byte) 0);

    // nonce is sent base64 by the Worker -> verify over the decoded bytes
    byte[] nonce = Base64.decode(nonceB64);
    mac.update(nonce);
    mac.update((byte) 0);

    mac.update(body);

    byte[] expected = mac.doFinal();
    byte[] provided = java.util.Base64.getDecoder().decode(providedB64);
    return MessageDigest.isEqual(expected, provided);
  }

  static byte[] signPdf(byte[] input, PrivateKey pk, X509Certificate cert) throws Exception {
    try (PDDocument doc = Loader.loadPDF(input)) {                // <-- Loader
      PDSignature sig = new PDSignature();
      sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
      sig.setName("dmj.one");
      sig.setLocation("dmj.one");
      sig.setSignDate(Calendar.getInstance());
      doc.addSignature(sig, new SignatureInterface() {
        @Override public byte[] sign(InputStream content) throws IOException {
          try {
            byte[] toSign = IOUtils.toByteArray(content);
            java.security.Signature jSig = java.security.Signature.getInstance("SHA256withRSA");
            jSig.initSign(pk);
            jSig.update(toSign);
            byte[] cms = jSig.sign(); // NOTE: placeholder (bare signature)
            return cms;
          } catch (Exception e){ throw new IOException(e); }
        }
      });

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      doc.save(baos);
      return baos.toByteArray();
    }
  }

  static Map<String,Object> verifyPdf(byte[] input, X509Certificate ourCert) throws Exception {
    Map<String,Object> out = new LinkedHashMap<>();
    boolean any = false;
    boolean anyValid = false;
    String issuer = null;
    try (PDDocument doc = Loader.loadPDF(input)) {               // <-- Loader
      List<PDSignature> sigs = doc.getSignatureDictionaries();
      any = !sigs.isEmpty();
      for (PDSignature s : sigs) {
        byte[] signedContent = s.getSignedContent(new ByteArrayInputStream(input));
        byte[] cms = s.getContents(new ByteArrayInputStream(input));
        if (cms == null) continue;
        CMSSignedData sd = new CMSSignedData(new org.bouncycastle.cms.CMSProcessableByteArray(signedContent), cms);
        SignerInformationStore signers = sd.getSignerInfos();
        for (SignerInformation si : signers.getSigners()) {
          SignerId sid = si.getSID();
          @SuppressWarnings("unchecked")
          java.util.Collection<X509CertificateHolder> certs = sd.getCertificates().getMatches(sid); // now resolvable
          boolean ok = si.verify(new JcaSimpleSignerInfoVerifierBuilder()
             .setProvider("BC").build(ourCert.getPublicKey()));
          anyValid |= ok;
          issuer = ourCert.getIssuerX500Principal().getName();
        }
      }
    }
    out.put("hasSignature", any);
    out.put("isValid", anyValid);
    out.put("issuer", issuer!=null?issuer:"");
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
      UploadedFile f = ctx.uploadedFile("file");
      if (f == null) { ctx.status(400).json(Map.of("error","file missing")); return; }
      byte[] data = IOUtils.toByteArray(f.content());
      Map<String,Object> v = verifyPdf(data, keys.cert);
      ctx.json(v);
    });

    app.post("/sign", ctx -> {
      if (shared.isBlank()) { ctx.status(500).json(Map.of("error","server not configured")); return; }
      String hmac = ctx.header(HMAC_HEADER);
      String ts = ctx.header(HMAC_TS);
      String nonce = ctx.header(HMAC_NONCE);
      if (hmac==null || ts==null || nonce==null) { ctx.status(401).json(Map.of("error","missing auth")); return; }
      UploadedFile f = ctx.uploadedFile("file");
      if (f==null){ ctx.status(400).json(Map.of("error","file missing")); return; }
      byte[] data = IOUtils.toByteArray(f.content());
      boolean ok = false;
      try { ok = verifyHmac(shared, "POST", "/sign", data, ts, nonce, hmac); } catch(Exception e){ ok=false; }
      if (!ok) { ctx.status(401).json(Map.of("error","bad auth")); return; }

      try {
        byte[] signed = signPdf(data, keys.priv, keys.cert);
        ctx.contentType("application/pdf");
        ctx.header("X-Signed-By", issuer);
        ctx.result(new ByteArrayInputStream(signed));
      } catch (Exception e){
        ctx.status(500).json(Map.of("error","sign failed", "detail", e.getMessage()));
      }
    });

    app.get("/healthz", ctx -> ctx.result("ok"));

    app.events(e -> e.serverStarted(() -> {
      System.out.println("Signer listening on " + port);
    }));

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


# PKI creation script (self-signed leaf in PKCS#12)
sudo tee "${SIGNER_DIR}/make-keys.sh" >/dev/null <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ -f keystore.p12 ]; then
  echo "[*] PKCS#12 already exists, skipping."
  exit 0
fi
PASS="$(openssl rand -hex 24)"
CN="${DMJ_ROOT_DOMAIN:-dmj.one} Document Signer"
openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
  -keyout signer.key -out signer.crt -days 3650 \
  -subj "/CN=${CN}/O=dmj.one" -addext "basicConstraints=CA:FALSE" \
  -addext "keyUsage = digitalSignature, keyEncipherment" \
  -addext "extendedKeyUsage = codeSigning, emailProtection"
# Bundle into PKCS12
openssl pkcs12 -export -out keystore.p12 -inkey signer.key -in signer.crt -name "dmj-one" -passout pass:"$PASS"
echo "$PASS" > keystore.pass
chmod 600 keystore.p12 keystore.pass signer.key
echo "[✓] Generated keystore.p12"
SH
sudo chmod +x "${SIGNER_DIR}/make-keys.sh"
sudo DMJ_ROOT_DOMAIN="$DMJ_ROOT_DOMAIN" bash "${SIGNER_DIR}/make-keys.sh"

echo "[+] Building Java signer..."
( cd "$SIGNER_DIR" && mvn -q -DskipTests clean package )

# Systemd service
sudo tee /etc/systemd/system/dmj-signer.service >/dev/null <<SERVICE
[Unit]
Description=DMJ Signer Microservice
After=network.target

[Service]
User=root
Environment=SIGNING_GATEWAY_HMAC_KEY=${SIGNING_GATEWAY_HMAC_KEY}
Environment=DMJ_ISSUER=${DMJ_ROOT_DOMAIN}
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
SIGNER_PORT="$(cat /etc/dmj/signer.port 2>/dev/null || echo 18080)"
sudo tee "$NGINX_SITE" >/dev/null <<NGX
server {
  listen 80;
  server_name ${SIGNER_DOMAIN};

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

echo "[+] Signer at https://${SIGNER_DOMAIN}/healthz"

### --- Worker project --------------------------------------------------------
echo "[+] Preparing Cloudflare Worker at ${WORKER_DIR} ..."
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
}

const text = (s: string) => new Response(s, { headers: { "content-type":"text/html; charset=utf-8", "x-frame-options":"DENY", "referrer-policy":"no-referrer", "content-security-policy":"default-src 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none'" }});
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
  const o = req.headers.get("origin"); if(!o) return false;
  const u = new URL(req.url);
  return o === `${u.protocol}//${u.host}`;
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
     )`
  ];

  for (const sql of stmts) {
    await env.DB.prepare(sql).run();
  }
}


async function sha256(buf: ArrayBuffer){ return hex(await crypto.subtle.digest("SHA-256", buf)); }
function now(){ return Math.floor(Date.now()/1000); }

async function setOneTimeAdminKey(env: Env, keyClear: string){
  const p = env.DB_PREFIX;
  await env.DB.exec(`INSERT OR REPLACE INTO ${p}bootstrap(k,v,consumed,created_at) VALUES('ADMIN_PORTAL_KEY', ?, 0, ?)`, [keyClear, now()]);
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

function renderHome(issuer: string){
  return text(`<!doctype html>
<html><head><meta charset="utf-8"><title>dmj.one verifier</title>
<style>body{font-family:ui-sans-serif,system-ui;padding:32px;max-width:860px;margin:auto}header{margin-bottom:24px}</style></head>
<body>
<header><h1>dmj.one — Document Verifier</h1><p>Upload a PDF to verify it was issued by <b>${issuer}</b>.</p></header>
<form method="post" action="/verify" enctype="multipart/form-data">
  <input type="file" name="file" accept="application/pdf" required>
  <button type="submit">Verify</button>
</form>
<p><a href="/admin">Admin</a></p>
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
      return text(`<!doctype html><meta charset="utf-8"><title>Admin bootstrap</title>
      <body style="font-family:ui-sans-serif;max-width:900px;margin:40px auto">
      <h1>dmj.one — Admin bootstrap</h1>
      <h2>Your admin portal login key (shown only once):</h2>
      <pre style="font-size:20px;background:#f6f6f6;padding:12px;border-radius:6px">${show}</pre>
      <p>Store this key securely. If it is lost, reinstall from scratch. Existing signed PDFs remain valid.</p>
      <h3>Environment diagnostics</h3>
      ${diagnostics(env, true)}
      <p><a href="/admin">Continue to Admin login</a></p>
      </body>`);
    }
    if (!session){
      // login form
      return text(`<!doctype html><meta charset="utf-8"><title>Admin login</title>
      <body style="font-family:ui-sans-serif;max-width:900px;margin:40px auto">
      <h1>Admin login</h1>
      <form method="post" action="/admin/login">
        <input type="password" name="password" placeholder="Admin key" required>
        <button type="submit">Login</button>
      </form>
      <h3>Diagnostics</h3>${diagnostics(env,true)}
      <p><a href="/">Back</a></p>
      </body>`);
    }
    // list documents
    const p = env.DB_PREFIX;
    const rows = await env.DB.prepare(`SELECT doc_sha256, signed_at, revoked_at, meta_json FROM ${p}documents ORDER BY signed_at DESC`).all() as any;
    const htmlRows = rows.results.map((r:any)=>`
      <tr>
        <td><code>${r.doc_sha256}</code></td>
        <td>${new Date((r.signed_at||0)*1000).toISOString()}</td>
        <td>${r.revoked_at ? ("❌ "+new Date(r.revoked_at*1000).toISOString()) : "✅ Active"}</td>
        <td><form method="post" action="/admin/revoke"><input type="hidden" name="sha" value="${r.doc_sha256}"><button ${r.revoked_at?"disabled":""}>Revoke</button></form></td>
      </tr>`).join("");
    return text(`<!doctype html><meta charset="utf-8"><title>Admin</title>
    <body style="font-family:ui-sans-serif;max-width:1100px;margin:40px auto">
      <h1>Admin — dmj.one</h1>
      <form method="post" action="/admin/logout" style="float:right"><button>Logout</button></form>
      <h2>Sign a new PDF</h2>
      <form method="post" action="/admin/sign" enctype="multipart/form-data">
        <input type="file" name="file" accept="application/pdf" required>
        <input type="text" name="meta" placeholder='optional metadata JSON'>
        <button>Sign</button>
      </form>
      <h2>Issued documents</h2>
      <table border="1" cellpadding="6" cellspacing="0"><tr><th>SHA-256</th><th>Signed</th><th>Status</th><th>Action</th></tr>${htmlRows}</table>
      <p><a href="/">Back</a></p>
    </body>`);
  }

  if (req.method === "POST"){
    const form = await req.formData();
    if (u.pathname.endsWith("/login")){
      const pass = String(form.get("password")||"");
      const ok = await verifyPBKDF2(env, pass);
      // if(!ok) return text("<h1>Unauthorized</h1>"), {status:401} as any;
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
    // if (!session) return text("<h1>Unauthorized</h1>"), {status:401} as any;
    if (!session) {
      return new Response("<h1>Unauthorized</h1>", {
        status: 401,
        headers: { "content-type": "text/html; charset=utf-8" }
      });
    }

    if (u.pathname.endsWith("/sign")){
      const file = form.get("file") as File | null;
      if(!file) return json({error:"file missing"}, 400);
      const buf = await file.arrayBuffer();
      const sha = await sha256(buf);

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

      const meta = String(form.get("meta")||"").trim();
      const p = env.DB_PREFIX;
      await env.DB.exec(`INSERT OR IGNORE INTO ${p}documents(id,doc_sha256,meta_json,signed_at,revoked_at) VALUES(?,?,?,?,NULL)`,
        [crypto.randomUUID(), sha, meta||"{}", now()]);
      await env.DB.exec(`INSERT INTO ${p}audit(id,at,action,doc_sha256,ip,ua,detail) VALUES(?,?,?,?,?,?,?)`,
        [crypto.randomUUID(), now(), "sign", sha, "", "", ""]);

      return new Response(signed, {
        headers:{
          "content-type":"application/pdf",
          "content-disposition":`attachment; filename="signed.pdf"`,
          "x-doc-sha256": sha,
          "x-issuer": env.ISSUER
        }
      });
    }

    if (u.pathname.endsWith("/revoke")){
      if (!sameOrigin(req)) return json({error:"bad origin"}, 400);
      const p = env.DB_PREFIX;
      const sha = String(form.get("sha")||"");
      await env.DB.exec(`UPDATE ${p}documents SET revoked_at=? WHERE doc_sha256=?`, [now(), sha]);
      await env.DB.exec(`INSERT INTO ${p}audit(id,at,action,doc_sha256,ip,ua,detail) VALUES(?,?,?,?,?,?,?)`,
        [crypto.randomUUID(), now(), "revoke", sha, "", "", ""]);
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

  // Also ask signer to validate embedded signature/issuer
  const vf = new FormData(); vf.set("file", new Blob([buf],{type:"application/pdf"}), "doc.pdf");
  const vres = await fetch(new URL("/verify", env.SIGNER_API_BASE).toString(), { method:"POST", body:vf });
  const vinfo = vres.ok ? await vres.json() : {isValid:false, issuer:""};

  const ok = !!row && !row.revoked_at && vinfo.isValid;
  const html = `<!doctype html><meta charset="utf-8"><title>Verify</title>
  <body style="font-family:ui-sans-serif;padding:32px">
  <h1>Verification result</h1>
  <p>SHA-256: <code>${sha}</code></p>
  <ul>
  <li>Registered by dmj.one: ${row? "✅":"❌"}</li>
  <li>Revoked: ${row?.revoked_at? "❌ (revoked)":"✅ (not revoked)"}</li>
  <li>Embedded signature valid: ${vinfo.isValid? "✅":"❌"}</li>
  <li>Issuer reported: <code>${vinfo.issuer||""}</code></li>
  </ul>
  <h2>${ok? "✅ Genuine (dmj.one)":"❌ Not valid / tampered"}</h2>
  <p><a href="/">Back</a></p></body>`;
  return text(html);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
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
    "ISSUER": "${DMJ_ROOT_DOMAIN}",
    "SIGNER_API_BASE": "https://${SIGNER_DOMAIN}",
    "DB_PREFIX": "${DB_PREFIX}"
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

echo "[+] Applying schema to remote D1..."
( cd "$WORKER_DIR" && "$WR" d1 execute "${D1_NAME}" --remote --file ./schema.sql )

# Insert one-time admin key for first GUI fetch
echo "[+] Storing one-time admin portal key for first GUI access..."
( cd "$WORKER_DIR" && "$WR" d1 execute "${D1_NAME}" --remote --command \
"INSERT OR REPLACE INTO ${DB_PREFIX}bootstrap(k,v,consumed,created_at) VALUES('ADMIN_PORTAL_KEY','${ADMIN_PORTAL_KEY}',0,${EPOCHSECONDS:-$(date +%s)});" )

# Upload Worker secrets (pipe, non-interactive) 
echo "[+] Pushing Worker secrets to Cloudflare..."
(
  cd "$WORKER_DIR"
  # turn off xtrace so secrets don't end up in logs
  _xtrace_state=$(set +o | grep xtrace); set +x

  printf '%s' "${SIGNING_GATEWAY_HMAC_KEY}" | "$WR" secret put SIGNING_GATEWAY_HMAC_KEY --name "${WORKER_NAME}"
  printf '%s' "${SESSION_HMAC_KEY}"        | "$WR" secret put SESSION_HMAC_KEY        --name "${WORKER_NAME}"
  printf '%s' "${TOTP_MASTER_KEY}"         | "$WR" secret put TOTP_MASTER_KEY         --name "${WORKER_NAME}"
  printf '%s' "${ADMIN_HASH}"              | "$WR" secret put ADMIN_PASS_HASH         --name "${WORKER_NAME}"

  # restore previous xtrace state
  eval "$_xtrace_state"
)

# Deploy Worker (modern command) 
echo "[+] Deploying Worker..."
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
