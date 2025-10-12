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
import org.bouncycastle.cms.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;


import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.apache.pdfbox.io.IOUtils;

import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts.FontName;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.util.Matrix;


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

import java.awt.Color;


public class SignerServer {

  static final String WORK_DIR = "/opt/dmj/signer-vm";
  static final Path P12_PATH = Paths.get(WORK_DIR, "keystore.p12");
  static final Path P12_PASS = Paths.get(WORK_DIR, "keystore.pass");
  static final String P12_ALIAS = "dmj-one";
  static final String HMAC_HEADER = "x-worker-hmac";
  static final String HMAC_TS = "x-worker-ts";
  static final String HMAC_NONCE = "x-worker-nonce";

  static final Set<String> RECENT_NONCES = Collections.synchronizedSet(new LinkedHashSet<>());

  static { java.security.Security.addProvider(new BouncyCastleProvider()); }

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

  // Convert a human rectangle (x,y from top-left) to a PDRectangle on page 0 (handles rotation).
  static PDRectangle signatureRectForPage(PDDocument doc, int pageIndex,
                                          float xTopLeft, float yTopLeft,
                                          float width, float height) {
    PDPage page = doc.getPage(pageIndex);
    PDRectangle pageRect = page.getCropBox();
    PDRectangle rect = new PDRectangle();
    int rot = page.getRotation();
    switch (rot) {
      case 90:
        rect.setLowerLeftY(xTopLeft);
        rect.setUpperRightY(xTopLeft + width);
        rect.setLowerLeftX(yTopLeft);
        rect.setUpperRightX(yTopLeft + height);
        break;
      case 180:
        rect.setUpperRightX(pageRect.getWidth() - xTopLeft);
        rect.setLowerLeftX(pageRect.getWidth() - xTopLeft - width);
        rect.setLowerLeftY(yTopLeft);
        rect.setUpperRightY(yTopLeft + height);
        break;
      case 270:
        rect.setLowerLeftY(pageRect.getHeight() - xTopLeft - width);
        rect.setUpperRightY(pageRect.getHeight() - xTopLeft);
        rect.setLowerLeftX(pageRect.getWidth() - yTopLeft - height);
        rect.setUpperRightX(pageRect.getWidth() - yTopLeft);
        break;
      case 0:
      default:
        rect.setLowerLeftX(xTopLeft);
        rect.setUpperRightX(xTopLeft + width);
        rect.setLowerLeftY(pageRect.getHeight() - yTopLeft - height);
        rect.setUpperRightY(pageRect.getHeight() - yTopLeft);
        break;
    }
    return rect;
  }

  // Build a minimal visual-appearance template with text (name, date, reason).
  static InputStream visibleTemplate(PDDocument srcDoc, int pageNum,
                                     PDRectangle rect, PDSignature signature) throws IOException {
    try (PDDocument tpl = new PDDocument()) {
      PDPage page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
      tpl.addPage(page);

      PDAcroForm acroForm = new PDAcroForm(tpl);
      tpl.getDocumentCatalog().setAcroForm(acroForm);
      PDSignatureField sigField = new PDSignatureField(acroForm);
      PDAnnotationWidget widget = sigField.getWidgets().get(0);
      acroForm.setSignaturesExist(true);
      acroForm.setAppendOnly(true);
      acroForm.getCOSObject().setDirect(true);
      acroForm.getFields().add(sigField);

      widget.setRectangle(rect);

      // Appearance form XObject
      PDStream stream = new PDStream(tpl);
      PDFormXObject form = new PDFormXObject(stream);
      PDResources res = new PDResources();
      form.setResources(res);
      form.setFormType(1);
      PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
      form.setBBox(bbox);

      // Attach appearance to widget
      PDAppearanceDictionary ap = new PDAppearanceDictionary();
      ap.getCOSObject().setDirect(true);
      PDAppearanceStream aps = new PDAppearanceStream(form.getCOSObject());
      ap.setNormalAppearance(aps);
      widget.setAppearance(ap);

      // Draw simple framed box + text
      try (PDPageContentStream cs = new PDPageContentStream(tpl, aps)) {
        // background (white) and border (black)
        // cs.setNonStrokingColor(Color.WHITE);
        cs.addRect(0, 0, bbox.getWidth(), bbox.getHeight()); cs.fill();
        cs.setLineWidth(0.8f);
        cs.setStrokingColor(Color.BLACK);
        cs.moveTo(0,0); cs.lineTo(bbox.getWidth(),0); cs.lineTo(bbox.getWidth(),bbox.getHeight());
        cs.lineTo(0,bbox.getHeight()); cs.closeAndStroke();

        // text
        float fs = 9f, leading = fs * 1.35f;
        cs.beginText();
        cs.setFont(new PDType1Font(FontName.HELVETICA_BOLD), fs);
        cs.setNonStrokingColor(Color.BLACK);
        cs.newLineAtOffset(6, bbox.getHeight() - leading - 4);
        cs.setLeading(leading);
        String date = signature.getSignDate() != null ? signature.getSignDate().getTime().toString() : "";
        cs.showText("Digitally signed by dmj.one");
        cs.newLine();
        cs.showText(date);
        cs.newLine();
        String reason = signature.getReason() != null ? signature.getReason() : "Verified and certified";
        cs.showText("Reason: " + reason);
        cs.endText();
      }

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      tpl.save(baos);
      return new ByteArrayInputStream(baos.toByteArray());
    }
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

  static String toHex(byte[] b){
  StringBuilder sb = new StringBuilder(b.length * 2);
  for (byte x : b) sb.append(String.format("%02x", x));
  return sb.toString();
}
static String jcaDigestNameFromOid(String oid){
  return switch (oid) {
    case "1.3.14.3.2.26" -> "SHA-1";
    case "2.16.840.1.101.3.4.2.1" -> "SHA-256";
    case "2.16.840.1.101.3.4.2.2" -> "SHA-384";
    case "2.16.840.1.101.3.4.2.3" -> "SHA-512";
    case "2.16.840.1.101.3.4.2.4" -> "SHA-224";
    default -> "SHA-256"; // safe default
  };
}


  // helper exactly like PDFBox example
  static class CMSProcessableInputStream implements CMSTypedData {
    private InputStream in;
    private final ASN1ObjectIdentifier type;

    CMSProcessableInputStream(InputStream in) {
      this(in, new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()));
    }
    CMSProcessableInputStream(InputStream in, ASN1ObjectIdentifier type) {
      this.in = in; this.type = type;
    }
    @Override public Object getContent() { return null; }
    @Override public ASN1ObjectIdentifier getContentType() { return type; }
    @Override public void write(OutputStream out) throws IOException, CMSException {
      IOUtils.copy(in, out); // from PDFBox IOUtils
      in.close();
    }
  }
  
  // build a detached CMS/PKCS#7 over the exact ByteRange bytes
  static byte[] buildDetachedCMS(InputStream content, PrivateKey pk, X509Certificate cert) throws Exception {
    // 1) Read the exact bytes that PDFBox wants signed
    byte[] toSign = IOUtils.toByteArray(content);

    // 2) Standard "SHA256withRSA" CMS generator
    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
        .setProvider("BC").build(pk);

    var sigInfoGen = new JcaSignerInfoGeneratorBuilder(
        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
        .build(signer, cert);

    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    gen.addSignerInfoGenerator(sigInfoGen);
    gen.addCertificates(new JcaCertStore(java.util.List.of(cert)));

    // 3) Sign the exact bytes as a detached CMS
    CMSTypedData msg = new org.bouncycastle.cms.CMSProcessableByteArray(toSign);
    CMSSignedData cms = gen.generate(msg, false);
    return cms.getEncoded(); // DER
  }



  // Set DocMDP transform so this becomes a *certification* signature.
  // P=1 => no changes allowed; 2 => form fill/annot; 3 => limited edits.
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
  
  // --- Sign the original PDF (external signing, detached PKCS#7) ---
  static byte[] signPdf(byte[] originalPdf, PrivateKey pk, X509Certificate cert) throws Exception {
    ByteArrayOutputStream baos = new ByteArrayOutputStream(originalPdf.length + 65536);
    try (PDDocument doc = Loader.loadPDF(originalPdf)) {
      PDSignature sig = new PDSignature();
      sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
      sig.setName("dmj.one");
      sig.setLocation("IN");
      sig.setReason("Contents securely verified by dmj.one against any tampering.");
      sig.setContactInfo("contact@dmj.one");
      sig.setSignDate(Calendar.getInstance());

      // Certification: no changes allowed after signing
      setMDPPermission(doc, sig, 1);

      // --- NEW: make it visible on page 1 (top-left coords, width x height) ---
      int pageIndex = 0; // first page
      PDRectangle rect = signatureRectForPage(doc, pageIndex,
          36, 36,            // x=36pt, y=36pt from top-left (≈0.5 inch margins)
          250, 70);          // width, height in points
      SignatureOptions options = new SignatureOptions();
      options.setPreferredSignatureSize(65536);
      options.setVisualSignature( visibleTemplate(doc, pageIndex, rect, sig) );
      options.setPage(pageIndex);

      // Register signature + options, then external signing
      doc.addSignature(sig, options);
      ExternalSigningSupport ext = doc.saveIncrementalForExternalSigning(baos);
      byte[] cmsSignature = buildDetachedCMS(ext.getContent(), pk, cert);
      ext.setSignature(cmsSignature);
    }
    return baos.toByteArray();
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

        byte[] cms = s.getContents(input);               // trimmed CMS (no padding)
        byte[] signedContent = s.getSignedContent(new ByteArrayInputStream(input));

        debug.put("sig"+sigIndex+".cms.len", cms != null ? cms.length : 0);
        debug.put("sig"+sigIndex+".signedContent.len", signedContent.length);
        debug.put("sig"+sigIndex+".signedContent.prefix32.hex",
                  toHex(Arrays.copyOf(signedContent, Math.min(32, signedContent.length))));

        try {
          CMSSignedData sd = new CMSSignedData(
              new org.bouncycastle.cms.CMSProcessableByteArray(signedContent), cms);

          for (SignerInformation si : sd.getSignerInfos().getSigners()) {
            String digestAlgOid = si.getDigestAlgOID();
            String encAlgOid = si.getEncryptionAlgOID();

            // Extract CMS 'message-digest' attribute
            byte[] mdAttrBytes = null;
            AttributeTable at = si.getSignedAttributes();
            if (at != null) {
              Attribute md = at.get(CMSAttributes.messageDigest);
              if (md != null) {
                ASN1Primitive v = md.getAttrValues().getObjectAt(0).toASN1Primitive();
                mdAttrBytes = ((ASN1OctetString) v).getOctets();
              }
            }

            // Recompute digest over ByteRange (signedContent)
            String jcaName = jcaDigestNameFromOid(digestAlgOid);
            byte[] calc = MessageDigest.getInstance(jcaName).digest(signedContent);

            debug.put("sig"+sigIndex+".digestAlgOid", digestAlgOid);
            debug.put("sig"+sigIndex+".encAlgOid", encAlgOid);
            debug.put("sig"+sigIndex+".cms.messageDigest.hex", mdAttrBytes != null ? toHex(mdAttrBytes) : "");
            debug.put("sig"+sigIndex+".recalc.messageDigest.hex", toHex(calc));

            // Standard BC verification (this is where CMSSignerDigestMismatchException comes from)
            Collection<X509CertificateHolder> matches = sd.getCertificates().getMatches(si.getSID());
            if (matches.isEmpty()) continue;
            X509CertificateHolder signerHolder = matches.iterator().next();
            boolean ok = si.verify(new JcaSimpleSignerInfoVerifierBuilder()
                                      .setProvider("BC")
                                      .build(signerHolder));
            anyValid |= ok;

            // Compare SPKI with our server cert (to set issuedByUs)
            String signerSpki = Base64.toBase64String(signerHolder.getSubjectPublicKeyInfo().getEncoded());
            String ourSpki = Base64.toBase64String(
                SubjectPublicKeyInfo.getInstance(ourCert.getPublicKey().getEncoded()).getEncoded());
            if (ok && signerSpki.equals(ourSpki)) {
              issuedByUs = true;
            }
            issuerDn = signerHolder.getSubject().toString();
          }
        } catch (Exception e) {
          errorMsg = "exception: " + e.getClass().getSimpleName();
          if (e.getMessage() != null && !e.getMessage().isEmpty()) {
            errorMsg += " - " + e.getMessage();
          }
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
    out.put("debug", debug);               // <— detailed diagnostics here
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
        ctx.json(v);            // 200 with verification object
      } catch (Exception e) {
        // Always return 200 with a negative result; worker will read JSON and decide.
        ctx.status(200).json(Map.of(
          "hasSignature", false,
          "isValid", false,
          "issuedByUs", false,
          "coversDocument", false,
          "issuer", "",
          "subFilter", "",
          "error", "exception: " + e.getClass().getSimpleName()
        ));
      }
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

      return new Response(signed, {
        headers:{
          "content-type":"application/pdf",
          "content-disposition":`attachment; filename="signed.pdf"`,
          "x-doc-sha256": sha,
          "x-issuer": env.ISSUER,
          "x-doc-verified": "true"
        }
      });
    }

    if (u.pathname.endsWith("/revoke")){
      // if (!sameOrigin(req)) return json({error:"bad origin"}, 400);
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
  
  const ok = !!row && !row.revoked_at && vinfo.hasSignature && vinfo.isValid && vinfo.issuedByUs && vinfo.coversDocument;
  const html = `<!doctype html><meta charset="utf-8"><title>Verify</title>
  <body style="font-family:ui-sans-serif;padding:32px">
  <h1>Verification result</h1>
  <p>SHA-256: <code>${sha}</code></p>
  <ul>
    <li>Registered by dmj.one: ${row ? "✅" : "❌"}</li>
    <li>Revoked: ${row?.revoked_at ? "❌ (revoked)" : "✅ (not revoked)"}</li>
    <li>Signature object present: ${vinfo.hasSignature ? "✅" : "❌"}</li>
    <li>Embedded signature cryptographically valid: ${vinfo.isValid ? "✅" : "❌"}</li>
    <li>Covers whole document (ByteRange): ${vinfo.coversDocument ? "✅" : "❌"}</li>
    <li>Signed by our key (dmj.one): ${vinfo.issuedByUs ? "✅" : "❌"}</li>
    <li>Issuer (from signature): <code>${vinfo.issuer||""}</code></li>
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
