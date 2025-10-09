package one.dmj.signer;

import io.javalin.Javalin;
import io.javalin.http.UploadedFile;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;

public class App {
    static PrivateKey privateKey;
    static X509Certificate signerCert;
    static List<X509Certificate> certChain;
    static String HMAC_B64;
    static String P12_PATH;
    static String P12_PASSWORD;
    static String BIND_HOST = "127.0.0.1";
    static int PORT;
    static String SPKI_B64URL;
    static final Map<String, Long> NONCES = new LinkedHashMap<>() {
        @Override protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) { return size() > 5000; }
    };
    public static void main(String[] args) throws Exception {
        P12_PATH = getenvOr("/etc/dmj/dmj-signer.p12", "P12_PATH");
        P12_PASSWORD = requiredEnv("P12_PASSWORD");
        HMAC_B64 = requiredEnv("SIGNING_GATEWAY_HMAC_KEY");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(P12_PATH)) { ks.load(in, P12_PASSWORD.toCharArray()); }
        String alias = Collections.list(ks.aliases()).get(0);
        privateKey = (PrivateKey) ks.getKey(alias, P12_PASSWORD.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        certChain = new ArrayList<>();
        for (Certificate c : chain) certChain.add((X509Certificate) c);
        signerCert = (X509Certificate) chain[0];
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        SPKI_B64URL = b64url(md.digest(signerCert.getPublicKey().getEncoded()));
        PORT = pickPort(18080);
        writeNginxIncludeAndReload(PORT);
        final int MAX_PDF = 20 * 1024 * 1024;
        var app = Javalin.create(conf -> {
            conf.http.defaultContentType = "application/json";
            conf.jetty.sessionHandler(() -> null);
        }).start(BIND_HOST, PORT);
        app.get("/healthz", ctx -> ctx.result("ok"));
        app.get("/spki", ctx -> ctx.json(Map.of("spkiSha256", SPKI_B64URL)));
        app.post("/sign", ctx -> {
            if (!checkHmac(ctx.header("X-DMJ-Timestamp"), ctx.header("X-DMJ-Nonce"), ctx.header("X-DMJ-FileSHA256"), ctx.header("Authorization"))) {
                ctx.status(401).result("{\"error\":\"auth\"}");
                return;
            }
            UploadedFile uf = ctx.uploadedFile("pdf");
            if (uf == null) {
                ctx.status(400).result("{\"error\":\"no_file\"}");
                return;
            }
            if (uf.size() > MAX_PDF) {
                ctx.status(413).result("{\"error\":\"too_large\"}");
                return;
            }
            byte[] input = uf.content().readAllBytes();
            if (!new String(input, 0, Math.min(5, input.length)).startsWith("%PDF-")) {
                ctx.status(415).result("{\"error\":\"not_pdf\"}");
                return;
            }
            String displayName = opt(ctx.formParam("displayName"), "dmj.one");
            String reason = opt(ctx.formParam("reason"), "Digitally signed by dmj.one");
            byte[] signed = signPdfDetached(input, "Adobe.PPKLite", "adbe.pkcs7.detached", displayName, reason);
            Map<String, String> meta = new LinkedHashMap<>();
            meta.put("certSerial", signerCert.getSerialNumber().toString(16));
            meta.put("sigAlg", "RSA-SHA256");
            meta.put("subfilter", "adbe.pkcs7.detached");
            meta.put("spkiSha256", SPKI_B64URL);
            ctx.header("X-DMJ-Meta", Base64.getEncoder().encodeToString(new org.json.JSONObject(meta).toString().getBytes()));
            ctx.contentType("application/pdf").result(signed);
        });
        app.post("/verify", ctx -> {
            UploadedFile uf = ctx.uploadedFile("pdf");
            if (uf == null) {
                ctx.status(400).result("{\"error\":\"no_file\"}");
                return;
            }
            if (uf.size() > MAX_PDF) {
                ctx.status(413).result("{\"error\":\"too_large\"}");
                return;
            }
            byte[] input = uf.content().readAllBytes();
            Map<String, Object> out = verifyPdf(input);
            ctx.json(out);
        });
    }

    static Map<String, Object> verifyPdf(byte[] input) {
        Map<String, Object> out = new LinkedHashMap<>();
        try (PDDocument doc = PDDocument.load(input)) {
            List<PDSignature> sigs = doc.getSignatureDictionaries();
            boolean valid = false;
            String reason = "";
            String signer = "";
            String spki = "";
            Instant when = null;
            for (PDSignature sig : sigs) {
                byte[] contents = sig.getContents(input);
                byte[] signedContent = sig.getSignedContent(input);
                CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signedContent), contents);
                SignerInformationStore signers = cms.getSignerInfos();
                Collection<SignerInformation> c = signers.getSigners();
                var certs = cms.getCertificates();
                for (SignerInformation si : c) {
                    Collection<?> matches = certs.getMatches(si.getSID());
                    X509CertificateHolder holder = (X509CertificateHolder) matches.iterator().next();
                    X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(holder);
                    valid = si.verify(new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder().build(cert));
                    signer = holder.getSubject().toString();
                    reason = opt(sig.getReason(), "");
                    when = (sig.getSignDate() != null) ? sig.getSignDate().getTime().toInstant() : null;
                    MessageDigest md2 = MessageDigest.getInstance("SHA-256");
                    spki = b64url(md2.digest(cert.getPublicKey().getEncoded()));
                }
            }
            out.put("valid", valid);
            out.put("reason", reason);
            out.put("signedAt", when == null ? "" : when.toString());
            out.put("signer", signer);
            out.put("spkiSha256", spki);
            return out;
        } catch (Exception e) {
            out.put("valid", false);
            out.put("error", e.getMessage());
            return out;
        }
    }

    static byte[] signPdfDetached(byte[] inputPdf, String filter, String subFilter, String name, String reason) throws Exception {
        try (PDDocument doc = PDDocument.load(inputPdf)) {
            PDSignature sig = new PDSignature();
            sig.setFilter(filter);
            sig.setSubFilter(subFilter);
            sig.setName(name);
            sig.setReason(reason);
            sig.setSignDate(Calendar.getInstance());
            doc.addSignature(sig, (content) -> {
                try {
                    byte[] toBeSigned = content.readAllBytes();
                    var certStore = new JcaCertStore(certChain);
                    var gen = new CMSSignedDataGenerator();
                    ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
                    var signerInfo = new org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder(
                            new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build()
                    ).build(sha256Signer, signerCert);
                    gen.addSignerInfoGenerator(signerInfo);
                    gen.addCertificates(certStore);
                    CMSProcessable msg = new CMSProcessableByteArray(toBeSigned);
                    CMSSignedData cms = gen.generate(msg, false);
                    return cms.getEncoded();
                } catch (Exception ex) {
                    throw new IOException(ex);
                }
            });
            var baos = new ByteArrayOutputStream();
            doc.saveIncremental(baos);
            return baos.toByteArray();
        }
    }

    static boolean checkHmac(String ts, String nonce, String fileSha, String auth) throws Exception {
        if (ts == null || nonce == null || fileSha == null || auth == null) return false;
        long now = Instant.now().getEpochSecond();
        long tsL = Long.parseLong(ts);
        if (Math.abs(now - tsL) > 300) return false;
        synchronized (NONCES) {
            if (NONCES.containsKey(nonce)) return false;
            NONCES.put(nonce, now);
        }
        String msg = ts + "|" + nonce + "|" + fileSha;
        byte[] key = Base64.getDecoder().decode(HMAC_B64);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        String calc = b64url(mac.doFinal(msg.getBytes()));
        return ("DMJ-HMAC " + calc).equals(auth);
    }

    static String b64url(byte[] in) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(in);
    }

    static String opt(String s, String d) {
        return (s == null || s.isEmpty()) ? d : s;
    }

    static String getenvOr(String dflt, String key) {
        String v = System.getenv(key);
        return (v == null || v.isEmpty()) ? dflt : v;
    }

    static String requiredEnv(String key) {
        String v = System.getenv(key);
        if (v == null || v.isEmpty()) throw new RuntimeException("Missing env: " + key);
        return v;
    }

    static int pickPort(int start) {
        for (int p = start; p < start + 100; p++) {
            try (ServerSocket s = new ServerSocket(p)) {
                return p;
            } catch (IOException ignored) {
            }
        }
        return start;
    }

    static void writeNginxIncludeAndReload(int port) throws Exception {
        File f = new File("/etc/nginx/conf.d/dmj_pdfsigner_port.conf");
        try (FileWriter w = new FileWriter(f)) {
            w.write("set $pdfsigner_port " + port + ";\n");
        }
        try {
            new ProcessBuilder("bash", "-lc", "nginx -s reload || true").inheritIO().start();
        } catch (Exception ignored) {
        }
    }
}
