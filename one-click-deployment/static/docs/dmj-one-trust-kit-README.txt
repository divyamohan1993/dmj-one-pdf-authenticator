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