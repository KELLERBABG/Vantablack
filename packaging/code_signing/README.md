# Windows Code-Signing Guide (Authenticode & SmartScreen Elimination)

Windows SmartScreen warns users when running newly released unsigned executables until the binary accumulates download reputation.
Signing the installer (`ggn-<version>-windows-setup.exe`) and binary (`ggn.exe`) eliminates this warning immediately.

---

## Option 1: Free Code Signing for Open Source via SignPath.io (Recommended)

[SignPath Foundation](https://about.signpath.io/open-source/) provides free code-signing certificates for open-source projects hosted on GitHub.

### Setup Steps:
1. Apply for a free open-source project account at [https://about.signpath.io/open-source/](https://about.signpath.io/open-source/).
2. Connect your GitHub repository `KELLERBABG/Vantablack`.
3. Add the SignPath GitHub Actions step into `.github/workflows/release.yml`:
   ```yaml
   - name: Sign Windows Artifacts with SignPath
     uses: signpath/github-action-submit-signing-request@v1
     with:
       api-token: ${{ secrets.SIGNPATH_API_TOKEN }}
       organization-id: ${{ secrets.SIGNPATH_ORG_ID }}
       project-slug: 'vantablack'
       signing-policy-slug: 'release-signing'
       artifact-path: 'dist/ggn-${{ github.ref_name }}-windows-setup.exe'
   ```

---

## Option 2: Commercial Authenticode Certificate (Certum / DigiCert / Sectigo)

If you acquire a Standard Code Signing Certificate (e.g., Certum Open Source ~70 EUR/year):

1. Export the certificate as a password-protected `.pfx` file.
2. Encode the `.pfx` as base64:
   ```powershell
   [Convert]::ToBase64String([IO.File]::ReadAllBytes("certificate.pfx")) | Set-Clipboard
   ```
3. Store in GitHub Repository Secrets as `WINDOWS_CERT_BASE64` and `WINDOWS_CERT_PASSWORD`.
4. Sign the binary and installer before creating the release in `.github/workflows/release.yml`:
   ```powershell
   # Decode cert in runner
   [IO.File]::WriteAllBytes("cert.pfx", [Convert]::FromBase64String($env:WINDOWS_CERT_BASE64))

   # Sign setup installer
   & "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe" sign /fd SHA256 /f cert.pfx /p $env:WINDOWS_CERT_PASSWORD /tr http://timestamp.digicert.com /td SHA256 dist\ggn-*-windows-setup.exe
   ```

---

## Option 3: Inno Setup Integrated Signing

In `installer/ggn.iss`, Inno Setup supports native signing hooks:
```pascal
[Setup]
SignTool=signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $f
```
This automatically signs both the uninstaller (`unins000.exe`) and the installer package itself during compilation!
