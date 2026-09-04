# MSIX packaging (T-156, Батч 3.8)

- `AppxManifest.template.xml` — `{{VERSION}}`/`{{PUBLISHER}}` placeholders, substituted by
  `pack-msix.ps1` at pack time. Never hand-edit a version/publisher directly into a generated
  `AppxManifest.xml` — regenerate it from the template instead, or the package's declared
  identity can drift from what the binaries and signing certificate actually carry.
- `pack-msix.ps1` — stages the three signed binaries + the three MSIX logo PNGs (copied from
  `../assets/icon/`, see below) + the substituted manifest, runs
  `makeappx pack`, then `signtool sign`s the resulting `.msix`. Run locally:

  ```powershell
  cargo build --release --workspace --locked
  .\packaging\pack-msix.ps1 -BinDir target\release -OutFile dist\dns-quorum-filter.msix
  ```

  Signs with an ephemeral self-signed certificate by default (same model as T-102's binary
  signing) — the `.cer` it emits alongside the `.msix` must be trusted on the target machine
  before `Add-AppxPackage` will install it. This is a **different** certificate from the one the
  running app installs for `127.0.0.1` DoH traffic (T-49) — trusting one does not trust the other.

  **Confirmed empirically (2026-09-04), not assumed:** `Cert:\CurrentUser\TrustedPeople` is
  *not* sufficient — `Add-AppxPackage` fails with `0x800B0109` ("root certificate ... not trusted
  by the trust provider") against a cert imported there. It must go into
  `Cert:\LocalMachine\Root` or `Cert:\LocalMachine\TrustedPeople`, both of which need an elevated
  (admin) PowerShell session to write to:

  ```powershell
  Import-Certificate -FilePath dist\dns-quorum-filter.cer -CertStoreLocation Cert:\LocalMachine\Root
  Add-AppxPackage -Path dist\dns-quorum-filter.msix
  ```

## The icon lives outside this directory

`../assets/gen-icon.py` (Pillow) is the single source for the project's icon everywhere it's
needed, not just MSIX — the tile logos here, a future Microsoft Store listing, README/site use
via `../assets/icon/wordmark.png`, and a future Linux desktop icon (Фаза 6 — the generator already
writes the freedesktop hicolor theme's standard sizes). Re-run it after editing rather than
hand-editing a PNG under `../assets/icon/`. `pack-msix.ps1` copies only the three MSIX-named
files it needs from there (`Square44x44Logo.png`/`Square150x150Logo.png`/`StoreLogo.png`) — the
other sizes and the wordmark aren't MSIX's concern and never get bundled into the `.msix`.

## Replacing the placeholder identity for a Microsoft Store submission

1. Partner Center assigns a real `Package/Identity/Name` and `Publisher` — replace both
   placeholders in `AppxManifest.template.xml`'s `<Identity>` (and `pack-msix.ps1`'s default
   `-Publisher`) with the assigned values.
2. Replace the icon (`../assets/gen-icon.py` + the PNGs it writes) with a real logo — a full Store
   submission also wants more sizes/promotional-image formats than this generator produces.
3. Drop the `-PfxPath`/`CODESIGN_PFX` self-signed path entirely for that submission — the Store
   re-signs the package with Microsoft's own certificate at publication, same as it does for the
   raw binaries (T-102, SPEC.md §"Наскрізні вимоги").

Nothing else in the manifest (capabilities, the startup-task extension, the application entry
point) needs to change for a Store submission — those describe what the app *does*, not who
publishes it.
