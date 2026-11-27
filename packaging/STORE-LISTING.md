# Microsoft Store listing and certification notes (T-287)

Source of truth for the text entered in Partner Center. The listing itself (name, descriptions,
features, search terms) lives per language in [`store-listing/`](store-listing/) as one JSON file
per interface locale (37); `store-listing/check.py` checks every file against the limits below.
Screenshots, age rating (IARC), price and the Partner Center identity belong to T-239, not here.

## Listing fields and limits

From Microsoft's "Add and edit Store listing info" (MSIX) page, checked 2026-11-27:

| JSON key | Partner Center field | Limit |
|---|---|---|
| `shortTitle` | Short title | 50 characters |
| `shortDescription` | Short description | 1000 characters; kept under 270 (Microsoft's own advice) |
| `description` | Description | 10 000 characters, plain text |
| `features` | Product features | up to 20 entries, 200 characters each, no own bullets |
| `searchTerms` | Search terms | not on that page; `check.py` uses 7 terms × 30 characters — confirm in Partner Center |

"DNS Quorum Filter" is never translated. Feature names follow the UI and
`crates/dnsqb-service/ui/i18n/GLOSSARY.md` ("Popular sites only", "unfiltered reference DNS").
Search terms carry no third-party product names. "What's new" stays empty for the first submission.

Languages: the package declares all 37 interface languages (`AppxManifest.template.xml`,
default `en-US`). The `en` and `uk` listings are written by hand; the other 35 are machine
translations, like the interface (`KNOWN-LIMITATIONS.md`).

## Why `runFullTrust` (restricted capability justification)

Paste into Partner Center → Submission options → restricted capabilities:

> DNS Quorum Filter is a packaged Win32 desktop app (three processes: a local DNS-over-HTTPS
> service, a watchdog and a tray icon). It needs full trust to: start and restart its own sibling
> processes by absolute path; add and remove its own self-signed certificate for 127.0.0.1 in the
> current user's trusted root store with certutil.exe, only after the user confirms (the browser
> must trust the local HTTPS address); keep private keys in Windows Credential Manager; use named
> pipes and files in its own data folder for the watchdog; read two values under
> HKEY_CURRENT_USER (its startup task state and the Windows region, to suggest a list); open its
> settings page and Windows Settings in the default browser and shell. It does not intercept or
> proxy traffic: the user points the browser's own "secure DNS" setting at
> https://127.0.0.1:8443/dns-query. It listens on 127.0.0.1 only.

The manifest comment above `<Capabilities>` lists the same uses.

## Notes for certification

Paste into Partner Center → Submission options → Notes for certification:

> The app is a local DNS filter for the browser. It works only after two one-time steps that the
> app asks for on first launch, and the browser must be pointed at it.
>
> 1. Launch "DNS Quorum Filter" from Start. A tray icon appears (grey until set up).
> 2. A dialog asks for consent to send looked-up domain names to the DNS filtering providers
>    (Quad9, Cloudflare malware filter, AdGuard DNS by default) and an unfiltered reference DNS.
>    Choose Yes. Until consent is given, the app sends no domain anywhere and answers every DNS
>    query with an error. Consent can be withdrawn on the settings page.
> 3. A second dialog offers to install the app's local certificate. Choose Yes, then confirm the
>    Windows security prompt. This adds a self-signed certificate for 127.0.0.1 / ::1 / localhost
>    to the current user's trusted root store. It is a leaf certificate, not a certificate
>    authority (basicConstraints CA:FALSE, no keyCertSign), so it cannot sign certificates for
>    other sites. The settings page then opens at https://127.0.0.1:8443/admin/ui.
> 4. In Microsoft Edge: edge://settings/privacy/security → "Use secure DNS" → "Choose a service
>    provider" → enter https://127.0.0.1:8443/dns-query. (Chrome, Brave, Opera, Vivaldi and
>    Firefox are described on the settings page; Firefox must use "Max Protection".)
> 5. To see filtering work: on the settings page, add a domain (for example example.org) to
>    "Blocked domains", then open that site in Edge. Edge cannot reach it, and the query log on the
>    settings page shows it as blocked. Remove the entry afterwards.
>
> Before uninstalling, use the tray menu → "Remove everything": it removes the certificate, the
> keys in Credential Manager and the app's data folder. Windows runs no app code on uninstall, so
> uninstalling alone leaves the certificate and those keys behind.
>
> Known browser behaviour: a browser may ask whether a website may access "apps and services on
> this device"; the app's instructions say to answer Block. The app never changes browser
> policies; if Edge's secure-DNS setting is greyed out, the device has an Edge policy set by
> someone else.
>
> Privacy policy: https://user137.github.io/dns-quorum-filter/privacy.html. No account, telemetry,
> analytics or ads.

The steps match the first-run wizard (`crates/dnsqb-tray/src/main.rs`, `run_setup_wizard`), the
certificate parameters in `crates/dnsqb-service/src/cert.rs` and the decisions in DECISIONS.md
2026-11-14 (browsers) and 2026-11-27 (consent).

## Uninstall (Store policy 10.2.7)

An MSIX uninstall runs no app code, so the certificate in `CurrentUser\Root` and the Credential
Manager entries stay unless the user ran "Remove everything" first. The listing description says
so (last paragraph of `description` in every language), the privacy policy says so ("Deleting your
data"), and the notes for certification above say so.
