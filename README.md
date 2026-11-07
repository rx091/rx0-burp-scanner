# Rx0 Vulnerability Scanner - Burp Suite Extension

A **Java** extension (Montoya API) for Burp Suite **Community/Pro** that runs a battery of
security checks against an authorized host and generates a **dark-themed HTML report**,
signed as *Created by Rx0 - @rodrigocoutinho91*.

> ⚠️ **Authorized use only.** This extension makes active requests (including XSS/SQLi/Open
> Redirect probes) against the host you provide. Use it exclusively against assets you have
> explicit permission to test.

## What it covers (v1.0.0)

- **Missing security headers**: CSP, X-Frame-Options, HSTS, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy + banner disclosure via `Server`/`X-Powered-By`.
- **Cookies**: missing `Secure`, `HttpOnly` and `SameSite` flags.
- **Misconfigured CORS**: reflection of an arbitrary `Origin`, especially combined with
  `Access-Control-Allow-Credentials: true`.
- **Exposed sensitive paths/files**: `.git/`, `.env`, backups, `phpinfo.php`,
  `swagger.json`, `/actuator/env`, common panels, etc.
- **Reflected XSS**: a non-intrusive probe on common query parameters.
- **SQL Injection (error-based)**: simple quote-character payloads on common parameters,
  looking for MySQL/PostgreSQL/MSSQL/Oracle/SQLite/PDO error signatures.
- **Open Redirect**: tests typical redirect parameters with a forged external domain.

### API-focused checks (OWASP API Security Top 10)

- **Unauthenticated endpoint discovery** (API1/API2): tests common API paths
  (`/api/users`, `/api/admin`, `/api/me`, etc.) with no credentials sent, and flags
  cases that return real data with HTTP 200.
- **Sequential IDOR / BOLA** (API1): accesses `/api/users/1`, `/2`, `/3` (and variations) with
  no authentication and flags it when **different** objects come back - a sign of
  missing ownership checks.
- **Excessive data exposure** (API3): scans API responses for fields like
  `password`, `secret`, `access_token`, national ID numbers, card numbers, etc.
  returned unnecessarily.
- **GraphQL introspection enabled**: tests `/graphql`, `/api/graphql` and variations with an
  introspection query - if enabled in production, this exposes the entire API schema.
- **Weak JWTs in the proxy history**: scans the Burp Proxy history for
  `Authorization: Bearer` tokens sent to the target host, decodes the header/payload and flags
  `alg: none` (unsigned token) and a missing `exp` claim (a token that never expires).
  *Browse the application while logged in before running the scan to populate the history with tokens.*
- **Dangerous HTTP methods**: detects `TRACE` enabled (Cross-Site Tracing) and write
  methods (`PUT`/`DELETE`/`PATCH`) advertised via `OPTIONS`.
- **Missing rate limiting** (API4): fires a burst of login attempts and checks whether the
  server applies HTTP 429/403 at any point.
- **Verbose errors / stack trace in APIs**: sends malformed JSON and looks for stack
  traces (Java/Python/PHP/.NET/Node) or server file paths in the error response.

### Injection / file inclusion / SSRF

- **SSRF**: tests parameters that accept a URL (webhook, callback, avatar, fetch...) against
  classic internal targets - including the AWS/GCP metadata endpoint - and confirms via the
  response's content signature that the SERVER made the request.
- **Path Traversal / LFI**: injects directory traversal payloads (`../../etc/passwd`,
  encoded and double-slash variations, `win.ini`) into parameters that serve a file/page.
- **RFI (Remote File Inclusion)**: injects a fake external URL into include/template
  parameters and looks for error messages confirming the server tried to
  fetch/include that remote URL (error-based detection, no need to host a payload).
- **NoSQL Injection**: compares a login with normal invalid credentials (baseline) against the
  same endpoint using `$ne` operators - if the behavior flips to "authenticated", it's a bypass.
- **Mass Assignment**: sends extra privileged fields (`isAdmin`, `role`, `balance`,
  `verified`...) on registration/profile-update endpoints and checks whether the response
  echoes those values back, a sign the backend directly binds the JSON to the entity with no allowlist.

### XSS (3 dedicated checks)

- **`ReflectedXssCheck`**: tests GET (query string) and POST (JSON and
  form-urlencoded body) with 6 payloads across different contexts (raw tag, attribute
  breakout, `<script>` breakout, `onerror`/`onload`).
- **`StoredXssCheck`**: sends the payload via POST to typical comment/feedback
  endpoints and confirms in a **separate second request** (GET) whether it comes back
  without escaping - i.e. whether it got persisted and reaches any visitor, not just the sender.
- **`DomXssCheck`**: a STATIC analysis of the page's HTML/JS - looks for a controllable source
  (`location.hash`, `location.search`, `document.URL`...) near a dangerous sink
  (`innerHTML`, `eval`, `document.write`...) in the same chunk of code. Doesn't actually
  execute the JS, so it's just a signal for you to confirm manually in DevTools.

### More checks (based on the Burp Scanner's check list)

- **SSTI** (`SstiCheck`): injects math expressions in 6 template-engine syntaxes
  (Jinja2/Twig, Freemarker/EL, Thymeleaf/ERB, ERB/EJS, Razor) and confirms whether the
  evaluated RESULT appears in the response, with an anti-false-positive baseline.
- **OS Command Injection** (`OsCommandInjectionCheck`): blind, time-based - injects
  delay commands (Unix and Windows) and only confirms the finding if the delay
  matches on **two** separate attempts.
- **XXE** (`XxeCheck`): sends XML with an external entity pointing at `/etc/passwd` to
  endpoints that accept XML.
- **LDAP Injection / XPath Injection** (`LdapXpathInjectionCheck`): error-based, same
  approach as SQLi, but for these two query engines.
- **Directory Listing** (`DirectoryListingCheck`): detects directory listing enabled
  in common folders (`/uploads/`, `/backup/`, `/assets/`...).
- **Exposed source code** (`SourceCodeDisclosureCheck`): tests backup/editor filename
  variations (`.bak`, `~`, `.swp`, `.orig`) on top of common names (`index`, `config`,
  `login`...) and confirms via real-code signatures (PHP/Java/.NET/JSP/SQL) in the body.
- **Sensitive data in the body** (`SensitiveDataInBodyCheck`): a private key, a private
  JWK, an internal IP, a possible credit card/national ID number, a database connection
  string, and mass email leakage (5+ distinct addresses).
- **CSRF** (`CsrfTokenCheck`): static analysis of POST forms with no hidden
  anti-CSRF token field.
- **ViewState / Autocomplete** (`ViewStateAndAutocompleteCheck`): ASP.NET `__VIEWSTATE` with no
  `__VIEWSTATEMAC`, and password fields with no `autocomplete="new-password"`.

### One more round: fingerprinting, host header, upload, cache poisoning, business logic

- **`TechFingerprintCheck`** (INFO): identifies the CMS/framework (WordPress, Laravel, Django,
  Rails, ASP.NET, React, Angular, Vue...) via HTML/cookie signatures, to help direct the
  rest of the manual testing.
- **`HostHeaderInjectionCheck`**: tests whether the server blindly trusts the `Host`/
  `X-Forwarded-Host` header - can lead to cache poisoning, a poisoned password-reset
  link, or internal SSRF.
- **`FileUploadCheck`**: sends a double-extension (`.php.jpg`) file disguised as an
  image to common upload endpoints, and reports whether it was accepted - the classic
  first step toward Unrestricted File Upload / RCE.
- **`WebCachePoisoningCheck`**: tests "unkeyed" headers (`X-Forwarded-Host`, `X-Forwarded-
  Scheme`...) that affect content but not the cache key - detects the RISK CONDITION
  (reflection + presence of a cache); confirming the poisoning itself is left as a manual step
  (documented in each finding's "Exploitation steps").
- **`BusinessLogicCheck`**: basic e-commerce heuristics - tests a negative quantity and a
  manipulated price sent directly in the cart/checkout payload.
- **JWT Algorithm Confusion** (added to the existing `JwtWeaknessCheck`): when the JWT uses
  RS256/384/512, looks for the public key on common JWKS endpoints (`/.well-known/jwks.json`) and,
  if found, **actually generates a forged token** signed with HS256 using the public key
  as the HMAC secret - the ready-to-use token appears in the "Exploitation steps" field so
  you can test it directly in Repeater against a protected endpoint.

### Light crawling (real parameters instead of just guessed names)

`LightCrawler` visits the home page ONCE per scan and extracts real parameter
names (from `?param=` links and `<input name="...">` form fields), making them
available via `ScanContext` to any check - complementing (not replacing) the list of
common names each check already tests.

### Authenticated scan and stealth mode

- **Session cookie**: a new, optional field in the tab - filling it with something like
  `sessionid=abc123`, this value is sent in the `Cookie` header on every request from the
  checks that use `ScanContext` (currently: the 4 OOB-confirmation checks plus the 5 checks
  from this latest round). This opens up the surface that sits behind a login.
- **Stealth mode**: a checkbox that reduces the scan to a single thread with a small delay
  between checks, instead of the default aggressive parallelization - useful against a
  sensitive WAF or when the client asks for a more discreet pace.

### JSON and CSV export

In addition to the HTML report, you can now export to **JSON** (`JsonReportGenerator` - for
integrating with other tools/pipelines) and **CSV** (`CsvReportGenerator` - to import
directly into a findings-tracking spreadsheet). Three buttons on the tab: "HTML Report",
"Export JSON", "Export CSV".

### Performance and effectiveness (parallelization + OOB confirmation via interactsh)

- **Parallelization**: the 31 checks now run in a pool of **6 concurrent threads**
  (instead of one after another), significantly cutting total scan time. The number is
  deliberately moderate so it doesn't overload the target or aggressively trigger a
  WAF/rate-limiting.
- **Out-of-band confirmation via interactsh** (`InteractshClient`): an open-source alternative
  to Burp Collaborator (which is Pro-only), implemented from scratch in plain Java - RSA-2048
  + AES-256 to register and decrypt interactions with public interactsh servers
  (`oast.pro`, `oast.live`, `oast.site`, `oast.online`, `oast.fun`). The **SSRF**, **OS
  Command Injection**, **XXE** and **RFI** checks now, in addition to their existing
  content/error/time-based detection, also fire an extra payload pointing at a
  uniquely generated domain. At the end of the scan the extension waits a few seconds and
  checks whether the target actually "called back" - if confirmed, it generates an
  additional finding with `[CONFIRMED via OOB]` in the title, marked as unambiguous (it
  doesn't depend on content reflection or timing measurement). This is **strictly additive**:
  if registration with interactsh fails (network blocked, server down), the extension simply
  doesn't generate that extra finding - everything else keeps working exactly as before.
- **Automatic deduplication**: if two different checks (or the OOB confirmation) find the
  same issue (same title + same URL), the final report shows it only once.
- **Top 5 risks**: the report now opens with a summary of the 5 highest-severity
  findings, before the full breakdown.

### Exploitation steps on every finding

Every finding in the report now has an **"Exploitation steps"** section, with a
step-by-step guide on how to manually reproduce/validate the flaw from what the check
already collected (URL, payload, parameter). The CRITICAL/HIGH severity checks most
relevant to pentesting (SQLi, reflected/stored XSS, SSTI, OS Command Injection, XXE, SSRF,
Path Traversal, RFI, NoSQL Injection, Mass Assignment, IDOR, CORS, LDAP/XPath Injection,
JWT) get **specific** instructions (e.g. how to escalate SQLi to data extraction, how to
confirm stored XSS reaching another user, how to forge an unsigned JWT). The remaining
checks get a generic exploitation note - resend the request in Repeater and observe the
described evidence.

> ⚠️ This content is for validation in an **authorized** environment, as part of the normal
> finding-confirmation process of a pentest - never for use outside the scope of authorization.

### Automatic false-positive reduction

The extension calculates, **once per scan**, a baseline by requesting a random path that
certainly doesn't exist (`FalsePositiveGuard`). If the server responds HTTP 200 for that path
(typical behavior of an SPA with a catch-all route, e.g. React Router serving `index.html` for
any URL), the path/endpoint checks (`SensitivePathsCheck`, `ApiEndpointDiscoveryCheck`,
`DirectoryListingCheck`, `SourceCodeDisclosureCheck`) compare each response against that
signature and **automatically discard** findings that match the catch-all pattern -
previously those apps would generate dozens of false "findings" just because every URL
returns 200 with the same page. Other checks (SSTI, OS Command Injection) use their own
confirmation techniques: a content baseline (SSTI) and double time-based confirmation (OS
Command Injection).

> This **does not replace** Burp Pro's Active Scanner or a full manual assessment - it's a
> lean, extensible set of quick checks for initial triage. The architecture was designed
> so you can keep plugging in new checks over time (see "How to add a new check" below).

## Requirements

- **JDK 17+**
- **Maven 3.8+**
- Burp Suite Community or Professional (tested from the 2023.x line onward, which already
  supports the Montoya API)

## How to build - step by step on Windows 10

You don't need to know Java for this, just follow the steps:

1. **Install JDK 17.**
   Download the "Windows x64 Installer (.msi)" for Eclipse Temurin 17 from
   `https://adoptium.net/temurin/releases/?version=17` and run it. Keep the
   "Set JAVA_HOME variable" option checked during installation.

2. **Install Maven.**
   Download the `.zip` "Binary zip archive" from `https://maven.apache.org/download.cgi`, extract it to
   `C:\Program Files\Apache\maven` (or another folder of your choice).

3. **Add Maven to the Windows PATH.**
   - Search for "Environment Variables" in the Start menu → "Edit the system
     environment variables" → "Environment Variables..." button.
   - Under "System variables", select `Path` → "Edit" → "New" → add
     `C:\Program Files\Apache\maven\bin` (adjust to the path you used).
   - Click OK everywhere.

4. **Check it worked.**
   Open **Command Prompt** (cmd) and type:
   ```
   java -version
   mvn -version
   ```
   If both show a version number (and not "command not recognized"), you're set.

5. **Extract the `rx0-burp-scanner.zip`** you were given into a folder, e.g.:
   `C:\Users\YourUser\Desktop\rx0-burp-scanner`.

6. **Build it.**
   In Command Prompt:
   ```
   cd C:\Users\YourUser\Desktop\rx0-burp-scanner
   mvn clean package
   ```
   This will download the dependencies (requires internet) and produce the file at:
   `target\rx0-vuln-scanner.jar`

7. **Install it in Burp.**
   Burp Suite → **Extensions** → **Installed** → **Add** → Extension type: **Java** →
   Extension file: select the `target\rx0-vuln-scanner.jar` you just built.

If you get a build error, send the full error text and it can be fixed.

## How to build online (without installing anything locally)

The most reliable option for this is **not** a "generic online code compiler" - most of
those don't support a multi-file Maven project with dependencies downloaded from Maven
Central. The right, free path is **GitHub Actions**, already configured in the project
(`.github/workflows/build.yml`): it builds automatically in the cloud and hands you the
ready `.jar` to download. Step by step:

1. Create a free account at `https://github.com` (if you don't have one yet).
2. Click **New repository** (green button), give it a name (e.g. `rx0-burp-scanner`), mark
   it as **Private** (your code stays yours) and click **Create repository**.
3. On the newly created repository's page, click **"uploading an existing file"** (or
   **Add file → Upload files**).
4. Drag the whole `rx0-burp-scanner` folder (or all the files extracted from the zip) into that
   upload area. Scroll down and click **Commit changes**.
5. Go to the repository's **Actions** tab - the "Build Rx0 Vulnerability Scanner" workflow
   should already be running automatically (or click **Run workflow** if it didn't start on its own).
6. Wait for the icon to turn green (✅), usually takes 1-2 minutes.
7. Click the workflow run → scroll down to **Artifacts** → download **rx0-vuln-scanner-jar**
   (it comes as a `.zip` containing the `.jar` inside - extract it).
8. Install that `.jar` in Burp as usual (Extensions → Installed → Add → Java).

Benefit: GitHub builds it in a clean, official environment, with no need to trust your code to
some unknown third-party site - and you can repeat this process every time an update
to the project is sent your way.

## How to install in Burp

1. Open Burp Suite → **Extensions** → **Installed** → **Add**.
2. Under **Extension type**, select **Java**.
3. For **Extension file**, point to `target/rx0-vuln-scanner.jar`.
4. Click **Next**. If everything's fine, the log will show the extension's welcome message.
5. A new **"Rx0 Scanner"** tab will appear in Burp's top bar.

## How to use it

1. In the **Rx0 Scanner** tab, enter the URL of the authorized host (e.g. `https://my-target.com`).
2. Click **Start scan**. The progress bar shows which check is running.
3. Findings appear in real time in the table (severity, title, URL).
4. When done, click **HTML Report** and choose where to save it - the report opens in
   any browser, with a dark theme and your signature in the footer.

> 💡 **Tip for the JWT check**: before running the scan, manually browse the application
> while logged in (through the Burp proxy) for a few minutes. This populates the Proxy
> history with authenticated requests, which is where the JWT check extracts tokens to analyze.

## How to add a new check

1. Create a class under `src/main/java/com/rx0/burp/scanner/checks/` implementing the
   `VulnCheck` interface (the `name()` and `execute(MontoyaApi api, String baseUrl)` methods).
2. Register the new class in `ScanEngine` (inside the constructor, `checks.add(new YourCheck())`).
3. Rebuild with `mvn clean package` and reinstall the `.jar` in Burp.

## Project structure

```
rx0-burp-scanner/
├── pom.xml
└── src/main/java/com/rx0/burp/
    ├── Rx0ScannerExtension.java      # entry point (BurpExtension)
    ├── model/
    │   ├── Finding.java              # represents one finding
    │   └── Severity.java             # CRITICAL / HIGH / MEDIUM / LOW / INFO
    ├── scanner/
    │   ├── VulnCheck.java            # interface every check implements
    │   ├── ScanEngine.java           # orchestrates running every check
    │   └── checks/                   # each class = one vulnerability check
    ├── report/
    │   └── HtmlReportGenerator.java  # builds the final dark-themed HTML
    └── ui/
        └── Rx0Panel.java             # Swing tab inside Burp
```

---
Created by **Rx0** - [@rodrigocoutinho91](https://www.instagram.com/rodrigocoutinho91/)
