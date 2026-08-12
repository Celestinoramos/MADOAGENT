# CWE Top-25 (amostra usada pela base RAG)

## CWE-89 — SQL Injection

The software constructs all or part of an SQL command using externally
influenced input from an upstream component, without neutralizing special
elements that could modify the intended SQL command. Classic example:
`query = "SELECT * FROM users WHERE id = " + user_id`. An attacker can inject
clauses that change the query semantics, enabling data theft, modification,
or deletion, and in some database engines arbitrary command execution.
Root cause: user input is concatenated into a SQL string. Fix: use
parameterized queries / prepared statements; validate input against an
allow-list; apply least-privilege database accounts.

## CWE-78 — OS Command Injection

The software constructs a command executed by an operating system shell using
externally influenced input, without neutralizing special elements. Example:
`os.system("ls " + user_input)` or `subprocess.call(cmd, shell=True)`.
An attacker can append operators such as `;`, `&&`, `|` to run arbitrary
commands with the privileges of the process. Fix: avoid shell invocation;
pass argument lists directly to exec-family functions without shell=True;
validate against a strict allow-list.

## CWE-79 — Cross-Site Scripting (XSS)

The software does not neutralize or incorrectly neutralizes user-controlled
input before it is placed in output that is used as web page content.
Reflected and stored XSS let an attacker execute script in the victim's
browser context, steal sessions, or deface the page. Root cause: untrusted
input rendered without contextual output encoding. Fix: encode output for the
correct context (HTML, attribute, JS), use auto-escaping templating, and
validate input server-side.

## CWE-798 — Use of Hard-Coded Credentials

The software contains hard-coded credentials (passwords, API keys, tokens)
in its source code or configuration files. These secrets cannot be rotated
quickly, leak through source control history and logs, and are identical
across deployments. Fix: move secrets to environment variables or a secret
manager, rotate any exposed value, and add secret-scanning to CI.

## CWE-502 — Deserialization of Untrusted Data

The software deserializes data supplied by an untrusted source without
validation, which can lead to object injection and arbitrary code execution.
Example: `pickle.loads(untrusted_bytes)` or unsafe `eval(json-ish)` patterns.
Fix: do not deserialize untrusted data; use safe formats and validate
structure; apply allow-lists and integrity checks (signatures).

## CWE-22 — Path Traversal

The software uses external input to construct a file path without
neutralizing traversal sequences (`../`, absolute paths). An attacker can
read or write files outside the intended directory. Fix: validate and
canonicalize paths, reject traversal sequences, and constrain access with
a base directory and allow-list.

## CWE-611 — Improper Restriction of XML External Entity Reference

The XML parser resolves external entities defined in attacker-supplied XML,
which can expose internal files, network shares, and enable SSRF. Fix:
disable DTDs and external entity resolution in the XML parser configuration;
prefer JSON.

## CWE-918 — Server-Side Request Forgery

The web server fetches a remote resource using a user-supplied URL without
validation. Attackers can access internal services and metadata endpoints.
Fix: allow-list protocols and hosts, block private address ranges, and
restrict where the request can reach.

## CWE-434 — Unrestricted Upload of File with Dangerous Type

The software allows uploading files without restricting type or content,
letting attackers upload executable scripts that the server later serves.
Fix: validate extension and MIME server-side, store uploads outside the web
root, and serve with a non-executable content type.

## CWE-601 — URL Redirection to Untrusted Site

The software accepts a URL as input and redirects the user to it without
validation, enabling phishing. Fix: avoid open redirects; validate that the
target is on an allow-listed host or use an indirect redirect mapping.
