# OWASP Top 10 (2021)

## A01:2021 — Broken Access Control (CWE-200, CWE-284, CWE-287)

Moving from A5 to the top position in the 2021 Top 10. Attacks exploit missing
authorization checks, allowing users to access functions or data they are not
allowed to see or modify. Common flaws include IDOR (direct object references),
missing access control on APIs, path traversal, and forced browsing.
Root cause: the application trusts that a request is allowed without enforcing
server-side authorization on every access. Fix: deny-by-default policies,
server-side enforcement of authorization for every function, disable directory
listing, and use rate limiting where appropriate.

## A02:2021 — Cryptographic Failures (CWE-327, CWE-331, CWE-759)

Previously called "Sensitive Data Exposure". Focuses on failures related to
cryptography that lead to exposure of sensitive data. Includes weak or broken
algorithms (MD5, SHA-1, RC4, DES), hardcoded keys, poor key management,
missing encryption in transit (HTTP instead of HTTPS), and predictable random
number generators. Fix: classify data, use strong modern algorithms with
proper key sizes, encrypt data in transit and at rest, and never invent custom
crypto or hardcode keys.

## A03:2021 — Injection (CWE-79, CWE-89, CWE-78, CWE-94)

Injection is when untrusted data is sent to an interpreter as part of a
command or query, tricking it into executing unintended commands. The most
well-known is SQL injection (CWE-89): user input is concatenated into a SQL
statement, so an attacker can alter its semantics, read or modify data, or
execute administrative operations. Also includes command injection (CWE-78),
OS command injection via shell=True, and XSS (CWE-79). Fix: use parameterized
queries / prepared statements, strict allow-list input validation, never
concatenate user input into queries, commands, or templates, and escape output
in the correct context.

## A04:2021 — Insecure Design (CWE-1188)

Distinct from insecure implementation. Refers to missing or ineffective
control design: no threat modeling, weak trust boundaries, missing rate
limiting or quota controls, and no secure defaults. Root cause: security
requirements are not considered during the design phase. Fix: establish
threat modeling and secure design patterns, use secure defaults, and add
controls such as rate limiting and request throttling before deployment.

## A05:2021 — Security Misconfiguration (CWE-16, CWE-611, CWE-20)

A very common category: missing security hardening, overly permissive CORS,
unnecessary features enabled, verbose error messages that leak stack traces,
default accounts still active, and debug modes enabled in production.
Includes XML external entity (XXE) processing (CWE-611) when XML parsers are
misconfigured to resolve external entities. Fix: automate hardening of all
environments, remove unused features and frameworks, disable directory
listing and verbose errors, and disable external entity resolution in parsers.

## A06:2021 — Vulnerable and Outdated Components (CWE-1104)

Using components (libraries, frameworks) with known vulnerabilities. Software
is vulnerable when you do not know the versions of all components, when the
software is unsupported or out of date, or when a known CVE is not patched.
Root cause: dependency versions are not tracked or updated regularly.
Fix: inventory all components and their versions, subscribe to advisories,
remove unused dependencies, and patch or replace vulnerable components.

## A07:2021 — Identification and Authentication Failures (CWE-287, CWE-384, CWE-307)

Including weak credential handling, allow brute force, credential stuffing,
default passwords, session fixation, and broken session management. Root
cause: weak or missing authentication logic, or sessions not invalidated.
Fix: implement multi-factor authentication, weak-password checks, rate
limit and delay failed login attempts, and invalidate sessions properly.

## A08:2021 — Software and Data Integrity Failures (CWE-502, CWE-345)

Code and infrastructure that do not protect against integrity violations.
Includes accepting untrusted data in deserialization (CWE-502 — unsafe
pickle/JSON eval), unsigned code or plugins, and compromised update channels.
Fix: verify integrity of signed artifacts, validate data received from
untrusted sources, and avoid unsafe deserialization of untrusted data.

## A09:2021 — Security Logging and Monitoring Failures (CWE-778, CWE-532)

Insufficient logging and monitoring lets attacks go undetected. Includes not
logging failed logins, not monitoring for abuse, and logging sensitive data
(CWE-532 — sensitive information inserted into log files). Fix: log security
relevant events with enough context, ensure logs are protected and not
polluted with secrets, and enable alerting on suspicious activity.

## A10:2021 — Server-Side Request Forgery (CWE-918)

SSRF occurs when a web application fetches a remote resource without
validating the user-supplied URL. An attacker can make the server send
requests to internal services, read internal metadata, or reach hosts
behind the firewall. Fix: validate and allow-list destination URLs and
schemes, block access to internal/private address ranges (127.0.0.0/8,
169.254.169.254, 10.0.0.0/8), and never pass user input directly to a
fetch/request helper.
