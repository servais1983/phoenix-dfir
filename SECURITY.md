# Security Policy

## Reporting a Vulnerability

If you discover a vulnerability in Phoenix DFIR, **do not open a public
issue**. Report it to the team by email, including:

- Description of the issue
- Steps to reproduce
- Estimated impact
- Affected version
- Optional: proposed patch

We acknowledge receipt within 72h and provide a fix schedule within 7 days.

---

## Threat Model (v4.10)

Phoenix DFIR is designed to be deployed in a **trusted environment**
(DFIR analyst network, internal SOC segment). The threat model explicitly
covers:

### In scope

- **Authentication and authorization**: credential compromise,
  privilege escalation, token abuse, brute force
- **Injection**: SQL injection (parameterized prepared statements everywhere),
  XSS (strict CSP, input sanitization), command injection
- **Path traversal**: every endpoint touching the filesystem is
  protected by `_sanitize_report_id`, `secure_filename` and regex validation
- **Rate limiting**: protection against brute force and application-level DoS
- **Audit**: all sensitive actions are logged
- **Secrets**: the JWT key is read from the environment or stored in
  `.secret_key` (chmod 600 when possible)
- **Tokens**: short-lived access tokens (15 min), long-lived refresh tokens
  with rotation and server-side revocation

### Out of scope

- **Infrastructure compromise**: if the host machine is compromised, the attacker
  can read the SQLite database and the uploads. Mitigations: disk encryption,
  SELinux/AppArmor, runtime security monitoring.
- **Attacks on the analyst's browser**: extensions, local malware,
  XSS in viewed artifacts (mitigated by CSP, but an analyst who
  opens a malicious file outside Phoenix bears that risk).
- **MITM on the internal network**: use TLS (nginx) in production, with a
  certificate signed by an internal CA.
- **Python/Node supply chain**: partially covered by `pip-audit` and an
  SBOM, but package signatures are not verified.

---

## Hardening checklist (production)

- [ ] `PHOENIX_SECRET_KEY` set in `.env` (never in plain text in the repo)
- [ ] `PHOENIX_DEBUG=false`
- [ ] Stack started with `docker-compose.prod.yml` (Redis + Nginx)
- [ ] TLS certificates in `deploy/tls/`, SSL directives uncommented in
      `deploy/nginx.conf`
- [ ] `REDIS_URL` configured (otherwise rate limiting is in-memory and not distributed)
- [ ] Periodic backup of the `phoenix-data` volume (contains the database)
- [ ] JSON logs exported to your log aggregation platform
- [ ] Prometheus metrics scraped (alerts on
      `phoenix_auth_failures_total`, `phoenix_rate_limit_blocks_total`)
- [ ] `pip-audit` and `bandit` integrated into the workflow (already in CI)
- [ ] Initial admin account created and its password changed immediately
- [ ] Roles assigned correctly (admin reserved for operators)

---

## Cryptographic primitives

| Usage | Algorithm | Parameters |
|---|---|---|
| Password hashing | PBKDF2-HMAC-SHA256 | 600 000 iterations, 32-byte random salt |
| JWT signature | HMAC-SHA256 | key >= 64 hex characters |
| File hashing | MD5 + SHA1 + SHA256 | all 3 exposed for existing tooling |
| Session entropy | `secrets.token_hex(64)` | when `PHOENIX_SECRET_KEY` is absent |
| Token jti | `uuid.uuid4().hex` | 128 random bits |

**Note on MD5/SHA1**: Phoenix DFIR computes MD5 and SHA1 on artifacts
**solely for interoperability** (matching against threat intelligence
databases that still only expose these hashes). SHA256 remains
the reference hash for Phoenix.

---

## Disclosure timeline

- T+0: report received
- T+72h: acknowledgment of receipt
- T+7d: assessment and fix schedule
- T+30d: fix released or public disclosure (depending on severity)
- T+90d: maximum delay before public disclosure (even without a fix)
