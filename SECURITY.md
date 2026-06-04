# Security Policy

## Reporting a Vulnerability

Si vous decouvrez une vulnerabilite dans Phoenix DFIR, **ne pas ouvrir d'issue
publique**. Reporter le probleme par email a l'equipe avec :

- Description du probleme
- Etapes de reproduction
- Impact estime
- Version concernee
- Optionnel : patch propose

Nous accusons reception sous 72h et fournissons un planning de fix sous 7 jours.

---

## Threat Model (v4.0)

Phoenix DFIR est concu pour etre deploye dans un **environnement de confiance**
(reseau d'analystes DFIR, segment SOC interne). Le threat model couvre
explicitement :

### In scope

- **Authentification et autorisation** : compromission de credentials,
  privilege escalation, abuse de tokens, brute force
- **Injection** : SQL injection (parametres prepared statements partout),
  XSS (CSP stricte, sanitisation des inputs), command injection
- **Path traversal** : tous les endpoints touchant au filesystem sont
  proteges par `_sanitize_report_id`, `secure_filename`, validation regex
- **Rate limiting** : protection contre le brute force et le DoS applicatif
- **Audit** : toutes les actions sensibles sont journalisees
- **Secrets** : la cle JWT est lue depuis l'environnement ou stockee dans
  `.secret_key` (chmod 600 quand possible)
- **Tokens** : access courts (15min), refresh longs avec rotation et
  revocation server-side

### Out of scope

- **Infrastructure compromise** : si la machine hote est compromise, l'attaquant
  peut lire la base SQLite et les uploads. Solutions : chiffrement disque,
  SELinux/AppArmor, runtime security (Falco).
- **Attaques sur le navigateur de l'analyste** : extensions, malware local,
  XSS dans les artefacts visualises (mitigation : CSP, mais l'analyste qui
  ouvre un fichier malveillant en dehors de Phoenix porte le risque).
- **MITM sur le reseau interne** : utiliser TLS (nginx) en prod, certificat
  signe par une CA interne.
- **Supply chain Python/Node** : couvert partiellement par `pip-audit` +
  SBOM, mais pas de signature verification des packages.

---

## Hardening checklist (production)

- [ ] `PHOENIX_SECRET_KEY` defini dans `.env` (jamais en clair dans le repo)
- [ ] `PHOENIX_DEBUG=false`
- [ ] Stack lancee avec `docker-compose.prod.yml` (Redis + Nginx)
- [ ] Certificats TLS dans `deploy/tls/`, directives SSL decommentees dans
      `deploy/nginx.conf`
- [ ] `REDIS_URL` configure (sinon rate limit in-memory = non-distribue)
- [ ] Backup periodique de `phoenix-data` volume (contient la BDD)
- [ ] Logs JSON exportes vers Loki/ELK/CloudWatch
- [ ] Metriques Prometheus scrappees (alertes sur
      `phoenix_auth_failures_total`, `phoenix_rate_limit_blocks_total`)
- [ ] `pip-audit` et `bandit` integres au workflow (deja en CI)
- [ ] Compte admin initial cree, mot de passe change immediatement
- [ ] Roles correctement attribues (admin reserve aux operateurs)

---

## Cryptographic primitives

| Usage | Algorithm | Parameters |
|---|---|---|
| Password hashing | PBKDF2-HMAC-SHA256 | 600 000 iterations, salt 32B random |
| JWT signature | HMAC-SHA256 | clef >= 64 caracteres hex |
| File hashing | MD5 + SHA1 + SHA256 | exposition des 3 pour les outils existants |
| Session entropy | `secrets.token_hex(64)` | quand `PHOENIX_SECRET_KEY` absent |
| Token jti | `uuid.uuid4().hex` | 128 bits aleatoires |

**Note sur MD5/SHA1** : Phoenix DFIR calcule MD5 et SHA1 sur les artefacts
**uniquement pour des questions d'interoperabilite** (matching avec des bases
de Threat Intelligence qui n'exposent encore que ces hashes). SHA256 reste
la reference pour Phoenix.

---

## Disclosure timeline

- T+0 : reception du rapport
- T+72h : accuse de reception
- T+7j : evaluation et planning de fix
- T+30j : fix release ou public disclosure (selon gravite)
- T+90j : disclosure public maximum (meme sans fix)
