# DomainExposure — Plan d'implementation (a valider)

## 1. Constats d'environnement (verifies le 2026-11-18)

| Source | Statut | Cle |
|---|---|---|
| HIBP `/api/v3/breaches?Domain=` | 200 OK, metadonnees completes | non |
| HIBP Domain Search `/breacheddomain/{d}` | non teste (necessite cle payante + domaine verifie) | oui |
| ransomware.live `/v2/searchvictims/{kw}` | 200 OK | non |
| crt.sh `?output=json` | 200 OK (lent, 503 fréquents en prod) | non |
| Shodan InternetDB | joignable (404 = "No information available") | non |
| URLhaus `/v1/host/` | **401 Unauthorized** — abuse.ch exige une Auth-Key depuis 2024 | oui (gratuite) |
| VirusTotal / AbuseIPDB / Shodan API | hotes autorises, non testes | oui |
| DNS UDP/53 du conteneur | **NXDOMAIN systematique** | — |
| DoH Cloudflare / Google | 200 OK | non |

Consequences :
1. Resolveur DNS abstrait obligatoire (backend `system` via dnspython / `doh` via JSON API / `auto`).
2. L'inspection TLS dans ce conteneur traverse un proxy MITM : le module doit le detecter et degrader
   le finding en "chaine non verifiable" plutot que rendre un verdict faux.
3. `example.com` est reserve par l'IANA pour la documentation/les tests : cible de demo ethiquement propre.
   Son MX est un null MX (`0 .`, RFC 7505) — bon cas limite pour le module email.

## 2. Arborescence

```
domainexposure/
├── README.md                     # FR : install, cles API, limites, cadre legal (RGPD, art. 323-1)
├── SCORING.md                    # ponderations, formule, bareme A-F, justification
├── PLAN.md                       # ce document
├── LICENSE                       # MIT
├── .env.example                  # toutes les cles, commentees (gratuite/payante/url d'obtention)
├── .gitignore
├── .dockerignore
├── pyproject.toml                # deps + config pytest/ruff
├── Dockerfile                    # python:3.12-slim + libs WeasyPrint (pango/cairo)
├── docker-compose.yml            # 1 service, port 8080, volume ./data
├── app/
│   ├── __init__.py
│   ├── __main__.py               # `python -m app` -> uvicorn (bind 127.0.0.1 par defaut)
│   ├── main.py                   # FastAPI : routes REST + SSE + static
│   ├── config.py                 # pydantic-settings ; etat de chaque cle (active/desactive + raison)
│   ├── models.py                 # Severity, Finding, Reference, ModuleResult, Report, Consents
│   ├── validation.py             # validation stricte du domaine (IDN/punycode, rejet IP & URL)
│   ├── httpclient.py             # httpx async : timeouts, retries + backoff, 429/Retry-After,
│   │                             #   token-bucket par source, User-Agent, cache SQLite 24 h
│   ├── resolver.py               # abstraction DNS : backends system | doh | auto (+ cache)
│   ├── scoring.py                # score par module, score global 0-100, note A-F
│   ├── storage.py                # SQLite : analyses, audit_log, http_cache, migrations
│   ├── audit.py                   # journal : date, utilisateur, domaine, cases cochees, IP, UA
│   ├── sanitize.py               # whitelist de champs + masquage email (j***@domaine.fr)
│   ├── orchestrator.py           # execution concurrente des modules + flux d'evenements SSE
│   ├── modules/
│   │   ├── __init__.py           # Protocol `async def run(ctx) -> ModuleResult` + registre
│   │   ├── breaches.py           # 1  HIBP (+ LeakCheck / Intelligence X, metadonnees seules)
│   │   ├── ransomware.py         # 2  ransomware.live
│   │   ├── email_hygiene.py      # 3  MX, SPF (lookups, ~all/-all), DMARC, DKIM, MTA-STS, BIMI
│   │   ├── dns_health.py         # 4  DNSSEC, NS/A/AAAA/TXT, AXFR declare, subdomain takeover
│   │   ├── subdomains.py         # 5  crt.sh -> dedup -> resolution
│   │   ├── exposure.py           # 6  Shodan InternetDB (gratuit) / API complete si cle
│   │   ├── tls_headers.py        # 7  TLS (version, expiration) + HSTS/CSP/XFO/...
│   │   ├── typosquatting.py      # 8  dnstwist en generateur de permutations + notre resolveur
│   │   └── reputation.py         # 9  VirusTotal / URLhaus / AbuseIPDB
│   ├── report/
│   │   ├── __init__.py
│   │   ├── html.py               # rapport HTML autonome (CSS/JS inlines, aucune dependance)
│   │   ├── pdf.py                # WeasyPrint ; desactivation propre si libs absentes
│   │   └── templates/
│   │       ├── report.html.j2    # garde, synthese executive, details, annexe des sources
│   │       └── report.css
│   ├── static/
│   │   ├── index.html            # SPA : Tailwind CDN, aucune etape de build
│   │   └── app.js                # SSE, jauge, cartes, timeline, comparaison
│   └── data/
│       ├── takeover_fingerprints.json   # empreintes S3/Azure/Heroku/GitHub Pages/...
│       └── dkim_selectors.json          # selecteurs courants (google, selector1/2, k1, dkim...)
├── tests/
│   ├── conftest.py               # app de test, SQLite en memoire, FakeResolver
│   ├── fixtures/                 # reponses API reelles capturees (anonymisees)
│   ├── test_validation.py
│   ├── test_scoring.py
│   ├── test_sanitize.py          # garantit l'absence de mdp/hash + masquage
│   ├── test_storage.py
│   ├── test_api.py               # refus sans consentement, SSE, exports
│   ├── test_reports.py
│   └── modules/test_<module>.py  # 9 fichiers, respx + FakeResolver
└── scripts/
    └── demo.sh                   # analyse de demo example.com + export des rapports
```

## 3. Decisions d'architecture

1. **SSE** (`text/event-stream`) plutot que WebSocket : flux unidirectionnel, pas de handshake,
   traverse les proxies, reconnexion natine cote navigateur.
2. **Resolveur abstrait** injecte dans le contexte de chaque module -> tests DNS sans monkeypatch,
   et fonctionnement en reseau restreint (DoH).
3. **dnstwist en bibliotheque de permutations uniquement** (`dnstwist.Fuzzer`), resolution confiee a
   notre resolveur : pas de threads concurrents, timeouts maitrises, module testable, cap configurable
   (defaut 200 permutations, TLD courants).
4. **Interface de module unique** : `async def run(ctx: ModuleContext) -> ModuleResult`. Un module sans
   cle renvoie `status="skipped"` + `disabled_reason` affiche dans le rapport, et est **exclu du
   denominateur du score** (une source absente ne doit ni penaliser ni flatter).
5. **Sanitisation en entree de pipeline** : whitelist de champs par source. Tout champ hors whitelist
   (password, hash, salt, data...) est supprime avant stockage. Les emails sont masques a la source ;
   non masques uniquement si `domain_verified` est coche (HIBP Domain Search).
6. **Zero action active** : un seul contact reseau avec la cible, le `GET https://<domaine>/` du module 7
   (+ handshake TLS). Aucun port scan, aucun bruteforce, aucun AXFR tente (on se contente de constater
   ce qui est publiquement declare). Documente et verifie par test.
7. **Cache 24 h au niveau HTTP** (cle = source+URL normalisee) : respecte les rate limits, rend les
   re-analyses instantanees, et le rapport indique pour chaque source `cached: true/false`.
8. **Politesse par source** : token bucket configurable (HIBP 1 req/1.5 s, crt.sh 1 req/s), respect de
   `Retry-After`, backoff exponentiel + jitter sur 429/5xx, 3 tentatives max.
9. **SQLite unique** (`data/domainexposure.db`), WAL, 3 tables + migrations idempotentes.
10. **Pas d'authentification applicative** : bind `127.0.0.1` hors Docker, avertissement README si exposition.

## 4. Scoring propose

Score par module : 100 - penalites plafonnees ; Critique 40, Eleve 25, Moyen 10, Faible 4, Info 0.

| Module | Poids |
|---|---|
| Hygiene email (SPF/DMARC/DKIM/MTA-STS/BIMI) | 20 |
| Services exposes (ports, CVE) | 15 |
| TLS & en-tetes HTTP | 15 |
| Fuites de donnees | 15 |
| Ransomware | 10 |
| Hygiene DNS (DNSSEC, takeover) | 10 |
| Sous-domaines (surface) | 5 |
| Typosquatting | 5 |
| Reputation | 5 |

Score global = somme ponderee des scores de modules **actifs**, renormalisee sur la somme de leurs poids.
Bareme : A >= 90, B >= 80, C >= 70, D >= 60, E >= 50, F < 50. Tout finding Critique plafonne la note a D.
Chaque finding porte : explication grand public, recommandation concrete, reference (ANSSI / CIS / OWASP).

## 5. Phases d'implementation

| Phase | Contenu | Validation |
|---|---|---|
| 0 | Socle : config, validation, models, resolver, httpclient, storage, scoring, audit, API + SPA minimale | tests socle verts, `/api/health` |
| 1 | Modules 3 (email) et 4 (DNS) | `example.com` : null MX, absence SPF/DMARC, DNSSEC |
| 2 | Modules 5 (crt.sh), 6 (InternetDB), 7 (TLS/en-tetes) | sous-domaines reels, caveat proxy MITM |
| 3 | Modules 1 (HIBP) et 2 (ransomware.live) | metadonnees seules, sanitisation prouvee |
| 4 | Modules 8 (dnstwist) et 9 (reputation) | permutations resolues, modules sans cle = skipped |
| 5 | Rapports HTML autonome + PDF, historique + comparaison de deux dates | exports ouvrables |
| 6 | README/SCORING, `docker compose up`, analyse de demo | demo de bout en bout |

## 6. Points a arbitrer

1. **Ponderations** du tableau ci-dessus : a confirmer ou ajuster.
2. **Cles API pour la demo live** : HIBP Domain Search (payante ~3,95 $/mois), Shodan, VirusTotal,
   AbuseIPDB, URLhaus (gratuite mais desormais obligatoire). Sans cle, ces modules s'affichent
   "desactive — cle absente". Je peux les recevoir via un formulaire securise (jamais dans le chat,
   jamais dans le code) si tu veux les tester en reel.
3. **Rétention** : cache 24 h (impose), journal d'audit 365 jours + commande de purge RGPD — a confirmer.
4. **Cible de demo** : `example.com` (reserve IANA, donc licite) ; un domaine dont tu es proprietaire
   donnerait une demo bien plus parlante.
