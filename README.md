# DomainExposure

**Évaluation de l'exposition cyber d'une organisation à partir d'un simple nom de
domaine.** L'outil agrège des sources ouvertes pour produire un score, une note de
A à F et un rapport exploitable par un comité de direction comme par une équipe
technique : fuites de données, revendications de rançongiciel, hygiène de la
messagerie et du DNS, surface exposée, TLS et en-têtes HTTP, typosquatting,
réputation.

Application locale : un conteneur, une page web, une base SQLite. Aucune donnée ne
quitte votre machine, hormis les requêtes adressées aux sources OSINT publiques.

---

## ⚠️ Cadre d'utilisation — à lire avant toute analyse

DomainExposure est un outil d'**audit passif**. Il est conçu pour qu'un
professionnel évalue l'exposition d'un domaine **qu'il administre ou pour lequel il
dispose d'un mandat**.

**Avant chaque analyse, deux cases doivent être cochées :**

1. *Je dispose d'une autorisation du propriétaire de ce domaine ou j'agis dans un
   cadre contractuel.*
2. *Je comprends que cette analyse se limite à de la collecte passive de sources
   ouvertes.*

La date, l'opérateur, le domaine et l'état exact des cases sont inscrits dans un
**journal d'audit** à chaque lancement — y compris lorsque l'analyse est refusée
faute de consentement. Voir la section [Cadre légal](#cadre-légal).

### Ce que l'outil ne fait jamais

| Interdit | Pourquoi |
|---|---|
| Balayage de ports, test de vulnérabilité actif | Sollicitation directe des systèmes de la cible |
| Tentative d'authentification, force brute | Idem, et constitutif d'une infraction |
| Transfert de zone DNS (AXFR) | Requête directe aux serveurs de la cible ; le rapport explique comment le vérifier soi-même |
| Énumération des versions TLS acceptées | Exigerait des dizaines de connexions forcées |
| Récupération de mots de passe, d'empreintes ou de dumps | Hors la loi et hors sujet : seules les **métadonnées** de fuite sont collectées |
| Aspiration de forums ou de places de marché | Seules des API officielles sont utilisées |

Les seuls échanges avec l'infrastructure analysée sont des **résolutions DNS
publiques** et, pour le module TLS, **une requête web standard sur la page
d'accueil** — exactement ce que fait un navigateur.

### Protection des données personnelles

- Aucun mot de passe, empreinte, jeton ou donnée personnelle en clair n'est
  récupéré, stocké ni affiché. Deux barrières l'appliquent : une liste blanche de
  champs par source, puis un nettoyage récursif de tout résultat avant stockage.
- Les adresses email éventuellement remontées sont **masquées** (`j***@domaine.fr`)
  et ne sont recherchées que si la case « domaine vérifié auprès de Have I Been
  Pwned » est cochée.
- Les adresses des sites de fuite (`.onion`) ne sont jamais enregistrées : seule
  l'existence d'une revendication est signalée.

---

## Installation

### Avec Docker (recommandé)

```bash
git clone <votre-dépôt> domainexposure && cd domainexposure
```

```bash
cp .env.example .env
```

```bash
docker compose up -d --build
```

L'interface est disponible sur <http://127.0.0.1:8080>.

Le service n'est publié que sur la boucle locale : l'application n'a pas
d'authentification, il ne faut donc pas l'exposer directement sur un réseau. Pour
un accès partagé, placez-la derrière un reverse proxy authentifié.

```bash
docker compose logs -f      # journaux
docker compose down         # arrêt
```

Les données (cache, analyses, journal d'audit) sont conservées dans le volume
nommé `domainexposure-data`. Pour y accéder directement depuis l'hôte, voyez le
commentaire dans `docker-compose.yml`.

### Sans Docker

Python 3.12 ou plus récent est requis.

```bash
python3.12 -m venv .venv && source .venv/bin/activate
```

```bash
pip install -r requirements.txt
```

```bash
cp .env.example .env && python -m app
```

L'export PDF repose sur WeasyPrint, qui a besoin de bibliothèques système. Sous
Debian ou Ubuntu :

```bash
sudo apt install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfribidi0 libcairo2 libgdk-pixbuf-2.0-0
```

Si elles manquent, l'application démarre quand même : seul l'export PDF est
désactivé, avec un message explicite. L'export HTML autonome reste disponible.

### Ligne de commande

```bash
python -m app serve              # démarre le serveur (comportement par défaut)
```

```bash
python -m app analyse exemple.fr # analyse ponctuelle, résultat affiché au terminal
```

```bash
python -m app purge              # purge le cache expiré et le journal d'audit
```

---

## Configuration

Tous les réglages se font dans `.env` (modèle commenté dans `.env.example`).

| Variable | Défaut | Rôle |
|---|---|---|
| `HOST`, `PORT` | `127.0.0.1`, `8080` | Écoute du serveur |
| `OPERATOR` | `operateur-local` | Identité inscrite dans le journal d'audit |
| `DB_PATH` | `data/domainexposure.db` | Base SQLite |
| `CACHE_TTL_HOURS` | `24` | Durée de vie du cache des réponses d'API |
| `AUDIT_RETENTION_DAYS` | `365` | Conservation du journal d'audit |
| `DNS_BACKEND` | `auto` | `system`, `doh` ou `auto` (bascule automatique) |
| `HTTP_TIMEOUT`, `HTTP_RETRIES` | `15.0`, `3` | Délais et nouvelles tentatives |
| `TYPO_MAX_PERMUTATIONS` | `200` | Variantes testées par le module typosquatting |
| `SUBDOMAIN_RESOLVE_LIMIT` | `150` | Sous-domaines résolus après dédoublonnage |

### Clés d'API

**Aucune clé n'est obligatoire.** Chaque module dont la clé manque se désactive
proprement, l'indique dans le rapport, et sort du calcul du score.

| Source | Variable | Tarif | Obtention | Apport |
|---|---|---|---|---|
| Have I Been Pwned | `HIBP_API_KEY` | Payant (≈ 3,95 $/mois) | <https://haveibeenpwned.com/API/Key> | Recherche des **comptes du domaine** présents dans des fuites. Sans clé, les fuites ayant touché le site restent listées via l'endpoint public. |
| Shodan | `SHODAN_API_KEY` | Payant (licence à vie fréquemment en promotion) | <https://account.shodan.io> | Détail par service. Sans clé, **Shodan InternetDB** fournit déjà ports, CVE connues et étiquettes, gratuitement et sans authentification. |
| VirusTotal | `VIRUSTOTAL_API_KEY` | Gratuit (4 requêtes/minute) | <https://www.virustotal.com/gui/my-apikey> | Réputation du domaine auprès de dizaines de moteurs |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | Gratuit (1 000 requêtes/jour) | <https://www.abuseipdb.com/account/api> | Signalements d'abus sur les adresses IP |
| URLhaus (abuse.ch) | `URLHAUS_AUTH_KEY` | Gratuit, **désormais obligatoire** | <https://auth.abuse.ch> | URL de distribution de logiciels malveillants hébergées sur le domaine |
| LeakCheck | `LEAKCHECK_API_KEY` | Payant | <https://leakcheck.io> | Seconde base de fuites, en métadonnées |
| Intelligence X | `INTELX_API_KEY` | Payant | <https://intelx.io> | Volumétrie des sélecteurs indexés |

> **Shodan et les en-têtes.** Shodan s'authentifie par paramètre d'URL (`?key=`)
> et non par en-tête HTTP : la clé doit figurer dans `.env`, elle ne peut pas être
> injectée par un proxy d'entreprise.

> **LeakCheck et Intelligence X** sont implémentés en mode « métadonnées
> uniquement » et validés par des tests à réponses simulées, faute de clé
> disponible lors du développement : vérifiez leur comportement avant de vous y
> fier en production.

---

## Modules d'analyse

| # | Module | Poids | Sources | Clé requise |
|---|---|---:|---|---|
| 1 | Fuites de données | 15 | Have I Been Pwned, LeakCheck, Intelligence X | non (partiel) |
| 2 | Ransomware | 10 | ransomware.live | non |
| 3 | Hygiène email | 20 | DNS (MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI) | non |
| 4 | Hygiène DNS | 10 | DNS (DNSSEC, NS, CAA), empreintes de reprise de sous-domaine | non |
| 5 | Sous-domaines | 5 | crt.sh (Certificate Transparency) | non |
| 6 | Services exposés | 15 | Shodan InternetDB, API Shodan | non (partiel) |
| 7 | TLS & en-têtes HTTP | 15 | Poignée de main TLS, requête web standard | non |
| 8 | Typosquatting | 5 | dnstwist + résolution DNS | non |
| 9 | Réputation | 5 | VirusTotal, URLhaus, AbuseIPDB | oui |

Chaque module expose la même interface (`app/modules/<nom>.py`) :

```python
KEY: str                 # identifiant stable
WEIGHT: int              # poids dans le score global
DEPENDS_ON: tuple[str]   # modules dont il réutilise le résultat
TIMEOUT: float           # délai maximal
async def run(ctx: ModuleContext) -> ModuleResult
```

Les modules s'exécutent en parallèle par vagues : ceux qui déclarent une
dépendance (`exposure` et `dns` dépendent de `subdomains`) attendent la vague
précédente. Un module en échec, trop lent ou sans clé n'interrompt jamais
l'analyse.

---

## Utilisation

### Interface web

Saisissez un domaine, cochez les cases obligatoires, lancez l'analyse. La
progression s'affiche module par module en temps réel (flux SSE). Le tableau de
bord présente le score, la répartition des constats, le détail par module, la
chronologie des fuites, les sous-domaines et les CVE.

Chaque constat est présenté en trois temps : **le constat technique**, **ce que
cela signifie** en français courant, et **la recommandation**, accompagnée de ses
références (ANSSI, CIS, OWASP, RFC).

### Rapports

- **HTML autonome** : un seul fichier, sans ressource externe ni script, avec page
  de garde, synthèse exécutive, détails techniques et annexe des sources.
- **PDF** : même contenu, mis en page pour l'impression (WeasyPrint).

### Historique et comparaison

Toutes les analyses sont conservées. Sélectionnez-en deux pour obtenir l'évolution
du score, les constats apparus, résolus et persistants.

### API

| Méthode | Route | Rôle |
|---|---|---|
| `GET` | `/api/health` | État du service |
| `GET` | `/api/modules` | Modules, poids, état des clés, barème |
| `POST` | `/api/analyses` | Lance une analyse (consentements obligatoires) |
| `GET` | `/api/analyses/{id}/stream` | Flux d'événements SSE |
| `GET` | `/api/analyses/{id}` | Rapport complet au format JSON |
| `GET` | `/api/analyses?domain=` | Historique |
| `GET` | `/api/compare?a=&b=` | Comparaison de deux analyses |
| `GET` | `/api/analyses/{id}/report.html` | Rapport HTML autonome |
| `GET` | `/api/analyses/{id}/report.pdf` | Rapport PDF |
| `GET` | `/api/audit` | Journal d'audit |

Documentation interactive : <http://127.0.0.1:8080/api/docs>.

```bash
curl -X POST http://127.0.0.1:8080/api/analyses \
  -H 'content-type: application/json' \
  -d '{"domain":"exemple.fr","authorization":true,"passive_only":true}'
```

---

## Score et note

Le score va de 0 à 100 et se traduit en note de A à F. La méthode complète — poids
de chaque module, pénalités par gravité, renormalisation des modules désactivés,
plafonnement en présence d'un constat critique — est documentée dans
**[SCORING.md](SCORING.md)**.

---

## Limites connues

- **crt.sh est fréquemment saturé.** La requête d'historique complet répond
  souvent en 502. Le module tente alors la variante restreinte aux certificats
  valides et signale que l'historique est incomplet.
- **Derrière un proxy HTTPS d'entreprise, l'inspection du certificat est
  impossible** : le proxy termine la connexion TLS. Le module le détecte, le
  signale comme limite d'environnement — et non comme défaut du domaine — et
  poursuit l'analyse des en-têtes.
- **Les sélecteurs DKIM sont arbitraires.** L'outil teste une cinquantaine de
  sélecteurs répandus : ne rien trouver ne prouve pas l'absence de DKIM, et le
  rapport le précise.
- **Derrière un CDN ou un hébergement mutualisé**, les ports et vulnérabilités
  observés appartiennent au fournisseur. Le module le détecte et ne les impute pas
  à l'organisation, mais l'infrastructure d'origine reste alors invisible.
- **La reprise de sous-domaine n'est jamais confirmée.** L'outil signale un CNAME
  orphelin vers un service tiers ; confirmer exigerait de réclamer la ressource,
  ce qui serait une action intrusive.
- **Le typosquatting est échantillonné.** dnstwist génère près de 2 000 variantes
  pour un domaine court, dont une écrasante majorité d'homoglyphes. L'outil teste
  en priorité les familles les plus exploitées en hameçonnage, dans la limite de
  `TYPO_MAX_PERMUTATIONS`.
- **Si le DNS ne répond pas du tout**, les modules concernés s'abstiennent au lieu
  de conclure à une absence de configuration.

---

## Cadre légal

### Autorisation préalable

En droit français, l'**article 323-1 du Code pénal** réprime « le fait d'accéder ou
de se maintenir, frauduleusement, dans tout ou partie d'un système de traitement
automatisé de données » (jusqu'à trois ans d'emprisonnement et 100 000 € d'amende).
La consultation de sources ouvertes ne constitue pas en elle-même un accès
frauduleux, mais la frontière se déplace dès qu'un outil sollicite directement les
systèmes d'un tiers. DomainExposure s'interdit donc toute sollicitation active, et
exige une attestation d'autorisation qu'il journalise.

La jurisprudence rappelle par ailleurs que le maintien dans un système dont l'accès
est ouvert par négligence reste répréhensible dès lors que son caractère non public
est manifeste. **En cas de doute, demandez une autorisation écrite.**

### RGPD

Les analyses portent sur des infrastructures, mais certains résultats constituent
des **données à caractère personnel** : adresses email professionnelles, noms
d'hôtes nominatifs, entrées du journal d'audit (opérateur, adresse IP).

- **Base légale** : l'intérêt légitime (article 6.1.f) couvre la sécurisation d'un
  système d'information que vous exploitez ou auditez sous mandat. Documentez ce
  mandat.
- **Minimisation** (article 5.1.c) : l'outil ne collecte que des métadonnées et
  masque les adresses ; ne cochez la case « domaine vérifié » que si vous en avez
  besoin.
- **Limitation de conservation** (article 5.1.e) : cache de 24 h, journal d'audit
  de 365 jours par défaut (`AUDIT_RETENTION_DAYS`), purge par
  `python -m app purge`.
- **Sécurité** (article 32) : un rapport décrit la surface d'attaque d'une
  organisation. Traitez-le comme un document confidentiel.
- Si une fuite vous concernant est découverte, les obligations de notification
  (articles 33 et 34) s'appliquent : CNIL sous 72 heures, et information des
  personnes concernées en cas de risque élevé.

### Conditions d'utilisation des sources

Chaque source a ses propres conditions et quotas. L'outil applique un délai minimal
entre deux appels à une même source, respecte l'en-tête `Retry-After` et met les
réponses en cache 24 heures. Avant un usage commercial ou intensif, vérifiez les
conditions de Have I Been Pwned, Shodan, VirusTotal, abuse.ch, AbuseIPDB,
ransomware.live et crt.sh.

---

## Développement

```bash
pip install -e ".[dev]"
```

```bash
pytest
```

```bash
ruff check app tests
```

La suite couvre la validation, le scoring, la sanitisation, la persistance, le
client HTTP, l'orchestrateur, l'API, les rapports et **chacun des neuf modules**,
avec des réponses d'API simulées (`respx`) et un résolveur DNS déterministe :
aucun test ne dépend du réseau.

### Arborescence

```
app/
├── main.py            API FastAPI, flux SSE, exports
├── orchestrator.py    Vagues d'exécution, scoring, persistance
├── modules/           Les neuf modules d'analyse
├── report/            Rendu HTML autonome et PDF
├── static/            Interface monopage (Tailwind via CDN, JS natif)
├── resolver.py        Résolution DNS : système ou DNS-over-HTTPS
├── httpclient.py      Cache 24 h, politesse, nouvelles tentatives
├── sanitize.py        Masquage et suppression des champs sensibles
├── scoring.py         Pondérations et barème
└── storage.py         SQLite : analyses, cache, journal d'audit
```

---

## Licence

MIT. Voir [LICENSE](LICENSE).
