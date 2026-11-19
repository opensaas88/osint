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

```bash
python -m app export exemple.fr  # range le rapport dans le suivi interne
```

---

## Configuration

Tous les réglages se font dans `.env` (modèle commenté dans `.env.example`).

| Variable | Défaut | Rôle |
|---|---|---|
| `HOST`, `PORT` | `127.0.0.1`, `8080` | Écoute du serveur |
| `OPERATOR` | `operateur-local` | Identité inscrite dans le journal d'audit |
| `DB_PATH` | `data/domainexposure.db` | Base SQLite |
| `REPORTS_DIR` | `suivi` | Répertoire d'export des rapports, exclu du dépôt |
| `CACHE_TTL_HOURS` | `24` | Durée de vie du cache des réponses d'API |
| `AUDIT_RETENTION_DAYS` | `365` | Conservation du journal d'audit |
| `DNS_BACKEND` | `auto` | `system`, `doh` ou `auto` (bascule automatique) |
| `HTTP_TIMEOUT`, `HTTP_RETRIES` | `15.0`, `3` | Délais et nouvelles tentatives |
| `RATE_LIMITS_ENABLED` | `true` | Délai minimal entre deux appels à une même source. À ne désactiver qu'en test : il protège les quotas des fournisseurs |
| `BRAND_NAME`, `BRAND_COLOR` | `DomainExposure`, bleu | Identité affichée |
| `BRAND_LOGO_PATH`, `BRAND_FOOTER` | — | Logo incorporé et mention de pied de page |
| `SCHEDULER_ENABLED` | `true` | Analyses planifiées du portefeuille |
| `SCHEDULER_TICK_SECONDS` | `300` | Fréquence de vérification des échéances |
| `SCHEDULER_CONCURRENCY` | `2` | Analyses planifiées menées en parallèle |
| `ALERT_SCORE_DROP` | `5` | Baisse de score déclenchant une alerte |
| `SMTP_HOST`, `SMTP_PORT`… | — | Serveur d'envoi des alertes par courriel |
| `TYPO_MAX_PERMUTATIONS` | `200` | Variantes testées par le module typosquatting |
| `SUBDOMAIN_RESOLVE_LIMIT` | `150` | Sous-domaines résolus après dédoublonnage |

### Clés d'API

**Aucune clé n'est obligatoire.** Chaque module dont la clé manque se désactive
proprement, l'indique dans le rapport, et sort du calcul du score.

| Source | Variable | Tarif | Obtention | Apport |
|---|---|---|---|---|
| Have I Been Pwned | `HIBP_API_KEY` | Payant | <https://haveibeenpwned.com/API/Key> | Recherche des **comptes du domaine** présents dans des fuites, et **journaux d'infostealers** (palier « Pro »). Sans clé, les fuites ayant touché le site restent listées via l'endpoint public. |
| Shodan | `SHODAN_API_KEY` | Payant (licence à vie fréquemment en promotion) | <https://account.shodan.io> | Détail par service. Sans clé, **Shodan InternetDB** fournit déjà ports, CVE connues et étiquettes, gratuitement et sans authentification. |
| VirusTotal | `VIRUSTOTAL_API_KEY` | Gratuit (4 requêtes/minute) | <https://www.virustotal.com/gui/my-apikey> | Réputation du domaine auprès de dizaines de moteurs |
| Google Safe Browsing | `SAFEBROWSING_API_KEY` | Gratuit | <https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com> | La liste que consultent Chrome, Firefox et Safari : un client peut vérifier le constat lui-même en trois secondes |
| GitHub | `GITHUB_SEARCH_TOKEN` | Gratuit | <https://github.com/settings/tokens> | Recherche de code public : fichiers citant votre domaine à côté de mots-clés d'identifiants |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | Gratuit (1 000 requêtes/jour) | <https://www.abuseipdb.com/account/api> | Signalements d'abus sur les adresses IP |
| URLhaus (abuse.ch) | `URLHAUS_AUTH_KEY` | Gratuit, **désormais obligatoire** | <https://auth.abuse.ch> | URL de distribution de logiciels malveillants hébergées sur le domaine |
| LeakCheck | `LEAKCHECK_API_KEY` | Payant | <https://leakcheck.io> | Seconde base de fuites, en métadonnées |
| Intelligence X | `INTELX_API_KEY` | Payant | <https://intelx.io> | Volumétrie des sélecteurs indexés |

> **Recherches par domaine chez HIBP.** Le Domain Search et les journaux
> d'infostealers exigent, en plus de la clé, que le domaine soit **ajouté et
> vérifié dans le tableau de bord de recherche par domaine** de Have I Been Pwned
> (enregistrement DNS TXT ou courriel). Sans cette vérification, l'API répond 403 —
> l'outil l'indique alors explicitement. Les journaux d'infostealers relèvent du
> palier « Pro ».

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
| 1 | Fuites de données | 15 | Have I Been Pwned (fuites, Domain Search, journaux d'infostealers), recherche de code public GitHub, LeakCheck, Intelligence X | non (partiel) |
| 2 | Ransomware | 10 | ransomware.live | non |
| 3 | Hygiène email | 20 | DNS (MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI) | non |
| 4 | Hygiène DNS | 10 | RDAP (expiration et verrou du domaine), DNS (DNSSEC, NS, CAA), empreintes de reprise de sous-domaine | non |
| 5 | Sous-domaines | 5 | crt.sh (Certificate Transparency, expiration des certificats) | non |
| 6 | Services exposés | 15 | Shodan InternetDB, API Shodan, RDAP des registres d'adresses | non (partiel) |
| 7 | TLS & en-têtes HTTP | 15 | Poignée de main TLS, requête web standard | non |
| 8 | Typosquatting | 5 | dnstwist + résolution DNS | non |
| 9 | Réputation | 5 | VirusTotal, URLhaus, AbuseIPDB, Google Safe Browsing | oui |

### Secrets dans le code public (module 1)

La façon la plus courante dont une clé d'API fuite est un fichier de configuration
versionné par inadvertance. Le module interroge la recherche de code GitHub pour les
fichiers publics citant votre domaine à côté de « password » ou « api_key ».

**Le contenu des fichiers n'est jamais récupéré.** L'en-tête `text-match`, qui
renverrait les extraits contenant l'identifiant, n'est pas utilisé : signaler une
fuite ne doit pas conduire l'outil à détenir lui-même le secret. Seuls le dépôt, le
chemin et le lien sont conservés — de quoi aller vérifier.

**Un seuil de bruit à 200 résultats.** Mesuré en conditions réelles : la requête
`"example.com" password` renvoie plus de **onze millions** de fichiers, pour la simple
raison que ce domaine sert d'exemple dans la documentation du monde entier. Au-delà du
seuil, le constat devient informatif et ne pénalise pas le score : annoncer onze
millions de fichiers comme une fuite d'identifiants serait spectaculaire et vide.

> La variable s'appelle `GITHUB_SEARCH_TOKEN` et non `GITHUB_TOKEN` : cette dernière
> est exportée par beaucoup d'environnements pour la CLI `gh`, et l'outil capterait
> alors silencieusement un jeton que vous ne lui avez pas destiné.

### Journaux d'infostealers (module 1)

Un logiciel voleur d'identifiants s'exécute sur le poste d'une personne et transmet
ce qu'elle saisit dans son navigateur. C'est un signal bien plus direct qu'une fuite
chez un prestataire : la machine elle-même a été compromise, et les cookies de
session volés permettent de contourner l'authentification multifacteur.

Deux angles sont interrogés, sous les mêmes conditions que le Domain Search (clé
« Pro » et domaine vérifié) :

| Angle | Endpoint | Ce que cela révèle |
|---|---|---|
| Domaine de messagerie | `/stealerLogsByEmailDomain/{domaine}` | Vos collaborateurs dont les identifiants ont été capturés, et les services concernés — gravité **critique** |
| Site web | `/stealerLogsByWebsiteDomain/{domaine}` | Vos utilisateurs qui saisissaient leurs identifiants sur votre site au moment de l'infection — gravité **élevée** |

Les alias et adresses sont **masqués** ; seuls la volumétrie, la répartition par
fournisseur de messagerie et les **domaines des services concernés** (qui ne sont
pas des données personnelles, et qui indiquent quels accès renouveler) sont
conservés. La liste nominative, nécessaire pour notifier les personnes, reste dans
votre tableau de bord Have I Been Pwned.

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

### Plan de remédiation et projection de score

Le rapport ne se contente pas de constater : il chiffre ce que la correction rapporte.
Chaque action est classée par gain de score et par effort estimé, et le plan affiche
le niveau atteint à chaque étape.

```
  1. +14 → 83/B   moins d'une heure   Fusionner les deux enregistrements SPF
  2.  +6 → 89/B   moins d'une heure   Publier une politique DMARC
  3.  +2 → 91/A   moins d'une heure   Renouveler le nom de domaine
```

Deux notions distinctes apparaissent dans le rapport :

- le **gain isolé** : ce que rapporterait la correction si elle était la seule menée ;
- le **gain marginal** : ce qu'elle apporte réellement à sa place dans le plan.

Les deux diffèrent dès qu'un constat critique plafonne la note : lever ce constat
débloque d'un coup tous les points retenus par le plafond. C'est le gain marginal qui
est affiché en priorité, car c'est lui qui décrit la progression réelle.

L'effort est une estimation **paramétrable** dans `app/remediation.py` : un prestataire
qui déploie DNSSEC en vingt minutes ajuste la table à son contexte.

### Conséquences métier

Chaque constat porte, en plus de son explication technique, **ce qu'il implique
concrètement pour l'organisation et qui le subit** :

> **2 enregistrements SPF publiés au lieu d'un seul**
> *Un tiers peut envoyer des emails qui semblent venir de votre entreprise : fausse
> facture, changement de coordonnées bancaires, demande urgente au nom d'un dirigeant.
> Vos interlocuteurs n'ont aucun moyen de s'en apercevoir. Concerne vos clients, vos
> fournisseurs et votre comptabilité.*

Ces formulations sont centralisées dans `app/impacts.py` et **ne contiennent aucun
chiffre** : une statistique citée de mémoire se démonétise au premier contrôle. Les
renvois pointent vers Cybermalveillance.gouv.fr et la CNIL, où le lecteur trouvera
les données à jour.

### Évolution du score

Dès la deuxième analyse d'un domaine, une courbe retrace son évolution — dans
l'interface comme dans le rapport. L'échelle verticale est **fixée de 0 à 100** et
jamais ajustée aux données : un cadrage automatique transformerait une variation de
deux points en falaise.

### Marque blanche

Le rapport et l'interface portent votre identité : nom, couleur d'accent, logo et
mention de pied de page (`BRAND_NAME`, `BRAND_COLOR`, `BRAND_LOGO_PATH`,
`BRAND_FOOTER`).

Le logo est **incorporé en base64** dans le rapport, qui reste donc un fichier
autonome, lisible hors ligne et transmissible tel quel. Et la marque n'habille que
les accents : **les couleurs de gravité ne sont jamais remplacées**, un constat
critique reste rouge chez tout le monde.

### Synthèse pour la direction

La première page du rapport est écrite pour un décideur, pas pour un administrateur :
le score, **les trois risques à retenir** formulés en conséquences concrètes, **les trois
actions prioritaires** avec leur effort, et la note qui serait atteinte en les traitant.
Le détail technique vient après.

### Rapports

- **HTML autonome** : un seul fichier, sans ressource externe ni script, avec page
  de garde, synthèse exécutive, détails techniques et annexe des sources.
- **PDF** : même contenu, mis en page pour l'impression (WeasyPrint).

### Portefeuille surveillé et analyses planifiées

Un domaine inscrit au portefeuille est réanalysé automatiquement — quotidiennement,
chaque semaine ou chaque mois — et le tableau de bord classe les domaines **du plus
exposé au moins exposé**, avec la tendance depuis l'analyse précédente.

| Client | Domaine | Score | Note | Tendance | Constats | Prochaine |
|---|---|---|---|---|---|---|
| Client A | exemple.fr | 40 | F | ▼ -20 | ◆ 1 ▲ 2 | demain |
| Client B | autre.fr | 95 | A | ▲ +5 | — | dans 6 j |

#### Le mandat permanent

Une analyse planifiée pose une difficulté : **personne ne coche de case au moment où
elle se déclenche**. La réponse retenue est le mandat permanent.

À l'inscription d'un domaine, l'opérateur atteste — avec les mêmes deux cases
obligatoires qu'une analyse ponctuelle — qu'il dispose d'une autorisation, et peut
joindre une référence contractuelle. Cette attestation est journalisée, puis **rappelée
dans le journal d'audit à chaque exécution automatique** :

```
analyse_planifiee  exemple.fr  operateur  « planifiee — mandat attesté par operateur
                                            le 2026-01-15, réf. contrat 42 »
```

Retirer le domaine du portefeuille révoque le mandat et arrête les analyses ; le retrait
est lui aussi journalisé.

#### Alertes de régression

Après chaque analyse planifiée, le résultat est comparé au précédent. Une alerte est
émise si :

- le score baisse d'au moins `ALERT_SCORE_DROP` points (5 par défaut) ;
- la note se dégrade ;
- un constat **critique** ou **élevé** apparaît, même à score constant ;
- la toute première analyse d'un domaine révèle un constat critique.

Une amélioration ne déclenche jamais d'alerte, et un constat résolu non plus.

Deux canaux, tous deux optionnels et indépendants.

**Webhook.** Le format est déduit de l'hôte de l'URL : chaque plateforme impose sa
propre structure, et poster le JSON brut de DomainExposure sur un webhook Slack
renvoie `invalid_payload`.

| Hôte détecté | Format émis | Où obtenir l'URL |
|---|---|---|
| `hooks.slack.com` | Block Kit (`text` + `blocks`) | Slack → application « Incoming Webhooks » → *Add New Webhook to Workspace* |
| `*.webhook.office.com` | MessageCard | Teams → canal → *Connecteurs* → *Webhook entrant* |
| `*.logic.azure.com` | Carte adaptative | Teams → canal → *Workflows* → *Publier dans un canal quand une requête webhook est reçue* |
| `discord.com/api/webhooks` | Embed coloré par gravité | Discord → paramètres du salon → *Intégrations* → *Webhooks* |
| tout autre hôte | JSON complet de l'alerte | n8n, Zapier, votre propre endpoint |

> **L'URL d'un webhook est un secret** : quiconque la détient peut publier dans votre
> canal. Saisissez-la dans le formulaire du portefeuille, jamais dans un ticket ou un
> message. Elle est stockée dans votre base SQLite locale, et seul l'**hôte** apparaît
> dans les journaux de l'application — jamais le jeton.

**Courriel.** Via votre serveur SMTP (`SMTP_HOST` et suivants). `SMTP_PASSWORD` est un
secret, à traiter comme tel.

Une notification en échec n'interrompt jamais l'analyse : l'échec est journalisé et
l'exécution se poursuit.

> **Un seul processus.** L'ordonnanceur tourne dans le processus applicatif. Avec
> plusieurs workers uvicorn, les analyses seraient dupliquées : la configuration livrée
> n'en utilise qu'un, et `SCHEDULER_ENABLED=false` désactive l'ordonnanceur sur les
> processus supplémentaires.

### Suivi interne

`python -m app export <identifiant | domaine>` range le rapport d'une analyse —
HTML autonome et PDF — dans un répertoire classé par domaine puis par date :

```
suivi/
├── README.md                     ← versionné : la convention d'usage
└── hci-pve.cloud/
    ├── 2026-11-19-0636-rapport.html
    └── 2026-11-19-0636-rapport.pdf   ← jamais versionnés
```

Avec un domaine, c'est la dernière analyse qui est exportée ; avec un identifiant,
celle-là précisément.

**Le contenu de ce répertoire est exclu du dépôt, et ce n'est pas un oubli.** Un
rapport d'exposition est le document qu'un attaquant rédigerait avant de viser la
cible : enregistrements de messagerie défaillants, échéances, adresses, serveurs.
Publié dans un dépôt — même retiré ensuite, l'historique Git le conserve — il
devient un mode d'emploi permanent.

Seule la convention voyage avec le code, dans `suivi/README.md`, qui décrit aussi
les deux conditions à réunir si vous choisissez malgré tout de versionner ces
rapports : un dépôt **privé**, et un chiffrement au repos (`git-crypt`, `age`).

Le répertoire se change avec `REPORTS_DIR`.

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
| `GET` | `/api/history?domain=` | Scores successifs et courbe d'évolution (SVG) |
| `GET` | `/api/impacts` | Conséquences métier documentées, par code de constat |
| `GET` | `/api/branding` | Identité visuelle appliquée |
| `GET` | `/api/watchlist` | Portefeuille consolidé et état de l'ordonnanceur |
| `POST` | `/api/watchlist` | Inscrit un domaine (mandat permanent obligatoire) |
| `PATCH` | `/api/watchlist/{id}` | Modifie périodicité, libellé, notifications |
| `DELETE` | `/api/watchlist/{id}` | Révoque le mandat et arrête le suivi |
| `POST` | `/api/watchlist/{id}/run` | Analyse immédiate, hors échéance |
| `GET` | `/api/analyses/{id}/plan` | Plan de remédiation : actions, effort, gain, score projeté |
| `POST` | `/api/analyses/{id}/simulate` | Score obtenu si les constats indiqués étaient corrigés |
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
- **La localisation de l'hébergement est indicative.** Le pays provient du registre
  d'adresses et peut désigner le siège de l'opérateur plutôt que l'emplacement réel
  des machines ; « EU » est une valeur générique du RIPE couvrant plusieurs pays. Les
  contacts nominatifs présents dans les fiches RDAP ne sont **jamais** conservés.
- **RDAP dépend du registre de l'extension.** `rdap.org` redirige vers le serveur du
  registre (`rdap.registry.cloud` pour `.cloud`, `rdap.afnic.fr` pour `.fr`…). Derrière
  un réseau filtrant, chacun de ces hôtes doit être joignable. Certains registres
  limitent aussi l'accès à leur service RDAP : le module le signale alors comme une
  limite, sans produire de constat.
- **L'expiration du renouvellement automatique n'est pas publique.** Un domaine qui
  expire dans cinq jours avec renouvellement automatique actif est sain : le constat
  le précise systématiquement plutôt que de crier au loup.
- **L'expiration des certificats de sous-domaines** se fonde sur les journaux de
  transparence, donc sur les certificats *émis* et non sur ceux réellement servis. Les
  seuils sont volontairement serrés (20 jours) pour ne pas alerter à chaque cycle de
  renouvellement automatique.

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
├── impacts.py         Conséquences métier par constat
├── chart.py           Courbe d'évolution du score (SVG)
├── branding.py        Marque blanche
├── watchlist.py       Portefeuille, mandat permanent, détection de régression
├── scheduler.py       Analyses planifiées
├── notify.py          Alertes par webhook et par courriel
├── remediation.py     Effort, gain et projection de score
├── scoring.py         Pondérations et barème
└── storage.py         SQLite : analyses, cache, journal d'audit
```

---

## Licence

MIT. Voir [LICENSE](LICENSE).
