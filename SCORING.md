# Méthode de notation

Ce document décrit intégralement le calcul du score et de la note produits par
DomainExposure. Il est volontairement explicite : un score d'exposition n'a de
valeur que si la méthode qui le produit est vérifiable.

## 1. Principe

Chaque module d'analyse produit des *constats* (findings). Chaque constat porte une
gravité. Le score d'un module part de 100 et décroît avec les constats relevés. Le
score global est la moyenne des scores de modules, pondérée par l'importance de
chaque module, et **renormalisée sur les seuls modules ayant produit un résultat**.

## 2. Gravités et pénalités

| Gravité | Pénalité | Signification |
|---|---|---|
| Critique | 40 | Exploitation directe possible, ou protection annulée dans son principe |
| Élevé | 25 | Faiblesse exploitable moyennant un effort modéré |
| Moyen | 10 | Défaut de configuration à corriger, sans exploitation immédiate |
| Faible | 4 | Écart aux bonnes pratiques, impact limité |
| Info | 0 | Observation, point de contexte ou bonne pratique constatée |

Les constats « Info » ne pénalisent jamais le score : ils documentent le contexte
(bonne pratique en place, limite méthodologique, dépendance tierce identifiée).

## 3. Score d'un module

```
score_module = max(0, min(100, 100 − Σ pénalités des constats du module))
```

Le score est borné à `[0, 100]` : un module cumulant trois constats critiques
tombe à 0 et n'y descend pas davantage.

**Exemple.** Le module « Hygiène email » relève un constat critique (deux
enregistrements SPF), un élevé (pas de DMARC), un moyen (aucun sélecteur DKIM) et
deux faibles (MTA-STS et TLS-RPT absents) :

```
100 − (40 + 25 + 10 + 4 + 4) = 17
```

## 4. Poids des modules

| Module | Poids | Pourquoi ce poids |
|---|---:|---|
| Hygiène email | 20 | L'usurpation d'adresse est le vecteur d'attaque initial le plus courant, et la configuration est entièrement sous le contrôle de l'organisation |
| Services exposés | 15 | Un service d'administration ou une base de données joignable depuis Internet est une porte d'entrée directe |
| TLS & en-têtes HTTP | 15 | Protège les échanges et les sessions des utilisateurs ; défauts très répandus |
| Fuites de données | 15 | Une fuite avérée a des conséquences immédiates sur les comptes et sur la conformité |
| Ransomware | 10 | Signal fort mais binaire : une revendication publique est rare et grave |
| Hygiène DNS | 10 | Socle de confiance de tous les autres services (DNSSEC, délégations, reprise de sous-domaine) |
| Sous-domaines | 5 | Mesure d'une surface d'attaque, rarement une faiblesse en soi |
| Typosquatting | 5 | Risque réel de hameçonnage, mais partiellement hors du contrôle de l'organisation |
| Réputation | 5 | Indicateur de conséquence plutôt que de cause |
| **Total** | **100** | |

## 5. Score global

Seuls les modules ayant produit un résultat exploitable (statut `exploité` ou
`partiellement exploité`) entrent dans le calcul :

```
score_global = round( Σ (score_module × poids_module) / Σ poids_module )
```

La somme porte uniquement sur les modules actifs. **Un module désactivé — clé API
absente, source indisponible, domaine non résolu — n'est ni pénalisant ni
avantageux** : il quitte simultanément le numérateur et le dénominateur. Sans cette
renormalisation, l'absence d'une clé gratuite ferait mécaniquement chuter la note,
ce qui n'aurait aucun sens au regard du risque réel.

## 6. Plafonnement par constat critique

Si au moins un constat critique est relevé, quel que soit le module, le score
global est plafonné à **69**, soit la note D au mieux :

```
si un constat critique existe : score_global = min(score_global, 69)
```

Sans ce plafond, une organisation très bien notée partout ailleurs pourrait
afficher un A tout en laissant une base de données ouverte sur Internet. Le
rapport indique explicitement quand ce plafonnement s'applique.

## 7. Barème des notes

| Note | Score | Lecture |
|---|---|---|
| A | 90 – 100 | Exposition maîtrisée |
| B | 80 – 89 | Bonne hygiène d'ensemble, correctifs mineurs |
| C | 70 – 79 | Défauts de configuration à corriger |
| D | 60 – 69 | Exposition préoccupante, actions correctives attendues |
| E | 50 – 59 | Exposition élevée, traitement prioritaire |
| F | 0 – 49 | Exposition critique, traitement immédiat |

## 8. Exemple complet

Analyse réelle du domaine de démonstration `hci-pve.cloud` :

| Module | Score | Poids | Contribution |
|---|---:|---:|---:|
| Hygiène email | 17 | 20 | 340 |
| Hygiène DNS | 82 | 10 | 820 |
| Sous-domaines | 100 | 5 | 500 |
| TLS & en-têtes HTTP | 80 | 15 | 1 200 |
| Fuites de données | 100 | 15 | 1 500 |
| Ransomware | 100 | 10 | 1 000 |
| Typosquatting | 100 | 5 | 500 |
| Services exposés | 100 | 15 | 1 500 |
| Réputation | désactivé | — | exclu |

```
Σ contributions = 7 360
Σ poids actifs  = 95          (100 − 5 pour le module Réputation désactivé)
score brut      = 7 360 / 95 = 77,5 → 77
plafonnement    = un constat critique (deux SPF) → 69
note            = D
```

## 9. Ce que le score ne dit pas

- **Il mesure une exposition observable de l'extérieur**, pas le niveau de sécurité
  interne : ni la gestion des correctifs, ni les sauvegardes, ni la sensibilisation
  des équipes, ni la segmentation du réseau n'entrent dans ce calcul.
- **L'absence de constat n'est pas une preuve d'absence de risque.** Une source
  consultée peut simplement ne rien référencer.
- **Un score élevé obtenu avec peu de modules actifs est moins significatif.** Le
  rapport indique toujours combien de modules ont été exploités.
- **Les pondérations sont un choix d'auteur**, cohérent avec les vecteurs d'attaque
  les plus fréquents, mais à adapter au contexte : elles se modifient dans
  `app/scoring.py` (`MODULE_WEIGHTS`), et la somme doit rester égale à 100.
