# Suivi interne

Ce répertoire reçoit les rapports produits par `python -m app export`. Il est
organisé par domaine, puis par date :

```
suivi/
├── hci-pve.cloud/
│   ├── 2026-11-19-1942-rapport.html
│   └── 2026-11-19-1942-rapport.pdf
└── client-exemple.fr/
    └── 2026-11-02-0915-rapport.pdf
```

## Son contenu n'est pas versionné, et ce n'est pas un oubli

Le `.gitignore` exclut tout ce qui se trouve ici, à l'exception de ce fichier.
**Seule la convention voyage avec le code ; les rapports restent sur votre
machine.**

Un rapport d'exposition liste les faiblesses exploitables d'une organisation :
enregistrements de messagerie défaillants, échéances de domaine, adresses IP,
serveurs de messagerie, versions logicielles. C'est, littéralement, le document
qu'un attaquant rédigerait avant de viser la cible. Publié dans un dépôt — même
retiré ensuite, l'historique Git le conserve — il devient un mode d'emploi
permanent et indexable.

## Si vous voulez malgré tout les versionner

Deux conditions, cumulatives :

1. **Un dépôt privé**, distinct de celui du code. Un dépôt public est exclu.
2. **Un chiffrement au repos** si le dépôt est hébergé chez un tiers :
   `git-crypt` ou `age` sur ce répertoire, afin que l'hébergeur lui-même ne
   puisse pas les lire.

Dans ce cas, retirez les lignes `/suivi/` du `.gitignore` et documentez la
décision ici même, avec sa date et son auteur.

## Conservation

Ces rapports contiennent des données à caractère personnel lorsque le module de
fuites a tourné avec un domaine vérifié : adresses masquées, volumétrie par
service. Fixez une durée de conservation cohérente avec votre registre de
traitements, et purgez. La base applicative, elle, est purgeable par
`python -m app purge`.
