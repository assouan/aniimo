# ADR 0001 — Capture immuable et stockage adressé par contenu

- Statut : accepted, amendé par ADR 0006
- Date : 2026-10-16

## Contexte

L'ancien lot a observé deux hashes complets différents de `GameAssembly.dll` pendant une même campagne, malgré des sections exécutables identiques. Une analyse directe du dossier Steam peut donc mélanger plusieurs états ou produire des rapports devenus faux lorsque le fichier vivant change.

## Décision

Le bind mount du jeu est lu uniquement par l'étape `capture`. Celle-ci vérifie le manifeste Steam, capture les entrées retenues dans le CAS et publie atomiquement un snapshot. Toutes les autres étapes utilisent ce snapshot. ADR 0006 remplace la double passe systématique par une lecture hachée avec contrôle avant/après et une seule nouvelle tentative en cas de dérive observée.

Les objets sont identifiés par SHA-256 brut. Les digests sémantiques servent uniquement aux décisions de cache documentées et ne remplacent jamais la provenance brute.

## Conséquences

- Un changement pendant la lecture échoue sans publication partielle.
- La première capture relit tous les octets du périmètre strict.
- Les builds suivants réutilisent les objets identiques.
- Le CAS nécessite une sauvegarde de manifests et un garbage collector conservateur.
