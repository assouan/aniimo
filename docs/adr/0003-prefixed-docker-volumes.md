# ADR 0003 — Volumes Docker nommés et préfixés

- Statut : superseded by `0005-capture-analyzer-input-boundary.md`
- Date : 2026-10-16

Cette décision est conservée pour l'historique. La topologie et le préfixe applicables sont ceux de l'ADR 0005.

## Contexte

SQLite, les projets Ghidra et des centaines de milliers de petits fichiers fonctionnent mal sur un bind mount Windows. L'ancien prototype a aussi produit plusieurs dizaines de Gio d'artefacts et de temporaires.

## Décision

Utiliser cinq volumes nommés : `state`, `objects`, `ghidra`, `cache` et `work`. Leurs noms sont préfixés par `ANIIMO_VOLUME_PREFIX`, par défaut `aniimo_modkit`. `output` reste un bind mount lisible par l'utilisateur ; les entrées du jeu et le manifeste Steam sont des bind mounts en lecture seule.

Les valeurs initiales sont 32 Gio de RAM pour le conteneur, 24 Gio de heap Ghidra et 12 CPU. Elles sont configurables et validées par `doctor`.

## Conséquences

- Les performances et verrous ne dépendent pas du partage NTFS.
- `work` peut être purgé indépendamment des preuves.
- Une commande d'export/import d'état sera nécessaire pour les sauvegardes.
- `.dockerignore` est une barrière obligatoire contre l'inclusion du lot local de 22 Gio.
