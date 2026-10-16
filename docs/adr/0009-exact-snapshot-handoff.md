# ADR 0009 — Remise exacte du snapshot entre conteneurs

- Statut : accepted
- Date : 2026-10-16
- Amende : ADR 0005 et ADR 0007

## Contexte

Attendre la fin de `capture` puis lancer `analyzer --snapshot current` n'attache pas l'analyse à cette capture précise. Une autre capture peut modifier le pointeur mutable `current` entre les deux opérations, même si chaque publication est atomique.

## Décision

Un septième volume préfixé, `aniimo-handoff`, transporte uniquement des enregistrements opérationnels. Après publication complète d'un snapshot, `capture` écrit atomiquement `/handoff/pending/<slot>.json` avec `schema_version`, `workflow_run_id`, `snapshot_id` et SHA-256 du manifeste.

`analyzer --handoff required` revendique atomiquement ce record, vérifie que le snapshot et son manifeste exact existent dans `inputs`, puis archive la remise dans `completed` ou son diagnostic d'échec. Le chemin Compose normal n'utilise jamais `current`. Ce pointeur reste disponible pour les commandes manuelles explicites.

`MODKIT_HANDOFF_SLOT` vaut `aniimo-default` par défaut. Une capture refuse d'écraser un slot encore occupé. Les orchestrations réellement concurrentes doivent choisir des slots distincts ; les écritures SQLite et Ghidra restent soumises à leurs verrous propres.

## Conséquences

- chaque analyse consomme le snapshot produit par sa capture, même si `current` change ;
- `inputs` reste strictement read-only dans l'analyseur ;
- la coordination ne contient aucun binaire du jeu ;
- une orchestration simple conserve une seule commande et aucune configuration supplémentaire ;
- un conflit de slot échoue explicitement au lieu d'analyser silencieusement le mauvais build.
