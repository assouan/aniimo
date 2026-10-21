# Migrations SQLite

Les migrations M1 sont ordonnées et contiguës :

- `0001_capture.sql` crée les builds, snapshots, objets d’entrée, observations et composants ;
- `0002_pipeline_scope.sql` ajoute les runs, étapes, caches, remises et décisions de périmètre.

`modkit.registry.Registry` active systématiquement les clés étrangères, vérifie la base existante, crée une sauvegarde SQLite cohérente avant toute migration d’une base non vide et restaure cette sauvegarde si une migration échoue. Les tests M1 ouvrent successivement une base au niveau 1 puis au niveau 2 et exécutent `foreign_key_check`.

M2 ajoute `0003_native_analysis.sql` pour les identités persistantes de symboles et de corps, les localisations, tentatives, références, couvertures et résultats de l’adaptateur IL2CPP.

`0004_native_lookup_indexes.sql` ajoute les index composites utilisés par la reprise, la réconciliation et les vues lisibles M2. Cette migration additive corrige les recherches par corps sans modifier la migration M2 déjà appliquée.

M3 ajoute `0005_multi_build_comparison.sql` pour les empreintes de dépendances, comparaisons de builds, candidats explicables, revues humaines, changements/invalidation et sorties documentaires incrémentales.

`0006_m3_bulk_lookup_indexes.sql` ajoute les index composites mesurés sur le vrai registre multi-build afin d’éviter une jointure quadratique lors de la publication et de stabiliser l’ordre des références sans tri temporaire global.

M4 ajoute `0007_lua_analysis.sql` pour les archives et scripts Lua observés, les symboles, dépendances, bindings, caches de dialecte/script et les observations runtime séparées par build, VM et scénario.

M5 ajoute `0008_sdk_capabilities.sql` pour les versions de SDK/adaptateur, bases de capacités, dépendances exactes, évaluations par build, validations techniques, choix de loader, packages et autorisations externes séparées.

M6 ajoute `0009_release_hardening.sql` pour les tests de compatibilité binaire d’un ancien mod non recompilé et les attestations de distribution liées au hash exact du package.

Une migration publiée n’est jamais modifiée : toute correction reçoit un nouveau numéro.
