# Architecture cible

## Flux principal

```text
Installation Aniimo RO + manifeste Steam RO
                    │
                    ▼
 préflight/doctor → plan → conteneur capture
                    │
                    ▼
 volume aniimo-inputs (CAS + snapshot immuable)
                    │
                    ├── remise exacte ──> aniimo-handoff
                    │                         │
                    ▼ lecture seule          ▼ revendication atomique
 préflight/doctor → plan → analyzer isolé
                    │
                    ▼
 détection → périmètre → extraction → Ghidra/BSim ciblés
                    │
                    ▼
 registre SQLite → comparaison → docs/rapports
                    │
                    ▼
       revue humaine et validations runtime
                    │
                    ▼
 contrats SDK → adaptateur → package de mod signé
                    │
                    ▼
   processus Windows autorisé (hors Docker)
```

Le pipeline statique est un DAG d'étapes déterministes. Une commande Compose enchaîne les deux conteneurs. Le préflight léger est systématique, le doctor stable est caché par digests, et les plans de capture/analyse sont toujours calculés puis réutilisés par le run. Chaque étape enregistre ses entrées, versions d'outils, configuration pertinente, sorties, erreurs et clé de cache. Seul `capture` possède le bind mount Steam. Il remet à `analyzer` le `snapshot_id` exact via un slot atomique du volume `handoff` ; `current` n'est pas la coordination du workflow normal. `analyzer` ne connaît que des chemins logiques du snapshot et reçoit `/inputs` en lecture seule.

La sélection d'entrées et l'autorisation de décompilation sont deux plans différents : `aniimo.inputs.yaml` limite ce qui est copié et active par défaut `core`, `lua`, `content_indexes` et `anti_cheat` ; `aniimo.decompilation.yaml` et le `scope-plan.json` observé limitent ce dont une implémentation peut être exportée. Les quatre composants anti-cheat connus sont des exceptions de modules complets explicitement approuvées. Ghidra et BSim sont activés, mais une clé de cache valide les transforme en no-op. L'ASM précède le C et survit à son échec ; les échecs inchangés sont cachés et la file difficile est plafonnée. BSim indexe le périmètre autorisé, mais ne lance une requête fuzzy que pour les identités non résolues.

## Plans de contrôle séparés

1. **Analyse** : les fichiers sont-ils compris et les preuves suffisantes ?
2. **Compatibilité** : les dépendances exactes d'une capacité sont-elles validées dans cet environnement ?
3. **Autorisation externe** : ce package précis est-il accepté pour le périmètre déclaré ?

Un état positif dans un plan ne force jamais les deux autres.

## Unités d'invalidation

- Enveloppe de capture et allowlist : `snapshot_id`.
- Contenu logique complet retenu : `build_id`.
- Paire IL2CPP, assembly, module natif ou archive Lua : `component_revision_id`.
- Méthode logique : `symbol_id`.
- Corps natif potentiellement partagé : `native_body_id`.
- Contrat public : `api_id`.
- Ensemble exact nécessaire à une capacité : `capability_basis_id`.

Cette granularité permet de créer un nouveau build lorsque du contenu change sans prétendre qu'un hook indépendant est cassé ou retesté.

## Matérialisation des résultats

SQLite, le CAS d'entrées et le CAS d'artefacts sont canoniques. `output/` contient seulement des manifests, rapports, CSV, vues navigables et exports demandés. Chaque corps possède un artefact canonique et un état parmi `c_and_asm`, `asm_only`, `disassembly_failed` ou `pending` ; `coverage.json` réconcilie tous les corps approuvés et liste séparément les inconnues. La vue de lecture obligatoire expose assembly → namespace → type → méthode ou module → fonction, sans dupliquer les corps partagés. Les entrées identiques et les milliers de corps ne sont pas dupliqués entre builds : les manifests référencent les objets immuables et les vues sont générées à la demande.

Chaque orchestration publie aussi `output/reports/<run_id>/run-report.json`, `report.md` et `timings.csv`. La hiérarchie des étapes expose durée, cache, statut, quantités traitées, outils et ressources disponibles ; le résumé distingue temps mural et chemin critique.

## Frontière runtime

Le MVP privilégie une DLL managée et un loader IL2CPP existant si leur compatibilité Aniimo est prouvée. Une voie DLL native reste possible, mais possède un contrat ABI/handles/callbacks distinct. Les contrats publics ne dévoilent pas les pointeurs ou types internes du jeu. Les adaptateurs convertissent ces contrats en interop, bindings Lua ou hooks natifs validés. Le hot reload n'est pas promis ; le redémarrage reste la stratégie sûre initiale.

