# Modèle de données et exports

## Base canonique

SQLite sert de registre de travail transactionnel. Exporter des JSON normalisés, validés par des JSON Schema versionnés, comme format d'échange. Les CSV sont des vues lisibles ; ils ne sont pas la seule représentation des relations complexes. Les preuves brutes et artefacts volumineux résident dans le stockage par hash.

Tables recommandées :

- capture et composants : `builds`, `external_build_refs`, `capture_rules`, `capture_observations`, `input_objects`, `input_files`, `components`, `component_revisions`, `build_components`, `snapshots` ;
- pipeline : `analysis_runs`, `stage_runs`, `stage_inputs`, `stage_outputs`, `cache_entries`, `toolchains` ;
- périmètre et preuves : `evidence`, `ownership_claims`, `scope_decisions`, `scope_exceptions` ;
- symboles : `symbols`, `symbol_observations`, `native_bodies`, `body_observations`, `symbol_body_links`, `references`, `matches`, `annotations` ;
- Lua : `lua_observations`, `lua_bindings`, `runtime_observations`, `observation_scenarios` ;
- SDK/runtime : `api_contracts`, `capabilities`, `capability_dependencies`, `capability_bases`, `capability_validations`, `runtime_authorizations`, `test_results`.

Les octets propriétaires capturés résident dans le CAS du volume `inputs`. Les artefacts générés résident dans un CAS distinct du volume `artifacts`. Le registre référence les deux par identifiant et digest, sans permettre à un artefact généré de se faire passer pour une entrée observée.

Le schéma SQLite est migré par des migrations ordonnées, transactionnelles et testées. `PRAGMA foreign_keys=ON` est obligatoire. Une migration crée d'abord une sauvegarde cohérente ou refuse de s'exécuter ; elle ne modifie jamais silencieusement les artefacts du CAS.

## Champs transversaux

`schema_version`, `workflow_run_id`, `snapshot_id`, `build_id`, `component_revision_id`, `analysis_id`, `producer_name`, `producer_version`, `producer_digest`, `source_artifact_id`, `evidence_refs`, `status`, `errors`.

Les timestamps opérationnels peuvent figurer dans les logs de run. Ils ne doivent pas affecter les identifiants de contenu ou polluer les fichiers de code et de documentation inchangés.

Les chemins canoniques sont relatifs à une racine logique (`game:/`, `snapshot:/`, `artifact:/`). Les chemins absolus de l'hôte peuvent exister dans un journal local privé, mais ne sont ni inclus dans les identifiants ni publiés dans les exports normalisés.

Chaque `capture_observation` enregistre la règle et son mode : `payload` ou `inventory_only`, ainsi que le feature set actif. `input_object_id` reste nul quand aucun corps n'a été conservé. Les éléments d'inventaire n'ont pas de hash complet implicite. Le manifeste stocke aussi `selection_id`, le digest canonique de l'allowlist et la preuve de publication atomique. L'analyseur refuse un snapshot dont un payload référencé est absent ou dont la politique ne correspond pas.

Les champs inconnus valent `null` en JSON et cellule vide en CSV. Le zéro d'une adresse, d'un offset ou d'un nombre de paramètres n'est pas un substitut à « inconnu ». Encoder les adresses en chaînes hexadécimales pour éviter la perte de précision des outils consommateurs.

## Exécutions et timings

`workflow_run_id` relie la capture et l'analyse d'une même orchestration. C'est un identifiant opérationnel aléatoire ou alloué, jamais une identité de contenu. Le fragment de capture peut être stocké dans `inputs` afin de traverser la frontière des conteneurs, mais ses timestamps et métriques sont exclus de `build_id`, `snapshot_id`, `analysis_id` et des clés de cache.

Chaque `stage_run` contient au minimum : `step_id`, `parent_step_id`, `workflow_run_id`, `stage_name`, `substep_name`, `component_id` nullable, `status`, `reason`, `cache_status`, `tool_name`, `tool_version`, `started_at`, `ended_at`, `duration_ms`, `input_item_count`, `input_bytes`, `output_item_count`, `output_bytes`, `cpu_time_ms` nullable, `peak_rss_bytes` nullable et `error_code` nullable.

Les durées sont calculées avec une horloge monotone ; les timestamps muraux servent seulement à corréler les logs. Les statuts couvrent au minimum `completed`, `cache_hit`, `skipped`, `failed` et `blocked_by_dependency`. Une étape parente agrège ses enfants sans écraser leurs mesures. Le rapport calcule séparément le temps mural, la somme des durées et le chemin critique afin de représenter correctement le parallélisme.

La capture publie `/inputs/run-reports/<workflow_run_id>.json`. Après analyse, les vues complètes se trouvent sous `/output/reports/<workflow_run_id>/`; `latest.json` est un pointeur atomique et non une copie. Une exécution échouée conserve les sous-étapes déjà mesurées et la raison d'arrêt.

## Identité d'un symbole

`symbol_id` : UUID ou identifiant alloué et conservé dans le registre, indépendant de la localisation. Une stratégie déterministe d'allocation initiale est possible, mais les renommages doivent être gérés explicitement par le registre.

`signature_key` : signature canonique de l'observation, versionnée par le schéma de normalisation. Inclure l'assembly logique, le nom de type qualifié et imbriqué, le nom de méthode, l'arité générique, les types des paramètres dans l'ordre, les modificateurs de passage et le retour. Conserver les modificateurs exacts d'origine dans l'observation. Ne pas se fonder sur les noms de paramètres ou la version numérique d'assembly.

`name_source` : `metadata`, `debug_symbol`, `export`, `lua_source`, `binding_registration`, `runtime_observation`, `manual_alias`, `inferred`, `unknown`.

`name_status` : `observed`, `reviewed`, `hypothesis`, `unknown`. Un nom obfusqué lu dans les métadonnées reste `observed`, sans être qualifié de nom original non obfusqué.

## Builds, composants et décisions de périmètre

`build_id` identifie le manifeste canonique des chemins logiques et contenus retenus. `snapshot_id` identifie l'enveloppe immuable qui ajoute le digest de l'allowlist, la version de schéma et les statuts de présence, sans timestamp. Une modification de règle qui ne change aucun payload peut donc conserver le même `build_id` tout en produisant un autre `snapshot_id`. Les identifiants Steam, SCM, version Unity et version Lua sont stockés dans `external_build_refs` avec source et statut de preuve.

`component_revision_id` identifie une unité cohérente de contenu. Pour IL2CPP, le composant principal inclut au minimum le binaire, les métadonnées associées et leur relation de cohérence. Pour Lua, les archives active et intégrée sont deux composants distincts. Une révision conserve le hash brut de chaque artefact et, lorsqu'il est calculé, un digest sémantique versionné propre à l'adaptateur.

Une `scope_decision` contient : sujet, granularité (`component`, `managed_assembly`, `type`, `symbol`, `native_body`, `lua_module`), classification, raison codifiée, preuves, version de politique, auteur/reviewer, domaine d'applicabilité et statut. Les valeurs sont `game_decompile`, `reference_only`, `excluded` ou `needs_review`. Un motif de nom ne crée qu'une `ownership_claim` ou un indice ; il ne crée jamais seul une décision `game_decompile`.

`game_decompile` désigne techniquement une implémentation dont l'export est autorisé ; ce nom de classification ne constitue pas une revendication de propriété intellectuelle. Dans le profil Aniimo, il couvre le code game-owned prouvé et les modules anti-cheat exacts placés dans `approved.full_module_decompile` par autorisation explicite. Conserver l'origine réelle du composant séparément dans `ownership_claims`.

Les exceptions sont plus étroites que la règle qu'elles remplacent, justifiées et liées à des symboles exacts. Une exception sur un symbole n'autorise pas l'assembly ou le module entier.

## Corps natifs et localisations

`native_body_id` n'est pas obligatoirement le `symbol_id`. Enregistrer les associations par `symbol_body_links`, avec spécialisation générique, rôle et contexte. Les méthodes abstraites, externes, supprimées ou intégrées peuvent ne pas avoir de corps autonome identifié ; les états doivent distinguer ces cas des erreurs de décompilation.

Une localisation native est attachée au build, au hash exact du module, à l'architecture et au format de fichier. Pour un PE, distinguer `rva`, `file_offset`, `preferred_va` et adresse effective observée en processus. Une adresse effective de runtime n'est pas un identifiant stable. Les locations Mono utilisent leur propre `location_kind` : IL/token/JIT observé, sans prétendre qu'un RVA de méthode IL pointe vers du code natif appelable.

Ne pas écraser les localisations précédentes. Un module identique peut réutiliser son extraction locale, mais les dépendances de contexte restent à vérifier.

## Empreintes et références

Conserver `raw_body_hash`, `relocation_normalized_hash`, `signature_hash`, `layout_hash`, `reference_context_hash`, `decompiler_context_hash` et la version de chaque algorithme. Aucun de ces champs n'est une preuve universelle d'équivalence comportementale.

Pour un PE, un digest de réutilisation d'analyse documente le contexte de chargement consommé : architecture, en-têtes pertinents, sections mappées et caractéristiques, imports/exports, relocations, données d'exception/unwind, tables et données référencées. L'égalité de deux seules sections exécutables ne suffit pas à réutiliser automatiquement un projet Ghidra.

Les références distinguent appel direct, candidat d'appel indirect, accès à un champ, lecture/écriture de donnée, référence à un type, chaîne, table virtuelle et dépendance Lua. Préserver la cible brute propre au build ET la cible logique résolue. Renseigner le niveau de couverture de résolution et ses limites.

## Matchs et changements

Un `match` porte source, destination, méthode d'appariement, preuves, contradictions, alternatives et décision. Ne pas fusionner automatiquement les identités sur une similarité seule. Les transformations split/merge et corps génériques partagés ne doivent pas être forcées en appariement bijectif.

Les `change_flags` sont multivalués : `relocated`, `body_changed`, `signature_changed`, `layout_changed`, `references_changed`, `referenced_data_changed`, `renamed`, `added`, `removed`, `not_observed`, `unknown`.

Séparer `match_status`, `analysis_status`, `decompile_status`, `runtime_validation_status` et `capability_status`. Un seul champ « compatible » ne suffit pas.

## Capacités et autorisations runtime

Une `capability_dependency` cible un symbole, corps, layout, champ, donnée, binding Lua, composant, résolveur, ABI ou test. `capability_basis_id` est le hash canonique de toutes les dépendances exactes et de leurs versions de résolution. Une validation porte sur `(api_id, capability_basis_id, runtime_environment_id)` et ne prétend pas tester un autre ensemble.

Le transfert d'une validation vers un autre `build_id` est permis uniquement par une règle explicite démontrant que toutes les dépendances de la capacité sont identiques et que le contexte requis n'a pas changé. Une dépendance inconnue produit `requires_validation` ou `unavailable`.

Une `runtime_authorization` représente une décision externe du support, de l'éditeur ou de l'anti-cheat. Elle stocke le hash du package distribué, la version, le signataire déclaré, le périmètre de builds, le statut, les dates et une référence de preuve privée. Elle reste distincte de `capability_validations` : une autorisation administrative n'est pas une preuve de correction technique et inversement.

## Export CSV

UTF-8, ordre déterministe des colonnes et des lignes, échappement CSV standard, identifiants complets sans troncature. Les listes complexes résident dans les JSON/tables liées, plutôt que dans des cellules arbitrairement séparées par des virgules.

| Fichier | Contenu |
|---|---|
| `methods.csv` | Identité, assembly, type, nom, signature, provenance, état |
| `native_locations.csv` | Corps/point d'entrée par build et module, rôle, RVA/offset |
| `symbol_body_links.csv` | Association méthode-corps, rôle et instanciation générique |
| `types.csv` | Types, bases connues, taille/layout et provenance |
| `fields.csv` | Champs, types, caractère statique et offsets contextualisés |
| `references.csv` | Dépendances et preuves de résolution |
| `changes.csv` | Changements source/destination et décision d'appariement |
| `lua_symbols.csv` | Chemin Lua, kind, signature, source, scénario et statut |
| `lua_bindings.csv` | Correspondance Lua / méthode managée / corps natif |
| `capabilities.csv` | Contrats SDK, dépendances et validations |
| `components.csv` | Composants logiques, révisions et artefacts du build |
| `scope_decisions.csv` | Classifications, raisons, portée et preuves |
| `capability_dependencies.csv` | Dépendances exactes constituant la base d'une capacité |
| `runtime_authorizations.csv` | Statut externe d'un package de mod exact, sans données administratives sensibles |
| `capture_observations.csv` | Résolution de l'allowlist, mode de capture, présence, hash et objet conservé |
| `stage_timings.csv` | Hiérarchie de run aplatie, durées, statuts de cache, volumes, outils et ressources |

Les noms provenant de binaires sont des données non fiables. L'export canonique ne doit pas altérer leur contenu pour un tableur. Prévoir, séparément, une vue explicitement étiquetée pour ouverture en tableur qui neutralise les cellules interprétables comme formules. Ne pas réimporter cette vue comme catalogue canonique.

## Documentation par propriété

La provenance doit exister au niveau des propriétés sensibles : nom, type de retour, paramètres, sémantique, thread et effets secondaires. Par exemple, le nom peut être extrait avec certitude alors que le sens métier est une hypothèse. Une confiance unique attachée à toute la méthode masquerait cette différence.

Les définitions LuaLS utilisent `any` ou une signature variadique lorsqu'aucune signature n'est établie, avec une annotation expliquant la limite. Ne pas transformer un appel observé en signature exhaustive ni un échantillon de retour en type complet.
