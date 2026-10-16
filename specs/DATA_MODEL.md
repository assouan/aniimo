# Modèle de données et exports

## Base canonique

SQLite sert de registre de travail transactionnel. Exporter des JSON normalisés, validés par des JSON Schema versionnés, comme format d'échange. Les CSV sont des vues lisibles ; ils ne sont pas la seule représentation des relations complexes. Les preuves brutes et artefacts volumineux résident dans le stockage par hash.

Tables recommandées : `builds`, `input_files`, `analysis_runs`, `symbols`, `symbol_observations`, `native_bodies`, `body_observations`, `symbol_body_links`, `references`, `matches`, `annotations`, `lua_observations`, `lua_bindings`, `api_contracts`, `capabilities`, `test_results`, `stage_runs`, `artifacts`.

## Champs transversaux

`schema_version`, `build_id`, `analysis_id`, `producer_name`, `producer_version`, `producer_digest`, `source_artifact_id`, `evidence_refs`, `status`, `errors`.

Les timestamps opérationnels peuvent figurer dans les logs de run. Ils ne doivent pas affecter les identifiants de contenu ou polluer les fichiers de code et de documentation inchangés.

Les champs inconnus valent `null` en JSON et cellule vide en CSV. Le zéro d'une adresse, d'un offset ou d'un nombre de paramètres n'est pas un substitut à « inconnu ». Encoder les adresses en chaînes hexadécimales pour éviter la perte de précision des outils consommateurs.

## Identité d'un symbole

`symbol_id` : UUID ou identifiant alloué et conservé dans le registre, indépendant de la localisation. Une stratégie déterministe d'allocation initiale est possible, mais les renommages doivent être gérés explicitement par le registre.

`signature_key` : signature canonique de l'observation, versionnée par le schéma de normalisation. Inclure l'assembly logique, le nom de type qualifié et imbriqué, le nom de méthode, l'arité générique, les types des paramètres dans l'ordre, les modificateurs de passage et le retour. Conserver les modificateurs exacts d'origine dans l'observation. Ne pas se fonder sur les noms de paramètres ou la version numérique d'assembly.

`name_source` : `metadata`, `debug_symbol`, `export`, `lua_source`, `binding_registration`, `runtime_observation`, `manual_alias`, `inferred`, `unknown`.

`name_status` : `observed`, `reviewed`, `hypothesis`, `unknown`. Un nom obfusqué lu dans les métadonnées reste `observed`, sans être qualifié de nom original non obfusqué.

## Corps natifs et localisations

`native_body_id` n'est pas obligatoirement le `symbol_id`. Enregistrer les associations par `symbol_body_links`, avec spécialisation générique, rôle et contexte. Les méthodes abstraites, externes, supprimées ou intégrées peuvent ne pas avoir de corps autonome identifié ; les états doivent distinguer ces cas des erreurs de décompilation.

Une localisation native est attachée au build, au hash exact du module, à l'architecture et au format de fichier. Pour un PE, distinguer `rva`, `file_offset`, `preferred_va` et adresse effective observée en processus. Une adresse effective de runtime n'est pas un identifiant stable. Les locations Mono utilisent leur propre `location_kind` : IL/token/JIT observé, sans prétendre qu'un RVA de méthode IL pointe vers du code natif appelable.

Ne pas écraser les localisations précédentes. Un module identique peut réutiliser son extraction locale, mais les dépendances de contexte restent à vérifier.

## Empreintes et références

Conserver `raw_body_hash`, `relocation_normalized_hash`, `signature_hash`, `layout_hash`, `reference_context_hash`, `decompiler_context_hash` et la version de chaque algorithme. Aucun de ces champs n'est une preuve universelle d'équivalence comportementale.

Les références distinguent appel direct, candidat d'appel indirect, accès à un champ, lecture/écriture de donnée, référence à un type, chaîne, table virtuelle et dépendance Lua. Préserver la cible brute propre au build ET la cible logique résolue. Renseigner le niveau de couverture de résolution et ses limites.

## Matchs et changements

Un `match` porte source, destination, méthode d'appariement, preuves, contradictions, alternatives et décision. Ne pas fusionner automatiquement les identités sur une similarité seule. Les transformations split/merge et corps génériques partagés ne doivent pas être forcées en appariement bijectif.

Les `change_flags` sont multivalués : `relocated`, `body_changed`, `signature_changed`, `layout_changed`, `references_changed`, `referenced_data_changed`, `renamed`, `added`, `removed`, `not_observed`, `unknown`.

Séparer `match_status`, `analysis_status`, `decompile_status`, `runtime_validation_status` et `capability_status`. Un seul champ « compatible » ne suffit pas.

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

Les noms provenant de binaires sont des données non fiables. L'export canonique ne doit pas altérer leur contenu pour un tableur. Prévoir, séparément, une vue explicitement étiquetée pour ouverture en tableur qui neutralise les cellules interprétables comme formules. Ne pas réimporter cette vue comme catalogue canonique.

## Documentation par propriété

La provenance doit exister au niveau des propriétés sensibles : nom, type de retour, paramètres, sémantique, thread et effets secondaires. Par exemple, le nom peut être extrait avec certitude alors que le sens métier est une hypothèse. Une confiance unique attachée à toute la méthode masquerait cette différence.

Les définitions LuaLS utilisent `any` ou une signature variadique lorsqu'aucune signature n'est établie, avec une annotation expliquant la limite. Ne pas transformer un appel observé en signature exhaustive ni un échantillon de retour en type complet.
