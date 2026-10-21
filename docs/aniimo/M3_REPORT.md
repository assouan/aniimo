# Rapport M3 — comparaison multi-build et invalidation

Date de validation : 2026-10-17

## Résultat

M3 est validé sur deux snapshots immuables réellement analysés :

- source : `snapshot-5c0bfbc5aca5b3e8ce1fd6845761a334b7944e787bea49a203e2c594204b07a4`, build `build-f6a55533606d4b70ad7983f6307b9d8a3e5d70524033ab3d7d85b7fdafd7d41f` ;
- destination : `snapshot-58a1510492a6987eb006e0ff901702f35bec414a416e184558ccdb1a4ca12adf`, build `build-6153068c4ea08c06123406e0873b667f6db5b02bb3d17aa71833d565ec3838ec`.

La comparaison publiée porte la clé `m3-3cb49fc51b95641ae7fbe130b597f818a02d9ebfa9b2ce0e056514bf1cd9f479`. Elle repose sur 53 348 corps source et 53 339 corps destination, tous issus des quatre modules natifs explicitement approuvés. Les composants Unity, .NET/IL2CPP, xLua générique et tiers restent hors export d’implémentation.

Seul `NEP2.dll` diffère entre les deux captures. Les trois modules dont les octets sont identiques représentent exactement les 7 549 correspondances confirmées et inchangées. En l’absence de catalogue managé sûr pour les métadonnées IL2CPP protégées, les ressemblances natives de NEP2 restent des candidats à revoir : aucun hash de corps, nom natif ou score BSim ne confirme seul une identité.

## Résultats de comparaison

| Mesure | Résultat |
|---|---:|
| Empreintes de dépendances | 106 687 |
| Lignes de correspondance | 53 847 |
| `confirmed` | 7 549 |
| `candidate` | 45 291 |
| `unmatched` | 1 007 |
| `unchanged` | 7 549 |
| `requires_review` | 45 799 |
| `not_applicable` | 499 |
| `added` | 499 |
| `not_observed` | 508 |
| `unknown` | 45 799 |

Les empreintes `dependency-fingerprint-v1-strict` conservent séparément signature logique, corps, constantes/opérandes sémantiques, prototype ABI, layouts et références. Les opérandes de relocalisation ne sont neutralisées que lorsqu’elles sont prouvées comme telles. Une disposition absente n’est jamais assimilée à une disposition inchangée, et une contradiction suspend la promotion automatique.

Le registre conserve les candidats, leurs alternatives, preuves et contradictions séparément des décisions humaines dans `profiles/aniimo.matching.yaml`. Les annotations ne sont transférées que pour une identité confirmée ; une correspondance incertaine produit `requires_review`.

## Analyse historique utilisée

Le bundle M0 historique a été réimporté avec validation dans le CAS M1, puis analysé avec la même chaîne M2 que le build courant. Cette analyse porte la clé `m2-27e0a4f8b74efa3be1806aa0f8462c8e38d2ed2a2cdcb089f675272e60e20790` et réconcilie 53 348 corps : 53 305 `c_and_asm`, 4 `asm_only`, 39 `disassembly_failed` et 0 `pending`.

Les quatre caches canoniques étaient invalidés par l’évolution du lock d’outillage. Les intermédiaires Ghidra privés ont cependant été revalidés avant reprise ; aucun traitement n’a utilisé l’installation Steam mutable. La publication à grande échelle a révélé des lectures SQLite N+1, corrigées par des requêtes groupées et les index de la migration `0006_m3_bulk_lookup_indexes.sql`.

## Sorties et incrémentalité

La vue publiée se trouve sous :

`output/comparisons/f6a55533606d4b70-to-6153068c4ea08c06/m3-3cb49fc51b95641a/`

Elle contient 46 307 fichiers pour 471 044 685 octets logiques : résumé JSON, CSV et NDJSON des correspondances et changements, empreintes strictes, invalidations, manifeste de sortie et fiches déterministes par symbole.

Le premier run `run-m3-real-a` a publié la comparaison en 43 627,595 ms. Le second run `run-m3-real-b` a duré 26 709,183 ms ; l’appariement est `cache_hit` et la documentation `content_identical_no_rewrite`. Les trois sentinelles sont restées strictement identiques :

- `comparison.json` : SHA-256 `4e452d1f8b59fbfc861d338745e81ddda4845691fb00a5a1226b917ba98febfb` ;
- `output-manifest.json` : SHA-256 `82950cda7e08de075eba861b85d122fa655d3accf5518f459117173e0aaa0527` ;
- `changes.ndjson` : SHA-256 `e17a53403555e998d465e3f08b78e7e04573ca60905e88485a2467d1e78057d0`.

Le recalcul des empreintes reste volontairement visible dans le rapport du second run ; il n’appelle aucun outil lourd et n’écrit aucune sortie lorsque le contenu est identique.

## Outils et artefacts de livraison

- image analyseur M3 : `sha256:c015667fbdb8af7f2e8780a99e1d93f02edc78fbeb110baa98546424092a6896` ;
- SBOM SPDX 2.3 : `.aitools/sbom/analyzer-m3.spdx.json`, 1 718 774 octets, SHA-256 `a69aa69e7c7e14ef78800a48558814a785da6c5cc71383dbf6c90d362e38dc0b` ;
- bundle : `.aitools/bundles/aniimo-m3-3cb49fc51b95641a.tar.gz`, 103 008 538 octets, SHA-256 `a6f909278b95acb9b0e0f67324cd0443cd1d140e6aaa7858f8076137b3a6210e` ;
- schéma d’échange : `schemas/build-comparison-v1.schema.json` ;
- audit read-only : `tools/audit_m3.py`.

Le bundle contient 46 317 entrées, y compris la comparaison et les rapports JSON/Markdown/CSV des deux runs. Il ne contient aucun binaire du jeu.

## Validations exécutées

| Contrôle | Résultat |
|---|---|
| `python -m pytest -q` | 38 tests réussis en 38,58 s |
| `python -m ruff check .` | aucun diagnostic |
| `tools/audit_m3.py` dans l’image sur le registre et le volume de sortie | `integrity_check=ok`, `foreign_key_check=ok`, `user_version=6` |
| Comparaison réelle de deux builds | 53 847 lignes, aucun candidat promu automatiquement |
| Second run réel | matching et documentation servis par le cache, aucune réécriture des sentinelles |
| Audit des chemins | aucun chemin absolu hôte ou conteneur dans les artefacts canoniques |
| Test de l’archive TAR.GZ | table lisible, 46 317 entrées |
| SBOM de l’image finale | SPDX 2.3 généré, 439 paquets indexés par Docker Scout |

Les tests synthétiques couvrent notamment les scénarios A07 à A11 et A76, les candidats BSim non confirmants, l’identité managée persistante, les invalidations sémantiques et l’absence de réécriture au second run.

## Limites

- les 45 799 observations de NEP2 concernées par le changement restent `requires_review` ; M3 ne revendique pas leur identité logique ni un `body_changed` sans preuve managée suffisante ;
- les métadonnées IL2CPP des deux builds restent `suspected_protection` ; aucun stub historique n’a été utilisé pour combler ce manque ;
- aucune correspondance n’est une certification runtime ou une autorisation de hook ;
- aucune sonde runtime, injection ou modification de l’installation du jeu n’a eu lieu.

## Suite

M4 peut maintenant extraire statiquement les archives Lua autorisées, identifier les bindings propres au jeu, produire les CSV et définitions LuaLS, et livrer séparément une sonde runtime bornée avec le statut `not_tested`. Cette sonde ne sera pas exécutée pendant le jalon statique.
