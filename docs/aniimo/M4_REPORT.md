# Rapport M4 — Lua statique, bindings et sonde séparée

Date de validation : 2026-10-17

## Résultat

M4 est validé statiquement sur les deux snapshots immuables déjà utilisés par M3. L’analyse ne monte pas l’installation Steam, n’exécute aucun script extrait et ne décompile pas l’implémentation générique xLua.

Le build courant porte la clé `m4-8a93addbb70efc6c58a6847473884092e10337f5fe957568fd8dec0f9dbb67ec`. Ses archives active et `StreamingAssets` sont suivies comme deux révisions de composant distinctes, même lorsque leurs octets sont identiques. Le build historique porte la clé `m4-9c4e82273fb077164a55b0c9fa4dce854ffb05b6bf7b4fb0049e4a4198857861`.

## Conteneur Lua et dialecte

`LuaScripts.xdf` est un ZIP valide de 114 885 463 octets contenant 8 703 entrées : 8 636 dumps LuaJIT v2 et 67 ressources non-Lua. Les ressources non-Lua sont seulement indexées ; elles ne sont ni analysées comme scripts ni publiées en masse. Chaque paire XDF/XDT est contrôlée par taille, MD5 global, ordre, noms, offsets, tailles compressées/décompressées et MD5 d’entrée. Les chemins dangereux, collisions de casse, entrées chiffrées et compressions inconnues échouent fermés.

Les dumps utilisent la structure LuaJIT v2 avec `FR2` et informations de débogage, mais une permutation d’opcodes propre au fournisseur. Le pipeline n’applique donc pas la table d’opcodes standard. Il a inféré uniquement un sous-ensemble appuyé par des motifs typés et répétés : `GGET=57`, `KSTR=39`, `CALL=66`, `FNEW=50`, `TSETS=63`, `TGETS=54`. Les preuves comptent 1 920 motifs `require`, 3 065 affectations de closures et 76 accès `CS.*` dans l’échantillon borné de 256 chunks.

Les noms de fichiers absolus présents dans les métadonnées de débogage ne sont jamais copiés : seuls leur SHA-256 et le booléen `chunk_name_is_absolute` sont conservés. Un format ou dialecte inconnu reste `unsupported` avec son hash et son diagnostic, sans faux pseudocode.

## Sorties statiques

| Mesure | Résultat courant |
|---|---:|
| Scripts uniques | 8 636 |
| Observations de modules, active + bundled | 17 272 |
| Observations de symboles | 213 836 |
| Dépendances `require` observées | 71 742 |
| Bindings `CS.*` | 10 106 |
| Candidats du namespace jeu | 4 340 |
| Références externes | 782 |
| Signatures de callable encore inconnues | 92 |
| Définitions LuaLS | 8 636 |
| Fichiers publiés par build | 8 646 |
| Octets logiques publiés par build | 152 790 876 |

Les CSV `lua_symbols.csv`, `lua_modules.csv`, `lua_dependencies.csv`, `lua_bindings.csv` et `lua_archives.csv` séparent build, révision de composant, rôle d’archive, preuve et statut. Les définitions `.d.lua` sont des aides d’éditeur avec `---@meta`; elles ne sont pas des scripts de jeu et ne doivent jamais être chargées par le runtime.

Le bridge `xlua.dll` est confirmé comme PE x86-64 avec 515 exports, dont 151 symboles `lua_*` ou `luaL_*`. Il reste `reference_only`, `implementation_exported=false`, avec lien vers la documentation officielle xLua. Un chemin `CS.FunPlus.WorldX.*` non relié à une identité managée prouvée reste `needs_review`; les namespaces Unity, système et xLua restent des références externes.

## Incrémentalité réelle

Le run courant initial `run-m4-real-current-a` a duré 231 558,747 ms, migration et sauvegarde du registre incluses. L’extraction active a analysé 8 636 scripts ; la paire bundled identique a été servie depuis le cache d’archive.

Le run historique `run-m4-real-historical-a` a duré 20 563,412 ms. Son XDT diffère par la version de contenu, donc le conteneur a été revalidé et réextrait, mais les 8 636 scripts dont le SHA-256 était inchangé ont tous été servis par le cache script. Cela valide la séparation entre cache du conteneur et cache du script.

Le second run courant `run-m4-real-current-b` a duré 2 197,803 ms. L’analyse et la documentation sont toutes deux `cache_hit`; aucun fichier généré n’a été réécrit. Les sentinelles courantes sont :

- `lua-analysis.json` : SHA-256 `93a35d57f20c78aa4e1c74d14d7e869369516c6c13513dedb8e3c966cb31afd2` ;
- `output-manifest.json` : SHA-256 `996807b92263fdff11d0ce6e1ec6e350e985175b6a0cd0f02ee83195a47f6385` ;
- `lua_symbols.csv` : SHA-256 `f19205cfb1601a4163190c45895a8c12affdca663f58774e60be686152469e9d`.

## Sonde runtime séparée

`runtime/lua-probe/probe.lua` est livré sans auto-exécution. Son parcours utilise les accès bruts `next`, `rawget` et `type`, borne profondeur, entrées par table et observations totales, évite les cycles, n’appelle aucune fonction/getter découvert, ne charge aucun module et n’accède à aucune métatable.

L’import `modkit lua-import` exige le snapshot, le build, le hash exact du module xLua, l’identité de VM et le scénario. Une observation provenant d’un autre build ou module est rejetée. Une fonction native garde la signature prudente `fun(...): any`; aucun type métier n’est déduit de `debug.getinfo`.

Cette sonde n’a pas été exécutée : son statut canonique est `not_tested`. M4 n’a installé aucun loader, injecté aucune DLL, démarré aucun jeu ni modifié l’installation live.

## Outils et artefacts de livraison

- image analyseur M4 : `sha256:16accaab9fc1b49be5a851bfc5d65e147f92d45371617a089bc00c6d5c362b92` ;
- SBOM SPDX 2.3 : `.aitools/sbom/analyzer-m4.spdx.json`, 1 718 774 octets, SHA-256 `ed30ac1f9c989fd52be9602c751e3610329871469125a3e1f07b2b805a7fd8cd` ;
- bundle : `.aitools/bundles/aniimo-m4-8a93addbb70efc6c.tar.gz`, 32 178 032 octets, SHA-256 `8ce3108ee64d4601741499c34e2f07c77fc70467896faf018db147b75203b702` ;
- schémas : `schemas/lua-analysis-v1.schema.json` et `schemas/lua-runtime-observation-v1.schema.json` ;
- audit read-only : `tools/audit_m4.py` ;
- registre : migration `0007_lua_analysis.sql`, `user_version=7`.

Le bundle contient 19 222 entrées : sorties courante et historique, rapports des trois runs, sonde, schémas et audit. Il ne contient aucun binaire, bytecode extrait ou archive du jeu.

## Validations exécutées

| Contrôle | Résultat |
|---|---|
| `python -m pytest -q` | 43 tests réussis en 38,28 s |
| `python -m ruff check modkit tools/audit_m4.py tests/test_m4_lua.py` | aucun diagnostic |
| Analyse réelle des deux builds | 8 636 scripts uniques chacun, 17 272 observations chacune, aucune exécution de script |
| `tools/audit_m4.py` sur volumes réels | hashes des 8 646 fichiers, intégrité/FK SQLite, cache et périmètre validés |
| Reprise inter-build | 8 636 hits script sur 8 636 après revalidation du XDT historique |
| Second run courant | analyse/documentation `cache_hit`, aucune réécriture |
| xLua | 515 exports indexés, implémentation non exportée |
| Sonde | tests statiques de bornage ; état runtime `not_tested` |
| Archive TAR.GZ | table lisible, 19 222 entrées |
| SBOM | SPDX 2.3 généré, 439 paquets indexés par Docker Scout |

Les tests ciblent notamment A27 à A32, A34, A40, A49 et A53 : invalidation script, cache par contenu, scénarios séparés, signatures C inconnues, parcours cyclique borné, bytecode inconnu, refus cross-build, statut runtime honnête, archives active/bundled distinctes et bridge tiers de référence.

## Limites

- l’analyse instructionnelle est volontairement limitée aux motifs prouvés ; elle n’est pas un décompilateur LuaJIT général ;
- les 4 340 chemins du namespace jeu restent des candidats tant que leur identité managée n’est pas résolue par une preuve indépendante ;
- les observations statiques ne prouvent pas la disponibilité d’une API dans chaque phase runtime ;
- aucune observation du menu ou d’une partie n’existe encore, donc l’absence d’un symbole n’est jamais interprétée comme une suppression.

## Suite

M5 peut construire une API publique minimale et versionnée au-dessus de dépendances exactes, évaluer un loader existant et fournir un mod exemple. La validation technique runtime et l’autorisation externe resteront deux axes distincts ; sans environnement de jeu explicitement autorisé, les tests in-game demeureront `not_tested` plutôt que simulés.
