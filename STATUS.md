# État du projet

Date de mise à jour : 2026-10-17

## Jalon courant

**Tous les jalons M-1 à M6 sont terminés et validés dans le périmètre statique, local et hors-jeu autorisé.**

M1 est terminé. Le magasin Docker Desktop a été réparé sans prune ni suppression volontaire de conteneur, volume ou image. Les images `capture` et `analyzer` ont été construites, testées en utilisateur non privilégié, munies d’attestations et de SBOM SPDX, puis validées par deux exécutions Compose réelles sur l’installation montée en lecture seule. Le second run a réutilisé le snapshot exact et servi `scope`, `ghidra` et `bsim` depuis le cache sans invocation lourde.

Le build Steam courant reste celui diagnostiqué en M0. Il a été réimporté sous un nouveau contrat M1 sans modifier ni rebaptiser le bundle d’acquisition M0.

M2 est terminé sur le snapshot Compose immuable. Les métadonnées IL2CPP protégées restent un échec explicite sans fallback, tandis que les quatre modules natifs approuvés ont été réellement auto-analysés par Ghidra, exportés corps par corps avec ASM avant C, signés par BSim, réconciliés, publiés et rejoués en cache complet.

M3 est terminé sur deux snapshots immuables réellement analysés. La comparaison confirme uniquement les identités appuyées par les trois modules strictement identiques et maintient tout le module NEP2 modifié en revue. Le second run sert l’appariement et la documentation depuis le cache sans réécrire les sorties.

M4 est terminé sur les mêmes deux snapshots. Les 8 636 scripts LuaJIT uniques ont été extraits et analysés sans exécution, les deux rôles d’archive sont séparés, xLua reste une référence externe et la sonde bornée est livrée mais conserve honnêtement le statut runtime `not_tested`. Le build historique a réutilisé les 8 636 analyses de scripts après revalidation de son conteneur, puis le second run courant n’a réécrit aucune sortie.

M5 est terminé. Le SDK `1.0.0` expose le catalogue Lua statique via un contrat `netstandard2.1`, un adaptateur exact par build et un mod exemple. Le même binaire de mod a passé les tests hors-jeu sur les deux builds, un build inconnu échoue fermé, le package est reproductible et strictement borné. BepInEx Unity IL2CPP a été évalué comme candidat mais n’a pas été installé ; la validation en jeu reste `not_tested` et l’autorisation externe `not_requested`.

M6 est terminé. Le SDK `1.1.0` ajoute l’identité de build sans casser l’ABI publique `1.0.0.0`, et le binaire du mod M5 non recompilé passe sur les deux builds avec le runtime et l’adaptateur M6. Le watcher optionnel réutilise la capture immuable avec verrou exclusif et reprise bornée. Le package est vérifié contre son manifeste interne, l’optimisation native est explicitement `not_needed`, et toutes les limites runtime restent fermées.

## Livré et validé dans M6

- `IBuildIdentity` est une extension additive ; `GameModAPI.Contracts.dll` conserve `AssemblyVersion=1.0.0.0` et expose séparément la version sémantique `1.1.0` ;
- le DLL original du mod M5 est chargé dynamiquement, sans recompilation, puis exécuté hors-jeu sur les deux builds exacts avec les composants M6 ;
- les manifests v2 séparent la base Lua commune des deux bases exactes d’identité de build, et tout build inconnu échoue fermé ;
- `modkit watch` repasse par le planificateur et la capture complets, sérialise chaque slot, mémorise l’état hors des identités de contenu et ne remet que les snapshots nouveaux ;
- les tests du watcher couvrent la première remise, l’absence de remise sans changement, un nouveau snapshot après modification, l’exclusion mutuelle, la reprise après erreur transitoire et l’arrêt propre ;
- le vérificateur de package contrôle hash externe, chemins, doublons, chiffrement, timestamps déterministes, allowlist, tailles et empreintes internes, sans script ou binaire du jeu ;
- le même package reconstruit est identique octet pour octet ; l’attestation de distribution et le test de compatibilité binaire sont inscrits dans le registre ;
- l’évaluation native conclut `not_needed` avec zéro hook : aucune optimisation, injection ou activation fondée sur une similarité n’est introduite ;
- la migration 9, les cinq schémas M6, `tools/audit_m6.py` et `docs/aniimo/M6_REPORT.md` rendent la release vérifiable ;
- les images finales et leurs SBOM SPDX sont verrouillés par digest dans `tools.lock.json`.

### Release réelle M6

| Élément | Résultat |
|---|---|
| Release / SDK | `m6-4e839d37fa81325caa82e44d37a6907e159e286395988873ac6a5482cd5a719a` / `1.1.0` |
| API publiques | `aniimo.lua-module-catalog`, `aniimo.build-identity` |
| Bases de capacité | 3 : une Lua commune et une identité exacte par build |
| Ancien mod non recompilé | SHA-256 `d623064583c6aba9b77b0ac77eea487039454b3a7f4cc46de9687534c1af3340` ; deux builds `passed` |
| Contrat M6 | SHA-256 `8ad23f5ae38f74e04a4c6ceaefed89d0d6896ef6f608d95e4049f55660adbb72` |
| Package | 864 843 octets, 10 entrées, SHA-256 `a70e211abbf315379bff1bea40180b3c57f38d72b9178a126348049e0e8002bf` |
| Cache final | `run-m6-real-generate-c`, `sdk.generation=cache_hit`, aucune réécriture |
| Validation | compatibilité binaire et distribution `passed` ; native `not_needed` ; runtime `not_tested` |
| Signature / autorisation | `unsigned` / `not_requested` |
| Images finales | capture `sha256:24dd76a…d9e9` ; analyseur `sha256:3d517279…7a65` |
| Bundle M6 | 78 entrées, 2 020 153 octets, SHA-256 `3e918fef49a8eb55afe9ea89821d2859cf549fddf59f8d8cff10e75b2a12f7ec` |

## Livré et validé dans M5

- `GameModAPI.Contracts` fournit `IGameMod`, `IModContext`, `IModLogger` et la capacité read-only `ILuaModuleCatalog`, sans offset, hook ou type interne du jeu ;
- deux manifests exacts de 8 636 modules partagent une base de capacité uniquement parce que leurs dépendances déclarées ont la même empreinte ;
- l’adaptateur refuse tout build inconnu et conserve les builds connus en `requires_validation` tant que le runtime n’est pas testé ;
- `LuaCatalogExample.dll` est le même binaire sur les deux builds et n’utilise que le contrat public ;
- le build .NET 8 hors ligne verrouille l’image SDK par digest et se termine avec zéro avertissement et zéro erreur ;
- BepInEx Unity IL2CPP `6.0.0-pre.2` est `selected_candidate`, `not_installed`, `not_tested` ;
- le package ZIP est produit depuis neuf chemins autorisés, sans binaire ou script du jeu, et deux constructions sont identiques octet pour octet ;
- la migration 8 sépare releases, adaptateurs, bases de capacité, validations techniques, packages et autorisations externes ;
- `tools/audit_m5.py`, les trois schémas M5 et `docs/aniimo/M5_REPORT.md` rendent la release vérifiable.

### Release réelle M5

| Élément | Résultat |
|---|---|
| Release / SDK | `m5-043c79de2e89c19b802c12b7444600685050ab85cb3496a6692468f6993ef9c1` / `1.0.0` |
| Base de capacité | `capability-basis:824c7634cfe094dae88791a9062ccbc32a66d5a0b2abdc470c89b32239b3a7e0` |
| Builds testés | `build-f6a555…afd7d41f` et `build-615306…3838ec` |
| Même mod | SHA-256 `d623064583c6aba9b77b0ac77eea487039454b3a7f4cc46de9687534c1af3340` |
| Package | 861 880 octets, 9 entrées, SHA-256 `1e721d7b9952003d6f3ce1a60cee63525bb1f2b688a58f0ce41889e51a215454` |
| Cache final | `run-m5-real-generate-b`, `sdk.generation=cache_hit` |
| Validation | statique/hors-jeu `passed` ; runtime `not_tested` ; autorisation `not_requested` |
| Image analyseur | `sha256:388e9340cdcf9f7a7e463b07c29ddfeab281a67d66935790584f24aa7d99930a` |
| Bundle M5 | SHA-256 `a5af994a46effcd5141cd65b42294ad081d9db24668cce5bd80b588c447239f5`, 1 736 685 octets |

## Livré et validé dans M4

- `modkit lua-analyze` valide les paires XDF/XDT capturées, extrait seulement les `.lua`, indexe les 67 entrées non-Lua et n’exécute jamais le contenu extrait ;
- le parseur borné reconnaît la structure LuaJIT v2 et conserve les formats inconnus en `unsupported` avec hash et diagnostic ;
- la permutation d’opcodes Aniimo n’est pas assimilée au dialecte standard : seuls six opcodes appuyés par des motifs répétés sont utilisés pour les dépendances, closures et chemins `CS.*` ;
- les chemins source absolus contenus dans le debug bytecode sont remplacés par un hash et un indicateur booléen ;
- les caches d’archive, de dialecte et de script sont séparés, ce qui permet de revalider un XDT modifié tout en réutilisant un script identique ;
- les CSV normalisés, 8 636 définitions LuaLS par build, bilans de couverture et manifestes sont publiés atomiquement ;
- `xlua.dll` est confirmé PE x86-64 avec 515 exports, dont 151 API Lua, mais son implémentation reste `reference_only` et n’est pas exportée ;
- `runtime/lua-probe` fournit un parcours brut et borné sans appel de getter/fonction inconnue, sans chargement de module et sans prétention d’exhaustivité ;
- `modkit lua-import` refuse un autre build ou module et conserve les fonctions natives sous `fun(...): any` sans types inventés ;
- la migration 7, les deux schémas M4, `tools/audit_m4.py` et `docs/aniimo/M4_REPORT.md` rendent le résultat reproductible.

### Analyse réelle M4

| Élément | Résultat |
|---|---|
| Snapshot / build courant | `snapshot-58a1510492a6987eb006e0ff901702f35bec414a416e184558ccdb1a4ca12adf` / `build-6153068c4ea08c06123406e0873b667f6db5b02bb3d17aa71833d565ec3838ec` |
| Clé courante | `m4-8a93addbb70efc6c58a6847473884092e10337f5fe957568fd8dec0f9dbb67ec` |
| Clé historique | `m4-9c4e82273fb077164a55b0c9fa4dce854ffb05b6bf7b4fb0049e4a4198857861` |
| Scripts / observations de modules | 8 636 uniques / 17 272 active + bundled |
| Symboles / dépendances / bindings | 213 836 / 71 742 / 10 106 |
| Dialecte borné | `GGET=57`, `KSTR=39`, `CALL=66`, `FNEW=50`, `TSETS=63`, `TGETS=54` |
| Premier run courant | `run-m4-real-current-a`, 231 558,747 ms, 8 646 fichiers |
| Reprise historique | `run-m4-real-historical-a`, 8 636 hits script sur 8 636 |
| Cache final | `run-m4-real-current-b`, 2 197,803 ms, analyse/documentation `cache_hit` |
| Runtime | sonde livrée, non exécutée, `not_tested` |
| Image analyseur | `sha256:16accaab9fc1b49be5a851bfc5d65e147f92d45371617a089bc00c6d5c362b92` |
| Bundle M4 | SHA-256 `8ce3108ee64d4601741499c34e2f07c77fc70467896faf018db147b75203b702`, 32 178 032 octets |

## Livré et validé dans M3

- `modkit compare-builds` matérialise les observations M2 de deux builds, calcule des empreintes de dépendances strictes, apparie avec preuves et contradictions, puis publie une documentation incrémentale ;
- les signatures, corps, constantes/opérandes sémantiques, prototypes ABI, layouts, données et références ont des composantes d’empreinte distinctes ;
- les adresses et relocalisations ne sont normalisées que lorsque leur caractère dépendant du chargement est prouvé ;
- les candidats par nom natif, hash ou BSim restent `candidate` et ne deviennent ni identité, ni compatibilité, ni hook automatique ;
- les décisions humaines et candidats externes restent dans `profiles/aniimo.matching.yaml`, séparés des sorties générées ;
- les migrations 5 et 6 ajoutent le modèle multi-build et les index de lecture groupée nécessaires à la publication réelle ;
- `schemas/build-comparison-v1.schema.json`, `tools/audit_m3.py` et `docs/aniimo/M3_REPORT.md` rendent le résultat auditable ;
- les vues CSV/NDJSON/JSON et fiches par symbole sont publiées atomiquement et ne contiennent aucun chemin absolu hôte.

### Comparaison réelle M3

| Élément | Résultat |
|---|---|
| Source | `build-f6a55533606d4b70ad7983f6307b9d8a3e5d70524033ab3d7d85b7fdafd7d41f`, 53 348 corps |
| Destination | `build-6153068c4ea08c06123406e0873b667f6db5b02bb3d17aa71833d565ec3838ec`, 53 339 corps |
| Clé de comparaison | `m3-3cb49fc51b95641ae7fbe130b597f818a02d9ebfa9b2ce0e056514bf1cd9f479` |
| Empreintes / correspondances | 106 687 / 53 847 |
| Statuts de matching | 7 549 `confirmed`, 45 291 `candidate`, 1 007 `unmatched` |
| Invalidations | 7 549 `unchanged`, 45 799 `requires_review`, 499 `not_applicable` |
| Changements | 499 `added`, 508 `not_observed`, 45 799 `unknown` |
| Premier run | `run-m3-real-a`, 43 627,595 ms, publication de 46 307 fichiers |
| Cache final | `run-m3-real-b`, matching et documentation `cache_hit`, aucune réécriture |
| Image analyseur | `sha256:c015667fbdb8af7f2e8780a99e1d93f02edc78fbeb110baa98546424092a6896` |
| Bundle M3 | SHA-256 `a6f909278b95acb9b0e0f67324cd0443cd1d140e6aaa7858f8076137b3a6210e`, 103 008 538 octets |

## Livré et validé dans M2

- l’adaptateur IL2CPP traite le binaire et les métadonnées comme une paire exacte et sépare `parsed`, `unsupported_metadata_version`, `inconsistent_metadata`, `parse_error` et `suspected_protection` ;
- le build courant est `suspected_protection`, avec preuves structurelles et entropiques, sans catalogue vide, stub ou alignement historique de remplacement ;
- le script Ghidra exporte l’ASM indépendamment avant le C, continue après un échec local et utilise exactement `c_and_asm`, `asm_only`, `disassembly_failed` ou `pending` ;
- les tentatives difficiles sont bornées à deux corps et quatre minutes, et leur contexte sémantique complet participe au cache ;
- les quatre signatures BSim sont générées avec la configuration d’architecture appropriée et restent des données de comparaison, pas des identités automatiques ;
- le registre SQLite niveau 4 conserve identités persistantes, localisations par build/module, prototypes ABI, relations symbole-corps, références, tentatives, régions non résolues et couvertures ;
- les vues obligatoires par module/fonction et chemins stables sans nom lient directement ASM, C, signatures, prototypes, références et diagnostics ;
- les noms natifs longs sont bornés avec un suffixe SHA-256 stable et les sorties sont publiées atomiquement sans barrières disque par fichier ;
- un cache complet saute Ghidra, BSim, la réingestion et la réécriture de sortie ;
- `tools/audit_m2.py`, les schémas M2 et `docs/aniimo/M2_REPORT.md` rendent les preuves reproductibles.

### Analyse réelle M2

| Élément | Résultat |
|---|---|
| Snapshot / build | `snapshot-58a1510492a6987eb006e0ff901702f35bec414a416e184558ccdb1a4ca12adf` / `build-6153068c4ea08c06123406e0873b667f6db5b02bb3d17aa71833d565ec3838ec` |
| Clé d’analyse | `m2-1da93dfb99e195f8f9a34fedd558dd8b3d6d868ea7f67c196d5167ab3de2e03e` |
| Corps approuvés | 53 339 = 53 294 `c_and_asm` + 3 `asm_only` + 42 `disassembly_failed` + 0 `pending` |
| Modules | KernelDumpAnalyzer 98 ; NEP2 45 790 ; NEPCleaner 666 ; NEPKernel 6 785 |
| Références / régions non résolues | 910 614 / 45 672 |
| Sorties utilisateur | 476 978 fichiers ; composant de chemin maximal 92 octets |
| Métadonnées | `suspected_protection`, catalogue absent, fallback absent, `discovery_complete=false` |
| Premier run publié | `run-m2-real-i`, 721 528,169 ms, reprise validée des quatre intermédiaires Ghidra/BSim |
| Cache final | `run-m2-real-k`, 2 079,976 ms, quatre modules et publication `cache_hit` |
| Image analyseur | `sha256:a9a985611751f76b1af44319011adc022c152db01501191542af6c02878bd5af` |
| Bundle M2 | SHA-256 `2b138c092a83f87b3b5aa290dee802905e08724df20c7f80fac12d9a59093159`, 129 835 076 octets |

## Livré et validé dans M1

- `modkit` fournit `doctor`, `capture`, `plan`, `analyze`, `import-m0` et `verify` ;
- le plan de capture borné est commun au dry-run et au run réel, puis réutilisé sans second inventaire ;
- le CAS d’entrée, les snapshots immuables, le pointeur manuel `current`, les rapports append-only et la remise exacte par slot sont publiés atomiquement ;
- l’analyseur vérifie le digest du manifeste remis et n’utilise ni Steam ni `current` comme fallback ; sa frontière read-only est testée ;
- le registre SQLite applique deux migrations transactionnelles, active les clés étrangères et sauvegarde une base existante avant migration ;
- le CAS d’artefacts, les clés de cache complètes et les checkpoints produisent un second run sans appel du seam lourd et sans réécriture des sorties ;
- les rapports JSON, Markdown et CSV fusionnent capture et analyse avec statuts, cache, durées monotones, volumes et métriques légères ;
- `compose.yaml` sépare les privilèges de `capture` et `analyzer` et emploie les sept volumes nommés préfixés ;
- les Dockerfiles verrouillent la base Python par digest et les archives PyYAML/JDK/Ghidra par SHA-256 ; un script de build demande provenance et SBOM ;
- les manifests, remises, plans et rapports disposent de JSON Schema versionnés ;
- les images Linux/amd64 réelles sont verrouillées par digest, le lock externe est monté read-only pour éviter toute autoréférence de digest, et les deux SBOM SPDX sont conservés sous `.aitools/sbom/` ;
- les smokes conteneur confirment Python 3.12.8, PyYAML 6.0.2, Microsoft OpenJDK 25.0.4+7-LTS, Ghidra et BSim 12.1.4 ;
- le rapport détaillé et les preuves reproductibles sont dans `docs/aniimo/M1_REPORT.md` et `.aitools/m1-validation/`.

### Réimportation réelle M1

| Élément | Résultat |
|---|---|
| Payloads / octets validés | 77 / 1 439 571 350 |
| Snapshot M1 | `snapshot-5c0bfbc5aca5b3e8ce1fd6845761a334b7944e787bea49a203e2c594204b07a4` |
| Build M1 | `build-f6a55533606d4b70ad7983f6307b9d8a3e5d70524033ab3d7d85b7fdafd7d41f` |
| Manifeste M1 | `c83d4c4038954b6c0fe1a5e3ea640bf0b0ce9461527bd845d6bab39eb1bef7b0` |
| Dernier run | `run-m1-schema-fix-b`, clé `analysis-710cd2fcd356341dda3a61af108213366a21ce4673983967cc3395c611fb77a6` ; `scope`, `ghidra`, `bsim` : `cache_hit` |
| Registre | migration 2, 15 runs, 90 étapes, 18 caches, 0 violation FK |
| Fuite de chemin hôte | 0 dans les JSON canoniques audités |

### Validation Compose réelle M1

| Élément | Résultat |
|---|---|
| Image capture | `sha256:7682c5f9d7cfe30f730b292273ef13fc7672fde36879aed08b3f7f5615137111` |
| Image analyseur | `sha256:ae0152abd6fd27cdf88df69a5db19a2187d04f736d49c5c6233d28a7c6834570` |
| SBOM capture / analyseur | `sha256:bb941169…` / `sha256:72194122…` |
| Snapshot Compose | `snapshot-58a1510492a6987eb006e0ff901702f35bec414a416e184558ccdb1a4ca12adf` |
| Build Compose | `build-6153068c4ea08c06123406e0873b667f6db5b02bb3d17aa71833d565ec3838ec` |
| Payloads / octets revérifiés | 81 / 1 513 966 479 |
| Second run | `run-9dc8670c-bacd-4fb7-a62e-d929aaffd1be` ; trois cache hits, 81 objets réutilisés, 0 créé |
| Frontière analyseur | rootfs read-only, réseau `none`, UID/GID 1000, `/inputs` read-only, aucun bind jeu/Steam |

Le snapshot Compose diffère du bundle M0 : les sept fichiers actifs d’index `3741626` sont remplacés par la révision `3743667`, à laquelle s’ajoutent quatre entrées de cache de contenu. Le `build_id` canonique change donc malgré la référence Steam inchangée ; ce changement d’acquisition n’élargit pas le périmètre de décompilation.

## Rappel du résultat M0

Le build Steam courant a été capturé depuis l'installation autorisée dans un bundle d'acquisition immuable et adressé par contenu. Le diagnostic a ensuite travaillé uniquement sur ce snapshot. Aucun binaire ou script du jeu n'a été exécuté, aucune archive n'a été décompressée, aucune décompilation globale n'a été lancée et l'installation live n'a pas été modifiée.

Le résultat courant est un client Windows x86-64 IL2CPP, Unity `2022.3.62f1`, avec un bridge xLua. Les métadonnées commencent par le magic IL2CPP standard, mais leur champ de version et leur structure ne sont pas directement conformes ; les contrôles bornés et les essais de deux extracteurs classent donc le cas `suspected_protection`, sans déduire cette conclusion du magic seul.

## Livré dans M0

- `tools/m0_diagnose.py` fournit `capture`, `diagnose` et `verify` pour ce jalon seulement ; il ne préfigure ni le CAS, ni le registre, ni la CLI de production M1 ;
- la capture applique `profiles/aniimo.inputs.yaml`, active `core`, `lua`, `content_indexes` et `anti_cheat`, résout le plan une fois, puis effectue une seule lecture SHA-256 par payload et par tentative avec contrôles avant/après et au plus une relance ;
- le bundle immuable est `.aitools/m0-acquisition/m0-2e5970fff08c8e9cdc829adfb026ad263037246ef31a47ba466b8a2e85809560/` ;
- le snapshot contient 77 payloads autorisés pour 1 439 571 350 octets et 69 observations d'inventaire sans corps ; les 77 lectures ont réussi à la première tentative ;
- le manifeste canonique ne contient aucun chemin absolu hôte, n'a décompressé aucun contenu et conserve la séparation entre acquisition et autorisation de décompilation ;
- `detection.json`, `scope-plan.json`, `tool-compatibility.json`, `additional-input-candidates.json`, `diagnostic-manifest.json` et `report.md` ont été produits sous `diagnostic/` ;
- `run-report/run-report.json` et `run-report.md` consignent hiérarchiquement les étapes exécutées, échouées ou sautées, leurs durées monotones, statuts de cache, volumes, outils et ressources légères sans participer aux identités ;
- les quatre modules anti-cheat explicitement approuvés ont été capturés et classés `game_decompile`, mais aucune décompilation n'a été exécutée en M0 ;
- l'inventaire guidé par `md5list.txt`, `ScriptingAssemblies.json`, les imports PE et les zones bornées a produit 86 candidats sans copie, hash complet ou ajout implicite à l'allowlist ;
- les essais d'outils, archives téléchargées, caches et projets Ghidra privés restent sous `.aitools/` ; les résultats condensés sont documentés dans `docs/aniimo/M0_REPORT.md`.

## Résultats sur le build courant

| Élément | Résultat M0 | Preuve ou limite |
|---|---|---|
| Steam | App `4126040`, build `25988361`, `StateFlags=4` | Le build historique `25962016` est donc contredit pour l'installation courante |
| Backend | `il2cpp`, confirmé | Couple cohérent `GameAssembly.dll` natif sans CLR + `global-metadata.dat` |
| Plateforme | Windows x86-64, client | Aucun exécutable de serveur dédié observé dans l'inventaire borné ; autorité serveur inconnue |
| Unity | `2022.3.62f1` | Valeur lue dans `globalgamemanagers` courant |
| Métadonnées IL2CPP | `suspected_protection` | Magic `0xFAB11BAF`, champ brut `28881824` impossible comme version directe, en-tête non conforme et entropie bornée `7,685424` bits/octet |
| Assemblies déclarées | 190 | Noms issus du `ScriptingAssemblies.json` courant ; ils ne prouvent pas la propriété du code |
| Lua | xLua confirmé | DLL PE x86-64 avec 151 exports d'API Lua ; archives actives et intégrées présentes, identiques et non décompressées |
| `SymbolMap` | absent | Aucune adresse de fonction n'a été importée |
| Debug symbols approuvés | absents | Les PDB recherchés par l'allowlist n'ont pas été inventés ni remplacés par des stubs |

### Modules anti-cheat approuvés

| Module | Format | Architecture / sous-système | Signature du snapshot | Décision |
|---|---|---|---|---|
| `NEP2.dll` | PE | x86-64 / GUI | valide, Pawprint Interactive Entertainment | `game_decompile`, module complet approuvé |
| `NEPKernel.sys` | PE | x86-64 / native | valide, Microsoft Windows Hardware Compatibility Publisher | `game_decompile`, module complet approuvé |
| `NEPCleaner.exe` | PE | x86 / GUI | valide, NetEase (Hangzhou) Network | `game_decompile`, module complet approuvé |
| `KernelDumpAnalyzer.exe` | PE | x86-64 / console | valide, Pawprint Interactive Entertainment | `game_decompile`, module complet approuvé |

Les signatures Authenticode servent uniquement de preuve de provenance. Elles ne valent ni autorisation de distribution, ni certification de compatibilité runtime. Le manifeste de contenu signale aussi `worldx_Data/Plugins/x86_64/NEP2.dll` comme candidat nominal distinct ; son corps n'a pas été observé dans les zones bornées et aucun rôle supplémentaire ne lui est attribué.

## Périmètre initial

Les 251 sujets courants recensés ont une décision explicite :

- 4 `game_decompile` : exactement les quatre modules anti-cheat approuvés ;
- 105 `reference_only` : moteur Unity, frameworks/runtime et dépendances dont xLua ;
- 2 `excluded` ;
- 140 `needs_review`, notamment les assemblies dont la propriété jeu n'est pas encore prouvée et les conteneurs natifs mixtes.

`GameAssembly.dll` reste un conteneur mixte et n'a aucune approbation globale. Les futurs corps IL2CPP devront être reliés à leur assembly/type managé d'origine avant tout export. Aucun corps `needs_review`, Unity, .NET/IL2CPP générique ou Lua standard n'a été exporté.

## Matrice d'outillage

- Cpp2IL `2022.1.0-pre-release.21+58fc404…` démarre, mais rejette la valeur de version brute `28881824` avant toute sortie ;
- Il2CppDumper `6.7.46+8a521…` démarre, mais échoue à initialiser les métadonnées avant tout dump ;
- Il2CppInspectorRedux `2026.2` est archivé avec son checksum vérifié, mais son CLI exige .NET 10 alors que l'hôte possède .NET 6/8 ; le couple du jeu ne lui a pas été fourni, notamment parce que son chemin documenté pour certains PE packés peut exécuter une initialisation non fiable ;
- LLVM `llvm-readobj 22.1.8` confirme les machines et sous-systèmes PE des six fichiers testés ;
- Ghidra `12.1.4` avec Microsoft OpenJDK `25.0.4.1+1-LTS` démarre en headless et importe avec `-noanalysis` les quatre modules anti-cheat approuvés ; quatre programmes sont créés, sans auto-analyse, décompilation ou BSim ;
- le CLI BSim `12.1.4` démarre, mais aucune signature et aucune base n'ont été générées en M0 ;
- `tools.lock.json` enregistre maintenant les digests d’images, SBOM, versions, checksums et codes de smoke réels. Son état global reste volontairement `unresolved` tant qu’aucun chargeur M2 n’interprète de façon sûre le couple IL2CPP protégé exact.

La branche active reste `il2cpp_with_protected_metadata`. M2 a confirmé sur le couple exact qu’aucun chargeur disponible ne peut publier un catalogue sûr ; l’adaptateur échoue donc fermé sans fallback. Cette limite est indépendante de l’analyse complète des quatre modules natifs approuvés.

## Vérifications exécutées

| Commande ou contrôle | Résultat réel |
|---|---|
| `python -B -m py_compile tools\m0_diagnose.py tests\test_m0_diagnose.py` | code de sortie 0 |
| `python -B -m unittest discover -s tests -v` | 16 tests exécutés, 16 réussis en 0,281 s |
| `python -B tools\m0_diagnose.py capture ...` | capture publiée ; 77 payloads, 1 439 571 350 octets, 69 observations, aucune relance |
| audit final des métadonnées source contre les états post-lecture | 77/77 payloads encore présents et inchangés en taille, mtime et identité de fichier |
| `python -B tools\m0_diagnose.py diagnose --bundle ... --policy profiles\aniimo.decompilation.yaml --external-tool-results ...` | six artefacts de diagnostic publiés atomiquement |
| `python -B tools\m0_diagnose.py verify --bundle ... --policy profiles\aniimo.decompilation.yaml` | `passed` ; 77 payloads et 1 439 571 350 octets revérifiés, zéro erreur |
| contrôle sémantique PowerShell des quatre JSON | capture commune, quatre approbations exactes, 0 violation de corps candidat, aucun code exécuté/décompilé |
| essais bornés Cpp2IL / Il2CppDumper sur le snapshot | échecs explicites avant sortie, respectivement `unsupported_metadata_version` et `invalid_metadata` |
| `Get-FileHash -Algorithm SHA256` sur les cinq archives d'outils | 5/5 correspondent aux empreintes consignées dans le rapport M0 |
| `llvm-readobj` sur l'exécutable, `GameAssembly.dll` et les quatre modules approuvés | six en-têtes cohérents avec le lecteur PE interne |
| Ghidra headless `12.1.4` avec `-noanalysis` sur les quatre modules approuvés | code de sortie 0, quatre imports en 51 689,768 ms, aucune auto-analyse/décompilation |
| `Get-AuthenticodeSignature` sur les six copies du snapshot | six signatures valides ; aucune lecture de l'installation live pendant ce contrôle |
| `ruff check` et `ruff format --check` sur l'outil et ses tests | aucun diagnostic ; deux fichiers déjà formatés |
| `git diff --check` et vérification des règles d'ignore | aucune erreur ; `.aitools`, `.ainotes` et `.sample` restent ignorés |

### Vérifications M1 exécutées

| Commande ou contrôle | Résultat réel |
|---|---|
| `python -m unittest discover -s tests -v` | 29 tests exécutés, 29 réussis en 2,214 s |
| `ruff check modkit tests` | aucun diagnostic |
| `ruff format --check modkit tests` | dix-sept fichiers conformes |
| `python -m compileall -q modkit` | code de sortie 0 |
| `python -m json.tool tools.lock.json` | JSON valide |
| `docker compose config --format json` avec chemins factices | configuration valide ; aucun bind Steam/jeu côté analyseur et `inputs` read-only |
| paire finale `modkit import-m0` réelle | 77 payloads validés à chaque run ; snapshot et manifeste M1 identiques |
| paire finale `modkit analyze` réelle | `run-m1-schema-fix-a` : 3 misses ; `run-m1-schema-fix-b` : 3 hits |
| `modkit verify --full-hash` | 77 payloads et 1 439 571 350 octets valides |
| validation JSON Schema des artefacts réels | manifeste, remise, plan et rapport valides |
| inspection SQLite | `user_version=2`, quinze runs, quatre-vingt-dix étapes, dix-huit caches, `foreign_key_check=[]` |
| audit récursif des JSON canoniques | zéro chemin absolu hôte |
| réparation puis `docker image ls` / `docker system df` | magasin de contenu de nouveau lisible ; aucun prune ni effacement volontaire |
| `scripts/build-images.ps1` | deux images Linux/amd64 construites avec provenance/SBOM ; digests et hashes SPDX consignés dans le lock |
| `docker compose run … doctor --refresh` | capture et analyseur `passed` ; Java, Ghidra et BSim réellement sondés dans l’image analyseur |
| deux `docker compose up --no-build analyzer` | même snapshot/build ; premier run 3 misses, second run 3 hits |
| `modkit verify --full-hash` dans l’analyseur | 81 payloads et 1 513 966 479 octets valides |
| inspection des conteneurs et mounts | rootfs read-only, réseau `none`, utilisateur 1000:1000 et `/inputs` read-only côté analyseur |

### Vérifications M2 exécutées

| Commande ou contrôle | Résultat réel |
|---|---|
| `python -m unittest discover -s tests -v` | 33 tests exécutés, 33 réussis en 2,961 s |
| `ruff check modkit tests tools/audit_m2.py` | aucun diagnostic |
| analyse Ghidra/BSim réelle des quatre modules | 53 339 corps, quatre signatures BSim, aucun module hors périmètre |
| `run-m2-real-i` | publication complète ; reprise validée des quatre intermédiaires lourds |
| `run-m2-real-k` | 2 079,976 ms ; quatre modules et publication `cache_hit` |
| `tools/audit_m2.py` sur volume et export NTFS | comptes identiques, `integrity_check=ok`, aucune violation FK |
| réconciliation des états | 53 339 = 53 294 + 3 + 42 + 0 ; catégories exclusives |
| audit des fichiers par corps | 53 297 ASM, 53 294 C et 53 339 vues de chaque sidecar obligatoire |
| audit de portabilité | 476 978 fichiers, composant maximal 92 octets |
| audit de chemin hôte | zéro correspondance dans l’analyse publiée |
| archive `.aitools/bundles/aniimo-m2-1da93dfb99e195f8.tar.gz` | test TAR réussi ; SHA-256 `2b138c092a83f87b3b5aa290dee802905e08724df20c7f80fac12d9a59093159` |
| SBOM analyseur M2 | 439 paquets indexés ; SHA-256 `b1e1458c18e8e6f5ae5b49f1ce42e506dad9834b6ca9405a8c02f08988ec0dda` |

### Vérifications M3 exécutées

| Commande ou contrôle | Résultat réel |
|---|---|
| `python -m pytest -q` | 38 tests réussis en 38,58 s |
| `python -m ruff check .` | aucun diagnostic |
| analyse M2 réelle du build source | 53 348 corps réconciliés ; 53 305 `c_and_asm`, 4 `asm_only`, 39 `disassembly_failed`, 0 `pending` |
| `run-m3-real-a` | 53 847 correspondances publiées en 43 627,595 ms |
| `run-m3-real-b` | matching et documentation `cache_hit`, sentinelles inchangées |
| `tools/audit_m3.py` sur volumes réels | `integrity_check=ok`, `foreign_key_check=ok`, `user_version=6`, aucun chemin absolu |
| audit de promotion | 45 291 candidats non confirmés ; aucune identité ou compatibilité issue du seul BSim/hash |
| archive `.aitools/bundles/aniimo-m3-3cb49fc51b95641a.tar.gz` | table TAR lisible, 46 317 entrées, SHA-256 `a6f909278b95acb9b0e0f67324cd0443cd1d140e6aaa7858f8076137b3a6210e` |
| SBOM analyseur M3 | SPDX 2.3, 439 paquets indexés ; SHA-256 `a69aa69e7c7e14ef78800a48558814a785da6c5cc71383dbf6c90d362e38dc0b` |

### Vérifications M4 exécutées

| Commande ou contrôle | Résultat réel |
|---|---|
| `python -m pytest -q` | 43 tests réussis en 38,28 s |
| `python -m ruff check modkit tools/audit_m4.py tests/test_m4_lua.py` | aucun diagnostic |
| analyse réelle Lua de deux builds | 8 636 scripts uniques chacun ; 17 272 observations de modules et 213 836 observations de symboles par build |
| `run-m4-real-current-a` | extraction, parse borné, bindings et 8 646 fichiers publiés |
| `run-m4-real-historical-a` | XDT revalidé ; 8 636 analyses script réutilisées sur 8 636 |
| `run-m4-real-current-b` | analyse et documentation `cache_hit`, aucune réécriture |
| `tools/audit_m4.py` sur volumes réels | hashes des sorties, `integrity_check=ok`, `foreign_key_check=ok`, `user_version=7` |
| bridge xLua | 515 exports indexés, dont 151 API Lua ; `reference_only`, aucune implémentation exportée |
| sonde runtime | bornage et absence d’appel implicite testés statiquement ; statut `not_tested` |
| archive `.aitools/bundles/aniimo-m4-8a93addbb70efc6c.tar.gz` | table TAR lisible, 19 222 entrées, SHA-256 `8ce3108ee64d4601741499c34e2f07c77fc70467896faf018db147b75203b702` |
| SBOM analyseur M4 | SPDX 2.3, 439 paquets indexés ; SHA-256 `ed30ac1f9c989fd52be9602c751e3610329871469125a3e1f07b2b805a7fd8cd` |

### Vérifications M5 exécutées

| Commande ou contrôle | Résultat réel |
|---|---|
| build .NET 8 hors ligne, exécuté deux fois | zéro avertissement, zéro erreur ; sorties reproductibles |
| même `LuaCatalogExample.dll` sur les deux builds | SHA-256 `d623064583c6aba9b77b0ac77eea487039454b3a7f4cc46de9687534c1af3340` ; deux résultats `passed` |
| build inconnu | adaptateur fermé, capacité indisponible |
| `run-m5-real-generate-b` | `sdk.generation=cache_hit`, aucune réécriture |
| `tools/audit_m5.py` | intégrité SQLite et clés étrangères valides ; package, release et statuts cohérents |
| double construction du package | ZIP identiques ; 9 entrées allowlistées, 861 880 octets |
| archive `.aitools/bundles/aniimo-m5-043c79de2e89c19b.tar.gz` | table TAR lisible, 68 entrées, SHA-256 `a5af994a46effcd5141cd65b42294ad081d9db24668cce5bd80b588c447239f5` |

### Vérifications M6 exécutées

| Commande ou contrôle | Résultat réel |
|---|---|
| `python -m pytest -q` | 47 tests réussis en 44,99 s |
| `python -m ruff check modkit tests tools` | aucun diagnostic |
| `python -m ruff format --check modkit tests tools` | 38 fichiers conformes |
| build .NET 8 M6, exécuté deux fois | zéro avertissement, zéro erreur ; contrat public `AssemblyVersion=1.0.0.0` |
| ancien DLL M5 chargé sans référence de projet | compatibilité binaire `passed` sur les deux builds exacts |
| `run-m6-real-generate-c` avec ordre de builds inversé | `sdk.generation=cache_hit`, aucune réécriture |
| `modkit sdk-verify` et double construction du package | package valide et identique ; 10 entrées, 864 843 octets |
| `tools/audit_m6.py` | release, trois bases, compatibilité, distribution, package, SQLite et clés étrangères `passed` ; `user_version=9` |
| tests CLI du watcher sur fixture synthétique | changement détecté, inchangé ignoré, verrou exclusif, reprise transitoire et arrêt propre |
| SBOM capture / analyseur M6 | 156 / 439 paquets ; SHA-256 `0606c564…ec31` / `a3ccb9af…2518` |
| archive `.aitools/bundles/aniimo-m6-4e839d37fa81325c.tar.gz` | table TAR lisible, 78 entrées, SHA-256 `3e918fef49a8eb55afe9ea89821d2859cf549fddf59f8d8cff10e75b2a12f7ec` |

Les tests synthétiques couvrent notamment la capture bornée et adressée par contenu, la suppression des chemins hôte, l'absence de hash/copie pour l'inventaire, le rejet des traversées de chemin, la validation de métadonnées au-delà du magic, l'état de protection séparé, le lecteur PE borné et la fermeture par défaut du périmètre. La matrice d'acceptation complète n'a pas été exécutée.

## Limites restantes

- aucun extracteur disponible n'interprète encore les métadonnées protégées du build courant ; aucun catalogue IL2CPP, stub, pseudocode ou prétendu source récupéré n'a été produit ;
- 140 sujets restent `needs_review` : M0 confirme leur présence déclarée, pas leur propriété ;
- 42 corps approuvés restent `disassembly_failed` et 45 672 régions/cibles sont explicitement non résolues ; la découverte complète n’est pas revendiquée ;
- 45 799 observations du module NEP2 modifié restent `requires_review` ; M3 ne prétend pas connaître leur identité logique ou leur changement de corps sans métadonnées managées suffisantes ;
- 4 340 chemins Lua du namespace jeu restent des candidats tant qu’aucune identité managée indépendante ne les confirme ; l’analyse Lua n’est pas présentée comme exhaustive ;
- la sonde Lua M4 est livrée mais non exécutée : aucun contexte de menu/partie n’est présenté comme observé ou validé ;
- le watcher M6 est validé sur fixture mais n’a pas été lancé contre l’installation Aniimo réelle pour éviter une acquisition lourde sans changement connu ; il reste opt-in ;
- le package SDK M6 est non signé, l’autorisation éditeur/support n’a pas été demandée et la validation dans le processus du jeu reste `not_tested` ;
- aucun serveur dédié, mode autorisé, contexte runtime ou autorité sur l'état global n'a été établi ;
- aucune injection, installation de loader, sonde runtime ou publication de binaire du jeu n'a eu lieu ;
- Docker Desktop conserve un ancien conteneur en sommeil noyau sur `aniimo-state` ; le registre M2 validé est isolé dans `aniimo-state-m2b` afin de ne pas redémarrer les autres services de l’hôte.

## Prochain travail

**Aucun jalon statique restant : M-1 à M6 sont clos.** Toute installation de loader, sonde dans le processus, signature ou distribution publique constitue un travail runtime/distribution distinct qui exige une autorisation explicite et ne doit pas être déduit de la réussite hors-jeu.
