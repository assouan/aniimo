# Rapport M0 — diagnostic du build Aniimo courant

## Conclusion

M0 est terminé sur une capture immuable du build Steam `25988361` (App ID `4126040`). Le diagnostic courant identifie un client Windows x86-64, IL2CPP, Unity `2022.3.62f1`, avec un bridge xLua. Il ne démontre aucun serveur dédié ni aucune autorité serveur.

Le snapshot est identifié par :

```text
m0-2e5970fff08c8e9cdc829adfb026ad263037246ef31a47ba466b8a2e85809560
```

Il se trouve sous `.aitools/m0-acquisition/<capture_id>/` et contient 77 payloads allowlistés pour 1 439 571 350 octets. Ses 69 observations d'inventaire ne conservent et ne hachent aucun corps. Les quatre feature sets ordinaires — `core`, `lua`, `content_indexes` et `anti_cheat` — sont présents.

## Preuves principales

- `GameAssembly.dll` est un PE natif sans répertoire CLR et forme une paire de capture cohérente avec `global-metadata.dat` ; aucun payload Mono managé ni configuration Mono sélectionnée n'est présent.
- `globalgamemanagers` contient la version Unity `2022.3.62f1`.
- `xlua.dll` est un PE x86-64 et expose 151 entrées de l'API Lua observées par le lecteur PE borné.
- Les paires d'archives Lua active et intégrée sont présentes et ont des contenus identiques ; elles n'ont pas été décompressées.
- `ScriptingAssemblies.json` énumère 190 noms d'assemblies. Un nom ne suffit pas à attribuer la propriété du code.
- `SymbolMap` et les PDB sélectionnés sont absents ; aucune adresse ou information de debug n'a été inventée.

Le fichier de métadonnées possède les octets initiaux `AF 1B B1 FA`, soit le magic standard `0xFAB11BAF`. Le champ suivant vaut `28881824`, valeur impossible comme version IL2CPP directe ; la région d'en-tête attendue est non conforme et son échantillon possède une entropie de `7,685424` bits/octet. Le statut est donc `suspected_protection`. Cette qualification combine ces preuves et ne repose jamais sur le magic seul.

## Périmètre

Les 251 sujets recensés sont répartis ainsi : 4 `game_decompile`, 105 `reference_only`, 2 `excluded` et 140 `needs_review`.

Les quatre seules approbations complètes M0 sont :

| Module | Résultat courant | Décision |
|---|---|---|
| `NEP2.dll` | PE x86-64 GUI, signature valide Pawprint | `game_decompile` |
| `NEPKernel.sys` | PE x86-64 native, signature WHCP valide | `game_decompile` |
| `NEPCleaner.exe` | PE x86 GUI, signature NetEase valide | `game_decompile` |
| `KernelDumpAnalyzer.exe` | PE x86-64 console, signature valide Pawprint | `game_decompile` |

Ils ont été capturés, mais pas décompilés. `GameAssembly.dll` reste un conteneur mixte `needs_review`, sans approbation globale. Unity, les frameworks, le runtime IL2CPP et xLua restent `reference_only`. Le manifeste éditeur signale en outre un candidat nominal `worldx_Data/Plugins/x86_64/NEP2.dll` ; son corps n'est pas observé dans l'inventaire borné et son rôle reste inconnu.

## Outils testés

| Outil | Essai M0 | Décision |
|---|---|---|
| Cpp2IL `2022.1.0-pre-release.21+58fc404…` | rejet du champ de version avant sortie | incompatible sans chargeur adapté |
| Il2CppDumper `6.7.46+8a521…` | initialisation des métadonnées en échec avant dump | incompatible sans chargeur adapté |
| Il2CppInspectorRedux `2026.2` | CLI bloqué faute de .NET 10 ; couple du jeu non fourni | non validé |
| `llvm-readobj 22.1.8` | six en-têtes PE recoupés | valide pour ce contrôle borné |
| Ghidra `12.1.4` + Microsoft OpenJDK `25.0.4.1+1-LTS` | import headless `-noanalysis` des quatre modules approuvés | formats pris en charge ; aucune analyse M2 effectuée |
| BSim CLI `12.1.4` | aide/initialisation réussie | aucune signature ou base générée en M0 |

Les archives effectivement essayées ou préparées ont les SHA-256 suivants :

| Paquet | SHA-256 de l'archive | Source |
|---|---|---|
| Cpp2IL `2022.1.0-pre-release.21` | `663fb432433b4371fd1ee0ebc321a8fff2a9aac5ac4230c843f9e03ddee4e04c` | [release officielle](https://github.com/SamboyCoding/Cpp2IL/releases/tag/2022.1.0-pre-release.21) |
| Il2CppDumper `6.7.46` | `d1117d66b9f8a130fd4933ae99f8eb9a0ecbbdb79d1fc494eb738ad910ff765a` | [release officielle](https://github.com/Perfare/Il2CppDumper/releases/tag/v6.7.46) |
| Il2CppInspectorRedux `2026.2` | `65c697bf79e03f1d530f98db5efd77b88831109cb7e91513bf132e56571358ef` | [release officielle](https://github.com/LukeFZ/Il2CppInspectorRedux/releases/tag/2026.2) |
| Ghidra `12.1.4` | `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` | [release officielle](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build) |
| Microsoft OpenJDK `25.0.4.1+1-LTS` | `3c9099e60a82e17f5847052f50f3b107bfc1d32b366e1a20adbd1d0f303760e7` | [téléchargement Microsoft](https://learn.microsoft.com/java/openjdk/download) |

Ces valeurs documentent les essais M0 ; elles ne constituent pas un verrou de production. La preuve structurée locale reste `.aitools/m0-tool-probes/results.json`. `tools.lock.json` demeure correctement `unresolved`, car aucune chaîne IL2CPP complète n'a réussi sur le couple exact et aucune image M1 n'existe encore.

## Artefacts

Le dossier `diagnostic/` du bundle contient :

- `detection.json` : faits courants, preuves, comparaison historique et incertitudes ;
- `scope-plan.json` : une décision initiale pour chaque sujet, avec raison, auteur, politique et capture applicables ;
- `tool-compatibility.json` : versions, checksums, essais, échecs et recommandation ;
- `additional-input-candidates.json` : 86 candidats de métadonnées, sans corps ni hash complet ;
- `report.md` : vue lisible du diagnostic ;
- `diagnostic-manifest.json` : hashes des cinq artefacts précédents.

Chaque JSON de diagnostic porte le hash du manifeste de capture, celui de la politique de décompilation et celui du producteur Python exact. La commande `verify` a relu les 1 439 571 350 octets des 77 payloads sans erreur.

Le rapport opérationnel séparé `run-report/` contient les versions JSON et Markdown du déroulé hiérarchique : capture, diagnostic et sous-étapes, essais réussis ou en échec, travaux M1/M2/runtime explicitement sautés, vérification, durées monotones, cache, quantités, outils et ressources légères. Ces données de temps ne participent ni au `capture_id`, ni aux empreintes des artefacts canoniques, ni à une clé de cache.

## Suite recommandée

La branche est `il2cpp_with_protected_metadata`. M1 doit construire la frontière reproductible entre capture et analyse, puis réimporter ou recapturer M0 selon son contrat versionné. Avant M2, un chargeur de métadonnées non exécutant devra être validé sur ce couple exact. Aucun fallback approximatif, loader runtime, injection ou décompilation globale n'est autorisé par ce résultat.
