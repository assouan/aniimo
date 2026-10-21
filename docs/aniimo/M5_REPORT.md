# Rapport M5 — contrat SDK, adaptateurs exacts et mod exemple

Date de validation : 2026-10-17

## Résultat

M5 est validé pour son périmètre statique et hors-jeu. La release SDK `1.0.0` expose une seule capacité publique utile et volontairement sûre, `ILuaModuleCatalog` (`aniimo.lua-module-catalog`). Elle permet à un mod de vérifier la présence et le hash d’un module Lua observé sans exposer d’offset, d’objet du jeu, de hook natif ou d’implémentation extraite.

La release porte la clé `m5-043c79de2e89c19b802c12b7444600685050ab85cb3496a6692468f6993ef9c1`. Les deux builds exacts partagent la base de capacité `capability-basis:824c7634cfe094dae88791a9062ccbc32a66d5a0b2abdc470c89b32239b3a7e0`, car leur catalogue actif de 8 636 modules, le bridge xLua, le résolveur, l’ABI et les tests requis ont la même empreinte. Ce partage est une conclusion limitée à cette capacité ; il ne certifie ni le build global ni un hook.

## Contrat et adaptateur

`GameModAPI.Contracts` cible `netstandard2.1` et définit `IGameMod`, `IModContext`, `IModLogger` et `ILuaModuleCatalog`. Le runtime et l’adaptateur Aniimo ciblent .NET 8. L’adaptateur ne résout que les manifests signés par leur identité de build exacte ; tout build inconnu renvoie `Unavailable` avec `unknown_build_fail_closed`.

Les manifests de build restent `requires_validation` et `runtime_validation_status=not_tested`. La compilation est reproductible hors ligne avec l’image .NET SDK `8.0.408-bookworm-slim` verrouillée au digest Linux/amd64 `sha256:f02ec8dea350dd13da18c4e4705a603221b4089a5c5d36c31bac335e3b5fa837`. Elle s’est terminée avec zéro avertissement et zéro erreur.

Le mod exemple `LuaCatalogExample.dll` recherche `Common.Ability.AbilityManager` uniquement via le contrat public. Le même binaire, SHA-256 `d623064583c6aba9b77b0ac77eea487039454b3a7f4cc46de9687534c1af3340`, a été chargé hors-jeu contre les deux adaptateurs. Les deux cas retrouvent le même module et son hash `6492c74f88a552a987a8b6971af45864d0c5acb8d410e894a77a5c7aa64f0105`; un build synthétique inconnu échoue fermé.

## Loader évalué

BepInEx Unity IL2CPP `6.0.0-pre.2` est retenu comme candidat existant au lieu de réécrire un loader. L’archive officielle Windows x64 fait 34 146 254 octets et porte le SHA-256 `616ec7eb06cf11b2a0000e8fcef04d1b12bb58e84a2e0bdac9523234fc193ceb`. Les assemblies embarquées ont été inspectées, notamment BepInEx Core/Unity IL2CPP `6.0.0.0`, Il2CppInterop Runtime `1.4.6.0` et Cpp2IL Core `2022.1.0.0`.

Le loader n’a pas été installé, l’installation Aniimo n’a pas été modifiée et aucun processus de jeu n’a été lancé. Son état est donc exactement `selected_candidate`, `not_installed`, `not_tested`. Aucune version plus récente d’Il2CppInterop n’est substituée silencieusement à celle du bundle évalué.

## Publication et preuves

Le ZIP `.aitools/packages/GameModAPI-1.0.0.zip` contient neuf entrées issues d’une allowlist explicite : trois assemblies SDK, le mod exemple, deux manifests d’adaptateur, la documentation, l’évaluation du loader et le manifeste du package. Il ne contient aucun binaire, script, dump ou donnée personnelle du jeu. Deux constructions indépendantes sont identiques octet pour octet : 861 880 octets, SHA-256 `1e721d7b9952003d6f3ce1a60cee63525bb1f2b688a58f0ce41889e51a215454`.

Le contrat compilé porte le SHA-256 `a0fa924148b858f81c5f20d09025d5d49044a74297dcfb62db14664a69cc0cfd`. Le registre SQLite niveau 8 contient deux validations `static_contract=passed`, deux `offline_adapter=passed` et deux `runtime_game=not_tested`. Les évaluations restent `requires_validation`, avec tests requis `partial`, et l’autorisation externe du package exact reste `not_requested`.

L’identité de release est indépendante de l’ordre des options `--build`. Le second run `run-m5-real-generate-b` a servi `sdk.generation` depuis le cache complet sans réécrire les sorties. Le manifeste de sortie porte le SHA-256 `d20d743691c68701977bd69c3f033cd3df8e5ddbd9870bc8e187d625d602a51e`.

Artefacts de preuve :

- SBOM SPDX 2.3 : `.aitools/sbom/analyzer-m5.spdx.json`, 1 718 774 octets, SHA-256 `5bed382d38164f38894f0616523009c4d1c86ac7e09c27cd0e45f920126c45f0` ;
- bundle M5 : `.aitools/bundles/aniimo-m5-043c79de2e89c19b.tar.gz`, 1 736 685 octets, 68 entrées, SHA-256 `a5af994a46effcd5141cd65b42294ad081d9db24668cce5bd80b588c447239f5` ;
- audit condensé : `.aitools/m5/audit-result.json` ;
- preuve de release : `.aitools/m5/release-evidence.json`.

## Validations réellement exécutées

| Commande | Résultat |
|---|---|
| build `docker/sdk.Dockerfile` avec export local | .NET SDK 8.0.408, zéro avertissement, zéro erreur |
| `GameModAPI.Tests` dans le conteneur .NET verrouillé | même DLL de mod passée sur deux builds ; build inconnu refusé |
| deux appels `modkit sdk-package` | ZIP identiques, même SHA-256 |
| `modkit sdk-finalize` | release `built`, validation hors-jeu `passed`, runtime `not_tested` |
| second `modkit sdk-generate` avec ordre inversé | `cache_hit`, aucune réécriture |
| `tools/audit_m5.py` | intégrité SQLite et clés étrangères `ok`, package/contrat/cache/statuts conformes |
| `python -m ruff check modkit tests tools` | succès |
| `python -m pytest -q` | 44 tests réussis en 36,85 s |

Les tests M5 couvrent notamment A37, A40, A42, A51, A53 et A58. A38, la compatibilité binaire d’un ancien mod non recompilé avec un nouvel adaptateur, est réservé à l’extension M6 puisqu’il faut deux versions réelles du contrat/adaptateur.

## Limites

- aucune validation dans le processus Aniimo n’a été exécutée ; les capacités ne sont donc pas marquées `compatible` pour le runtime ;
- aucune autorisation de distribution n’a été demandée ou supposée ;
- le catalogue est une vue statique exacte des modules observés, pas une promesse que chaque module est chargeable dans chaque phase du jeu ;
- aucun hook, callback, objet Unity ou fonction native n’est exposé par cette release.

## Suite

M6 peut ajouter une capacité additive d’identité de build, tester un ancien mod `1.0.0` non recompilé contre le nouvel adaptateur, durcir la vérification de distribution et fournir un watcher local optionnel. Le matching natif avancé n’est pas nécessaire pour ces capacités sans hook et ne doit pas être activé artificiellement.
