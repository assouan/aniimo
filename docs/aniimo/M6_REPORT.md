# Rapport M6 — extension additive, watcher et distribution durcie

Date de validation : 2026-10-17

## Résultat final

M6 est terminé pour le périmètre local, statique et hors-jeu autorisé. GameModAPI `1.1.0` ajoute `IBuildIdentity` sans casser le contrat binaire `1.0.0.0`, valide un ancien mod non recompilé, durcit le package avec des empreintes internes, et fournit le watcher optionnel du service de capture.

La release porte la clé `m6-4e839d37fa81325caa82e44d37a6907e159e286395988873ac6a5482cd5a719a`. Elle couvre les deux builds déjà analysés et trois bases de capacité : une base commune pour le catalogue Lua, plus une base d’identité exacte par build. Toutes restent `requires_validation` pour le processus Aniimo, avec validation runtime `not_tested`.

## Extension additive et compatibilité binaire A38

`IBuildIdentity` expose uniquement `BuildId`, `SnapshotId`, backend, architecture, base de capacité et disponibilité. Cette capacité ne donne aucun accès à un objet du jeu, offset ou hook. Les manifests v2 la lient au build/snapshot exact et l’adaptateur refuse toujours un build inconnu.

`GameModAPI.Contracts.dll` conserve `AssemblyVersion=1.0.0.0` et passe à `FileVersion=1.1.0.0`. Le test n’a pas recompilé le mod M5 : il a chargé par réflexion le fichier original `.aitools/sdk-build-m5c/compiled/LuaCatalogExample.dll`, SHA-256 `d623064583c6aba9b77b0ac77eea487039454b3a7f4cc46de9687534c1af3340`, puis l’a exécuté avec le contrat, le runtime et l’adaptateur M6 sur les deux builds exacts. Les deux résultats passent ; un build inconnu renvoie les deux capacités indisponibles.

Le contrat M6 compilé porte le SHA-256 `8ad23f5ae38f74e04a4c6ceaefed89d0d6896ef6f608d95e4049f55660adbb72`. La migration 9 enregistre ce test dans `sdk_binary_compatibility_tests` et le relie à la release exacte.

## Matching natif avancé

Il n’est pas nécessaire pour les deux capacités publiées : elles consomment des manifests statiques exacts et n’installent aucun hook. `native-optimization-evaluation.json` consigne donc `decision=not_needed`, `advanced_native_matching_enabled=false` et `native_hook_count=0`.

Cette décision est un garde-fou, pas un travail omis : les 45 291 candidats M3 ne sont pas promus artificiellement pour justifier une optimisation sans consommateur. Si une future capacité exige un point natif, elle devra déclarer ses symboles/corps/layouts, résoudre toute ambiguïté et obtenir ses propres tests.

## Watcher local optionnel

`modkit watch --interval 300` est disponible dans l’image `capture` uniquement. À chaque itération il réutilise le pipeline complet de plan/capture : lecture SHA-256 en flux, contrôles pré/post, une seule relance en cas de dérive et publication atomique. Il ne se contente pas de notifications filesystem.

Le watcher :

- exécute les captures séquentiellement, avec un verrou exclusif par slot ;
- ne publie une remise que si le `snapshot_id` diffère du dernier snapshot remis ;
- reconnaît une remise identique déjà en attente après une reprise ;
- conserve un état opérationnel sous `inputs/watch/`, hors identités de contenu ;
- poursuit après une erreur transitoire et libère le verrou lors d’un arrêt propre `SIGINT`/`SIGTERM` ;
- ne démarre ni analyseur concurrent, ni jeu, ni sonde runtime.

Les tests utilisent une installation synthétique : première capture remise, capture identique non remise, payload modifié donnant un nouveau snapshot, erreur transitoire reprise, second watcher du même slot refusé et arrêt propre. Aucun watcher n’a été lancé sur l’installation Aniimo réelle simplement pour tester la plomberie, conformément au budget de validation.

## Distribution durcie

Le package `.aitools/packages/GameModAPI-1.1.0.zip` contient dix entrées autorisées. Son manifeste v2 enregistre le SHA-256 et la taille de chaque entrée. `modkit sdk-verify` contrôle le hash externe attendu, les chemins, doublons, chiffrement, timestamps déterministes, limites compressées/décompressées, assemblies/mod autorisés, absence de `.lua`, allowlist déclarée et hashes internes.

Deux constructions indépendantes sont identiques octet pour octet : 864 843 octets, SHA-256 `a70e211abbf315379bff1bea40180b3c57f38d72b9178a126348049e0e8002bf`. Le manifeste interne porte le SHA-256 `0dc607de725c982ec831481f07c9a630ff1650638594b458553ab253dc462b8c`. Un package fixture dont seul `README.md` est altéré est refusé avec `sdk_package_content_mismatch`.

La migration 9 enregistre une attestation `verification_status=passed`. Aucun mécanisme de signature ou identité de publication n’a été inventé : la release reste explicitement `signature_status=unsigned`. Son autorisation externe demeure séparément `not_requested`.

## Validation réelle et cache

Le premier run correct `run-m6-real-generate-b` a publié les manifests v2 avec le SHA-256 de sortie `143263751834eec86c935d5d4e1f478268cb76b1fca2d5813e97b945adedfae4`. Le second run `run-m6-real-generate-c`, appelé avec les builds dans l’ordre inverse, a servi `sdk.generation` depuis le cache complet. L’identité d’une release ne dépend donc pas de l’ordre des arguments.

L’audit final constate SQLite niveau 9, `integrity_check=ok`, aucune violation de clé étrangère, quatre évaluations de capacité, douze validations : quatre `static_contract=passed`, quatre `offline_adapter=passed` et quatre `runtime_game=not_tested`.

| Commande ou contrôle | Résultat |
|---|---|
| build `docker/sdk.Dockerfile` verrouillé | deux builds C# réussis, 0 avertissement, 0 erreur |
| `GameModAPI.Tests` avec le DLL M5 | compatibilité binaire `passed` sur deux builds, sans recompilation |
| deux `modkit sdk-package` | mêmes 864 843 octets et même SHA-256 |
| `modkit sdk-verify --expected-sha256 …` | 10 entrées et tous les hashes internes valides |
| `modkit sdk-finalize` | release `built`, compatibilité/distribution `passed` |
| second `modkit sdk-generate` | `cache_hit`, aucune réécriture |
| `tools/audit_m6.py` | registre, fichiers, package, preuve, cache et statuts conformes |
| `python -m ruff check modkit tests tools` | succès |
| `python -m ruff format --check modkit tests tools` | 38 fichiers conformes |
| `python -m pytest -q` | 47 tests réussis en 44,99 s |

## Images et artefacts

- image capture : `sha256:24dd76a551e6dc6b3550f31b30989dcc59ca41f29d39a37e0a74594f6217d9e9` ;
- image analyseur : `sha256:3d517279c44fbc3c349c6c37ce4995923851fc56e5d9c02a015db8c9b3e77a65` ;
- SBOM capture : `.aitools/sbom/capture-m6.spdx.json`, 732 807 octets, 156 paquets indexés, SHA-256 `0606c564a8084fc97d5dd341fa6894ba82c1d978769fe11f73a5340a44e9ec31` ;
- SBOM analyseur : `.aitools/sbom/analyzer-m6.spdx.json`, 1 718 774 octets, 439 paquets indexés, SHA-256 `a3ccb9afa9b2d39ae741e685fa474e2088a48c6b0c0f870eb24b8f4547152518` ;
- bundle final : `.aitools/bundles/aniimo-m6-4e839d37fa81325c.tar.gz`, 2 020 153 octets, 78 entrées, SHA-256 `3e918fef49a8eb55afe9ea89821d2859cf549fddf59f8d8cff10e75b2a12f7ec` ;
- audit condensé : `.aitools/m6/audit-result.json` ;
- validation watcher : `.aitools/m6/watch-validation.json` ;
- preuve de release : `.aitools/m6/release-evidence.json`.

Le bundle ne contient aucun binaire, script ou dump du jeu. Il contient les contrats/assemblies SDK, le package, les manifests, le vieux mod exemple utilisé comme entrée A38, les rapports, schémas, audits et SBOM.

## Limites qui restent explicites

- aucun loader n’a été installé et aucun test dans le processus Aniimo n’a été exécuté : runtime `not_tested` ;
- aucun artefact n’est signé et aucune autorisation éditeur/support n’a été demandée : `unsigned` et `not_requested` ;
- l’identité retournée est celle du manifest sélectionné ; sa comparaison à un processus réel dépendra du futur bootstrap loader autorisé ;
- aucune capacité native n’est publiée, donc aucune correspondance native candidate n’est activée ;
- le watcher doit être lancé explicitement et n’est actif que tant que son processus `capture` s’exécute.

Ces limites ne sont pas masquées comme des échecs du jalon statique. Toute installation de loader, injection, sonde ou validation en jeu constitue un jalon runtime séparé nécessitant un environnement et une autorisation explicites.
