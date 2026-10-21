# Rapport M1 — infrastructure reproductible

Date : 2026-10-17

## État du jalon

M1 est terminé et validé. Les validations hôte, synthétiques, images et Compose réussissent. M2 peut commencer.

Le magasin Docker Desktop contenait un index OCI référencé dont le blob manquait. Le blob exact a été reconstruit depuis les manifests locaux encore présents, vérifié par taille et SHA-256, puis restauré atomiquement. Docker Desktop a été redémarré ; les sept services actifs ont retrouvé leur état `running`. Aucun prune et aucune suppression volontaire de conteneur, volume ou image n’ont été effectués.

## Livré

- la CLI Python `modkit` fournit `doctor`, `capture`, `plan`, `analyze`, `import-m0` et `verify` ;
- `capture` résout l’allowlist une fois, vérifie `StateFlags=4`, sépare payload et inventaire, contrôle chaque lecture avant/après et publie les objets SHA-256 et snapshots immuables atomiquement ;
- `--dry-run` emploie le même planificateur et s’arrête avant toute écriture dans `inputs` ;
- la remise contient le `snapshot_id` exact et le SHA-256 du manifeste, utilise un slot créé sans écrasement et est revendiquée avant analyse ;
- l’analyseur refuse une remise absente, partielle ou au mauvais digest, ne retombe pas sur `current` et possède une sonde de frontière read-only ;
- les migrations `0001_capture.sql` et `0002_pipeline_scope.sql` créent le registre SQLite avec clés étrangères, sauvegarde préalable et restauration sur erreur ;
- les CAS d’entrée et d’artefacts sont séparés ; les checkpoints et sorties ne sont réécrits que si leur contenu change ;
- les clés de cache incorporent snapshot, profil, politique et lock d’outillage ; les étapes logiques Ghidra/BSim de M1 ne décompilent rien et disposent d’un seam d’invocation testé ;
- les rapports fusionnés JSON, Markdown et CSV conservent la hiérarchie des étapes, les durées monotones, statuts de cache, volumes et ressources légères ;
- `compose.yaml` sépare effectivement `capture` et `analyzer` et déclare exactement les sept volumes préfixés ; seul `capture` voit les binds du jeu et de Steam, et `analyzer` monte `inputs` en lecture seule ;
- les Dockerfiles utilisent Python `3.12.8-slim-bookworm` par digest, PyYAML `6.0.2` par hash, Microsoft OpenJDK `25.0.4` et Ghidra/BSim `12.1.4` par archives SHA-256 ; le script `scripts/build-images.ps1` demande les attestations SBOM et exporte des SBOM SPDX avec Docker Scout ;
- quatre JSON Schema versionnent le manifeste, la remise, le plan d’analyse et le rapport de run.
- `tools.lock.json` est monté comme configuration read-only au lieu d’être incorporé aux images, ce qui évite une autoréférence impossible entre le lock et le digest de l’image ;
- les deux images possèdent une attestation SBOM BuildKit et un export SPDX contrôlé par SHA-256.

## Images et SBOM validés

| Élément | Digest |
|---|---|
| `aniimo-capture:m1` Linux/amd64 | `sha256:7682c5f9d7cfe30f730b292273ef13fc7672fde36879aed08b3f7f5615137111` |
| `aniimo-analyzer:m1` Linux/amd64 | `sha256:ae0152abd6fd27cdf88df69a5db19a2187d04f736d49c5c6233d28a7c6834570` |
| SBOM SPDX capture | `sha256:bb941169f0467acf8ab5814ae3a08c2ae51c380db56383841fb7147f6b882ea4` |
| SBOM SPDX analyseur | `sha256:7219412278834da1538181f13078b63b1c8acb504d3848f8f9075068ca9bcf29` |

Les smokes dans l’image non privilégiée confirment Python 3.12.8, PyYAML 6.0.2, Microsoft OpenJDK 25.0.4+7-LTS, Ghidra headless 12.1.4 et BSim 12.1.4. L’URL JDK est l’artefact final immuable observé derrière le redirect Microsoft et son SHA-256 reste vérifié pendant le build.

## Réimportation réelle M0 → M1

Le bundle M0 n’a pas été renommé ni adopté implicitement. `modkit import-m0` a relu et validé ses 77 payloads, puis créé un nouveau snapshot M1 sous `.aitools/m1-validation/` :

| Élément | Valeur |
|---|---|
| Source M0 | `m0-2e5970fff08c8e9cdc829adfb026ad263037246ef31a47ba466b8a2e85809560` |
| Manifeste M0 | `fc6e73d5b924ad6cc1224594452a14dbe2fb21572379edd4e50d16f211e91677` |
| Payloads validés | 77 |
| Octets validés | 1 439 571 350 |
| Snapshot M1 | `snapshot-5c0bfbc5aca5b3e8ce1fd6845761a334b7944e787bea49a203e2c594204b07a4` |
| Build M1 | `build-f6a55533606d4b70ad7983f6307b9d8a3e5d70524033ab3d7d85b7fdafd7d41f` |
| Manifeste M1 | `c83d4c4038954b6c0fe1a5e3ea640bf0b0ce9461527bd845d6bab39eb1bef7b0` |

Une seconde réimportation a produit exactement le même snapshot et le même manifeste. L’analyse associée a marqué `scope`, `ghidra` et `bsim` `cache_hit`, sans réécrire leurs sorties. Les enrichissements successifs du contexte — lock d’outillage, digest du producteur, extension à tout le package `modkit`, digest de manifeste de base par plateforme, puis correction du contrat publié du plan d’analyse — ont chacun invalidé les trois étapes exactement une fois ; le run suivant de chaque contexte a de nouveau produit trois hits. La paire finale utilise la clé `analysis-710cd2fcd356341dda3a61af108213366a21ce4673983967cc3395c611fb77a6`. Le contrôle complet du CAS a rehaché les 1 439 571 350 octets avec succès. Un audit récursif des JSON canoniques a trouvé zéro chemin hôte absolu.

Le registre réel est au niveau de migration 2, contient quinze runs d’analyse, quatre-vingt-dix étapes et dix-huit entrées de cache couvrant les six contextes successifs ; `PRAGMA foreign_key_check` ne retourne aucune violation. Le dernier run de capture a relu une fois chacun des 77 payloads, créé zéro objet et réutilisé les 77 objets existants. Le plan M1 des 77 payloads retient exactement quatre modules `game_decompile`, quatre conteneurs/candidats `needs_review` et 69 éléments `reference_only`. Il ne remplace pas le catalogue M0 plus large de 251 sujets.

## Orchestration Compose réelle

Deux exécutions complètes ont monté l’installation live uniquement dans `capture`, en lecture seule, puis transmis le snapshot immuable par deux slots distincts. Elles ont produit le même snapshot `snapshot-58a1510492a6987eb006e0ff901702f35bec414a416e184558ccdb1a4ca12adf`, le même build `build-6153068c4ea08c06123406e0873b667f6db5b02bb3d17aa71833d565ec3838ec` et le manifeste `843038e8c6f93e84ffce0b734febaf10440b5f8413399e75524c67885e022d73`.

Le snapshot Compose contient 81 payloads et 1 513 966 479 octets. Depuis le bundle M0, les sept chemins actifs de l’index de contenu `3741626` ont été remplacés par leur révision `3743667`, et quatre entrées du cache de contenu `3743667` sont désormais sélectionnées. Cette dérive de contenu explique le nouveau `build_id` même si la référence Steam reste utile ; elle ne change aucune autorisation de décompilation. Le second run `run-9dc8670c-bacd-4fb7-a62e-d929aaffd1be` a réutilisé 81 objets, n’en a créé aucun et a servi `scope`, `ghidra` et `bsim` depuis le cache. Le hash intégral des 81 payloads passe.

L’inspection effective confirme `read_only=true`, réseau `none`, utilisateur `1000:1000`, aucun bind jeu/Steam côté analyseur et `/inputs` monté read-only. Les quatre artefacts réels — manifeste, remise, plan et rapport — valident leurs JSON Schema, et aucun chemin Windows absolu n’apparaît dans les sorties canoniques.

## Validations exécutées

| Commande ou contrôle | Résultat réel |
|---|---|
| `python -m unittest discover -s tests -v` | 29 tests exécutés, 29 réussis en 2,214 s |
| `ruff check modkit tests` | aucun diagnostic |
| `ruff format --check modkit tests` | dix-sept fichiers conformes |
| `python -m compileall -q modkit` | code de sortie 0 |
| `python -m json.tool tools.lock.json` | JSON valide |
| `docker compose config --format json` avec chemins factices | configuration valide ; frontières de mounts inspectées |
| paire finale `modkit import-m0` sur le bundle réel | même snapshot/manifeste ; reçus d’import distincts |
| paire finale `modkit analyze` sur les deux remises réelles | `run-m1-schema-fix-a` : trois misses ; `run-m1-schema-fix-b` : trois hits |
| `modkit verify --full-hash` sur le snapshot M1 | 77 payloads et 1 439 571 350 octets valides |
| audit des chemins canoniques | zéro chemin absolu hôte |
| validation JSON Schema des artefacts réels | manifeste, remise, plan et rapport valides |
| inspection SQLite | version 2, quinze runs, quatre-vingt-dix étapes, dix-huit caches, aucune violation de clé étrangère |
| `scripts/build-images.ps1` | deux images construites avec provenance et attestations ; deux SBOM SPDX exportés |
| smokes `doctor --refresh` dans Compose | capture et analyseur `passed`, outils natifs réellement sondés |
| deux runs `docker compose up --no-build analyzer` | première exécution : trois misses ; seconde : trois hits sur le même snapshot |
| `modkit verify --full-hash` dans l’image | 81 payloads, 1 513 966 479 octets, statut `valid` |
| validation JSON Schema / audit de chemins | 4/4 valides ; zéro chemin hôte absolu dans `output` |

Les assertions ciblent directement A02–A04, A35, A43–A45, A54–A55, A57, A59–A60, A63–A69 et A79–A80 à l’échelle de fixtures ; elles ne prétendent pas exécuter le catalogue d’acceptation complet. Le seam synthétique appelle quatre cibles approuvées pour chacune des étapes logiques Ghidra et BSim au premier run, puis zéro au second.

## Limites et condition de reprise

- `tools.lock.json` conserve l’état global `unresolved` uniquement parce que le chargeur des métadonnées IL2CPP protégées n’est pas encore validé ; les images, SBOM, JDK, Ghidra et BSim y sont désormais réellement consignés ;
- les artefacts `ghidra-plan.json` et `bsim-plan.json` sont des contrats M1 de plan/cache, pas des résultats Ghidra, signatures BSim ou pseudocode ;
- aucune décompilation, extraction Lua, sonde runtime, injection ou installation dans le jeu n’a eu lieu ;
- M2 reste conditionné à la validation d’un chargeur non exécutant pour les métadonnées IL2CPP protégées exactes.

M1 ne conserve aucun blocage. M2 doit maintenant valider un chargeur déterministe et non exécutant pour le couple IL2CPP exact, puis produire les exports natifs bornés aux cibles approuvées. Les plans Ghidra/BSim M1 ne sont pas présentés comme des résultats de décompilation.

