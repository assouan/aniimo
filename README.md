# Aniimo Mod SDK — atelier d’analyse et runtime de mods

Ce dépôt décrit et accueillera une chaîne locale, reproductible et incrémentale pour analyser le code propre à Aniimo, suivre ses mises à jour et construire une API stable consommable par des mods `.dll`.

Le dépôt versionné ne contient aucun binaire du jeu, aucun dump global et aucun loader prêt à installer. Le dossier local ignoré `.sample` conserve un ancien lot de travail ; il fournit des indices historiques, mais ne constitue ni une détection du build actuellement installé, ni une dépendance reproductible du projet.

## État

Les jalons M-1 à M6 sont terminés. M1 a validé l’orchestration et les snapshots ; M2 a analysé les quatre modules natifs approuvés et réconcilié 53 339 corps ; M3 a comparé deux builds sans promouvoir les candidats ; M4 a analysé 8 636 scripts Lua uniques ; M5 a livré le premier SDK ; M6 ajoute l’identité de build, prouve la compatibilité d’un ancien mod non recompilé, durcit la distribution et fournit le watcher optionnel. Les validations dans le processus du jeu restent honnêtement `not_tested`. Voir `STATUS.md` et les rapports `docs/aniimo/M0_REPORT.md` à `M6_REPORT.md`.

## Frontières du système

- Le conteneur léger `capture` est le seul à voir l’installation Steam, en lecture seule. Il copie uniquement l’allowlist dans le volume nommé `inputs` et publie un snapshot atomique.
- Le conteneur `analyzer` ne monte jamais le dossier du jeu. Il revendique la remise contenant le `snapshot_id` immuable exact de ce run, lit ce snapshot depuis `inputs` en lecture seule, puis exécute l’analyse statique, les comparaisons, la documentation et éventuellement la compilation des assemblies managées. Le pointeur `current` reste un raccourci manuel et n'est pas utilisé par l'orchestration normale.
- Le jeu et les hooks s’exécutent sous Windows dans un processus autorisé, jamais dans le conteneur Linux d’analyse.
- L’autorisation éditeur/support applicable à la distribution est enregistrée séparément de la validation technique d’un hook ou d’un build.
- Les entrées du jeu sont montées en lecture seule. Après la capture, les étapes travaillent exclusivement sur un snapshot immuable adressé par contenu.

## Périmètre strict

Le pipeline décompile les implémentations propres au jeu, les intégrations approuvées et les composants anti-cheat explicitement autorisés par ce profil. `NEP2.dll`, `NEPKernel.sys`, `NEPCleaner.exe` et `KernelDumpAnalyzer.exe` sont des cibles de décompilation et de documentation complètes. Unity, .NET/Mono/IL2CPP, le moteur Lua et les autres bibliothèques tierces restent exclus de l’export massif de leurs implémentations.

Avec IL2CPP, `GameAssembly.dll` est un conteneur mixte. Les corps sont sélectionnés d’après l’assembly managée d’origine et les preuves de propriété ; le module n’est jamais traité comme un bloc entièrement propriétaire du jeu.

La liste de copie et la liste de décompilation sont volontairement distinctes. `profiles/aniimo.inputs.yaml` contient les payloads autorisés dans `aniimo-inputs`. Le profil Aniimo active déjà `core`, les archives Lua, les index de contenu et `anti_cheat` afin qu'une mise à jour standard soit complète. `profiles/aniimo.decompilation.yaml` préapprouve les quatre composants anti-cheat connus comme modules complets ; M0 les a confirmés et a classé chaque sujet courant dans son `scope-plan.json` sans lancer de décompilation.

## Aniimo : indices historiques et résultat M0

Le lot local du 16 octobre 2026 indique, pour le Steam build `25962016`, Windows x64, Unity `2022.3.62f1`, IL2CPP, xLua et les octets de magic `AF 1B B1 FA`. Ce magic est la représentation little-endian de la valeur IL2CPP standard `0xFAB11BAF` ; la conformité du reste des métadonnées reste inconnue. Ces éléments sont consignés dans `docs/aniimo/HISTORICAL_EVIDENCE.md` et dans `profiles/aniimo.yaml` avec le statut `unverified_for_current_installation`.

M0 les a comparés indépendamment au snapshot courant, sans utiliser `.sample`. La version Unity, le backend IL2CPP, l'architecture x86-64 et xLua sont confirmés ; le build historique est contredit par le build courant `25988361`. Aucun résultat historique n’a été promu automatiquement.

## Exécution cible

```powershell
Copy-Item .env.example .env
New-Item -ItemType Directory -Force output | Out-Null
./scripts/build-images.ps1
docker compose up --abort-on-container-failure
```

La surveillance locale reste une commande explicite du seul service autorisé à lire l’installation :

```powershell
docker compose run --rm capture watch --interval 300
```

Elle sérialise les captures, reprend les erreurs transitoires et ne publie une remise que pour un nouveau snapshot. Elle ne lance pas le jeu ni l’analyseur en parallèle.

La commande `up` exécute automatiquement : préflight/`doctor`, plan de capture, capture, plan d'invalidation, extraction nécessaire, ILSpy ou chaîne IL2CPP, Ghidra, BSim, Lua, comparaison, documentation, rapport et publication. Chaque étape consulte d'abord son cache.

Le préflight léger s'exécute à chaque run. Les contrôles stables de `doctor` — présence et version des outils, chargement des adaptateurs — sont mis en cache selon les digests des images, du lock et du profil, puis relancés automatiquement seulement si l'un change. La commande explicite `doctor --refresh` force un diagnostic complet.

Le plan utilisé par `capture --dry-run` est déjà calculé par le vrai workflow puis réutilisé sans second inventaire. L'option `--dry-run` signifie uniquement « afficher ce plan et s'arrêter avant l'écriture ». `verify` et les sondes runtime restent explicites car ils valident une release ou un processus de jeu, pas une mise à jour statique ordinaire.

Le préfixe littéral `ANIIMO_VOLUME_PREFIX`, par défaut `aniimo-`, produit `aniimo-inputs`, `aniimo-handoff`, `aniimo-state`, `aniimo-artifacts`, `aniimo-ghidra`, `aniimo-cache` et `aniimo-work`. Le conteneur de capture utilise par défaut 4 CPU et 4 Gio ; l’analyseur utilise 12 CPU, 32 Gio et 24 Gio de heap Ghidra. Ces valeurs restent configurables dans `.env`.

`capture` est incrémental et ne décompresse rien. Il effectue une seule lecture SHA-256 des payloads configurés, avec un contrôle léger avant/après. Un objet déjà présent n’est pas recopié. Si les clés de cache complètes sont identiques, `analyzer` marque extraction, Ghidra, décompilation et BSim comme `cache_hit`, sans relancer les outils ni réécrire les sorties. Les échecs C inchangés sont eux aussi mémorisés et ne sont pas retentés à chaque update. Une nouvelle DLL, archive Lua ou index modifié produit une nouvelle révision ; seules les étapes dépendantes sont invalidées.

Pour chaque corps natif approuvé et lisible, l'ASM est produit indépendamment du succès du C. Les sorties utilisent les états exclusifs `c_and_asm`, `asm_only`, `disassembly_failed` et `pending`, avec un `coverage.json` réconcilié. La vue obligatoire permet de naviguer par assembly/namespace/type/méthode ou par module/fonction et lie directement C, ASM, signature, prototype natif, références et diagnostics.

Chaque exécution publie sous `output/reports/<run_id>/` un rapport JSON, Markdown et CSV détaillant les étapes et sous-étapes, leurs durées, cache hits/misses, quantités traitées, erreurs et ressources mesurables. `output/reports/latest.json` pointe vers le dernier rapport complet.

## Contenu

- `WORKFLOW.md` : architecture, pipeline, incrémentalité, Lua et SDK.
- `STUDY.md` : revue externe ayant motivé les garanties ASM, couverture, reprise et remise de snapshot.
- `AGENTS.md` : invariants de développement et de preuve.
- `STATUS.md` : état réel des jalons et validations exécutées.
- `CODEX_PROMPT.md` : contrat initial des jalons ; `STATUS.md` reste l’état d’exécution courant.
- `specs/DATA_MODEL.md` : registre, identités, preuves et exports.
- `specs/ACCEPTANCE.md` : scénarios de validation automatisables.
- `specs/DOCKER_CONTRACT.md` : contrat du conteneur et des volumes.
- `docs/architecture/OVERVIEW.md` : vue d'ensemble des flux et frontières.
- `docs/adr/` : décisions architecturales durables.
- `docs/aniimo/` : preuves historiques résumées sans binaire du jeu.
- `docs/aniimo/INPUT_PIPELINE.md` : séparation allowlist, capture et décompilation.
- `docs/aniimo/M0_REPORT.md` : synthèse du diagnostic réel et de la matrice d'outillage, sans chemins hôte.
- `docs/aniimo/M1_REPORT.md` : validation du pipeline conteneurisé, des snapshots et du cache.
- `docs/aniimo/M2_REPORT.md` : couverture native réelle, sorties, limites IL2CPP et preuves de cache.
- `docs/aniimo/M3_REPORT.md` : comparaison réelle de deux builds, invalidations, candidats et documentation incrémentale.
- `docs/aniimo/M4_REPORT.md` : extraction Lua réelle, dialecte borné, bindings, définitions LuaLS et sonde séparée.
- `docs/aniimo/M5_REPORT.md` : contrat SDK, adaptateurs exacts, loader évalué, mod exemple et package reproductible.
- `docs/aniimo/M6_REPORT.md` : extension additive, ancien mod non recompilé, watcher et distribution durcie.
- `tools/m0_diagnose.py` : utilitaire borné `capture`/`diagnose`/`verify` propre au jalon M0.
- `tools/audit_m2.py` : audit read-only du registre, de la couverture et des fichiers M2.
- `tools/audit_m3.py` : audit read-only de la comparaison, du registre multi-build et du cache documentaire.
- `tools/audit_m4.py` : audit read-only des sorties Lua, du registre, du périmètre xLua et du cache.
- `tools/audit_m5.py` : audit read-only de la release SDK, des validations, du package et de sa reproductibilité.
- `tools/audit_m6.py` : audit final de la compatibilité binaire, de l’attestation de distribution et des statuts M6.
- `profiles/aniimo.yaml` : profil spécifique, sûr par défaut.
- `profiles/aniimo.inputs.yaml` : liste bornée des fichiers copiables vers le volume d’entrées.
- `profiles/aniimo.decompilation.yaml` : politique de périmètre ; composants inconnus fermés par défaut et quatre modules anti-cheat préapprouvés intégralement.
- `profiles/game.example.yaml` : modèle générique.
- `profiles/input-selection.example.yaml` et `profiles/decompilation.example.yaml` : contrats génériques séparés.
- `compose.yaml` : orchestration M1 exécutable en une commande avec images validées.
- `examples/compose.example.yaml` : modèle commenté de la même frontière de services.
- `modkit/` : CLI de capture, analyse, CAS, remise, registre et rapports.
- `docker/` : images séparées et entrypoint non privilégié.
- `migrations/` et `schemas/` : contrats SQLite et JSON versionnés de M1 à M6.
- `examples/csv/` : en-têtes des vues CSV demandées.
- `SOURCES.md` : sources primaires utilisées pour la conception.

## Source de vérité

Les sorties décompilées sont des artefacts reproductibles, pas du code source original. La source de vérité est le registre de symboles, composants, décisions de périmètre et preuves. La compatibilité runtime est approuvée par capacité selon l’empreinte exacte de ses dépendances, son environnement et ses tests ; elle n’est pas déduite du seul succès d’une analyse globale.

Les sauvegardes, journaux, données personnelles, binaires du jeu et dumps restent locaux ou privés. La publication du SDK utilise une liste explicite de fichiers autorisés.
