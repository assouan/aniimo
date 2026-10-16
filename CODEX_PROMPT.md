# Instruction à transmettre à Codex

Construis dans ce dépôt un atelier d'analyse Unity et une base de SDK de mods conformément à `WORKFLOW.md`, `AGENTS.md` et `specs/`. Les explications et la documentation sont en français ; le code, les commentaires et les docstrings sont en anglais.

Je ne veux plus de dumps C monolithiques par DLL. Je veux des références fiables, des fichiers d'analyse par fonction/type, des exports CSV, une documentation Lua et une maintenance incrémentale entre versions du jeu. Le but final est que les mods dépendent d'une API publique stable, pas des offsets ou des types internes du jeu.

## Périmètre impératif : cibles approuvées, pas moteur Unity

Décompile et documente **le code développé pour ce jeu, son interface Lua spécifique et les modules complets explicitement approuvés par le profil Aniimo**. Ne décompile ni `UnityPlayer.dll`, ni les `UnityEngine.*`/packages Unity, ni les frameworks .NET/Mono/IL2CPP, ni les bibliothèques Lua standard, ni les autres bibliothèques tierces génériques par défaut. Tu peux lire les signatures/types et références croisées nécessaires à comprendre les cibles, mais tu ne dois pas exporter les implémentations des dépendances exclues ni réécrire leur documentation officielle.

Commence par classifier chaque assembly et module en `game_decompile`, `reference_only`, `excluded` ou `needs_review` et justifie la classification. Toute provenance incertaine est `needs_review` ; aucun export de corps en automatique pour cette catégorie. Le mode `full` ne concerne que les fonctions du jeu approuvées. Pour IL2CPP, `GameAssembly.dll` est un conteneur mixte à analyser pour localiser les méthodes ; sélectionne les corps d'après l'assembly managée d'origine, et **ne décompile pas tout `GameAssembly.dll`**. Des exceptions ponctuelles ne sont autorisées qu'avec une justification enregistrée.

Le rapport et les tests doivent confirmer que les classes Unity référencées restent disponibles comme dépendances, mais qu'aucun gros export C/C#/documentation du moteur ou des bibliothèques standard n'est créé.

Le profil Aniimo autorise explicitement l'analyse complète de `NEP2.dll`, `NEPKernel.sys`, `NEPCleaner.exe` et `KernelDumpAnalyzer.exe`. Capture leurs corps, classe-les comme cibles complètes approuvées, puis décompile et documente toutes leurs fonctions lors du jalon d'analyse approprié. M0 doit d'abord confirmer les fichiers réellement présents et signaler tout composant anti-cheat supplémentaire sans inventer son rôle.

## Travail immédiat : M0 uniquement

Inspecte d'abord, en lecture seule, les fichiers du jeu réellement accessibles et les outils déjà présents. Capture les entrées pertinentes dans un snapshot immuable avant toute analyse ultérieure. Détermine Mono/IL2CPP, plateforme, architecture, version Unity si identifiable, intégration Lua, assemblages et modules pertinents. Documente les preuves et les incertitudes dans `detection.json`, `scope-plan.json`, `tool-compatibility.json`, `additional-input-candidates.json` et un rapport lisible. L'inventaire de candidats reste guidé par les manifestes/références et ne copie ni ne hache leurs corps. Ne lance pas une décompilation globale avant cette classification.

Utilise `profiles/aniimo.inputs.yaml` comme allowlist d'acquisition et `profiles/aniimo.decompilation.yaml` comme politique distincte. Les feature sets par défaut `core`, `lua`, `content_indexes` et `anti_cheat` font partie du bundle M0 afin que le diagnostic soit complet sans relance manuelle. La présence d'un fichier dans le volume d'entrées ne l'autorise pas à être décompilé, sauf approbation explicite dans la politique comme pour les quatre modules anti-cheat connus. Le futur analyseur ne doit jamais monter le dossier Steam : seul le service `capture` y aura accès, et le volume `inputs` sera en lecture seule côté analyse.

Pour M0, cette capture est un bundle d'acquisition borné au diagnostic sous `.aitools/m0-acquisition/<capture_id>/` : manifeste canonique, hashes et copies des seules entrées nécessaires. Elle doit être reproductible et auditée, mais ne préjuge pas du schéma du CAS ni de la CLI de production de M1. M1 réimporte ou recapture ensuite ces entrées avec son contrat versionné ; M0 ne fabrique pas à l'avance le registre ou les caches définitifs.

Le dossier `.sample` contient des indices historiques, notamment un ancien build IL2CPP/x64/xLua et le magic standard IL2CPP `AF 1B B1 FA`. Il n'est ni une vérité sur l'installation courante, ni une fixture, ni une dépendance. Le magic ne prouve pas que le reste des métadonnées est standard, personnalisé ou protégé. Importe seulement les faits résumés et leur provenance comme observations historiques ou candidats ; confirme chaque résultat sur le snapshot courant.

Sans fichiers de jeu disponibles, exécute uniquement les contrôles M0 possibles sur fixtures synthétiques existantes et écris explicitement que le diagnostic réel reste non effectué. Ne commence pas l'infrastructure M1 pour masquer cette absence. N'invente ni nom de classe du jeu, ni résultat d'analyse, ni version d'outil compatible.

M0 s'arrête après le diagnostic, la classification, la matrice de compatibilité des outils et la recommandation de branche technique. Ne commence pas M1 dans la même livraison. Ne remplis `tools.lock.json` avec des versions et checksums qu'après les avoir réellement validés ; son état `unresolved` doit sinon être conservé.

## Jalons suivants

M1 : implémente les images séparées `capture` et `analyzer` avec une orchestration en une commande, préflight léger systématique, contrôles stables de `doctor` mis en cache, `capture`, `plan` et `analyze`, le manifeste SHA-256, le registre SQLite, les CAS d'entrées et d'artefacts, les snapshots immuables, la remise atomique du `snapshot_id` exact, les clés de cache, les checkpoints, la publication atomique, le rapport détaillé de timings et un petit test sans changement sur fixture synthétique. Utilise les sept volumes nommés préfixés du contrat Docker. Le vrai run calcule le même plan que `--dry-run` puis le réutilise sans second inventaire ; `--dry-run` s'arrête seulement avant l'écriture. Ghidra et BSim sont activés par défaut sur leur périmètre autorisé, mais une deuxième exécution identique doit les marquer `cache_hit` sans les invoquer ni réécrire une sortie. Prouve aussi que l'analyseur ne voit aucun chemin Steam, que `/inputs` y est read-only et que deux captures entrelacées ne peuvent pas échanger leurs snapshots. Seuls le refresh complet de `doctor`, l'arrêt dry-run et la suite d'acceptation complète restent des actions explicites.

Le rapport de chaque run contient toutes les étapes et sous-étapes, y compris celles sautées ou servies par le cache : durée monotone, statut, raison, cache hit/miss, outil/version, éléments et octets traités, et ressources disponibles à faible coût. Produis JSON, Markdown et `stage_timings.csv`, sans relire les payloads uniquement pour mesurer.

M2 : implémente l'adaptateur du backend réellement identifié. Pour Mono, export C# par type. Pour IL2CPP, métadonnées/types/pointeurs avant Ghidra. Exporte toujours l'ASM disponible avant de tenter le C par corps, puis utilise les états exclusifs `c_and_asm`, `asm_only`, `disassembly_failed` et `pending`. Cache les échecs inchangés et borne la file difficile. Produis `coverage.json`, `native_bodies.csv`, les localisations par build, les relations méthodes-corps et une vue obligatoire assembly/type/méthode ou module/fonction. Sépare `managed_signature` et `native_prototype`. Distingue pseudocode, stubs et SDK compilable. Une version non prise en charge, une incohérence, une erreur de parsing ou une protection suspectée échoue explicitement dans sa propre catégorie et ne déclenche aucun fallback approximatif.

M3 : compare deux builds, ajoute l'appariement explicable, l'invalidation des signatures/layouts/références et la génération documentaire incrémentale. Un hash normalisé ou un score BSim n'autorise jamais seul un hook. Les constants métier et offsets de champs ne sont pas masqués. Une nouvelle DLL peut nécessiter une nouvelle auto-analyse globale.

M4 : extrais les scripts Lua du périmètre, analyse le bridge et les registrations, génère les CSV et définitions LuaLS. Ajoute séparément une sonde runtime bornée et non destructive, avec provenance du build/VM/scénario. Ne promets pas l'exhaustivité d'un parcours de `_G`, ne déduis pas les signatures C depuis `debug.getinfo`, et n'appelle pas de getter/fonction inconnue pour l'énumération.

M5 : construis une capacité publique utile et testable, un adaptateur versionné et un mod d'exemple. Évalue un loader existant compatible avant d'en réécrire un. En cas de dépendance inconnue ou de résolution ambiguë, désactive la capacité affectée. Teste le même mod contre deux builds et distingue analyse statique, validation technique en jeu et autorisation externe du binaire distribué.

M6 : étends l'API selon les besoins, puis ajoute les optimisations natives avancées et le mode de surveillance local seulement lorsque les tests de base sont fiables.

## Mode de livraison

Travaille par changements limités, un jalon à la fois. À chaque jalon, livre le code, uniquement les tests rapides et proportionnés au risque, les commandes réellement exécutées, leurs résultats, les artefacts attendus, les limites restantes et `STATUS.md` mis à jour. Ne lance pas une analyse de gros binaire pour valider un simple contrat de dépôt et ne présente pas une fixture ou un mock comme un test sur le jeu. Ne modifie pas les entrées du jeu et ne publie pas ses binaires ou dumps globaux.

Commence et termine M0 uniquement. N'implémente pas un framework de hooks générique non testé avant que les références, le cache et les exports soient fiables.
