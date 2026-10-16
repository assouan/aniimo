# Instruction à transmettre à Codex

Construis dans ce dépôt un atelier d'analyse Unity et une base de SDK de mods conformément à `WORKFLOW.md`, `AGENTS.md` et `specs/`. Les explications et la documentation sont en français ; le code, les commentaires et les docstrings sont en anglais.

Je ne veux plus de dumps C monolithiques par DLL. Je veux des références fiables, des fichiers d'analyse par fonction/type, des exports CSV, une documentation Lua et une maintenance incrémentale entre versions du jeu. Le but final est que les mods dépendent d'une API publique stable, pas des offsets ou des types internes du jeu.

## Périmètre impératif : code du jeu, pas moteur Unity

Décompile et documente **uniquement le code développé pour ce jeu** et son interface Lua spécifique. Ne décompile ni `UnityPlayer.dll`, ni les `UnityEngine.*`/packages Unity, ni les frameworks .NET/Mono/IL2CPP, ni les bibliothèques Lua standard, ni les autres bibliothèques tierces génériques par défaut. Tu peux lire les signatures/types et références croisées nécessaires à comprendre le code du jeu, mais tu ne dois pas exporter les implémentations de ces dépendances ni réécrire leur documentation officielle.

Commence par classifier chaque assembly et module en `game_decompile`, `reference_only`, `excluded` ou `needs_review` et justifie la classification. Toute provenance incertaine est `needs_review` ; aucun export de corps en automatique pour cette catégorie. Le mode `full` ne concerne que les fonctions du jeu approuvées. Pour IL2CPP, `GameAssembly.dll` est un conteneur mixte à analyser pour localiser les méthodes ; sélectionne les corps d'après l'assembly managée d'origine, et **ne décompile pas tout `GameAssembly.dll`**. Des exceptions ponctuelles ne sont autorisées qu'avec une justification enregistrée.

Le rapport et les tests doivent confirmer que les classes Unity référencées restent disponibles comme dépendances, mais qu'aucun gros export C/C#/documentation du moteur ou des bibliothèques standard n'est créé.

## Travail immédiat : M0 puis M1

Inspecte d'abord les fichiers du jeu réellement accessibles et les outils déjà présents. Détermine Mono/IL2CPP, plateforme, architecture, version Unity si identifiable, intégration Lua, assemblages et modules pertinents. Documente les preuves et les incertitudes dans `detection.json` et un rapport lisible. Ne lance pas une décompilation globale avant cette classification.

Sans fichiers de jeu disponibles, implémente la détection et l'infrastructure sur fixtures synthétiques ; écris explicitement que le diagnostic réel reste non effectué. N'invente ni nom de classe du jeu, ni résultat d'analyse, ni version d'outil compatible.

Implémente ensuite un MVP Docker avec les commandes cibles `doctor`, `plan`, `update`, le manifeste SHA-256 des entrées, un registre SQLite, les snapshots immuables, les clés de cache, les checkpoints, la publication atomique et les tests d'absence de changement. Vérifie les versions/commits et checksums avant d'écrire le lock d'outillage. Les commandes sont des fonctionnalités à construire, pas des binaires supposés existants.

Prouve notamment qu'une deuxième exécution avec les mêmes entrées n'appelle aucun décompilateur et ne réécrit aucune sortie existante. Prouve qu'un changement de contenu est détecté même avec une taille et un mtime identiques. N'utilise pas les timestamps dans les IDs de contenu.

## Jalons suivants

M2 : implémente l'adaptateur du backend réellement identifié. Pour Mono, export C# par type. Pour IL2CPP, métadonnées/types/pointeurs avant Ghidra. Exporte le pseudocode natif par corps, les localisations par build, les relations méthodes-corps et les CSV. Conserve l'ASM et les preuves, distingue pseudocode, stubs et SDK compilable.

M3 : compare deux builds, ajoute l'appariement explicable, l'invalidation des signatures/layouts/références et la génération documentaire incrémentale. Un hash normalisé ou un score BSim n'autorise jamais seul un hook. Les constants métier et offsets de champs ne sont pas masqués. Une nouvelle DLL peut nécessiter une nouvelle auto-analyse globale.

M4 : extrais les scripts Lua du périmètre, analyse le bridge et les registrations, génère les CSV et définitions LuaLS. Ajoute séparément une sonde runtime bornée et non destructive, avec provenance du build/VM/scénario. Ne promets pas l'exhaustivité d'un parcours de `_G`, ne déduis pas les signatures C depuis `debug.getinfo`, et n'appelle pas de getter/fonction inconnue pour l'énumération.

M5 : construis une capacité publique utile et testable, un adaptateur versionné et un mod d'exemple. Évalue un loader existant compatible avant d'en réécrire un. En cas de build inconnu ou de résolution ambiguë, désactive la capacité affectée. Teste le même mod contre deux builds et distingue analyse statique de validation réelle en jeu.

M6 : étends l'API selon les besoins, puis ajoute les optimisations natives avancées et le mode de surveillance local seulement lorsque les tests de base sont fiables.

## Mode de livraison

Travaille par changements limités, un jalon à la fois. À chaque jalon, livre le code, les tests, les commandes réellement exécutées, leurs résultats, les artefacts attendus, les limites restantes et `STATUS.md` mis à jour. Ne présente pas une fixture ou un mock comme un test sur le jeu. Ne modifie pas les entrées du jeu et ne publie pas ses binaires ou dumps globaux.

Commence par M0/M1. N'implémente pas un framework de hooks générique non testé avant que les références, le cache et les exports soient fiables.
