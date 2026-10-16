# Workflow Unity : analyse, maintenance et API de mods

## 1. Objectif et frontières

Construire deux produits distincts : un atelier d'analyse versionné et un runtime de mods. L'atelier extrait des références et des preuves. Le runtime traduit une API stable en appels au jeu. Le SDK public ne dépend pas des fichiers C décompilés.

L'analyse statique doit être exécutable dans un conteneur Linux. L'observation Lua et les tests de hooks s'exécutent dans une instance autorisée du jeu ou du serveur, sur la plateforme cible. Docker n'est pas supposé lancer un jeu Windows ni inspecter son processus hôte.

Le backend du jeu reste inconnu jusqu'au diagnostic. Les chemins usuels sont des indices, pas une preuve : `*_Data/Managed/*.dll` pour du code managé, `GameAssembly.dll` et `global-metadata.dat` pour IL2CPP sur Windows. Vérifier le format réel des fichiers, la présence de métadonnées CLR et de corps IL, ainsi que les composants du runtime. Ne pas confondre des DLL de mods/interop générées avec les assemblies originales.

Mono : décompiler les assemblies contenant l'IL en C# par type avec ILSpy. IL2CPP : extraire d'abord les métadonnées et les pointeurs de méthodes, puis appliquer les informations à Ghidra avant de décompiler les corps natifs. Unity compile l'IL en C++ puis en code natif pour IL2CPP. [S01, S02, S03, S11]

Des métadonnées peuvent fournir des noms présents dans la distribution sans garantir qu'ils sont les noms non obfusqués du projet original. Le stripping peut retirer du code ; un outil ne doit pas présenter un élément absent comme retrouvé. [S12]

### Périmètre strict : code spécifique au jeu uniquement

Par défaut, **ne décompiler que les implémentations de gameplay et d’intégration propres au jeu** : assemblies de scripts (`Assembly-CSharp`, `Assembly-CSharp-firstpass` si présentes), assemblies identifiées comme appartenant au jeu, bibliothèques natives développées spécifiquement pour le jeu et scripts Lua authored/exposés par le jeu. Identifier ces composants pendant M0 ; les noms de fichiers seuls ne prouvent pas leur provenance. Les assemblies inconnues vont dans une file de revue et ne sont **pas décompilées automatiquement**.

Sont **exclus par défaut de l’export de pseudocode, de la reconstruction de projet, des CSV détaillés de fonctions et de la documentation générée** : `UnityEngine.*`, `Unity.*` du moteur ou des packages, les assemblies du framework (`System.*`, `mscorlib`, `netstandard`, etc.), `UnityPlayer.dll`, le runtime `libil2cpp`, les composants Mono, les DLL système, les frameworks Lua standard et les bibliothèques tierces génériques. Ne pas copier/dupliquer la documentation Unity et .NET officielle. Une exception ciblée, explicitement configurée et documentée, peut être nécessaire pour une bibliothèque réellement modifiée par le jeu ou un point d’intégration impossible à comprendre autrement.

Pour les dépendances exclues, **la lecture des métadonnées est permise uniquement pour les signatures/types effectivement référencés**, les imports/exports, les références croisées et la validation de compatibilité. Conserver ces références dans les graphes, les CSV de liens et les fiches des fonctions du jeu, mais ne jamais exporter automatiquement le corps de ces dépendances comme pseudocode du jeu. Pour les classes Unity, privilégier un lien vers la documentation officielle. Les métadonnées ne sont pas une autorisation implicite de décompiler le code.

**Spécificité IL2CPP : ne pas exclure `GameAssembly.dll` en bloc.** Sur Windows, ce module regroupe du code de scripts IL2CPP et le runtime. Importer/analyser le module autant que nécessaire pour découvrir les limites et les références ; sélectionner ensuite les méthodes à décompiler **en fonction de leur assembly managée d’origine** et des preuves de leur appartenance au jeu. Un corps partagé jeu/bibliothèque doit être annoté avec plusieurs propriétaires et exporté seulement si nécessaire pour un symbole du jeu, sans conclure que tout son contenu appartient au jeu. Les méthodes natives sans provenance fiable restent en revue. `UnityPlayer.dll` reste hors périmètre de décompilation, sauf exception ciblée justifiée.

**Spécificité Lua : documenter l’API Lua exposée par le jeu, ses scripts et ses bindings** (y compris les signatures de méthodes Unity appelables si le bridge les expose). Ne pas redécompiler ni redocumenter les bibliothèques standards de Lua ou le moteur Lua ; conserver uniquement les liens et le contexte d’interopérabilité nécessaires.

Le mode `full` signifie « toutes les implémentations du jeu retenues et approuvées dans le profil », **jamais « toutes les méthodes de Unity et tous les corps de GameAssembly »**. Inclure un test d’acceptation démontrant qu’un symbole moteur référencé est conservé comme dépendance, sans aucun export de son implémentation. Le plan d’exécution affiche distinctement `game_decompile`, `reference_only`, `excluded` et `needs_review`, avec un décompte par assembly/module et les raisons.

## 2. Stack minimale

Utiliser un orchestrateur Python, SQLite comme registre local et des fichiers JSON/CSV comme échanges. Les outils externes sont isolés derrière des adaptateurs. Une image d'analyse, un répertoire persistant d'état et un répertoire de sorties suffisent pour le MVP. Ne pas ajouter de cluster, de service de recherche, de serveur de base de données ou de BSim distribué sans besoin mesuré.

Choix à évaluer sur le jeu :

| Besoin | Candidat | Limite à traiter |
|---|---|---|
| Code IL/Mono | ILSpy / ilspycmd | Décompilation C#, pas restauration du projet original |
| Métadonnées IL2CPP | Il2CppInspectorRedux | Choisir une version compatible et tester son intégration Ghidra |
| Extraction IL2CPP alternative | Il2CppDumper | Sa matrice documentée ne suffit pas à garantir un jeu récent |
| Chaîne interop | Cpp2IL + Il2CppInterop | Couples de versions à tester ensemble ; récupération des corps non garantie |
| Analyse native | Ghidra headless | Projet persistant, scripts par fonction et erreurs explicites |
| Mod runtime | BepInEx adapté au backend | Compatibilité plateforme/jeu à prouver, pas à supposer |
| Aide à l'appariement | Version Tracking / BSim | Option tardive ; résultats à vérifier |
| Scripts dans assets | Parseur Unity compatible, éventuellement AssetRipper | Extraction ciblée des scripts ; aucun besoin de reconstruire tout le projet |
| Documentation Lua | Définitions LuaLS + Markdown | Types inconnus conservés comme inconnus |

Références : [S01–S09, S14, S15, S20, S25].

Pour Il2CppInspectorRedux, vérifier notamment le mode Python/PyGhidra demandé par les scripts de la version choisie. Ne pas supposer qu'un script Python moderne est compatible avec le mode Jython historique. Les assemblages factices et fichiers de types sont des descriptions, pas des implémentations récupérées. [S02, S03]

La documentation primaire confirme aussi que BSim génère ses vecteurs via le décompilateur : il ne constitue donc pas un détecteur de changements gratuit avant toute décompilation. [S08]

## 3. Organisation du dépôt et du stockage

```text
project/
  AGENTS.md
  WORKFLOW.md
  STATUS.md
  profiles/
  schemas/
  tools.lock.json
  pipeline/
    adapters/
    matching/
    exporters/
  ghidra/
  annotations/
    symbols/
    aliases/
    docs/
  contracts/
    public-api/
    capabilities/
  runtime/
    loader/
    adapters/
    lua-probe/
  sdk/
  tests/
  docs/manual/

state/                         # Private persistent state
  registry.sqlite
  objects/sha256/
  snapshots/<build_id>/
  ghidra/<toolchain>/<build_id>/<module_hash>/
  checkpoints/

output/                        # Generated, never edited manually
  builds/<build_id>/<analysis_id>/
    manifest.json
    detection.json
    symbols/
    managed/
    native/
    lua/
    docs/
    reports/
  current.json
  approved.json
```

Les dossiers `state` et `output` ne sont pas des copies de travail à modifier manuellement. Le dépôt Git conserve surtout le code de l'outil, les profils, les annotations et les contrats. Une vue normalisée peut être versionnée en privé pour les revues, sans obliger à stocker chaque binaire et chaque export dans Git.

`current.json` pointe vers le dernier ensemble d'artefacts d'analyse complet. `approved.json` identifie les capacités runtime validées pour un build exact. Un succès d'analyse ne doit jamais mettre automatiquement à jour l'approbation runtime.

## 4. Identités et source de vérité

Le registre distingue :

- `build_id` : hash du manifeste canonique des entrées du jeu pertinentes et de leurs contenus, indépendamment de la date ou du chemin absolu d'installation.
- `analysis_id` : identité d'une analyse du build avec versions d'outils, options, schémas, annotations applicables et observations importées.
- `symbol_id` : identifiant persistant de la méthode, du type ou du champ logique.
- `native_body_id` : identité suivie d'un corps natif, distincte de la méthode managée.
- `api_id` : contrat stable choisi par le SDK, indépendant des noms du jeu.

La clé de recherche d'une méthode inclut l'identité logique d'assembly, le type qualifié et imbriqué, le nom, l'arité générique, les paramètres ordonnés, les modificateurs de passage, le retour et le caractère statique/instance. Elle exclut les adresses et tokens. Conserver les tokens comme preuves locales au build.

Un renommage ou changement de signature produit une nouvelle observation et, après examen, éventuellement un lien de succession ou un alias. Ne pas remplacer le registre par `SHA256(nom)` ou `SHA256(corps)` : ces valeurs changent avec le nom ou l'implémentation.

IL2CPP peut partager des implémentations génériques. Prévoir la relation plusieurs-à-plusieurs entre méthodes logiques et corps/points d'entrée : méthode, invoker, thunk, spécialisation, implémentation partagée. [S13]

## 5. Pipeline d'une exécution `update`

### Étape A — Contrôle et capture des entrées

Vérifier le profil, l'espace disque, les versions et la présence des outils. L'installation du jeu doit avoir terminé sa mise à jour. Travailler sur une copie cohérente et immuable des entrées d'analyse ; refuser une capture qui change pendant sa lecture.

Deux inventaires identiques espacés dans le temps ne prouvent pas, seuls, qu'un installateur n'est pas momentanément arrêté au milieu d'une mise à jour. Le contrat d'exploitation exige une installation terminée ou un export de snapshot déjà cohérent.

Hacher les contenus, et non uniquement les dates ou tailles. Les raccourcis fondés sur le mtime sont optionnels et doivent être décrits comme moins sûrs. Exclure explicitement les journaux, sauvegardes et propres sorties de la pipeline. Garder un manifeste complet du périmètre réellement retenu.

### Étape B — Détection et plan

Produire `detection.json` puis un plan explicite : entrées inchangées, ajouts, retraits, étapes invalidées et raisons. Classer les composants en code du jeu, moteur, bibliothèques tierces, runtime, scripts et conteneurs d'assets.

Indexer largement les métadonnées ; décompiler en priorité le code du jeu et les points d'intégration nécessaires. Le mode `full` couvre tous les corps natifs reconnus dans le périmètre autorisé, pas toutes les DLL système par défaut.

### Étape C — Extraction structurelle

Mono : métadonnées, types, méthodes, signatures, corps IL, champs, attributs, chaînes et références via des bibliothèques de lecture d'assemblies. Export C# par type avec ILSpy. Une assembly modifiée peut devoir être redécompilée intégralement, puis ses sorties comparées avant publication.

IL2CPP : traiter le binaire et son fichier de métadonnées comme une unité de cohérence. Extraire les noms, types, layouts, champs, signatures et correspondances de code disponibles. Toute extraction incomplète doit être signalée, jamais convertie en un catalogue vide marqué « succès ».

### Étape D — Analyse Ghidra

Conserver un programme par build/module et configuration d'analyse ; ne pas écraser l'ancien binaire avec le nouveau. Importer les symboles, signatures et types avant la passe de décompilation détaillée. Utiliser les API supportées de la version verrouillée. Ghidra propose le traitement headless et une décompilation fonction par fonction. [S05, S06, S07]

Le script doit d'abord parcourir les fonctions reconnues, établir un index et calculer les caractéristiques nécessaires. Il décompile ensuite la liste demandée par le plan. Un timeout produit une entrée d'erreur avec preuve et motif, pas un fichier vide prétendument valide.

Un module natif recompilé peut nécessiter une nouvelle auto-analyse globale. La pipeline doit réduire le travail réutilisable, pas prétendre que quelques octets différents suffisent à reconstruire toutes les limites de fonctions.

### Étape E — Appariement entre builds

Ordre de préférence : identité managée issue des métadonnées ; symboles de débogage valides pour le binaire exact ; signatures/logique déjà approuvées ; empreintes et références concordantes ; similarité de graphe et BSim pour proposer des candidats ; revue humaine.

Conserver les alternatives et contradictions, pas seulement le meilleur score. Un score n'est pas une probabilité calibrée de correction. Un appariement logique n'est pas une preuve d'équivalence comportementale ni une autorisation d'appeler la fonction.

### Étape F — Invalidation des dépendances

Comparer séparément : corps, signature, layout des types, cibles d'appels, données référencées, offsets de champs, tables virtuelles, wrappers, enums, scripts, bindings Lua et contrats du SDK.

Propager l'invalidation vers les consommateurs connus. Si une dépendance ne peut pas être caractérisée, choisir une invalidation conservatrice et signaler la limite du graphe. Les appels indirects, les données globales et l'inlining empêchent d'assimiler un graphe incomplet à une preuve d'absence d'impact.

### Étape G — Génération et contrôle

Émettre les exports par corps/type, les CSV, les définitions Lua, les pages de documentation et le rapport de différences. Réutiliser uniquement les objets dont la clé de cache et le contexte sont vérifiés. Ne réécrire une sortie visible que si son contenu change.

Conserver les octets identiques dans un stockage adressé par contenu. Les manifests de la nouvelle analyse référencent ces objets ; il n'est pas nécessaire de recopier tous les fichiers dans chaque snapshot.

### Étape H — Publication atomique

Construire dans un espace temporaire. Vérifier les schémas, les références et les états d'étapes. Publier ensuite la nouvelle analyse atomiquement. En cas d'échec, conserver le dernier état valide, les logs et les checkpoints. Sérialiser les écritures SQLite et les écritures d'un projet Ghidra ; ne pas partager une même base de travail entre plusieurs écrivains.

## 6. Incrémentalité : ce qui est garanti et ce qui ne l'est pas

| Situation | Travail attendu |
|---|---|
| Aucun changement d'entrée, d'outil ou d'annotation | Aucun appel au décompilateur ; sorties inchangées |
| Une annotation documentaire change | Régénération de la doc dépendante, sans analyse binaire |
| Un script Lua source change | Analyse du script, de ses dépendants et de son API ; pas de Ghidra sans dépendance native affectée |
| Un bundle contenant des scripts change | Nouvelle extraction du conteneur, comparaison des contenus extraits |
| Une assembly Mono change | Nouvelle lecture ; export concerné et comparaison par type/méthode |
| GameAssembly ou global-metadata change | Nouvelle extraction cohérente ; mapping et analyse du module concernés |
| Un type change de layout | Révalidation des adaptateurs et fonctions dépendants, même à corps identique |
| Une fonction ne change que de localisation | Mise à jour des localisations ; contrôle des références et du contexte avant réutilisation du texte |
| L'outil d'analyse ou ses options changent | Nouvelle analyse pour les étapes dépendantes, sans présenter le changement d'outil comme un changement du jeu |
| Une observation runtime manque | Statut non observé/non testé ; aucune suppression automatique |

Une empreinte normalisée ne doit neutraliser que ce qui est démontré comme dépendant des relocations. Conserver les constantes métier, les offsets de champs, les tailles de structures et l'identité des cibles. Remplacer aveuglément tous les immédiats par des jokers pourrait masquer une modification de dégâts ou un changement de structure.

Une clé de réutilisation de pseudocode doit inclure le corps, les prototypes et types consommés, les symboles et données référencés, le modèle d'architecture/ABI, les options du décompilateur et les annotations qui affectent son interprétation. Quand l'équivalence de contexte n'est pas établie, redécompiler. Il est acceptable qu'une grosse mise à jour invalide beaucoup de résultats.

## 7. Découpage du code

Pour Mono, conserver un fichier C# par type, avec export plus fin si utile. Exemple d'option ILSpy disponible : [S01]

```sh
ilspycmd -p --nested-directories -o /output/managed /input/Assembly-CSharp.dll
```

Pour le natif, la granularité canonique est un corps natif :

```text
native/bodies/<native_body_id>.c
native/bodies/<native_body_id>.asm
native/bodies/<native_body_id>.json
native/bodies/<native_body_id>.refs.json
native/types/<type_id>.h
native/index/by-class/<assembly>/<namespace>/<type>/index.json
```

Une vue navigable peut présenter `TakeDamage__<symbol_id>.c` sous le type concerné, mais doit référencer le corps canonique au lieu de dupliquer une implémentation partagée en la présentant comme indépendante. Prévoir des noms de chemins portables, une gestion des surcharges, des génériques, des noms imbriqués et des collisions.

Ne pas découper par paquets arbitraires de lignes et ne pas utiliser une regex sur un gigantesque export C. Utiliser `DecompInterface.decompileFunction` puis le résultat de la fonction. [S06, S07]

Les informations volatiles du build et les adresses sont dans les sidecars/manifests. Ne pas injecter la date courante dans chaque fichier. Une fonction géante peut rester un fichier géant : ne pas inventer de nouvelles fonctions pour satisfaire une limite de lignes.

Ces fichiers `.c` sont du pseudocode d'analyse, exclus des cibles de compilation du SDK. Les assemblages factices et `.h` de structure ne deviennent pas automatiquement une ABI sûre.

## 8. Lua : trois sources de connaissance

### Analyse statique

Identifier l'interpréteur et le bridge : Lua natif, LuaJIT, xLua, ToLua, MoonSharp ou une solution particulière. MoonSharp est un interpréteur managé : supposer systématiquement la présence d'un `lua_State` serait incorrect. [S17, S18, S19, S26]

Repérer les `.lua`, bytecodes, `.bytes`, TextAssets et bundles réellement utilisés. Employer un parseur syntaxique du dialecte détecté, pas des regex pour documenter un langage entier. Extraire modules, déclarations, méthodes avec `:` ou `.`, constantes, dépendances `require`, structures de tables et métatables lorsque cela est prouvable.

Ne pas employer un décompilateur de bytecode Lua standard pour un bytecode LuaJIT sans validation. En présence d'un format inconnu, conserver le hash, le contexte et l'état `unsupported` plutôt qu'inventer du texte. Des informations de débogage absentes peuvent rendre certains noms irrécupérables.

### Bindings C#/C/C++

Analyser les wrappers et points d'enregistrement de l'intégration identifiée. Recueillir les noms exposés, types, surcharges, conversions, signatures et liens vers les méthodes managées/natives. Les chemins de type `CS.*` ne signifient pas que toutes les classes sont immédiatement énumérables ni disponibles dans tous les contextes.

Créer `lua_bindings.csv` reliant le chemin Lua observé à `symbol_id` et, lorsqu'il est connu, à `native_body_id`. Documenter séparément fonction Lua, callback natif, type managé exposé et objet userdata.

### Sonde d'observation dans le jeu

Une sonde optionnelle effectue des snapshots sur le thread et dans l'état Lua appropriés, lors de scénarios identifiés : démarrage, menu, chargement d'une partie, démarrage serveur, connexion locale de test, chargement de modules.

Énumérer de manière bornée les tables accessibles, les modules déjà chargés, les inscriptions et métatables visibles. Éviter les cycles et les conversions implicites déclenchant du code. Ne pas appeler les fonctions ou getters inconnus pour « découvrir » leurs arguments. Ne pas charger automatiquement tous les modules. Privilégier les accès bruts et des adaptateurs spécialisés pour les objets exposés par le bridge.

Conserver le `build_id`, le hash du module, la version de sonde, le bridge, la VM/état observé, le scénario et la phase. L'absence dans un snapshot ne prouve pas la suppression. Un symbole connu seulement depuis une ancienne observation garde cet historique mais ne doit pas être affiché comme validé sur le nouveau build.

Le manuel Lua précise notamment que les informations de paramètres des fonctions C ne décrivent pas leur signature métier. En Lua 5.4, `nparams` vaut 0 et `isvararg` est vrai pour les fonctions C. Les noms et types métier doivent venir d'autres preuves. [S16]

### Sorties Lua

Produire les symboles, bindings, modules, constantes/enums, événements lorsqu'ils sont identifiés, paramètres, retours, surcharges et conditions de disponibilité. Ajouter les statuts `recovered`, `observed`, `inferred`, `reviewed`, ainsi que les preuves par propriété documentée.

Générer une définition LuaLS par module ou classe, avec `---@meta`, `---@class`, `---@param`, `---@return`, et `---@overload` lorsque justifié. Les définitions servent à l'éditeur et ne sont jamais déployées comme scripts exécutés dans le jeu. [S20, S21]

Le bilan de couverture distingue les scripts trouvés/parsés, les inscriptions reconnues, les scénarios observés et les signatures encore inconnues. Ne jamais afficher « 100 % de l'API du jeu » sans périmètre démontré.

## 9. Construire une véritable API de mods

```text
Mods C# / scripts Lua
        |
GameModAPI.Contracts
        |
Capabilities + events + lifecycle + scheduling
        |
GameModAPI.Adapter.<backend>.<build>
        |
Interop / metadata resolver / validated native hook
        |
Authorized game or server process
```

Évaluer BepInEx pour le chargement et Il2CppInterop pour l'interopérabilité IL2CPP, plutôt que réécrire ces couches sans nécessité. Leur support doit être validé sur le jeu et la plateforme réels. Les possibilités de patching du code managé et du code natif ne sont pas interchangeables. [S14, S15, S24]

Exposer des interfaces de domaine stables : joueurs, inventaires, événements, entités, configuration et planification. Conserver les objets du jeu derrière des adaptateurs et handles contrôlés ; ne pas laisser chaque mod manipuler les offsets et structures natives. Une couche basse expérimentale peut exister, explicitement hors contrat de stabilité.

Priorité de résolution : références/metadata et signatures exactes, interop adaptée, puis résolution native encadrée lorsque nécessaire. Une signature d'octets est une stratégie de secours, pas l'identité d'une méthode. Exiger une occurrence unique dans le module attendu, une section et des limites plausibles, une ABI vérifiée, des références compatibles et des tests. Zéro ou plusieurs candidats désactivent la capacité concernée.

Pour le natif, valider conventions d'appel, représentation des types, éventuels paramètres cachés, durée de vie, GC, thread, contexte serveur/client et méthode réellement interceptée. Pour Mono, un token est local à l'assembly du build ; une adresse de code JIT n'est pas une RVA portable d'un fichier.

Chaque capacité du SDK déclare ses dépendances en symboles, layouts et tests. Une mise à jour produit `compatible`, `requires_validation`, `unavailable` ou `breaking` avec preuves. Le runtime charge seulement les capacités approuvées pour le build exact et conserve un mode de dégradation sûr.

Séparer la version sémantique du SDK des versions de jeu supportées. Tester au moins un ancien mod non recompilé contre le nouvel adaptateur lorsque la compatibilité binaire est promise.

Les mods serveur ne peuvent pas créer automatiquement des ressources ou comportements absents du client. Classer chaque fonctionnalité en serveur seul, client requis ou protocole partagé, puis tester la réplication et la persistance.

Une gestion d'erreur C# n'isole pas un crash natif. Ne pas promettre le déchargement à chaud d'un plugin dont les hooks, callbacks et threads ne sont pas prouvés libérables. Préférer le redémarrage sûr pour le MVP.

## 10. Documentation et maintenance humaine

Deux niveaux : référence interne extraite, potentiellement vaste et incertaine ; SDK public sélectionné et testé. Générer les pages depuis le registre et les annotations, jamais depuis une nouvelle paraphrase globale des fichiers C.

Chaque page décrit signature, provenance du nom, disponibilité, build, contexte client/serveur, contraintes d'appel connues, dépendances pertinentes, exemples testés et changements. Un « nom inconnu » ou un « type de retour non établi » est une information valide.

Pour éviter des centaines de milliers de pages, produire une navigation par assembly/type/module, des ancres par symbole et des index paginés. Garder l'ASM et les traces détaillées en artefacts internes.

Les annotations humaines sont rattachées aux identifiants persistants, avec leur domaine d'applicabilité. Une correspondance incertaine suspend leur transfert automatique. Un changement de comportement marque les exemples et explications dépendants comme à revoir.

Codex peut proposer une interprétation de fonction dans une annotation séparée, accompagnée de preuves et d'un niveau de confiance. Le run automatique quotidien reste déterministe et ne nécessite aucun appel à un modèle.

## 11. Ordre d'implémentation

M0 : diagnostic du jeu et sélection vérifiée d'outils.

M1 : image, manifeste, registre, identités, snapshots, plan, cache, checkpoints, fixtures et exécution sans changement.

M2 : branche Mono ou IL2CPP réelle, CSV et découpage propre du code, sans imposer l'autre backend avant que le premier fonctionne.

M3 : comparaison multi-build, invalidation des layouts/références, revue d'appariement et documentation incrémentale.

M4 : Lua statique et bindings, puis sonde runtime séparée et définitions LuaLS.

M5 : une capacité SDK utile, loader adapté, un mod exemple et tests réels sur deux builds.

M6 : extension de l'API, matching natif avancé si nécessaire, surveillance locale optionnelle et durcissement de distribution.

Le critère final n'est pas le nombre de lignes décompilées : c'est la capacité à expliquer un changement, adapter une dépendance interne, et garder un mod existant fonctionnel sans lui faire connaître les nouveaux offsets.
