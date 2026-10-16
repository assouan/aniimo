# Workflow Unity : analyse, maintenance et API de mods

## 1. Objectif et frontières

Construire deux produits distincts : un atelier d'analyse versionné et un runtime de mods. L'atelier extrait des références et des preuves. Le runtime traduit une API stable en appels au jeu. Le SDK public ne dépend pas des fichiers C décompilés.

L'analyse statique doit être exécutable dans un conteneur Linux. L'observation Lua et les tests de hooks s'exécutent dans une instance autorisée du jeu ou du serveur, sur la plateforme cible. Docker n'est pas supposé lancer un jeu Windows ni inspecter son processus hôte.

### Cible Aniimo et statut des preuves

Le produit visé accepte des mods `.dll`, mais ne suppose pas qu'Aniimo possède un serveur dédié comparable à celui d'ARK. M0 doit identifier le processus cible, le contexte client/serveur, l'autorité réelle sur l'état de jeu et les modes autorisés. Si seul le client Windows existe, le runtime reste une API de mods cliente et ne promet pas des capacités serveur globales.

Le dossier local `.sample` documente un ancien lot daté du 16 octobre 2026. Il fournit des indices historiques — Windows x64, IL2CPP, Unity `2022.3.62f1`, xLua, Steam build `25962016`, module principal pressenti `FunPlus.WorldX.Scripts.dll` et métadonnées à en-tête personnalisé — mais **aucun de ces éléments n'est un résultat courant**. Le pipeline doit fonctionner lorsque `.sample` est absent. Les faits retenus sont importés avec une provenance et le statut `historical_unverified`, puis confirmés ou contredits sur le snapshot courant.

L'exploitant du projet a explicitement autorisé l'analyse complète de l'anti-cheat dans son environnement éditeur/serveur. Le profil Aniimo traite donc `NEP2.dll`, `NEPKernel.sys`, `NEPCleaner.exe` et `KernelDumpAnalyzer.exe` comme des cibles natives complètes à capturer, décompiler et documenter. M0 doit encore confirmer leur présence, leur format et leurs relations sur le build courant ; il ne doit pas inventer un résultat depuis les seuls noms historiques. Toute autorisation applicable à un futur package distribué reste enregistrée séparément de sa validation technique.

Le backend du jeu reste inconnu jusqu'au diagnostic. Les chemins usuels sont des indices, pas une preuve : `*_Data/Managed/*.dll` pour du code managé, `GameAssembly.dll` et `global-metadata.dat` pour IL2CPP sur Windows. Vérifier le format réel des fichiers, la présence de métadonnées CLR et de corps IL, ainsi que les composants du runtime. Ne pas confondre des DLL de mods/interop générées avec les assemblies originales.

Mono : décompiler les assemblies contenant l'IL en C# par type avec ILSpy. IL2CPP : extraire d'abord les métadonnées et les pointeurs de méthodes, puis appliquer les informations à Ghidra avant de décompiler les corps natifs. Unity compile l'IL en C++ puis en code natif pour IL2CPP. [S01, S02, S03, S11]

Des métadonnées peuvent fournir des noms présents dans la distribution sans garantir qu'ils sont les noms non obfusqués du projet original. Le stripping peut retirer du code ; un outil ne doit pas présenter un élément absent comme retrouvé. [S12]

### Périmètre strict : code du jeu et modules explicitement approuvés

Par défaut, **ne décompiler que les implémentations de gameplay et d’intégration propres au jeu** : assemblies de scripts (`Assembly-CSharp`, `Assembly-CSharp-firstpass` si présentes), assemblies identifiées comme appartenant au jeu, bibliothèques natives développées spécifiquement pour le jeu et scripts Lua authored/exposés par le jeu. Identifier ces composants pendant M0 ; les noms de fichiers seuls ne prouvent pas leur provenance. Les assemblies inconnues vont dans une file de revue et ne sont **pas décompilées automatiquement**.

Sont **exclus par défaut de l’export de pseudocode, de la reconstruction de projet, des CSV détaillés de fonctions et de la documentation générée** : `UnityEngine.*`, `Unity.*` du moteur ou des packages, les assemblies du framework (`System.*`, `mscorlib`, `netstandard`, etc.), `UnityPlayer.dll`, le runtime `libil2cpp`, les composants Mono, les DLL système, les frameworks Lua standard et les bibliothèques tierces génériques. Ne pas copier/dupliquer la documentation Unity et .NET officielle. Une exception ciblée, explicitement configurée et documentée, peut être nécessaire pour une bibliothèque réellement modifiée par le jeu ou un point d’intégration impossible à comprendre autrement.

Le profil Aniimo contient une exception explicite de module complet pour les quatre composants anti-cheat connus. Cette exception autorise l'export de leurs corps et de leur documentation ; elle ne change pas le statut du moteur Unity, des runtimes ou des autres bibliothèques tierces.

Pour les dépendances exclues, **la lecture des métadonnées est permise uniquement pour les signatures/types effectivement référencés**, les imports/exports, les références croisées et la validation de compatibilité. Conserver ces références dans les graphes, les CSV de liens et les fiches des fonctions du jeu, mais ne jamais exporter automatiquement le corps de ces dépendances comme pseudocode du jeu. Pour les classes Unity, privilégier un lien vers la documentation officielle. Les métadonnées ne sont pas une autorisation implicite de décompiler le code.

**Spécificité IL2CPP : ne pas exclure `GameAssembly.dll` en bloc.** Sur Windows, ce module regroupe du code de scripts IL2CPP et le runtime. Importer/analyser le module autant que nécessaire pour découvrir les limites et les références ; sélectionner ensuite les méthodes à décompiler **en fonction de leur assembly managée d’origine** et des preuves de leur appartenance au jeu. Un corps partagé jeu/bibliothèque doit être annoté avec plusieurs propriétaires et exporté seulement si nécessaire pour un symbole du jeu, sans conclure que tout son contenu appartient au jeu. Les méthodes natives sans provenance fiable restent en revue. `UnityPlayer.dll` reste hors périmètre de décompilation, sauf exception ciblée justifiée.

**Spécificité Lua : documenter l’API Lua exposée par le jeu, ses scripts et ses bindings** (y compris les signatures de méthodes Unity appelables si le bridge les expose). Ne pas redécompiler ni redocumenter les bibliothèques standards de Lua ou le moteur Lua ; conserver uniquement les liens et le contexte d’interopérabilité nécessaires.

Le mode `full` signifie « toutes les implémentations retenues et approuvées dans le profil », y compris les modules anti-cheat explicitement listés, **jamais « toutes les méthodes de Unity et tous les corps de GameAssembly »**. Inclure un test d’acceptation démontrant qu’un symbole moteur référencé est conservé comme dépendance, sans aucun export de son implémentation. Le plan d’exécution affiche distinctement `game_decompile`, `reference_only`, `excluded` et `needs_review`, avec un décompte par assembly/module et les raisons.

## 2. Stack minimale

Utiliser un orchestrateur Python, SQLite comme registre local et des fichiers JSON/CSV comme échanges. Les outils externes sont isolés derrière des adaptateurs. Une image minimale de capture, une image d'analyse, six volumes nommés aux responsabilités séparées et un répertoire de sorties suffisent pour le MVP. Ne pas ajouter de cluster, de service de recherche, de serveur de base de données ou de BSim distribué sans besoin mesuré.

Choix à évaluer sur le jeu :

| Besoin | Candidat | Limite à traiter |
|---|---|---|
| Code IL/Mono | ILSpy / ilspycmd | Décompilation C#, pas restauration du projet original |
| Métadonnées IL2CPP | Il2CppInspectorRedux | Choisir une version compatible et tester son intégration Ghidra |
| Extraction IL2CPP alternative | Il2CppDumper | Sa matrice documentée ne suffit pas à garantir un jeu récent |
| Chaîne interop | Cpp2IL + Il2CppInterop | Couples de versions à tester ensemble ; récupération des corps non garantie |
| Analyse native | Ghidra headless | Projet persistant, scripts par fonction et erreurs explicites |
| Mod runtime | BepInEx adapté au backend | Compatibilité plateforme/jeu à prouver, pas à supposer |
| Aide à l'appariement | Version Tracking / BSim | Activé par défaut sur le périmètre approuvé ; cache et résultats à vérifier |
| Scripts dans assets | Parseur Unity compatible, éventuellement AssetRipper | Extraction ciblée des scripts ; aucun besoin de reconstruire tout le projet |
| Documentation Lua | Définitions LuaLS + Markdown | Types inconnus conservés comme inconnus |

Références : [S01–S09, S14, S15, S20, S25, S27].

Pour Il2CppInspectorRedux, vérifier notamment le mode Python/PyGhidra demandé par les scripts de la version choisie. Ne pas supposer qu'un script Python moderne est compatible avec le mode Jython historique. Les assemblages factices et fichiers de types sont des descriptions, pas des implémentations récupérées. [S02, S03]

La documentation BepInEx IL2CPP actuelle dirige vers des builds Bleeding Edge. BepInEx/Cpp2IL/Il2CppInterop forment donc un couple de versions candidat, jamais une dépendance flottante. Tester la génération hors ligne avec les métadonnées Aniimo capturées et préalimenter les bibliothèques Unity/caches nécessaires avant tout test runtime. [S15, S27]

La documentation primaire confirme aussi que BSim génère ses vecteurs via le décompilateur : il ne constitue donc pas un détecteur de changements gratuit avant toute décompilation. [S08]

## 3. Organisation du dépôt et du stockage

```text
project/
  AGENTS.md
  WORKFLOW.md
  STATUS.md
  .dockerignore
  .env.example
  profiles/
    aniimo.yaml
    aniimo.inputs.yaml
    aniimo.decompilation.yaml
  schemas/
  migrations/
  tools.lock.json
  docker/
    capture.Dockerfile
    analyzer.Dockerfile
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
  docs/
    adr/
    aniimo/
    manual/

inputs/                        # Named volume: <prefix>inputs; analyzer read-only
  objects/sha256/
  snapshots/<snapshot_id>/
  current.json

state/                         # Named volume: <prefix>state
  registry.sqlite
  checkpoints/
  home/

artifacts/                     # Named volume: <prefix>artifacts
  sha256/

ghidra-state/                  # Named volume: <prefix>ghidra
  <toolchain>/<analysis_input_digest>/

cache/                         # Named volume: <prefix>cache

work/                          # Named volume: <prefix>work; disposable

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

Les volumes `inputs`, `state`, `artifacts`, `ghidra-state`, `cache` et `work`, ainsi que le dossier `output`, ne sont pas des copies de travail à modifier manuellement. Le dépôt Git conserve surtout le code de l'outil, les profils, les annotations et les contrats. Une vue normalisée peut être versionnée en privé pour les revues, sans obliger à stocker chaque binaire et chaque export dans Git. Le CAS `inputs` reste append-only dans le MVP. Son futur garbage collector exigera un pinset exporté depuis le registre ; il ne déduira jamais seul qu'un ancien snapshot est inutile. Le CAS `artifacts` utilise un mark-and-sweep explicite qui protège toute analyse publiée ou approbation.

`current.json` pointe vers le dernier ensemble d'artefacts d'analyse complet. `approved.json` identifie les capacités runtime validées, leur empreinte de dépendances, leur environnement et leurs preuves. Un succès d'analyse ne doit jamais mettre automatiquement à jour l'approbation runtime.

## 4. Identités et source de vérité

Le registre distingue :

- `snapshot_id` : hash de l'enveloppe de capture canonique, incluant le `build_id`, le digest de l'allowlist, le schéma et les statuts de présence ; il n'inclut aucun timestamp.
- `build_id` : hash du manifeste canonique des entrées du jeu pertinentes et de leurs contenus, indépendamment de la date ou du chemin absolu d'installation.
- `component_revision_id` : identité du contenu exact d'un composant cohérent, par exemple le couple `GameAssembly.dll`/métadonnées, une assembly, un module natif ou une paire d'archives Lua.
- `analysis_id` : identité d'une analyse du build avec versions d'outils, options, schémas, annotations applicables et observations importées.
- `symbol_id` : identifiant persistant de la méthode, du type ou du champ logique.
- `native_body_id` : identité suivie d'un corps natif, distincte de la méthode managée.
- `api_id` : contrat stable choisi par le SDK, indépendant des noms du jeu.
- `capability_basis_id` : hash canonique des dépendances exactes d'une capacité, de l'adaptateur/résolveur, de l'ABI et des tests requis.
- `runtime_authorization_id` : enregistrement d'une autorisation externe visant un artefact de mod exact, un signataire déclaré et un périmètre de builds ; ce n'est pas une preuve technique de compatibilité.

Le Steam build ID, la version interne, la version Unity et les identifiants de contenu Lua sont des références externes utiles, pas des identités canoniques. Un même Steam build peut être resigné ou voir un contenu actif évoluer ; inversement, une capacité peut rester valable sur un nouveau `build_id` si toutes ses dépendances exactes sont identiques et qu'une règle de transfert revue l'autorise.

La clé de recherche d'une méthode inclut l'identité logique d'assembly, le type qualifié et imbriqué, le nom, l'arité générique, les paramètres ordonnés, les modificateurs de passage, le retour et le caractère statique/instance. Elle exclut les adresses et tokens. Conserver les tokens comme preuves locales au build.

Un renommage ou changement de signature produit une nouvelle observation et, après examen, éventuellement un lien de succession ou un alias. Ne pas remplacer le registre par `SHA256(nom)` ou `SHA256(corps)` : ces valeurs changent avec le nom ou l'implémentation.

IL2CPP peut partager des implémentations génériques. Prévoir la relation plusieurs-à-plusieurs entre méthodes logiques et corps/points d'entrée : méthode, invoker, thunk, spécialisation, implémentation partagée. [S13]

## 5. Pipeline `capture` puis `analyze`

### Étape A — Contrôle et capture des entrées

Le service minimal `capture` est le seul à monter l'installation sous `/source/game` et le manifeste Steam sous `/source/steam`, tous deux en lecture seule. Il applique l'allowlist versionnée `profiles/aniimo.inputs.yaml`. Le service lourd `analyzer` ne possède aucun accès au dossier Steam.

Lors d'une capture normale, exécuter le préflight rapide : profil lisible, mounts requis, permissions, espace minimal, frontière de volumes et installation non annoncée en cours de mise à jour. Exécuter aussi les contrôles stables de `doctor` depuis leur cache, indexé par les digests d'images, du lock d'outillage et du profil ; présence/version des outils et chargement des adaptateurs ne sont réellement revérifiés que si cette base change. La commande explicite `doctor --refresh` force leur recalcul. Pour Aniimo/Steam, lire le manifeste `appmanifest_4126040.acf` monté séparément et enregistrer son état et son build ID comme preuves, sans les considérer comme une garantie suffisante.

Activer par défaut les feature sets `core`, `lua`, `content_indexes` et `anti_cheat`. Lire chaque `payload_rule` activée une seule fois par tentative, calculer SHA-256 sur le flux et contrôler taille/identité avant et après la lecture. Une dérive déclenche au maximum une nouvelle tentative, puis la capture échoue. Les règles d'inventaire ne lisent que leurs champs bornés et ne calculent pas le hash complet des composants exclus. La capture ne décompresse aucun fichier.

Pour un candidat inchangé, hacher sans écrire de staging ; si l'objet existe déjà, le référencer sans recopie. Pour un fichier nouveau ou dont les métadonnées ont changé, hacher pendant l'écriture en staging puis publier l'objet atomiquement. Un cas rare où les métadonnées sont identiques mais le SHA diffère nécessite une seconde lecture pour stocker les nouveaux octets ; ce n'est pas une double passe systématique. Construire ensuite le manifeste et la vue du snapshot, puis publier atomiquement `/inputs/current.json`. Toutes les étapes B à H lisent ce volume en lecture seule. Une dérive persistante, une paire IL2CPP incohérente ou un manifeste Steam non stabilisé invalide la capture entière.

`profiles/aniimo.decompilation.yaml` est une politique séparée. La présence d'un payload dans `inputs` signifie seulement qu'il est disponible pour détection, références ou analyse ; seul `scope-plan.json`, complété par des décisions prouvées, autorise l'export d'une implémentation.

Deux inventaires identiques espacés dans le temps ne prouvent pas, seuls, qu'un installateur n'est pas momentanément arrêté au milieu d'une mise à jour. Le contrat d'exploitation exige une installation terminée ou un export de snapshot déjà cohérent.

Hacher les contenus activés, et non uniquement les dates, tailles ou signatures Authenticode. Le mtime peut choisir une stratégie d'I/O mais ne prouve jamais l'identité. Exclure explicitement les journaux, sauvegardes, captures/photos, données de joueur, `.sample`, `.ainotes`, `.aitools` et propres sorties de la pipeline. Garder un manifeste complet du périmètre réellement retenu. Les artefacts canoniques utilisent des chemins relatifs normalisés et ne publient pas le chemin absolu de l'hôte.

### Étape B — Détection et plan

Produire `detection.json` puis un plan explicite : entrées inchangées, ajouts, retraits, étapes invalidées et raisons. Classer les composants en code du jeu, moteur, bibliothèques tierces, runtime, scripts et conteneurs d'assets.

Les motifs de noms du profil produisent des indices de classification, jamais directement une décision `game_decompile`. Une décision de périmètre est une donnée versionnée avec sujet, portée, preuves, raison, auteur/reviewer et version de politique. Les nouveaux composants Aniimo et les corps sans propriétaire fiable restent `needs_review`.

Indexer largement les métadonnées ; décompiler en priorité le code du jeu et les points d'intégration nécessaires. Le mode `full` couvre tous les corps natifs reconnus dans le périmètre autorisé, pas toutes les DLL système par défaut.

### Étape C — Extraction structurelle

Mono : métadonnées, types, méthodes, signatures, corps IL, champs, attributs, chaînes et références via des bibliothèques de lecture d'assemblies. Export C# par type avec ILSpy. Une assembly modifiée peut devoir être redécompilée intégralement, puis ses sorties comparées avant publication.

IL2CPP : traiter le binaire et son fichier de métadonnées comme une unité de cohérence. Extraire les noms, types, layouts, champs, signatures et correspondances de code disponibles. Toute extraction incomplète doit être signalée, jamais convertie en un catalogue vide marqué « succès ». Pour Aniimo, un en-tête ou format personnalisé non reconnu produit `unsupported_protected_metadata` jusqu'à validation d'un adaptateur spécifique ; aucun alignement historique ou ordinal ne remplace silencieusement l'extraction courante.

### Étape D — Analyse Ghidra

Conserver un programme par entrée d'analyse sémantique et configuration ; ne pas écraser un ancien programme avec un nouveau binaire. L'observation de chaque localisation reste attachée au build exact. Importer les symboles, signatures et types avant la passe de décompilation détaillée. Utiliser les API supportées de la version verrouillée. Ghidra propose le traitement headless et une décompilation fonction par fonction. [S05, S06, S07]

Une différence limitée au certificat PE n'autorise pas à comparer seulement `.text` et une section nommée `il2cpp`. La réutilisation d'un projet exige un manifeste du contexte de chargement pertinent : architecture, en-têtes et sections mappées, RVA/caractéristiques, imports, exports, relocations, données d'exception/unwind, tables et données référencées. En cas de doute, importer et analyser à nouveau.

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

### Chemin rapide et contrôles

Le run quotidien utilise une commande Compose qui enchaîne préflight/doctor, plan et écriture de capture, puis préflight/doctor et `analyze --snapshot current` après succès. Le plan de capture est résolu une fois et réutilisé pour l'écriture ; `capture --dry-run` est le même chemin arrêté avant toute écriture. `analyze` calcule son plan d'invalidation avant d'agir. Ghidra et BSim sont activés par défaut, mais si les entrées, les outils, la configuration et les annotations pertinentes ont les mêmes digests, ils sont marqués `cache_hit` sans être invoqués et aucune sortie n'est réécrite.

Les contrôles obligatoires par run sont uniquement ceux qui protègent la cohérence : préflight rapide, résultat mis en cache du doctor stable, parsing de configuration, présence des entrées requises, hash des payloads activés, contrôle avant/après lecture, cohérence des groupes, validation du manifeste, calcul des clés de cache et publication atomique. Le refresh complet de `doctor`, l'arrêt volontaire `--dry-run`, les sondes runtime, les tests de compatibilité d'outils et la matrice d'acceptation complète restent explicites.

Les tests unitaires et contractuels ordinaires emploient de minuscules fixtures synthétiques. Ils ne montent pas le jeu, ne lisent pas `GameAssembly.dll` et ne lancent pas Ghidra. Le catalogue de `specs/ACCEPTANCE.md` est sélectionné par jalon et par risque ; ce n'est pas une suite à rejouer intégralement après chaque capture.

### Rapport de run et mesures

Attribuer un `run_id` à l'orchestration complète. La capture conserve son fragment append-only dans `/inputs/run-reports/<run_id>.json` ; ces timestamps et mesures n'entrent dans aucun `snapshot_id`, `build_id` ou cache key. L'analyseur fusionne ce fragment avec ses mesures et publie atomiquement `run-report.json`, `report.md` et `timings.csv` sous `/output/reports/<run_id>/`, puis met à jour `/output/reports/latest.json`.

Chaque étape et sous-étape possède `step_id`, `parent_step_id`, catégorie, composant, statut, cache hit/miss, outil/version, heures de début/fin et durée monotone. Enregistrer aussi les nombres d'éléments et d'octets lus/écrits et, lorsque le système les fournit sans instrumentation lourde, temps CPU et pic RSS. Les étapes sautées ou en échec restent dans le rapport avec leur raison.

Le résumé sépare durée murale du workflow, somme des durées et chemin critique ; des sous-étapes parallèles ne doivent pas être additionnées comme si elles étaient séquentielles. Le chronométrage mesure le travail existant et ne déclenche aucun test ni recalcul supplémentaire.

## 6. Incrémentalité : ce qui est garanti et ce qui ne l'est pas

| Situation | Travail attendu |
|---|---|
| Aucun changement d'entrée, d'outil ou d'annotation | Aucun appel au décompilateur ; sorties inchangées |
| Seule la signature Authenticode/certificat PE change | Nouvelle provenance et contrôle de confiance ; réutilisation d'analyse uniquement si tout le contexte de chargement requis est identique |
| Une annotation documentaire change | Régénération de la doc dépendante, sans analyse binaire |
| Un script Lua source change | Analyse du script, de ses dépendants et de son API ; pas de Ghidra sans dépendance native affectée |
| Un bundle contenant des scripts change | Nouvelle extraction du conteneur, comparaison des contenus extraits |
| L'archive Lua active change mais pas la copie intégrée | Nouvelle `component_revision_id` Lua active ; aucun changement natif inventé et capacités Lua dépendantes à revalider |
| Une assembly Mono change | Nouvelle lecture ; export concerné et comparaison par type/méthode |
| GameAssembly ou global-metadata change | Nouvelle extraction cohérente ; mapping et analyse du module concernés |
| Un type change de layout | Révalidation des adaptateurs et fonctions dépendants, même à corps identique |
| Une fonction ne change que de localisation | Mise à jour des localisations ; contrôle des références et du contexte avant réutilisation du texte |
| Un asset sans dépendance déclarée change | Nouveau `build_id`; les capacités ne sont transférées que si leur empreinte exacte et leur règle de transfert l'autorisent |
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

Chaque capacité du SDK déclare ses dépendances en symboles, corps, layouts, données, bindings, résolveur/adaptateur, ABI et tests. Le registre calcule son `capability_basis_id`. Une mise à jour produit `compatible`, `requires_validation`, `unavailable` ou `breaking` avec preuves. Le runtime charge seulement les capacités dont la base exacte est approuvée pour l'environnement observé et conserve un mode de dégradation sûr. Un build global inconnu n'invalide pas par principe une capacité dont toutes les dépendances sont inchangées, mais aucune approbation n'est transférée sans règle explicite et vérifiable.

L'autorisation externe du mod distribué est un axe séparé : `not_requested`, `pending`, `approved`, `rejected`, `expired` ou `unknown`. Elle référence au minimum le hash exact du package, l'identité du signataire lorsqu'elle existe, la version du mod, le périmètre de builds déclaré, la preuve administrative et ses dates. Le pipeline peut développer et tester localement avant cette autorisation, mais ne marque jamais un artefact comme autorisé par simple réutilisation d'un certificat ou d'un nom de fichier.

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

M-1 : contrat d'architecture, hygiène Git/Docker, profil Aniimo prudent, décisions ADR et tests d'acceptation spécifiés. Ce jalon ne touche pas à l'installation du jeu.

M0 : bundle d'acquisition borné et diagnostic en lecture seule du build courant, classification initiale, import séparé des preuves historiques et sélection vérifiée d'outils. Le bundle réside sous `.aitools/m0-acquisition/<capture_id>/`, applique les feature sets par défaut `core`, `lua`, `content_indexes` et `anti_cheat` de `profiles/aniimo.inputs.yaml` et contient un manifeste canonique, les hashes et les copies immuables des seules entrées autorisées ; il ne fige pas le schéma du CAS de production. Livrer `detection.json`, `scope-plan.json`, `tool-compatibility.json` et le rapport, puis s'arrêter.

M1 : images séparées `capture`/`analyzer`, orchestration en une commande, préflight/doctor mis en cache, commandes `doctor`/`capture`/`plan`/`analyze`, manifeste, registre, migrations, identités, CAS d'entrées et d'artefacts, snapshots, plans réutilisables, cache, checkpoints, rapport détaillé de timings, petites fixtures et exécution sans changement. Prouver que l'analyseur ne reçoit aucun bind mount Steam, que `inputs` y est read-only, qu'un dry-run et la capture partagent le même planificateur et qu'un cache hit Ghidra/BSim n'appelle aucun outil lourd. Réimporter avec validation ou recapturer le bundle M0 ; ne jamais lui attribuer implicitement le nouveau contrat.

M2 : branche Mono ou IL2CPP réelle, CSV et découpage propre du code, sans imposer l'autre backend avant que le premier fonctionne.

M3 : comparaison multi-build, invalidation des layouts/références, revue d'appariement et documentation incrémentale.

M4 : Lua statique et bindings, puis sonde runtime séparée et définitions LuaLS.

M5 : une capacité SDK utile, loader adapté, un mod exemple et tests réels sur deux builds, avec validation technique et autorisation externe représentées séparément.

M6 : extension de l'API, matching natif avancé si nécessaire, surveillance locale optionnelle et durcissement de distribution.

Le critère final n'est pas le nombre de lignes décompilées : c'est la capacité à expliquer un changement, adapter une dépendance interne, et garder un mod existant fonctionnel sans lui faire connaître les nouveaux offsets.
