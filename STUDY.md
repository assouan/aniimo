## Mon verdict

**Je conserverais l’architecture actuelle, mais je ne considérerais pas encore le dépôt comme prêt à garantir tous tes objectifs.** Le choix central que tu privilégies est déjà bien posé : **un fichier C par corps natif, avec une organisation par classe et namespace**, des identifiants persistants et un traitement incrémental. Les principales corrections concernent la garantie de sortie ASM après échec, la mesure de couverture et la reprise des fonctions difficiles.

J’ai examiné le dépôt au commit [`68eb547b2f5679684d21dfe7988a35471fb7efd2`](https://github.com/assouan/aniimo/tree/68eb547b2f5679684d21dfe7988a35471fb7efd2), récupéré ses **52 fichiers** et vérifié leur correspondance avec l’arbre Git de cette révision. Les **10 tests existants passent en 0,022 seconde** ; les six profils YAML et le modèle Compose sont également parsables.

Il faut cependant garder l’état réel du projet en tête : **M-1 est un jalon d’architecture. La CLI, les Dockerfiles, les analyseurs, les schémas et les migrations ne sont pas encore implémentés.** Le dépôt le dit correctement dans [STATUS.md](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/STATUS.md#L47). Les points positifs ci-dessous sont donc des engagements de conception, pas encore des résultats démontrés sur Aniimo.

**Cette revue n’a pas appliqué de modifications au dépôt.**

## Réponse directe à tes exigences

| Ton objectif | Évaluation de l’architecture actuelle |
|---|---|
| Décompiler le code natif du jeu en ASM puis en C | Bonne chaîne prévue : métadonnées et types avant Ghidra. Compatibilité réelle à établir pendant M0. |
| Écarter le code purement Unity | Bien prévu, notamment le traitement de `GameAssembly.dll` comme conteneur mixte. |
| Retrouver les noms et signatures | Bonne priorité aux métadonnées, symboles et bindings. Le prototype natif doit être mieux formalisé. |
| Produire beaucoup de `.c` lisibles, organisés | **Oui pour le découpage par corps. La vue de lecture par classe doit devenir obligatoire.** |
| Ne pas tout recommencer après une mise à jour | Architecture incrémentale solide, avec une réserve sur la mémorisation des échecs. |
| Raccorder une fonction dont l’intérieur a complètement changé | Correctement envisageable quand son identité logique reste identifiable. Une correspondance certaine n’est pas toujours possible. |
| Indexer fonctions, signatures et références | Bien décrit dans le modèle de données, encore à implémenter. |
| Générer une petite documentation | Bonne approche : génération déterministe depuis le registre, sans paraphraser tout le C. |
| Conserver au minimum de l’ASM quand le C échoue | **Insuffisamment garanti par les contrats actuels.** |
| Éviter les longues vérifications inutiles | Bonne séparation entre contrôles quotidiens et validations de jalon. Le budget des fonctions difficiles reste à préciser. |

---

## 1. Le C multifichier : le bon choix est déjà là

La [section « Découpage du code »](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/WORKFLOW.md#L269) impose déjà une granularité canonique par corps natif :

| Artefact | Rôle |
|---|---|
| `native/bodies/<native_body_id>.c` | Pseudocode de ce corps |
| `native/bodies/<native_body_id>.asm` | Désassemblage correspondant |
| `native/bodies/<native_body_id>.json` | Informations structurées et provenance |
| `native/bodies/<native_body_id>.refs.json` | Références de ce corps |
| `native/types/<type_id>.h` | Types récupérés |
| `native/index/by-class/.../index.json` | Navigation par assembly, namespace et type |

Le workflow interdit aussi de produire un gigantesque C puis de le découper avec des expressions régulières. Il prévoit l’utilisation de `DecompInterface.decompileFunction`, ce qui correspond bien à l’API officielle de Ghidra : décompilation fonction par fonction, avec une interface persistante réutilisable. [ghidra.re](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html?utm_source=chatgpt.com)

### Ce que je renforcerais pour obtenir le résultat que tu attends

**La vue lisible doit être un livrable obligatoire.** Actuellement, le texte dit qu’une vue navigable *peut* présenter des noms comme `TakeDamage__<symbol_id>.c`. Cela laisse encore la possibilité de livrer principalement un grand dossier de fichiers identifiés par UUID, accompagné d’index JSON.

Pour ton usage, j’imposerais :

- une vue par **assembly → namespace → type → méthode** lorsque l’origine managée est connue ;
- une vue par **module → fonction** pour le natif sans type managé identifié ;
- un nom lisible accompagné d’un identifiant stable pour les surcharges et collisions ;
- des liens directs vers le C, l’ASM, la signature et les références ;
- un chemin stable pour les fonctions encore sans nom établi.

Le stockage canonique peut rester organisé par identifiants. **Le livrable que tu parcours doit présenter les noms, les classes et les modules.**

Autre bon choix à conserver : une méthode managée et un corps natif sont deux objets distincts. IL2CPP peut partager une implémentation entre plusieurs instanciations génériques. Il faut donc exporter ce corps une seule fois, tout en le rendant accessible depuis chacun des symboles associés. Le dépôt le prévoit déjà, et Unity documente ce mécanisme de partage. [unity.com](https://unity.com/blog/engine-platform/il2cpp-full-generic-sharing-in-unity-2022-1-beta?utm_source=chatgpt.com)

Enfin, « beau C » doit aussi signifier **types, champs, appels et constantes bien identifiés**. Le formatage ne compensera pas une décompilation réalisée avant l’import des types. L’ordre actuel — récupérer les métadonnées, appliquer les signatures et layouts, puis décompiler — est donc à préserver.

---

## 2. Priorité haute : rendre le résultat C ou ASM obligatoire

C’est le principal écart avec ta demande.

Le [workflow, à l’étape Ghidra](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/WORKFLOW.md#L199), demande qu’un timeout produise une erreur explicite. Le [scénario A21](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/specs/ACCEPTANCE.md#L27) demande un échec local, un checkpoint et une couverture honnête.

**Aucun des deux ne dit explicitement qu’un fichier ASM doit survivre à cet échec.**

Un futur exporteur pourrait donc attraper l’exception, écrire un diagnostic et passer à la fonction suivante. Il respecterait une bonne partie du contrat actuel, sans te fournir l’ASM attendu.

### Le contrat à ajouter

**Pour chaque corps natif approuvé dont les instructions sont disponibles, exporter l’ASM indépendamment de la réussite du C.**

Concrètement, l’étape de désassemblage doit produire son artefact avant la tentative de décompilation, ou dans une étape indépendante dont le résultat reste disponible si le décompilateur plante.

Je définirais au minimum ces états :

| État du corps | Résultat attendu |
|---|---|
| `c_and_asm` | C produit, ASM disponible, provenance et avertissements conservés |
| `asm_only` | ASM disponible, raison précise de l’absence de C |
| `disassembly_failed` | Octets et contexte conservés lorsque disponibles, erreur explicite |
| `pending` | Corps identifié, traitement encore incomplet |

Un `.c` vide, tronqué ou constitué d’un message d’erreur ne doit jamais compter comme une réussite. Les avertissements doivent rester visibles même quand Ghidra termine : son API indique qu’un résultat terminé peut encore comporter des avertissements. [ghidra.re](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html?utm_source=chatgpt.com)

Cette règle doit aussi permettre de continuer les autres fonctions après un échec local.

Il reste une limite technique incontournable : si les limites d’une fonction ou ses instructions ne sont pas connues, on ne peut pas fabriquer honnêtement son ASM. Dans ce cas, **le résultat attendu est une lacune explicite et indexée**, avec les éléments disponibles pour la résoudre.

---

## 3. Priorité haute : compter ce qui manque, pas seulement ce qui a réussi

Le dépôt définit actuellement `full` comme tous les corps natifs **reconnus** dans le périmètre, puis demande de parcourir les fonctions **reconnues** par l’analyse. Voir [WORKFLOW.md](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/WORKFLOW.md#L185).

C’est une base utile, mais elle ne suffit pas à garantir ta demande d’exhaustivité.

**Traiter toutes les fonctions découvertes ne prouve pas qu’on a découvert toutes les fonctions pertinentes.**

Il faut ajouter un bilan à trois niveaux.

### A. Les symboles attendus ou observés

Pour chaque méthode issue des métadonnées, symboles ou bindings :

- son identité ;
- ses associations éventuelles avec des corps natifs ;
- la raison d’une absence de corps autonome, lorsqu’elle est établie.

Les méthodes abstraites, externes, éliminées ou intégrées dans une autre fonction doivent avoir des états distincts. Le modèle actuel reconnaît déjà cette difficulté dans [DATA_MODEL.md](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/specs/DATA_MODEL.md#L64), mais il faut en faire un contrat de sortie précis.

### B. Les corps natifs

Chaque corps doit avoir une origine de découverte, une décision de périmètre, ses plages d’instructions et un résultat C/ASM.

Le bilan doit réconcilier exactement :

**corps approuvés = C + ASM disponibles + ASM seul + erreurs de désassemblage + corps en attente.**

Les catégories doivent être exclusives. Un corps partagé est compté une fois côté natif, avec plusieurs associations côté méthodes.

### C. Les zones ou candidats non résolus

Le rapport doit aussi montrer :

- les méthodes attendues sans correspondance native ;
- les pointeurs ou cibles d’appels non résolus ;
- les candidats de fonctions non confirmés ;
- les plages exécutables encore non attribuées.

Toutes les plages exécutables ne sont pas nécessairement des fonctions du jeu : elles peuvent contenir du padding ou des données. Il faut conserver cette incertitude plutôt que leur attribuer artificiellement un nombre de fonctions.

Je compléterais la découverte par le recoupement des métadonnées IL2CPP, symboles de débogage, exports, références d’appels et informations de fonctions disponibles dans le format binaire.

**Ajout ciblé utile : `SymbolMap`.** L’allowlist actuelle ne le mentionne pas. Unity documente ce fichier comme pouvant contenir les adresses et longueurs de fonctions managées. Une règle optionnelle permettrait de l’utiliser lorsqu’il est distribué, après vérification de sa cohérence avec le module courant. Cela ne présume pas de sa présence dans Aniimo. [Unity Docs](https://docs.unity.com/en-us/engine/6000.0/manual/platform-specific/windows/develop/player-il2cppscripting-backend?utm_source=chatgpt.com)

Avec cette comptabilité, tu peux distinguer « tous les corps identifiés ont été traités » et « des parties du code restent à découvrir ». C’est une garantie beaucoup plus utile qu’un pourcentage global trompeur.

---

## 4. Un point technique concret à corriger avant M0 : le magic IL2CPP

J’ai trouvé une qualification insuffisamment étayée dans les documents.

Le [README](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/README.md#L29) et le [workflow](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/WORKFLOW.md#L13) évoquent un **en-tête de métadonnées personnalisé**. Or la preuve versionnée dans [HISTORICAL_EVIDENCE.md](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/docs/aniimo/HISTORICAL_EVIDENCE.md#L18) est :

`AF 1B B1 FA`

**Ces quatre octets correspondent exactement au magic IL2CPP standard `0xFAB11BAF`, stocké en little-endian.** Le parseur d’Il2CppDumper vérifie précisément cette valeur. [GitHub](https://github.com/Perfare/Il2CppDumper/blob/master/Il2CppDumper/Il2Cpp/Metadata.cs?utm_source=chatgpt.com)

Cela ne démontre pas que le reste du fichier est standard : sa version, ses tables ou ses données peuvent être modifiées. Mais **ces quatre octets seuls ne justifient pas la qualification « personnalisé »**.

Je remplacerais l’affirmation par :

> Magic IL2CPP standard observé ; conformité du reste des métadonnées à déterminer.

C’est pertinent pour ton souci de temps : Codex doit commencer par tester le format et les parseurs compatibles, puis établir la cause d’un éventuel échec. Une version non prise en charge, un fichier incohérent et une protection particulière ne doivent pas être assimilés automatiquement au même problème.

---

## 5. Les mises à jour : la conception est solide, avec des limites bien choisies

Sur l’incrémentalité, le dépôt a déjà pris plusieurs bonnes décisions :

- snapshots immuables ;
- composants et révisions séparés ;
- registre persistant ;
- stockage par contenu ;
- clés de cache tenant compte des dépendances sémantiques ;
- absence de réécriture des sorties identiques ;
- séparation entre modification du jeu, modification des outils et modification des annotations.

Ces règles sont détaillées dans les [sections « Identités » et « Incrémentalité »](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/WORKFLOW.md#L145).

### Le comportement à obtenir

| Situation | Travail attendu |
|---|---|
| Entrées, outils et contexte inchangés | Contrôle des entrées, puis réutilisation ; aucun nouvel appel de décompilation |
| Une note documentaire change | Régénération des pages concernées |
| Un composant Lua change sans dépendance native affectée | Analyse Lua et dépendances concernées |
| Une DLL indépendante change | Analyse de ce composant et de ses consommateurs concernés |
| `GameAssembly.dll` est recompilé | Nouvelle découverte/auto-analyse du module si nécessaire, puis réutilisation des résultats dont le contexte reste valide |
| Un layout ou une cible d’appel change | Invalidation des fonctions dépendantes, même si leurs octets paraissent identiques |
| Une fonction est seulement déplacée | Résolution de sa nouvelle localisation et vérification du contexte avant réutilisation |

**Le changement du `build_id` global ne doit pas devenir une invalidation automatique de tous les caches locaux.** Le contrat actuel va dans ce sens ; l’implémentation M1 devra le démontrer.

À l’inverse, le dépôt a raison de ne pas promettre qu’une modification de quelques octets permet toujours une analyse limitée à cette petite plage. Une recompilation peut modifier les limites, les références et l’organisation des fonctions. Il peut être nécessaire de refaire l’auto-analyse du module, tout en évitant de redécompiler ou réécrire chaque sortie.

### Une fonction entièrement réécrite peut-elle être raccordée ?

**Oui, si son identité logique reste identifiable.**

Par exemple, si les métadonnées permettent toujours de reconnaître la même méthode, on peut :

1. conserver son `symbol_id` ;
2. enregistrer une nouvelle observation de son corps et de sa localisation ;
3. marquer `body_changed` ;
4. produire son nouveau C ;
5. invalider les annotations et capacités dépendantes concernées.

Il n’est pas nécessaire que l’ancien et le nouveau corps aient une forte similarité ASM. Le [modèle d’appariement actuel](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/specs/DATA_MODEL.md#L80) prévoit déjà identités, preuves, contradictions et changements séparés.

**Si le nom, la signature et l’implémentation changent ensemble**, la correspondance peut devenir incertaine. Dans ce cas, les candidats doivent rester des candidats. Le dépôt prévoit correctement de ne pas fusionner automatiquement les identités sur un score de similarité.

BSim est utile pour ces recherches, mais ses caractéristiques omettent volontairement certaines informations, notamment les valeurs des constantes. Il ne faut donc jamais l’utiliser seul pour conclure que le comportement est inchangé. Les empreintes et références supplémentaires prévues dans ton architecture sont nécessaires. [ghidra.re](https://ghidra.re/ghidra_docs/GhidraClass/BSim/BSimTutorial_Intro.html?utm_source=chatgpt.com)

---

## 6. Éviter de perdre du temps : compléter le cache des échecs

Le fonctionnement quotidien est raisonnablement borné : préflight léger, contrôles stables de `doctor` mis en cache, absence de Ghidra/BSim sur cache hit et pas de matrice d’acceptation complète à chaque update. Voir le [budget de vérification](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/specs/DOCKER_CONTRACT.md#L81).

**Je garderais ces règles.**

Le trou se trouve dans le traitement des fonctions difficiles. Le [profil Aniimo](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/profiles/aniimo.yaml#L83) fixe un timeout de **120 secondes par fonction**, mais les contrats ne précisent pas assez ce qui arrive à une tentative déjà échouée lors du run suivant.

À titre d’illustration, 100 fonctions atteignant chacune ce délai représentent **3 h 20 de temps cumulé**, avant prise en compte du parallélisme. Ce n’est pas une mesure sur Aniimo.

### La règle à ajouter

Un échec C connu doit être conservé avec :

- le corps et son contexte ;
- la version de l’outil ;
- les options et le budget utilisés ;
- le diagnostic ;
- l’ASM disponible ;
- les conditions autorisant une nouvelle tentative.

Une update identique doit réutiliser ce résultat `asm_only`. Une nouvelle tentative doit être déclenchée par une raison concrète : nouveaux types, meilleure signature, correction du parseur, autre version du décompilateur, changement pertinent du contexte ou demande ciblée de reprise.

Pour maximiser progressivement la proportion de C, je prévoirais **une première passe bornée**, puis une file de fonctions difficiles. Le budget de cette file doit être mesuré et contrôlé. Les fonctions en ASM restent visibles et retravaillables ; elles ne doivent ni disparaître, ni monopoliser chaque update.

Pour BSim, je distinguerais aussi la construction de l’index et la recherche de correspondances. Une méthode déjà identifiée exactement par ses métadonnées n’a pas besoin d’une recherche fuzzy pour établir son identité.

Enfin, une update sans changement relira encore les payloads sélectionnés pour établir leurs hashes. C’est prévu explicitement. **« Aucun recalcul d’analyse » ne signifie donc pas « aucune lecture disque ».** Supprimer ce contrôle reviendrait à faire confiance aux dates et tailles, ce que le contrat refuse à juste titre.

---

## 7. Noms et signatures : bonne stratégie, modèle natif à préciser

La priorité donnée aux métadonnées et aux symboles avant la décompilation est correcte. Le modèle conserve également la provenance des noms : métadonnées, symboles, exports, bindings, observations ou inférences. Voir [DATA_MODEL.md](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/specs/DATA_MODEL.md#L42).

Il faut toutefois maintenir deux distinctions.

### Noms récupérés et noms inférés

Un nom présent dans les métadonnées est un nom observé dans la distribution. S’il est obfusqué, il ne devient pas automatiquement le nom original du développeur.

Codex peut proposer un nom fonctionnel plus lisible, mais celui-ci doit rester un alias avec ses preuves. Il ne doit pas remplacer silencieusement l’information extraite.

Il2CppInspectorRedux fournit précisément des structures, types, pointeurs et informations utiles à cette récupération. Son README précise cependant que l’outil n’est pas un décompilateur restituant les implémentations complètes. [GitHub](https://github.com/LukeFZ/Il2CppInspectorRedux?utm_source=chatgpt.com)

### Signature managée et prototype natif

Je formaliserais séparément :

- `managed_signature` : signature logique de la méthode ;
- `native_prototype` : prototype du point d’entrée natif, lié au build, à l’architecture et à son rôle.

Le dépôt connaît déjà les méthodes, invokers, thunks et corps partagés, mais leur prototype natif reste insuffisamment structuré dans le contrat d’échange. Un adaptateur ne doit pas appliquer aveuglément la signature managée à tous ces points d’entrée.

Il existe aussi une petite divergence documentaire : [WORKFLOW.md](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/WORKFLOW.md#L161) inclut explicitement le caractère statique/instance dans la clé de signature ; [DATA_MODEL.md](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/specs/DATA_MODEL.md#L46) l’omet dans son énumération. Les deux définitions doivent être alignées avant d’écrire le normaliseur.

---

## 8. Deux autres points d’architecture à préciser

### Découvrir les nouveaux emplacements de code

L’allowlist est volontairement bornée, ce qui est utile pour éviter de copier toute l’installation. Mais les [règles d’inventaire actuelles](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/profiles/aniimo.inputs.yaml#L237) couvrent surtout les DLL/EXE racine et les DLL/PDB de `Plugins/x86_64`. Les archives Lua connues sont sélectionnées par leurs chemins exacts.

Un nouveau conteneur de scripts ou un module situé ailleurs pourrait donc ne même pas apparaître comme élément à examiner.

Je compléterais cela par un **inventaire borné guidé par les manifestes et références disponibles**, avec une liste `additional_input_candidates` et une description des zones effectivement inspectées. Cela permet de détecter les nouveaux besoins de capture sans décompresser tous les assets.

### Attacher chaque analyse à sa capture exacte

Le [Compose cible](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/examples/compose.example.yaml#L53) attend la fin de la capture, puis lance `analyze --snapshot current`.

Si deux captures utilisent les mêmes volumes, la seconde peut remplacer `current` avant que l’analyseur de la première ne le lise. L’atomicité du pointeur évite un fichier partiel, mais ne garantit pas l’association avec la bonne capture.

Le correctif est simple : **transmettre à l’analyseur le `snapshot_id` immuable produit par son run**, directement ou par un enregistrement de remise identifié par run. `current` peut rester un raccourci pour les lancements manuels.

---

## 9. Index et mini-documentation : garder l’approche actuelle

Le [modèle de données](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/specs/DATA_MODEL.md#L96) prévoit déjà les vues utiles : méthodes, localisations, associations méthodes-corps, types, champs, références et changements.

Je conserverais SQLite comme registre de travail et les exports JSON/CSV comme vues. Il faut surtout rendre les relations facilement consultables.

Pour chaque fonction, la référence minimale devrait permettre de trouver :

| Information | Utilité |
|---|---|
| Identifiant, nom et provenance du nom | Retrouver le même symbole et connaître la fiabilité de son nom |
| Signature logique et prototype natif connu | Comprendre les paramètres et le point d’entrée |
| Module, build et localisation | Revenir à l’observation binaire exacte |
| Liens C et ASM | Lire directement le résultat |
| Appelants, appelés et données/types référencés | Comprendre ses relations |
| État de décompilation et diagnostics | Voir immédiatement les limites |
| Changements depuis le build précédent | Orienter la maintenance |

J’ajouterais une vue explicite par corps, par exemple `native_bodies.csv`, ainsi qu’un `coverage.json` calculé depuis le registre.

La stratégie documentaire actuelle est bonne : pages regroupées par type/module, ancres par symbole, index paginés et génération déterministe. Elle évite de demander à un modèle de réexpliquer des centaines de milliers de fonctions à chaque mise à jour. Voir [la section documentation](https://github.com/assouan/aniimo/blob/68eb547b2f5679684d21dfe7988a35471fb7efd2/WORKFLOW.md#L364).

---

## 10. Le C décompilé et l’API DLL doivent rester séparés

**Le corpus C multifichier peut être excellent pour comprendre et maintenir les bindings. Sa présence ne suffit pas à créer une API DLL utilisable.**

Le dépôt prend déjà la bonne direction : contrats publics stables, adaptateurs internes versionnés et validation par capacité. Les fichiers décompilés sont exclus des cibles de compilation du SDK.

Il faut aussi préciser ce que recouvre « DLL » :

| Type de mod | Conséquence pour le projet |
|---|---|
| DLL managée C# | Correspond à la trajectoire actuelle avec un loader et une interop adaptés |
| DLL native C/C++ | Demande un contrat d’API native explicite : types, handles, conventions d’appel, durée de vie et callbacks |

Il2CppInterop fournit un pont entre IL2CPP et CoreCLR ainsi que des outils de génération d’assemblies ; c’est une piste cohérente pour la première trajectoire, dont la compatibilité Aniimo reste à vérifier. [GitHub](https://github.com/BepInEx/Il2CppInterop?utm_source=chatgpt.com)

Deux limites doivent rester clairement représentées dans les résultats :

- Pour Mono, l’IL et le C# sont les représentations adaptées ; pour Lua, les scripts ou le bytecode doivent rester exploités dans leur forme pertinente. Une conversion artificielle de tout cela en C n’améliorerait pas automatiquement la compréhension. Les backends Mono et IL2CPP suivent des chaînes différentes. [docs.unity3d.com](https://docs.unity3d.com/6000.6/Documentation/Manual/scripting-backends.html?utm_source=chatgpt.com)
- Le code supprimé lors de la compilation n’est pas forcément présent dans les fichiers distribués. Unity documente ce stripping. De même, une implémentation uniquement présente sur un serveur distant ne peut pas être récupérée depuis les seuls fichiers du client. [docs.unity3d.com](https://docs.unity3d.com/6000.0/Documentation/Manual/managed-code-stripping.html?utm_source=chatgpt.com)

L’objectif vérifiable est donc : **un corpus aussi complet que possible du code présent et accessible, avec chaque omission explicitée, puis des capacités de modding construites et testées à partir de ces connaissances.**

---

## Ordre de travail recommandé pour Codex

Je garderais les jalons actuels, avec ces compléments ciblés.

### Avant M0 : fermer les ambiguïtés du contrat

1. Rendre obligatoire la vue C lisible par assembly/type/module.
2. Imposer l’ASM indépendant du succès C.
3. Définir les états et la réconciliation de couverture.
4. Définir le cache des échecs et les conditions de reprise.
5. Corriger la qualification du magic IL2CPP.
6. Aligner les signatures et attacher chaque run à son snapshot exact.

### M0 : établir la faisabilité réelle sur les entrées disponibles

Confirmer le backend, le format des métadonnées, les composants et les outils compatibles. Le dépôt a raison de ne pas remplir le verrou d’outillage avec des versions supposées fonctionner.

### M1–M2 : prouver rapidement les garanties principales

Les petits tests prioritaires seraient :

| Cas | Preuve attendue |
|---|---|
| Plusieurs fonctions, dont un corps partagé | Plusieurs C canoniques correctement indexés, aucun monobloc, associations conservées |
| Timeout C imposé | ASM et diagnostic disponibles ; les autres fonctions continuent |
| Deuxième run identique après ce timeout | Aucun nouvel appel coûteux à conditions inchangées |
| Même méthode, corps entièrement remplacé | Identité logique conservée, nouveau corps observé, `body_changed` |
| Constante ou layout modifié | Changement détecté et dépendances concernées invalidées |
| Méthode attendue sans corps résolu | Lacune visible dans le bilan |
| Deux captures entrelacées | Chaque analyse consomme son snapshot exact |

Ces tests doivent être automatisés au jalon concerné sur de petites fixtures. Ils n’ont pas à devenir une longue vérification du jeu entier à chaque update.

**Pour ton besoin principal, je poserais ce critère de livraison de M2 : ouvrir une classe ou un module, accéder directement à ses fonctions en fichiers C séparés, retrouver leur ASM et leurs références, et voir immédiatement la liste exacte de ce qui reste en ASM seul ou non résolu.** C’est la garantie concrète qui manque encore entre l’architecture actuelle et le résultat que tu veux obtenir.
