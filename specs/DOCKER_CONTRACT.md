# Contrat Docker et interface CLI

## Statut

La CLI `modkit`, `docker/capture.Dockerfile`, `docker/analyzer.Dockerfile` et les scripts sont à implémenter. `examples/compose.example.yaml` est un modèle de configuration, pas un service existant. Copier le modèle à la racine seulement après création des deux images et de la CLI.

Le contexte de build doit contenir `.dockerignore`. Il exclut obligatoirement `.sample`, `.ainotes`, `.aitools`, `.git`, les entrées du jeu, `state`, `inputs`, `artifacts`, `output`, les bases locales et les caches. La construction échoue dans un test si un de ces chemins est visible depuis le contexte. `.gitignore` ne remplace pas `.dockerignore`.

## Interface cible

Chemin normal après construction des images :

```sh
docker compose up --abort-on-container-failure
```

Commandes explicites de diagnostic, préparation ou release :

```sh
docker compose build capture analyzer
docker compose run --rm --no-deps analyzer doctor --refresh
docker compose run --rm capture capture --dry-run
docker compose run --rm capture capture --disable-feature content_indexes
docker compose run --rm --no-deps analyzer plan --snapshot current
docker compose run --rm --no-deps analyzer diff --from <build-id> --to <build-id>
docker compose run --rm --no-deps analyzer docs
docker compose run --rm --no-deps analyzer verify --scope static
docker compose run --rm --no-deps analyzer lua-import /observations/snapshot.json
```

Les mounts nécessaires à `lua-import` doivent être ajoutés explicitement. La sonde produit ses observations à l'extérieur du conteneur. Les commandes ci-dessus sont un contrat, pas la preuve qu'un outil `modkit` est déjà installé.

Le chemin normal comprend automatiquement deux niveaux de `doctor` : contrôles rapides à chaque run (configuration, mounts, permissions, espace et frontière read-only), puis contrôles stables mis en cache par digests d'images, `tools.lock.json` et profil (présence/version des outils et chargement des adaptateurs). `doctor --refresh` invalide volontairement ce cache pour un diagnostic complet ; il n'est pas nécessaire avant chaque mise à jour.

Le plan de capture résout toujours l'allowlist et produit les payloads, fichiers seulement inventoriés, absences et volume estimé. Le run réel réutilise exactement ce plan dans le même processus, sans second inventaire. `capture --dry-run` exécute le même plan mais s'arrête avant le hash/copie et toute écriture dans `inputs`. Le rapport réel de capture enrichit ensuite le plan avec les hashes et statuts effectivement observés.

La commande par défaut de `capture` exécute préflight, plan et capture, publie un snapshot puis s'arrête. Compose attend son code 0 grâce à `condition: service_completed_successfully`, puis lance `analyzer` sur le snapshot `current` sans lui permettre de relire Steam. L'analyseur exécute son préflight et son plan d'invalidation avant les étapes nécessaires ; il échoue explicitement si `current` est absent, incomplet ou ne correspond pas aux schémas/politiques attendus.

Plus tard, seul le service de capture peut surveiller l'installation à intervalles configurables :

```sh
docker compose run --rm capture watch --interval 300
```

Le watcher n'est utile que tant que ce processus s'exécute. Prévoir arrêt propre, contrôle de fin d'installation, absence d'exécutions superposées et reprise des erreurs. Ne pas s'appuyer uniquement sur les notifications filesystem d'un montage hôte.

`capture` lit `/source/game` et le manifeste Steam en lecture seule. Il applique par défaut les feature sets `core`, `lua`, `content_indexes` et `anti_cheat` de `profiles/aniimo.inputs.yaml`, place les nouveaux octets sélectionnés dans le CAS du volume `/inputs`, puis publie atomiquement `/inputs/current.json`. Les entrées absentes et les éléments seulement inventoriés sont enregistrés sans être présentés comme copiés. Les quatre composants anti-cheat connus sont des payloads exacts et complets.

`plan`, les extracteurs, Ghidra et BSim utilisent uniquement le snapshot du volume `/inputs`, monté en lecture seule dans `analyzer`. Ce service reçoit aussi l'allowlist comme configuration read-only afin de vérifier son digest contre le snapshot, mais ne possède aucun bind mount vers le jeu ou Steam. Une commande Compose enchaîne les deux services tout en conservant deux conteneurs et deux frontières de privilèges auditables.

Le snapshot fournit une vue matérialisée sous `/inputs/snapshots/<snapshot_id>/files/` pour les outils exigeant des chemins ordinaires. Les fichiers peuvent être des hardlinks en lecture seule vers `/inputs/objects/sha256/` lorsque le filesystem le permet ; le manifeste reste la source de vérité. Un objet identique n'est jamais recopié entre snapshots.

## Construction

L'image `capture` reste minimale : runtime de la CLI, hachage, lecture sûre de PE/manifestes et publication atomique. Elle ne contient ni Ghidra ni décompilateur. L'image `analyzer` installe les versions exactes de Python, Java/Ghidra, .NET et des extracteurs choisis. Les sources, releases, commits, checksums et versions sont consignés dans `tools.lock.json`. Les valeurs du lock ne sont remplies qu'après vérification ; aucun hash fictif. Les fixtures et tests de compatibilité sont exécutés lors de la validation des images.

Installer et initialiser les outils pendant la construction de l'image. Le runtime d'analyse ne télécharge rien, ne résout pas de nouvelles dépendances et ne contacte pas un service de modèle. Mettre les caches/home nécessaires dans les volumes écrits, pas dans la racine en lecture seule.

Les builds vérifient qu'aucun binaire ou dump provenant du jeu n'a été copié dans une couche. Ils produisent un SBOM par image et enregistrent les deux digests dans le lock d'outillage après validation. Une image construite avec un `tools.lock.json` à l'état `unresolved` peut exécuter les tests d'infrastructure, mais refuse toute analyse réelle qui dépend d'un outil non verrouillé.

Les outils GUI ne sont pas obligatoires : utiliser leurs interfaces CLI/bibliothèques disponibles et testées. Une fonctionnalité exclusivement graphique doit être remplacée par un adaptateur scriptable ou explicitement sortie du périmètre automatique.

## Exécution

Monter les données de jeu et le manifeste Steam uniquement dans `capture`, en lecture seule. Monter `inputs` en lecture-écriture dans `capture`, puis en lecture seule dans `analyzer`. Monter l'état, les artefacts et les sorties en lecture-écriture uniquement où ils sont nécessaires. Utiliser un UID non privilégié, supprimer les capabilities Linux inutiles, ne pas monter le socket Docker, et désactiver le réseau après la construction. [S22, S28]

Utiliser six volumes nommés : entrées propriétaires capturées (`inputs`), registre/home (`state`), artefacts générés adressés par contenu (`artifacts`), projets Ghidra (`ghidra`), caches (`cache`) et travail transitoire (`work`). Le préfixe littéral `ANIIMO_VOLUME_PREFIX` inclut son séparateur ; sa valeur par défaut `aniimo-` produit notamment `aniimo-inputs` et `aniimo-state`. Seul `output` reste un bind mount destiné à l'utilisateur. Cette séparation évite de placer SQLite et les projets Ghidra sur un partage NTFS de Docker Desktop et permet de nettoyer `work` ou `cache` sans toucher aux preuves ni aux entrées.

Le volume `inputs` est append-only pendant le MVP, hors publication atomique du pointeur `current`. Aucun nettoyage automatique n'est permis tant qu'un pinset conservateur des snapshots référencés par `state` n'a pas été exporté et validé. L'analyseur ne reçoit jamais un accès en écriture temporaire à `inputs` pour effectuer ce nettoyage.

Les Dockerfiles créent leurs points de montage avec les UID/GID fournis comme arguments de build, avant le passage à l'utilisateur non privilégié : `/inputs` dans les deux images, puis `/state`, `/artifacts`, `/ghidra-state`, `/cache` et `/work` dans `analyzer`. Ainsi, même un `doctor` lancé avant la première capture ne crée pas `inputs` avec une propriété incompatible. Compose transmet les mêmes valeurs au build et à `user`. Un volume déjà créé avec une autre identité n'est jamais réparé silencieusement : `doctor` indique les chemins non inscriptibles et la procédure explicite de migration ou de correction.

Les valeurs de départ Aniimo sont 4 CPU/4 Gio pour `capture`, puis 12 CPU/32 Gio et 24 Gio de heap Ghidra pour `analyzer`, sur la machine de 96 Gio disponible. Elles sont configurables. `MODKIT_GHIDRA_MAX_HEAP` est un contrat du futur wrapper `modkit`, pas une variable supposée native de Ghidra : le wrapper doit la traduire vers le mécanisme réellement validé pour la version verrouillée. Le préflight automatique vérifie les marges mémoire, les permissions, l'espace de chaque volume et le caractère réellement read-only de `/inputs` côté analyse ; le doctor stable vérifie outils et adaptateurs depuis son cache. `capture` hache un candidat inchangé sans l'écrire, et diffuse un fichier nouveau ou dont les métadonnées ont changé vers une zone de staging du volume `/inputs` tout en le hachant. `/tmp` ne reçoit que de petits temporaires ; `analyzer` place ses gros temporaires sous `/work/tmp/analyzer`.

Créer sur l'hôte le dossier `output` avec des permissions compatibles avec l'UID/GID choisi. Fournir plus tard `modkit state export` et `modkit state import` pour sauvegarder/restaurer le registre et les manifests sans publier les objets propriétaires du jeu par défaut.

Définir `GAME_DIR` et `STEAM_APP_MANIFEST` dans un fichier `.env` local non commité ; ils doivent désigner l'installation et `appmanifest_4126040.acf`. Sous Windows, utiliser de préférence des chemins avec `/` dans `.env`. Compose ne transmet ces chemins qu'à `capture` ; ils ne doivent même pas être visibles dans la configuration effective d'`analyzer`.

Le manifeste Steam est une preuve auxiliaire. La capture compare l'état de chaque payload avant et après son unique lecture normale ; en cas de changement elle réessaie une fois, puis refuse la capture. Les archives Lua actives peuvent évoluer indépendamment de Steam et sont donc hachées comme composants séparés ; le feature set `lua` est activé par défaut.

## Budget de vérification courant

Une capture ordinaire ne lance ni décompression, ni extraction, ni outil d'analyse. Une analyse ordinaire commence par les clés de cache complètes ; un hit saute l'étape et ne réécrit pas sa sortie. Sur miss, Ghidra et BSim sont activés dans leur périmètre autorisé. Les contrôles par run se limitent au parsing, aux entrées requises, à la stabilité de lecture, aux SHA-256 des payloads activés, à la cohérence du manifeste et à la publication atomique.

Les petits tests unitaires/contractuels sur fixtures synthétiques s'exécutent après un changement de code ou de configuration. Les tests de compatibilité d'outils, grosses fixtures, analyses réelles de référence, sondes runtime et matrice d'acceptation complète sont réservés aux jalons concernés ou à une release explicite.

## Rapport d'exécution

La capture attribue un `run_id`, écrit son fragment de mesures sous `/inputs/run-reports/<run_id>.json`, puis place ce `run_id` dans la partie opérationnelle de `/inputs/current.json`. Ce fragment est append-only mais n'entre ni dans le hash du snapshot ni dans les clés de cache. L'analyseur le fusionne avec ses mesures et publie atomiquement `/output/reports/<run_id>/run-report.json`, `report.md`, `timings.csv` et le pointeur `/output/reports/latest.json`.

Le JSON conserve la hiérarchie complète via `step_id` et `parent_step_id`, y compris préflight/doctor, plans de capture et d'analyse, puis toutes les étapes de traitement. Pour chaque étape/sous-étape : catégorie, composant, statut, raison, cache hit/miss, outil/version, timestamps muraux informatifs, durée issue d'une horloge monotone, éléments et octets lus/écrits, temps CPU et pic RSS lorsqu'ils sont disponibles à faible coût. Le CSV est une vue plate de ces mêmes données. Le Markdown présente les totaux, le chemin critique, les étapes les plus lentes, les cache misses, erreurs et limites.

La somme des durées n'est pas assimilée au temps mural lorsque des tâches se chevauchent. L'instrumentation se limite aux mesures locales et statistiques déjà disponibles ; elle ne relit aucun payload et ne lance aucun test supplémentaire.

## Codes de sortie proposés

`0` : commande terminée dans son périmètre déclaré.

`2` : profil/outil/entrée manquante ou incompatible.

`3` : capture incohérente, verrou ou entrée modifiée pendant lecture.

`4` : échec d'analyse obligatoire ou violation de schéma.

`5` : validation/capacité demandée non satisfaite.

`6` : autorisation externe demandée pour une publication mais absente, expirée ou ne visant pas l'artefact exact.

Pour `analyze`, le code 0 ne veut pas dire que tous les mods sont compatibles. Le rapport contient séparément le statut de l'analyse, ses trous de couverture et l'approbation runtime. Une capacité requise par un profil de livraison doit être validée par une commande de vérification avant publication.
