# Contrat Docker et interface CLI

## Statut

La CLI `modkit`, le Dockerfile et les scripts d'analyse sont à implémenter. `examples/compose.example.yaml` est un modèle de configuration, pas un service existant. Copier le modèle à la racine seulement après création de `docker/Dockerfile`, de la CLI et du profil réel.

## Interface cible

```sh
docker compose build analyzer
docker compose run --rm analyzer doctor
docker compose run --rm analyzer plan
docker compose run --rm analyzer update
docker compose run --rm analyzer diff --from <build-id> --to <build-id>
docker compose run --rm analyzer docs
docker compose run --rm analyzer verify --scope static
docker compose run --rm analyzer lua-import /observations/snapshot.json
```

Les mounts nécessaires à `lua-import` doivent être ajoutés explicitement. La sonde produit ses observations à l'extérieur du conteneur. Les commandes ci-dessus sont un contrat, pas la preuve qu'un outil `modkit` est déjà installé.

Le comportement par défaut du conteneur est un `update` ponctuel. Plus tard, un mode optionnel peut exécuter le même plan localement à intervalles configurables :

```sh
docker compose run --rm analyzer watch --interval 300
```

Le watcher n'est utile que tant que ce processus s'exécute. Prévoir arrêt propre, contrôle de fin d'installation, absence d'exécutions superposées et reprise des erreurs. Ne pas s'appuyer uniquement sur les notifications filesystem d'un montage hôte.

## Construction

Le Dockerfile installe les versions exactes de Python, Java/Ghidra, .NET et des extracteurs choisis. Les sources, releases, commits, checksums et versions sont consignés dans `tools.lock.json`. Les valeurs du lock ne sont remplies qu'après vérification ; aucun hash fictif. Les fixtures et tests de compatibilité sont exécutés lors de la validation de l'image.

Installer et initialiser les outils pendant la construction de l'image. Le runtime d'analyse ne télécharge rien, ne résout pas de nouvelles dépendances et ne contacte pas un service de modèle. Mettre les caches/home nécessaires dans les volumes écrits, pas dans la racine en lecture seule.

Les outils GUI ne sont pas obligatoires : utiliser leurs interfaces CLI/bibliothèques disponibles et testées. Une fonctionnalité exclusivement graphique doit être remplacée par un adaptateur scriptable ou explicitement sortie du périmètre automatique.

## Exécution

Monter les données de jeu et la configuration en lecture seule. Monter l'état et les sorties en lecture-écriture. Utiliser un UID non privilégié, supprimer les capabilities Linux inutiles, ne pas monter le socket Docker, et désactiver le réseau après la construction. Les options de montage et de service sont prises en charge par Compose. [S22]

Créer sur l'hôte les dossiers `state` et `output` avec des permissions compatibles avec l'UID/GID choisi. Les limites CPU/RAM du modèle sont des valeurs de départ configurables, pas une estimation de consommation pour le jeu.

Définir `GAME_DIR` dans un fichier d'environnement local non commité ; il doit désigner une installation complète et cohérente. Sous Windows, adapter le chemin au montage Docker Desktop/WSL utilisé. L'image Linux peut analyser des fichiers PE sans exécuter le jeu Windows.

## Codes de sortie proposés

`0` : commande terminée dans son périmètre déclaré.

`2` : profil/outil/entrée manquante ou incompatible.

`3` : capture incohérente, verrou ou entrée modifiée pendant lecture.

`4` : échec d'analyse obligatoire ou violation de schéma.

`5` : validation/capacité demandée non satisfaite.

Pour `update`, le code 0 ne veut pas dire que tous les mods sont compatibles. Le rapport contient séparément le statut de l'analyse, ses trous de couverture et l'approbation runtime. Une capacité requise par un profil de livraison doit être validée par une commande de vérification avant publication.
