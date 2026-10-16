# Unity Mod Workflow — dossier de conception

Ce dossier décrit le projet à faire implémenter par Codex. Il ne contient ni un décompilateur opérationnel, ni un loader prêt à installer, ni le code d'un jeu. Les commandes `modkit` et le service `analyzer` désignent l'interface cible à construire. Aucun binaire du jeu n'a été analysé pour préparer ce dossier.

## Utilisation

Copier ce dossier dans le dépôt du projet, conserver `AGENTS.md` à la racine, puis transmettre à Codex `CODEX_PROMPT.md`. Commencer par le jalon M0, puis M1. Ne pas lui demander de réaliser tous les jalons dans une seule modification.

Le premier livrable doit être un diagnostic réel des fichiers disponibles : backend Mono ou IL2CPP, plateforme, architecture, version Unity si identifiable, implémentation Lua, compatibilité des outils et périmètre. Sans fichiers réels, Codex doit construire et tester l'infrastructure avec des fixtures, sans inventer le diagnostic du jeu.

## Périmètre strict

Ce workflow ne décompile **que le code spécifique au jeu**. UnityEngine, UnityPlayer, .NET/Mono/IL2CPP, le moteur Lua et les bibliothèques tierces restent exclus de l'export d'implémentations ; seules leurs signatures et les références nécessaires sont consultées. Avec IL2CPP, `GameAssembly.dll` est inspecté comme conteneur mixte mais ses fonctions ne sont pas toutes décompilées. Les exceptions sont explicites et auditées. Voir `WORKFLOW.md` et le profil pour le détail des critères.

## Contenu

- `WORKFLOW.md` : architecture, pipeline, incrémentalité, Lua et SDK.
- `AGENTS.md` : invariants de développement et de preuve.
- `CODEX_PROMPT.md` : instruction de lancement et jalons.
- `specs/DATA_MODEL.md` : registre, identités, exports CSV et provenance.
- `specs/ACCEPTANCE.md` : scénarios de validation automatisables.
- `specs/DOCKER_CONTRACT.md` : contrat d'exécution et conditions d'exploitation.
- `examples/compose.example.yaml` : modèle Compose, non exécutable tant que le projet n'est pas implémenté.
- `profiles/game.example.yaml` : exemple de profil à adapter après détection.
- `examples/csv/` : en-têtes des exports demandés ; aucune donnée de jeu réelle.
- `examples/Player.api.lua` : illustration de définition LuaLS ; aucune API de jeu réelle.
- `SOURCES.md` : documentation primaire consultée le 16 octobre 2026.

## Décision centrale

Les sorties décompilées sont des artefacts reproductibles. La source de vérité est un registre de symboles et de preuves ; la surface consommée par les mods est une API stable, entretenue séparément des offsets et des types internes du jeu.

Les sauvegardes, journaux et données personnelles ne doivent pas être publiés. Conserver les binaires et le code décompilé en stockage local ou privé. Les publications de SDK et de documentation passent par une liste explicite de fichiers autorisés à distribuer.
