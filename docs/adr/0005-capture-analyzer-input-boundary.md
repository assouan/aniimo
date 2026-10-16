# ADR 0005 — Frontière capture/analyse et volume d'entrées

- Statut : accepted, amendé par ADR 0006
- Date : 2026-10-16

## Contexte

L'analyseur n'a pas besoin de voir l'installation Steam complète. Lui donner ce bind mount élargirait inutilement son accès, permettrait à une étape longue de lire des fichiers modifiés en cours de mise à jour et encouragerait la copie de dizaines de Gio d'assets sans rapport avec le code.

Le préfixe de volumes choisi par l'utilisateur est `aniimo-`.

## Décision

Deux images et services sont séparés :

- `capture`, minimal, monte l'installation et le manifeste Steam en lecture seule ;
- `analyzer`, lourd, ne monte jamais Steam et reçoit le volume `inputs` en lecture seule.

`profiles/aniimo.inputs.yaml` est une allowlist bornée. Seuls ses `payload_rules` entrent dans le CAS `/inputs/objects/sha256`. Les règles d'inventaire ne copient aucun corps. ADR 0006 supprime le hash intégral par défaut des composants exclus et rend Lua et les index de contenu optionnels.

La politique `profiles/aniimo.decompilation.yaml` est indépendante. Un fichier capturé reste `needs_review` tant que les preuves M0 ne l'ont pas classé. `GameAssembly.dll` demeure un conteneur mixte.

Six volumes persistants utilisent le préfixe littéral : `aniimo-inputs`, `aniimo-state`, `aniimo-artifacts`, `aniimo-ghidra`, `aniimo-cache` et `aniimo-work`.

## Conséquences

- une mise à jour recopie seulement les nouveaux objets SHA-256 de l'allowlist ;
- l'analyse se déroule sur un snapshot stable même si Steam change ensuite ;
- ajouter un fichier demande une modification explicite de l'allowlist et une nouvelle capture ;
- capturer, référencer et décompiler restent trois décisions distinctes ;
- les entrées propriétaires et les artefacts générés ont des cycles de sauvegarde/nettoyage séparés.
