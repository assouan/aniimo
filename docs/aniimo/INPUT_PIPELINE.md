# Chaîne d'entrées Aniimo

## Trois niveaux distincts

1. `profiles/aniimo.inputs.yaml` décide quels fichiers de l'installation peuvent être observés ou copiés.
2. `profiles/aniimo.decompilation.yaml` décide quelles catégories peuvent recevoir une approbation de décompilation.
3. `scope-plan.json`, produit pour un snapshot réel, contient les décisions exactes par composant, assembly, type ou corps.

Un fichier peut donc être capturé pour identifier une version ou résoudre un import tout en restant `reference_only`, `excluded` ou `needs_review`.

## Modes de la liste d'entrées

| Mode | Lit tout le corps | Conserve le corps dans `aniimo-inputs` | Usage |
|---|---:|---:|---|
| `payload_rules` | oui, une fois par tentative | oui, par SHA-256, uniquement si l'objet est nouveau | détection, référence ou analyse autorisable |
| `inventory_rules` | non ; métadonnées bornées seulement | non | découverte, identité PE et rôle d'un module |
| aucune règle | non | non | ignoré |

Le workflow Aniimo active par défaut `core`, `lua`, `content_indexes` et `anti_cheat`. Il contient l'exécutable, les preuves Unity minimales, les alternatives Mono/IL2CPP, quelques noms exacts de symboles de debug, le `SymbolMap` optionnel, les modules d'intégration candidats, les archives Lua, les petits index de contenu et les quatre composants anti-cheat connus. `NEP2.dll`, `NEPKernel.sys`, `NEPCleaner.exe` et `KernelDumpAnalyzer.exe` sont copiés et hachés une fois comme payloads complets ; la politique de décompilation les approuve comme modules entiers. Les PDB `NEP*.pdb` et `KernelDumpAnalyzer.pdb` sont également retenus s'ils existent afin de privilégier les symboles correspondants avant Ghidra. `SymbolMap` ne contribue aux limites/adresses que s'il correspond au module exact. Les autres PDB sont seulement inventoriés. Pour les fichiers inventoriés, `signer_fingerprint` désigne seulement l'empreinte du certificat embarqué lorsqu'il existe, pas une validation Authenticode qui relirait tout le fichier.

Les quatre feature sets restent désactivables pour un diagnostic ciblé, mais aucun argument n'est nécessaire pour obtenir la capture complète prévue. Les assets généraux, sauvegardes, journaux, captures d'écran et plugins de mods ne sont jamais pris implicitement.

## Passage entre conteneurs

```text
Steam RO ──> capture ──RW──> aniimo-inputs ──RO──────────> analyzer
                       └──RW──> aniimo-handoff ──claim RW──┘
```

`capture` publie les objets, le manifeste et le snapshot immuable, puis une remise atomique contenant le `workflow_run_id`, le `snapshot_id` exact et le digest du manifeste. `analyzer` revendique cette remise avant l'analyse et refuse toute discordance. `current.json` reste un raccourci pour les commandes manuelles ; le workflow Compose ne s'en sert pas. Un slot occupé est refusé et les orchestrations concurrentes doivent utiliser des valeurs `ANIIMO_HANDOFF_SLOT` distinctes. L'analyseur ne tente jamais de revenir au dossier Steam.

Pour chaque payload activé, la capture effectue une seule lecture normale avec SHA-256 et compare les métadonnées avant/après cette lecture. Si le fichier bouge pendant la lecture, une seule nouvelle tentative est permise, puis la capture échoue proprement. La capture ne décompresse rien.

Pour un candidat inchangé, les octets sont envoyés au hacheur sans être réécrits dans le volume. Si le SHA-256 existe déjà, l'objet, les extractions et les analyses correspondantes sont réutilisés. Pour un fichier nouveau ou dont les métadonnées ont changé, le flux est haché pendant son écriture en staging, puis publié atomiquement. La date et la taille servent à choisir le chemin d'I/O, jamais à prouver l'identité du contenu.

## Chemin normal et contrôles explicites

Le chemin normal vise une commande Compose : préflight et doctor mis en cache, plan de capture, `capture`, plan d'analyse, puis `analyzer`. Ghidra et BSim sont activés par défaut, mais ne sont invoqués que si leur clé de cache est absente ou invalidée. Le refresh complet de `doctor`, la suite d'acceptation complète et les tests runtime restent explicites.

L'ASM d'un corps approuvé est exporté avant la tentative C lorsqu'une plage d'instructions est connue. Un échec C devient `asm_only` et sa tentative complète est mémorisée. Le profil limite la première passe à 15 secondes par corps et 16 timeouts, puis la file difficile automatique à deux corps et quatre minutes par run. Sans changement de corps, contexte, outils, types, prototype ou budget, le run suivant réutilise l'échec au lieu de le recalculer. Les résultats finaux sont réconciliés dans `coverage.json` et exposés par une vue lisible obligatoire.

Le plan de capture est toujours produit puis réutilisé sans second parcours. `capture --dry-run` emploie exactement ce plan et s'arrête simplement avant les hashes/copies ; il n'est donc ni nécessaire ni souhaitable de lancer un dry-run séparé avant chaque vraie capture.

Les seuls contrôles systématiques sont ceux qui empêchent un résultat corrompu : profil lisible, fichiers requis présents, SHA-256 des payloads activés, stabilité avant/après lecture, cohérence des paires, manifeste complet, clés de cache et publication atomique. Une étape lourde activée mais inchangée apparaît comme `cache_hit` sans appel au décompilateur.

Chaque run publie un rapport JSON, Markdown et CSV sous `output/reports/<run_id>/`. Il décompose capture, hash, copie, extraction, Ghidra, décompilation, BSim, génération et publication en étapes/sous-étapes avec durée, statut, cache hit/miss, volumes traités et ressources disponibles. Le rapport mesure le workflow ; il n'ajoute pas de tests cachés.

Un inventaire secondaire borné exploite seulement les manifestes capturés, `ScriptingAssemblies.json`, les imports PE et références observées. Il publie `additional-input-candidates.json` et les zones inspectées, sans hacher ou retenir les corps candidats, ni décompresser tous les assets.

## Ajouter un fichier

1. Laisser l'inventaire signaler le chemin sans en copier le corps.
2. Justifier son rôle et déterminer s'il s'agit d'une cible décompilable, d'une dépendance `reference_only`, ou d'un composant moteur/runtime à exclure. Les modules anti-cheat explicitement autorisés sont des cibles complètes.
3. Ajouter une règle dotée d'un `id` stable, d'un feature set et d'un nombre maximal de correspondances.
4. Exécuter le futur `capture --dry-run` seulement pour revoir un changement de liste, sa taille et ses chemins.
5. Classer le composant dans le nouveau `scope-plan.json`. Ne jamais déduire `game_decompile` du seul ajout à l'allowlist.
