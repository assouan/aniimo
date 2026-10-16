# État du projet

Date de mise à jour : 2026-10-16

## Jalon courant

**M-1 — architecture du dépôt : terminé.**

Le dépôt possède désormais un contrat Aniimo explicite pour la capture immuable, le stockage adressé par contenu, le périmètre d'analyse approuvé, les volumes Docker persistants, la compatibilité par capacité et la séparation entre validation technique et autorisation externe d'un mod. ADR 0005 sépare le conteneur de capture du conteneur d'analyse ; ADR 0006 garantit l'incrémentalité ; ADR 0007 rend le workflow complet par défaut et impose son rapport de performance ; ADR 0008 garantit l'ASM, la couverture et la reprise bornée ; ADR 0009 attache chaque analyse à son snapshot exact.

Le jalon **M0 n'a pas commencé**. Aucun fichier de l'installation courante de `C:\Program Files (x86)\Steam\steamapps\common\Aniimo` n'a été inspecté ou exécuté pendant M-1. Les informations issues de `.sample` restent des observations historiques non vérifiées.

## Livré dans M-1

- profil dédié `profiles/aniimo.yaml`, fermé par défaut pour les composants inconnus et avec quatre modules anti-cheat complets explicitement préapprouvés ;
- allowlist bornée `profiles/aniimo.inputs.yaml` distincte de la politique `profiles/aniimo.decompilation.yaml`, avec `core`, `lua`, `content_indexes` et `anti_cheat` activés par défaut ;
- Ghidra et BSim activés par défaut sur leur périmètre autorisé, avec no-op obligatoire sur cache hit ;
- ASM exporté indépendamment du succès C, quatre états exclusifs de corps, avertissements conservés et poursuite après échec local ;
- échecs C cachés avec leur contexte, première passe de 15 s plafonnée à 16 timeouts et file difficile limitée à deux corps/240 s par run ;
- comptabilité de couverture à trois niveaux, `coverage.json`, `native_bodies.csv` et prototypes natifs séparés des signatures managées ;
- vue lisible obligatoire par assembly/namespace/type/méthode ou module/fonction, avec chemin stable pour les fonctions sans nom ;
- préflight léger automatique, contrôles stables de doctor cachés par digests et refresh complet explicite ;
- plans de capture et d'analyse automatiques et réutilisés ; `--dry-run` arrête le même plan avant écriture sans second inventaire ;
- `NEP2.dll`, `NEPKernel.sys`, `NEPCleaner.exe` et `KernelDumpAnalyzer.exe` copiés/hachés comme payloads et préapprouvés pour décompilation/documentation complète ;
- une lecture SHA-256 par payload et par tentative, contrôle avant/après, une seule nouvelle tentative en cas de dérive, aucune décompression pendant la capture ;
- cache no-op : un objet inchangé n'est pas recopié et une clé d'étape complète inchangée n'appelle ni extracteur, ni décompilateur, ni Ghidra/BSim ;
- services Compose séparés mais enchaînés par une commande : `capture` seul accès à Steam, puis `analyzer` avec `inputs` en lecture seule ;
- remise atomique du `snapshot_id` exact par slot ; le workflow normal n'analyse jamais le pointeur mutable `current` ;
- contrat de rapport par run : JSON, Markdown et CSV hiérarchiques avec timings, cache, volumes, outils, erreurs et ressources ;
- sept volumes nommés `aniimo-inputs`, `aniimo-handoff`, `aniimo-state`, `aniimo-artifacts`, `aniimo-ghidra`, `aniimo-cache` et `aniimo-work` ;
- ressources par défaut : 4 CPU/4 Gio pour la capture, puis 12 CPU/32 Gio et 24 Gio de heap Ghidra pour l'analyse ;
- isolation du contexte Docker et des données privées/générées via `.dockerignore` et `.gitignore` ;
- frontière entre installation mutable, capture cohérente, snapshot immuable et étapes d'analyse ;
- modèle de composants/révisions, décisions de périmètre, dépendances de capacités et autorisations runtime externes ;
- magic historique corrigé en IL2CPP standard, sans conclure sur le reste du format ; `SymbolMap` optionnel capturable et inventaire secondaire borné des nouveaux candidats ;
- ADR, synthèse des indices historiques Aniimo, exemples CSV et critères d'acceptation complémentaires ;
- verrou d'outillage explicitement `unresolved` plutôt que des versions ou checksums inventés ;
- tests de contrat du dépôt indépendants de `.sample`.

## Vérifications exécutées

| Commande | Résultat |
|---|---|
| `python -B -m unittest discover -s tests -v` | 10 tests exécutés, 10 réussis en 0,126 s |
| parsing et contrôles sémantiques PyYAML/CSV | 6 profils YAML et 18 en-têtes CSV valides ; 43 règles aux IDs uniques ; sélection/politique cohérentes et quatre états de corps exacts |
| `docker compose --project-directory . --env-file .env.example -f examples/compose.example.yaml config --quiet` | code de sortie 0 ; `analyzer` attend le succès de `capture`, ne voit pas Steam, reçoit `/inputs` read-only et utilise la remise obligatoire |
| parsing JSON de `tools.lock.json` | JSON valide |
| `git diff --check` | aucune erreur d'espacement |
| `git check-ignore -v` sur `.sample`, `.ainotes`, `.aitools`, `state`, `output`, `.env` et le profil runtime local | tous les chemins attendus sont ignorés |

Ces contrôles valident uniquement le contrat du dépôt. Ils ne lisent aucun gros fichier du jeu, ne lancent aucun conteneur d'analyse et ne constituent ni une analyse des composants anti-cheat, ni un test d'un hook. La matrice d'acceptation est un catalogue sélectionné par jalon, pas une suite exécutée à chaque update.

## Limites restantes

- aucun des deux Dockerfiles, paquet Python ou exécutable `modkit` n'existe encore ; le Compose décrit le contrat cible mais ne peut pas encore construire les services ;
- aucune détection Mono/IL2CPP, Unity, architecture, conformité des métadonnées ou bridge Lua n'a été effectuée sur le build installé ;
- la présence, le format et les relations des quatre composants anti-cheat préapprouvés restent à confirmer sur le snapshot courant ; aucune décompilation réelle n'a été exécutée ;
- les versions des outils d'analyse restent à tester puis à verrouiller ;
- aucun loader, DLL de mod, hook, test runtime ou dossier d'autorisation externe n'a été produit ;
- les schémas JSON et migrations SQLite ne seront créés qu'avec leur producteur M1, afin d'éviter des contrats fictifs non testés.

## Prochain jalon

**M0 — diagnostic Aniimo en lecture seule et matrice de compatibilité des outils.**

M0 devra produire `detection.json`, `scope-plan.json`, `tool-compatibility.json`, `additional-input-candidates.json` et un rapport lisible à partir d'un bundle d'acquisition cohérent contenant les seules entrées nécessaires, avec `anti_cheat` activé par défaut. Il devra confirmer les quatre composants connus, leurs formats et dépendances, tester la conformité réelle des métadonnées au-delà du magic standard, utiliser `SymbolMap` seulement s'il correspond au module, puis signaler tout composant supplémentaire. Il s'arrêtera avant l'implémentation du pipeline M1 et avant toute injection ou modification du jeu.
