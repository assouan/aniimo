# Tests d'acceptation

Ces scénarios forment un catalogue d'exigences ; ils n'ont pas été exécutés sur le jeu et ne constituent pas une suite monolithique à lancer après chaque mise à jour. Chaque jalon automatise uniquement le sous-ensemble directement concerné, avec de petites fixtures synthétiques. Les scénarios lourds sur builds autorisés, Ghidra ou runtime sont réservés à une validation explicite de jalon ou de release. Une capture/analyse ordinaire n'exécute aucun de ces tests en arrière-plan.

| ID | Modification / scénario | Résultat attendu |
|---|---|---|
| A01 | Première analyse | Inventaire, détection, catalogue, artefacts et rapport cohérents |
| A02 | Deuxième exécution strictement identique après une analyse complète | Aucun appel au décompilateur, mêmes contenus et mêmes dates de modification des sorties existantes ; logs de run permis |
| A03 | Changement du mtime sans changement de contenu | Pas de faux changement de code |
| A04 | Changement du contenu avec taille et mtime conservés | Détecté en mode strict par le hash du contenu |
| A05 | Dossier d'installation déplacé | Identités de build/symboles inchangées si les entrées logiques sont identiques |
| A06 | Une DLL sans lien avec une capacité change | La capacité n'est pas déclarée testée à nouveau sans test ; invalidations limitées aux dépendances prouvées |
| A07 | Binaire natif recompilé avec déplacements | Localisations mises à jour, pas de faux renommage fondé sur une RVA |
| A08 | Constante métier changée | Changement détecté, même si le graphe de contrôle est identique |
| A09 | Offset de champ modifié | Layout et consommateurs invalidés ; pas de réutilisation abusive du pseudocode/hook |
| A10 | Donnée globale changée, code identique | Dépendances et capacités concernées marquées à revalider |
| A11 | Cible d'appel changée à instruction similaire | Référence modifiée détectée |
| A12 | Token de métadonnées renuméroté | Identité logique conservée si la signature et les preuves concordent |
| A13 | Deux surcharges homonymes | IDs et chemins distincts ; paramètres correctement normalisés |
| A14 | Méthode renommée | Candidat de succession/alias ; aucune perte silencieuse des annotations |
| A15 | Méthode change de signature | Contrat interne marqué modifié ; pas de compatibilité SDK automatique |
| A16 | Plusieurs méthodes partagent un corps natif | Un corps canonique, plusieurs associations documentées |
| A17 | Méthode abstraite / extern / sans corps identifié | Statut distinct d'une erreur de décompilation |
| A18 | Signature d'octets donne deux candidats | Aucune installation automatique du hook ; ambiguïté rapportée |
| A19 | Correspondance fuzzy forte mais prototype contradictoire | Rejet/suspension, jamais une compatibilité automatique |
| A20 | Fonction native anonyme devient identifiable | Historique préservé après validation de la correspondance |
| A21 | Décompilateur timeout/crash | ASM déjà publié si les instructions sont disponibles, état `asm_only`, diagnostic/avertissements conservés, autres corps poursuivis |
| A22 | Arrêt du conteneur en cours d'écriture | `current.json` reste valide ; reprise sans fichier partiel publié |
| A23 | Deux runs simultanés | Verrou correct ; aucun double écrivain SQLite/Ghidra |
| A24 | Jeu en cours de mise à jour | Capture refusée ou analyse différée ; ne pas certifier un couple binaire/métadonnées incohérent |
| A25 | Mise à jour Ghidra ou extracteur | Invalidation des étapes dépendantes ; différence d'outillage séparée du changement de jeu |
| A26 | Modification d'une note documentaire | Seulement les pages dépendantes changent ; aucune décompilation |
| A27 | Modification d'un script Lua | Analyse du module et des dépendants ; autres sorties non affectées |
| A28 | Script source inchangé dans un bundle recompilé | Nouvelle extraction du conteneur mais réutilisation de l'artefact script identique |
| A29 | Fonction Lua non présente au menu, présente en partie | Contextes séparés ; aucune suppression déduite du snapshot menu |
| A30 | Fonction native Lua sans type connu | Signature inconnue/variadique, pas de types inventés à partir de debug.getinfo |
| A31 | Table Lua cyclique, getter avec effet de bord, __index dynamique | Parcours borné sans appel implicite non autorisé ; trous de couverture signalés |
| A32 | Bytecode Lua inconnu ou dialecte incompatible | `unsupported`, hash et preuve conservés, aucun faux succès |
| A33 | Métadonnées absentes ou format inconnu | Diagnostic actionnable, pas de catalogue complet fictif |
| A34 | Snapshot Lua provenant d'un autre build | Refus de fusion silencieuse ; conservation dans son historique d'origine |
| A35 | Nom de fichier/symbole path-traversal ou collision de casse | Sorties confinées au répertoire prévu, IDs non confondus |
| A36 | Export CSV contenant un nom ressemblant à une formule | Canonique fidèle ; vue tableur dédiée neutralisée et non réimportable |
| A37 | Jeu inédit lancé avec un ancien adaptateur | Hooks concernés désactivés tant que le build n'est pas validé |
| A38 | Ancien mod non recompilé avec nouvel adaptateur | Test de compatibilité binaire du contrat public, résultat enregistré |
| A39 | Erreur d'un callback / changement de scène | Nettoyage des abonnements, état sûr et pas d'accès à un objet détruit |
| A40 | Sonde ou test runtime non disponible | État `not_tested`, jamais `passed` |
| A41 | Mod serveur exige un asset absent des clients | Dépendance client explicitement signalée |
| A42 | Publication du SDK | Liste autorisée, aucun binaire du jeu, dump global ou donnée personnelle |
| A43 | Construction Docker depuis la racine contenant `.sample` | `.sample`, notes privées, caches, état et sorties absents du contexte et de toutes les couches |
| A44 | Exécution depuis un clone où `.sample` n'existe pas | `doctor`, fixtures et tests restent fonctionnels ; aucune dépendance cachée au lot historique |
| A45 | Manifeste Steam stable mais fichier modifié pendant capture | Une seule nouvelle tentative ; si la dérive persiste, capture refusée et aucun mélange d'états |
| A46 | `GameAssembly.dll` et métadonnées provenant de captures différentes | Couple rejeté comme incohérent, sans catalogue ni fallback approximatif |
| A47 | Magic standard IL2CPP présent mais parsing impossible | Distinguer version non prise en charge, incohérence, erreur de parsing et protection suspectée ; le magic seul ne prouve pas une protection et aucun faux catalogue vide n'est publié |
| A48 | Seul le certificat/signature PE change | Nouvelle provenance ; réutilisation uniquement après égalité de tout le contexte de chargement requis, pas de `.text` seule |
| A49 | Archive Lua active différente de la copie `StreamingAssets` | Deux révisions de composant distinctes, priorité/runtime documentés, diff ciblé |
| A50 | Asset sans dépendance d'une capacité modifié | Nouveau `build_id`; aucune capacité déclarée retestée, transfert seulement selon règle explicite et base identique |
| A51 | Dépendance exacte d'une capacité modifiée ou inconnue | Nouvelle base, capacité `requires_validation`/`unavailable`, hook désactivé |
| A52 | Assembly nommée `Assembly-CSharp` ou module au nom plausible sans autre preuve | Indice seulement ; `needs_review`, aucune décompilation automatique |
| A53 | UnityPlayer, xLua ou SDK tiers référencé par le jeu | Signature/référence disponible selon besoin, aucune implémentation exportée sans exception ciblée |
| A54 | Chemin absolu Windows déplacé ou nom utilisateur présent | Identités et exports canoniques inchangés ; aucun chemin absolu publié |
| A55 | Deux migrations SQLite successives puis restauration | Contraintes et références intactes ; échec atomique restaurable |
| A56 | Nettoyage du CAS avec snapshots publiés et approbations | Seuls les objets non référencés sont supprimables ; rapport de conservation vérifiable |
| A57 | Préfixe de volumes personnalisé | Tous les volumes persistants utilisent exactement ce préfixe, sans volume anonyme inattendu |
| A58 | Autorisation support/anti-cheat visant une ancienne DLL ou un autre hash | Non applicable au nouvel artefact ; état externe distinct de la compatibilité technique |
| A59 | Inspection de la configuration effective d'`analyzer` | Aucun chemin Steam/GAME_DIR ni bind mount du jeu ; `/inputs` est read-only |
| A60 | Inspection de la configuration effective de `capture` | Jeu et manifeste Steam read-only ; seul `inputs` reçoit les payloads |
| A61 | Fichier volumineux absent de `aniimo.inputs.yaml` | Corps non copié ; aucune lecture implicite par l'analyseur |
| A62 | Module découvert par une règle d'inventaire | Métadonnées bornées seulement ; état `needs_review`, pas de corps dans le volume |
| A63 | Deux captures avec un payload de SHA-256 identique | Objet d'entrée réutilisé, zéro recopie et nouveau snapshot seulement si le manifeste logique change |
| A64 | Remise absente/partielle, digest faux ou snapshot incomplet | `analyzer --handoff required` refuse l'analyse ; aucune utilisation de `current` ou de Steam en fallback |
| A65 | `ANIIMO_VOLUME_PREFIX=aniimo-` | Volumes `aniimo-inputs`, `aniimo-handoff`, `aniimo-state`, `aniimo-artifacts`, `aniimo-ghidra`, `aniimo-cache`, `aniimo-work` exactement |
| A66 | Exécution standard sans option de feature | `core`, `lua`, `content_indexes` et `anti_cheat` capturés ; Ghidra et BSim planifiés sur les seuls cache misses autorisés |
| A67 | Run réussi, partiellement caché ou en échec | Rapport hiérarchique JSON/Markdown/CSV avec chaque étape et sous-étape, durée monotone, statut, cache, volumes, outils et erreur éventuelle |
| A68 | Deux runs avec mêmes images, lock et profil | Préflight rapide rejoué ; contrôles doctor stables servis par le cache, sans smoke test d'outil répété |
| A69 | Dry-run puis vraie capture, ou vraie capture seule | Même planificateur et même sélection ; la vraie capture réutilise son plan dans le run sans second inventaire |
| A70 | Exécution standard avec les quatre composants anti-cheat connus présents | `NEP2.dll`, `NEPKernel.sys`, `NEPCleaner.exe` et `KernelDumpAnalyzer.exe` copiés/hachés une fois et planifiés pour décompilation/documentation complète ; PDB correspondants utilisés s'ils sont présents et valides |
| A71 | Deuxième exécution avec composants anti-cheat inchangés | Aucun nouvel appel Ghidra/décompilateur/BSim pour ces modules ; artefacts et documentation réutilisés |
| A72 | Un seul composant anti-cheat change | Nouvelle révision et analyse complète du module concerné ; invalidation limitée à ses sorties et consommateurs déclarés |
| A73 | Trois corps approuvés dont un partagé par deux méthodes | Trois artefacts canoniques par corps, quatre entrées lisibles, aucune duplication du corps partagé et liens C/ASM/références corrects |
| A74 | C valide, C en timeout, limites d'un troisième corps inconnues | États exclusifs `c_and_asm`, `asm_only`, `disassembly_failed` ou `pending` selon les preuves ; aucun C vide compté comme succès |
| A75 | Deuxième run strictement identique après un timeout C | Tentative `asm_only` servie par le cache, aucun nouvel appel coûteux pour ce corps ; d'autres corps encore `pending` peuvent progresser |
| A76 | Même méthode logique, corps entièrement remplacé | `symbol_id` conservé si l'identité métadonnée reste établie, nouvelle observation de corps/localisation et `body_changed` |
| A77 | Méthode attendue sans corps résolu | Méthode présente dans la couverture avec `body_resolution_status=unresolved`, distincte des états de décompilation |
| A78 | Rapport de couverture d'une petite fixture | Égalité exacte corps approuvés = `c_and_asm` + `asm_only` + `disassembly_failed` + `pending`; zones et cibles inconnues listées séparément |
| A79 | Deux captures entrelacées sur des slots distincts | Chaque analyse revendique et consomme son `snapshot_id` exact, indépendamment de la valeur de `current` |
| A80 | Deux captures utilisent simultanément le même slot | La seconde échoue sans écraser la remise en attente |
| A81 | `SymbolMap` présent mais ne correspondant pas au module | Fichier conservé comme preuve, aucune adresse/longueur importée dans le catalogue courant |
| A82 | Manifestes ou imports référencent un nouveau module hors allowlist | Chemin dans `additional-input-candidates.json`, zone inspectée documentée, aucun corps copié/haché/décompilé implicitement |

## Rapport d'acceptation

Le rapport contient le nombre de tests exécutés, réussis, échoués et non exécutés, les builds et outils utilisés, les logs associés et les limites. Ne pas calculer un pourcentage de couverture sur l'intégralité supposée du jeu : indiquer le dénominateur réellement connu.

Mesurer séparément le temps de hash/capture, extraction, auto-analyse, décompilation, matching et documentation. Le gain visé est vérifié expérimentalement ; aucune réduction universelle de temps n'est promise.

Le rapport indique aussi le snapshot exact utilisé, le nombre d'objets CAS créés/réutilisés, le préfixe des volumes, les ressources effectives, les migrations appliquées et la présence/absence d'une autorisation externe lorsque celle-ci fait partie de la commande demandée. Il distingue temps mural, somme des sous-étapes et chemin critique lorsque des travaux se chevauchent.

## Périmètre approuvé

- Quand une méthode du jeu appelle `UnityEngine.Transform`, la signature du symbole externe peut apparaître comme référence, mais aucun corps Unity n'est exporté en `.c` ou `.cs` ni inclus dans la documentation d'implémentation du jeu.
- Pour IL2CPP, `GameAssembly.dll` peut être indexé/auto-analysé dans Ghidra ; les exports ciblent seulement les méthodes mappées au code du jeu, pas les méthodes .NET/Unity/libil2cpp du même module.
- Une assembly ou un corps natif de provenance incertaine reçoit `needs_review` et n'est pas décompilé automatiquement.
- Un traitement en mode `full` respecte exactement les mêmes exclusions de bibliothèque et moteur qu'un traitement incrémental.
- Les bibliothèques Lua standard sont référencées lorsqu'elles sont utilisées mais leurs sources ne sont pas décompilées ou dupliquées en documentation.
- Le rapport de périmètre contient les noms, décisions, raisons, décomptes d'éléments décompilés/référencés/exclus/à revoir et les exceptions autorisées.
