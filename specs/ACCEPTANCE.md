# Tests d'acceptation

Ces scénarios sont des exigences à implémenter ; ils n'ont pas été exécutés sur le jeu. Utiliser des fixtures synthétiques versionnées, puis deux builds autorisés du jeu dès qu'ils sont disponibles.

| ID | Modification / scénario | Résultat attendu |
|---|---|---|
| A01 | Première analyse | Inventaire, détection, catalogue, artefacts et rapport cohérents |
| A02 | Deuxième exécution strictement identique | Aucun appel au décompilateur, mêmes contenus et mêmes dates de modification des sorties existantes ; logs de run permis |
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
| A21 | Décompilateur timeout/crash | Échec local explicite, checkpoint utilisable et couverture honnête |
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

## Rapport d'acceptation

Le rapport contient le nombre de tests exécutés, réussis, échoués et non exécutés, les builds et outils utilisés, les logs associés et les limites. Ne pas calculer un pourcentage de couverture sur l'intégralité supposée du jeu : indiquer le dénominateur réellement connu.

Mesurer séparément le temps de hash/capture, extraction, auto-analyse, décompilation, matching et documentation. Le gain visé est vérifié expérimentalement ; aucune réduction universelle de temps n'est promise.

## Périmètre game-only

- Quand une méthode du jeu appelle `UnityEngine.Transform`, la signature du symbole externe peut apparaître comme référence, mais aucun corps Unity n'est exporté en `.c` ou `.cs` ni inclus dans la documentation d'implémentation du jeu.
- Pour IL2CPP, `GameAssembly.dll` peut être indexé/auto-analysé dans Ghidra ; les exports ciblent seulement les méthodes mappées au code du jeu, pas les méthodes .NET/Unity/libil2cpp du même module.
- Une assembly ou un corps natif de provenance incertaine reçoit `needs_review` et n'est pas décompilé automatiquement.
- Un traitement en mode `full` respecte exactement les mêmes exclusions de bibliothèque et moteur qu'un traitement incrémental.
- Les bibliothèques Lua standard sont référencées lorsqu'elles sont utilisées mais leurs sources ne sont pas décompilées ou dupliquées en documentation.
- Le rapport de périmètre contient les noms, décisions, raisons, décomptes d'éléments décompilés/référencés/exclus/à revoir et les exceptions autorisées.
