# ADR 0006 — Chemin par défaut léger et incrémental

- Statut : accepted, amendé par ADR 0007
- Date : 2026-10-16
- Amende : ADR 0001 et ADR 0005

## Contexte

Le coût principal vient de l'extraction et de l'analyse de gros modules, pas des petits contrôles de configuration. Une double lecture systématique, le hash intégral de composants exclus ou la réexécution d'une étape déjà en cache augmenteraient le temps courant sans améliorer le résultat utile.

## Décision

Les feature sets activés sont déclarés dans `profiles/aniimo.inputs.yaml`; ADR 0007 définit les defaults Aniimo complets.

Chaque payload activé est lu une fois par tentative. Sa taille et son identité de fichier sont observées avant et après la lecture, et SHA-256 est calculé sur le flux. Un changement pendant la lecture autorise une seule nouvelle tentative avant échec. Les métadonnées de date et taille peuvent optimiser la stratégie d'I/O, mais ne remplacent pas le hash de contenu.

Un candidat inchangé est haché sans être recopié. Si son objet SHA-256 existe, toutes les extractions, décompilations et sorties dont la clé de cache complète correspond sont réutilisées. Un objet nouveau ou manifestement modifié est haché pendant son écriture en staging puis publié atomiquement. La capture ne décompresse et n'analyse aucun payload.

Les composants exclus ou seulement référencés, notamment `UnityPlayer.dll` et les SDK FPX génériques, utilisent par défaut un inventaire de métadonnées bornées ; ils ne reçoivent plus un hash intégral sans besoin d'analyse explicite. Les quatre composants anti-cheat connus sont des cibles explicitement autorisées et suivent donc le chemin normal des payloads complets.

Une étape d'analyse activée consulte toujours sa clé de cache avant d'invoquer son outil. Le préflight et le résultat caché du doctor stable font partie du run ; seuls le refresh complet, l'arrêt volontaire après le plan (`--dry-run`), les sondes runtime et la suite d'acceptation complète restent explicites. Les tests automatiques courants utilisent de petites données synthétiques et ne lisent jamais les gros binaires du jeu.

## Conséquences

- le run sans changement lit une fois les payloads activés, puis n'appelle ni extracteur ni décompilateur et ne réécrit aucune sortie ;
- la signature Authenticode ou le nom d'un fichier ne suffisent pas à prouver l'égalité des octets ; SHA-256 reste l'identité de cache ;
- le choix des feature sets ne compromet pas l'incrémentalité des étapes aval ;
- une vérification plus lourde demeure disponible pour une release ou un diagnostic, mais n'allonge pas chaque mise à jour locale ;
- les anciens passages d'ADR 0001 imposant deux passes stables et d'ADR 0005 décrivant `fingerprint_only` sont remplacés par cette décision ; ADR 0007 active Lua, les index, Ghidra et BSim par défaut tout en conservant les garanties de cache et de lecture unique.
