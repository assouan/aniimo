# ADR 0007 — Mise à jour complète par défaut et rapport de performance

- Statut : accepted
- Date : 2026-10-16
- Amende : ADR 0006
- Amendé par : ADR 0008 et ADR 0009

## Contexte

Le workflow doit être utilisable sans connaître à l'avance la partie du jeu qui a changé. Une configuration minimale mais incomplète obligerait à relancer manuellement la capture pour Lua ou les index, puis à se souvenir d'activer Ghidra ou BSim. Cela réduit la simplicité recherchée et peut laisser une mise à jour partiellement analysée.

L'utilisateur veut également identifier les vrais goulots d'étranglement à partir de mesures, sans transformer chaque run en campagne de tests.

## Décision

Le profil Aniimo active par défaut les feature sets `core`, `lua`, `content_indexes` et `anti_cheat`. Ghidra et BSim sont également activés. Ces capacités restent configurables, mais une exécution standard couvre tout le périmètre configuré sans option supplémentaire.

« Activé » ne signifie pas « recalculé systématiquement ». Chaque étape calcule d'abord sa clé de cache complète. Un hit produit une sous-étape `cache_hit` et n'appelle pas l'outil. Ghidra ne travaille que sur les modules invalidés nécessaires au plan ; les exports restent limités aux cibles approuvées. BSim traite les corps approuvés du jeu, des intégrations et des modules anti-cheat explicitement listés ; ses résultats restent des candidats de rapprochement.

Compose enchaîne `capture`, puis `analyzer` uniquement après une capture réussie. Le chemin utilisateur cible une seule commande d'orchestration. Le conteneur d'analyse conserve `/inputs` en lecture seule et ne reçoit toujours aucun chemin Steam.

Le workflow lance à chaque fois un préflight léger. Les contrôles stables de `doctor` sont activés eux aussi, mais leur résultat est mis en cache d'après les digests des images, du lock d'outillage et du profil ; ils ne sont recalculés que lorsque cette base change. `doctor --refresh` reste disponible pour forcer le diagnostic complet.

Le planificateur de capture est toujours exécuté avant les écritures. La capture réelle consomme directement ce plan sans refaire l'inventaire. `capture --dry-run` n'est donc pas une vérification supplémentaire désactivée par défaut : c'est le même chemin qui s'arrête volontairement après le plan et avant les hashes/copies. Le plan d'invalidation de l'analyse suit le même principe.

Chaque workflow reçoit un `run_id`. La capture écrit un fragment opérationnel append-only dans `/inputs/run-reports/<run_id>.json`, sans l'inclure dans les identités de contenu. L'analyseur lit ce fragment, ajoute ses propres mesures et publie atomiquement :

- `/output/reports/<run_id>/run-report.json` pour l'automatisation ;
- `/output/reports/<run_id>/report.md` pour la lecture humaine ;
- `/output/reports/<run_id>/timings.csv` pour comparer et trier les coûts ;
- `/output/reports/latest.json` comme pointeur vers le dernier rapport complet.

Chaque étape et sous-étape possède un identifiant et un parent, un statut, son état de cache, une durée monotone, le nombre d'éléments et d'octets lus/écrits, l'outil invoqué et, lorsque disponible sans coût important, le temps CPU et le pic RSS. Les étapes sautées et les échecs restent visibles. Le rapport distingue temps mural, somme des durées et chemin critique afin de ne pas additionner naïvement des tâches parallèles.

Les tests d'acceptation et sondes runtime restent explicites : le rapport mesure le travail normal, il n'en ajoute pas.

## Conséquences

- une seule exécution standard observe aussi Lua et les index de contenu ;
- préflight, doctor mis en cache et plans de capture/analyse font partie de cette exécution ;
- Ghidra et BSim sont prêts sans option manuelle, mais un run inchangé reste un no-op d'analyse ;
- le premier run ou un module réellement modifié peut être long, ce qui apparaîtra précisément dans le rapport ;
- les coûts de hash, copie, extraction, auto-analyse, décompilation, BSim, génération et publication peuvent être comparés séparément ;
- ADR 0006 reste applicable pour la lecture unique, l'absence de décompression pendant la capture, les caches et les tests ciblés, mais ses anciens defaults optionnels sont remplacés ici.
