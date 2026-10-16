# ADR 0008 — Sortie native, couverture et reprise bornée

- Statut : accepted
- Date : 2026-10-16
- Amende : ADR 0007

## Contexte

Une erreur ou un timeout du décompilateur C ne doit pas faire disparaître le désassemblage disponible. De plus, traiter toutes les fonctions déjà reconnues ne prouve pas que toutes les fonctions pertinentes ont été découvertes. Enfin, retenter à chaque update les mêmes corps difficiles rendrait le chemin quotidien inutilement lent.

## Décision

Pour chaque corps natif approuvé dont les instructions sont disponibles, l'exporteur produit l'ASM avant ou indépendamment du C. Un corps possède exactement un état : `c_and_asm`, `asm_only`, `disassembly_failed` ou `pending`. Un fichier C vide, tronqué ou constitué d'un diagnostic n'est jamais valide. Les avertissements Ghidra restent associés à la tentative et un échec local n'arrête pas les autres corps.

La couverture réconcilie exactement les corps approuvés avec ces quatre états. Elle recense séparément les méthodes attendues sans corps, cibles d'appels non résolues, candidats non confirmés et plages exécutables non attribuées. `coverage.json` et `native_bodies.csv` sont calculés depuis le registre.

Les échecs C sont des résultats de cache. Leur clé comprend corps/plage, contexte de références, outil/options, architecture/ABI, types/layouts, signature managée, prototype natif et classe de budget. Une tentative identique réutilise `asm_only`. Une reprise exige un changement pertinent ou une demande ciblée.

Le profil Aniimo applique une première passe de 15 secondes par corps, au plus 16 timeouts, puis une file automatique limitée à deux corps et 240 secondes par run. Les corps non encore tentés restent `pending` et progressent lors des updates suivantes. Ces valeurs sont configurables et mesurées dans le rapport. BSim sépare construction d'index et recherche ; une identité exacte n'entraîne aucune requête fuzzy.

La vue humaine est obligatoire : assembly → namespace → type → méthode lorsque l'origine managée est connue, sinon module → fonction avec un chemin stable pour les inconnues. Elle lie C, ASM, signatures, prototypes, références et diagnostics au corps canonique.

## Conséquences

- un échec C conserve une représentation utile sans bloquer le reste du corpus ;
- les mises à jour identiques ne repayent pas les mêmes timeouts ;
- la proportion de C peut progresser par reprises ciblées sans monopoliser le workflow normal ;
- « tous les corps identifiés traités » reste distinct de « aucune zone pertinente inconnue » ;
- le stockage par identifiant demeure canonique tandis que la navigation quotidienne reste lisible.
