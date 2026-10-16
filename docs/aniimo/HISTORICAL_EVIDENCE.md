# Aniimo — preuves historiques locales

## Statut

Ces éléments proviennent du lot local `.sample` observé le 16 octobre 2026. Ils servent à orienter M0 mais ne décrivent pas nécessairement l'installation actuelle. Aucun binaire ni pseudocode du jeu n'est versionné ici.

## Observations consignées

| Propriété | Observation historique | Statut courant |
|---|---|---|
| Steam App ID | `4126040` | indice à confirmer |
| Steam build ID | `25962016` | ancien build |
| Plateforme/architecture | Windows x86-64 | à redétecter |
| Unity | `2022.3.62f1` | à redétecter |
| Backend | IL2CPP | à redétecter |
| Bridge Lua | xLua | à redétecter |
| Assembly principale pressentie | `FunPlus.WorldX.Scripts.dll` | candidat de propriété |
| Métadonnées | magic standard IL2CPP `AF 1B B1 FA` (`0xFAB11BAF` little-endian) | conformité du reste du format actuel inconnue |
| Anti-cheat | NEP observé | cible complète explicitement autorisée ; présence et composition actuelles à confirmer |

Le lot ancien a exporté 511 310 fonctions pseudo-C sur 22 composants, dont de nombreuses bibliothèques tierces et composants NEP. Cette couverture volumique globale n'est pas un objectif du nouveau pipeline. La sélection porte sur les cibles approuvées après classification ; contrairement aux dépendances tierces génériques, les composants anti-cheat connus sont intégralement dans le périmètre autorisé.

## Limites de la cartographie historique

La table noms managés ↔ fonctions natives utilisait un ancien `dump.cs` indexé dans une base externe. Le couple exact `GameAssembly.dll`/`global-metadata.dat` ayant produit ce dump n'avait pas été archivé. L'alignement par fenêtres de deltas est donc une preuve candidate utile, mais pas une identité persistante ni une autorisation de hook.

L'ancien lot a aussi observé deux hashes complets de `GameAssembly.dll`, avec égalité de sections exécutables déclarée. Le nouveau pipeline conserve cette observation pour tester sa logique de capture et de provenance, mais exige un contexte de chargement plus complet avant toute réutilisation Ghidra.

## Entrées Aniimo à rechercher pendant M0

- `Aniimo.exe`, `GameAssembly.dll`, `UnityPlayer.dll` et métadonnées IL2CPP.
- `globalgamemanagers` pour la version Unity.
- Plugins natifs x86-64 et informations de signature/provenance.
- Archives Lua actives sous `Aniimo_Data/cvs` et copies intégrées sous `StreamingAssets`.
- Manifestes/version de contenu et `appmanifest_4126040.acf`.

Chaque résultat M0 indiquera s'il confirme, contredit ou laisse inconnue l'observation historique correspondante.

Le magic seul ne prouve ni un format personnalisé, ni une protection. M0 doit distinguer une version non prise en charge, des métadonnées incohérentes, une erreur de parsing et une protection suspectée, cette dernière qualification exigeant des preuves supplémentaires. [S31]
